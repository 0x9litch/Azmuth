"""
Azmuth SSH/SFTP connection layer (AsyncSSH 2.24.1).

Responsibilities:
- Establish and manage SSH connections.
- Verify remote host keys using SHA256 fingerprint pinning.
- Authenticate using the configured SSH private key (or one unlocked in memory).
- Install a public key with password auth (ssh-copy-id equivalent).
- Execute remote commands.
- Execute sudo commands using a password sent through SSH stdin.
- Manage remote files through SFTP.
- Classify SFTP permission and missing-path errors.
- Support directory creation, rename, stat and SHA-256 verification.

Host-key policy:
- First contact: capture the server fingerprint and reject the
  connection until the user explicitly confirms it.
- Later contacts: accept only an exact match with the saved fingerprint.
- A changed host key is rejected.

Security:
- No passwords or private keys are stored in the database.
- Sudo passwords are sent through SSH stdin, never command arguments.
- Sudo passwords are not written to application logs or audit records.
- Host-key verification is never disabled.
- Directory deletion is non-recursive.
- Rename refuses an existing destination.
"""

import asyncio
import contextlib
import errno
import os
import re
import shlex
import stat
import time

from pathlib import Path

import asyncssh
from .sanitize import clean_text, valid_remote_name


# ======================================================================
# Exceptions
# ======================================================================


class ConnectionErrorAzmuth(Exception):
    """Generic Azmuth connection error."""


class SFTPPermissionDenied(ConnectionErrorAzmuth):
    """
    Raised when an SFTP operation fails because of insufficient
    permissions.

    The backend can catch this exception and request a sudo password.
    """

    def __init__(self, operation, path, original=None):
        self.operation = operation
        self.path = path
        self.original = original

        super().__init__(f"Permission denied during {operation}: {path}")


class SFTPPathNotFound(ConnectionErrorAzmuth):
    """Raised when an SFTP operation references a missing path."""

    def __init__(self, operation, path, original=None):
        self.operation = operation
        self.path = path
        self.original = original

        super().__init__(f"Path not found during {operation}: {path}")


class SFTPPathExists(ConnectionErrorAzmuth):
    """Raised when an operation would overwrite an existing path."""

    def __init__(self, path):
        self.path = path
        super().__init__(f"Destination already exists: {path}")


class HostKeyPending(ConnectionErrorAzmuth):
    """Raised when a server's host key needs user confirmation."""

    def __init__(self, fingerprint):
        super().__init__(f"Unknown host key: {fingerprint}")
        self.fingerprint = fingerprint


class HostKeyMismatch(ConnectionErrorAzmuth):
    """Raised when a server presents a different host key."""

    def __init__(self, expected, presented):
        super().__init__(f"Host key mismatch (expected {expected}, got {presented})")
        self.expected = expected
        self.presented = presented


# OpenSSH allows 10 simultaneous channels (sessions) per connection by
# default (sshd_config MaxSessions). Every command and every SFTP operation
# uses one, so stay safely below that limit; extra work waits its turn.
MAX_CHANNELS_PER_CONNECTION = 6


def _channel_error(exc):
    """Readable message for a refused channel (asyncssh says 'open failed')."""
    if isinstance(exc, asyncssh.ChannelOpenError):
        return (
            "Server refused a new SSH channel (too many open sessions — "
            f"sshd MaxSessions). Details: {exc.reason}"
        )
    return str(exc)


# ======================================================================
# Command result
# ======================================================================


class CommandResult:
    """Result returned by a remote command."""

    def __init__(self, stdout, stderr, exit_code, duration):
        self.stdout = stdout
        self.stderr = stderr
        self.exit_code = exit_code
        self.duration = duration

    def to_dict(self):
        return {
            "stdout": self.stdout,
            "stderr": self.stderr,
            "exit_code": self.exit_code,
            "duration": self.duration,
        }


# ======================================================================
# SSH clients for host-key validation
# ======================================================================


class _FingerprintCaptureClient(asyncssh.SSHClient):
    """Capture an unknown server fingerprint and reject the connection."""

    def __init__(self):
        self.fingerprint = None

    def validate_host_public_key(self, host, addr, port, key):
        try:
            self.fingerprint = key.get_fingerprint("sha256")
        except Exception:
            self.fingerprint = None

        # First contact must never be accepted automatically.
        return False


class _PinnedKeyClient(asyncssh.SSHClient):
    """Accept a server only when its fingerprint matches the saved one."""

    def __init__(self, expected_fingerprint):
        self.expected = expected_fingerprint
        self.mismatch = None
        self.presented = None

    def validate_host_public_key(self, host, addr, port, key):
        try:
            presented = key.get_fingerprint("sha256")
        except Exception:
            presented = None

        self.presented = presented

        if presented is not None and presented == self.expected:
            return True

        self.mismatch = presented
        return False


# ======================================================================
# One SSH connection to one server
# ======================================================================


class ServerConnection:
    def __init__(self, host, port, username, key_path):
        self.host = host
        self.port = int(port)
        self.username = username
        self.key_path = key_path

        self.conn = None
        self.status = "disconnected"
        self.error = None
        self.fingerprint = None

        # Caps simultaneous channels on this connection (see constant).
        self._channels = asyncio.Semaphore(MAX_CHANNELS_PER_CONNECTION)

    # ------------------------------------------------------------------
    # Connection state
    # ------------------------------------------------------------------

    def is_connected(self):
        return self.conn is not None and not self.conn.is_closed()

    def _get_key_path(self):
        """Expand and validate the configured private-key path."""

        if not self.key_path:
            return None

        key_path = os.path.expanduser(str(self.key_path))

        if not Path(key_path).is_file():
            raise ConnectionErrorAzmuth(f"Private key not found: {key_path}")

        return key_path

    async def connect(self, expected_fingerprint, timeout=20, client_keys=None):
        """
        Connect using pinned host-key verification.

        client_keys: optional list of already-loaded asyncssh keys (e.g. a
        passphrase-protected key unlocked in memory). When omitted the
        configured key_path is used.
        """

        self.status = "connecting"
        self.error = None

        if expected_fingerprint is None:
            await self._first_contact(timeout)
            return False

        if client_keys is None:
            try:
                key_path = self._get_key_path()

            except ConnectionErrorAzmuth as exc:
                self.status = "error"
                self.error = str(exc)
                raise

            client_keys = [key_path] if key_path else None

        client = _PinnedKeyClient(expected_fingerprint)

        try:
            conn = await asyncssh.connect(
                host=self.host,
                port=self.port,
                username=self.username,
                known_hosts=asyncssh.import_known_hosts(b"\n"),
                client_factory=lambda: client,
                client_keys=client_keys,
                connect_timeout=timeout,
                login_timeout=timeout,
                keepalive_interval=30,
                keepalive_count_max=3,
            )

        except asyncssh.HostKeyNotVerifiable as exc:
            self.status = "error"

            presented = client.mismatch or client.presented or "unknown"

            self.error = f"Host key rejected: {presented}"

            raise HostKeyMismatch(
                expected_fingerprint,
                presented,
            ) from exc

        except asyncssh.PermissionDenied as exc:
            self.status = "error"
            self.error = f"Authentication failed: {exc}"

            raise ConnectionErrorAzmuth(self.error) from exc

        except (asyncssh.Error, OSError, asyncio.TimeoutError) as exc:
            self.status = "error"
            self.error = str(exc)

            raise ConnectionErrorAzmuth(str(exc)) from exc

        self.conn = conn
        self.status = "connected"
        self.error = None
        self.fingerprint = expected_fingerprint

        return True

    async def _first_contact(self, timeout):
        """
        Retrieve the server fingerprint without authenticating.

        The connection is intentionally rejected after the fingerprint
        is captured. The application must ask the user to trust it.
        """

        client = _FingerprintCaptureClient()

        try:
            await asyncssh.connect(
                host=self.host,
                port=self.port,
                username=self.username,
                known_hosts=asyncssh.import_known_hosts(b"\n"),
                client_factory=lambda: client,
                connect_timeout=timeout,
                login_timeout=timeout,
            )

        except asyncssh.HostKeyNotVerifiable:
            # Expected: the callback captures the fingerprint and
            # returns False to reject the unknown host.
            pass

        except (asyncssh.Error, OSError, asyncio.TimeoutError) as exc:
            self.status = "error"
            self.error = str(exc)

            raise ConnectionErrorAzmuth(str(exc)) from exc

        if client.fingerprint is None:
            self.status = "error"
            self.error = "Could not obtain host key fingerprint"

            raise ConnectionErrorAzmuth(self.error)

        self.fingerprint = client.fingerprint
        self.status = "disconnected"
        self.error = None

        raise HostKeyPending(client.fingerprint)

    async def disconnect(self):
        """Close the active SSH connection safely."""

        if self.conn is not None:
            try:
                self.conn.close()
                await self.conn.wait_closed()

            except Exception:
                pass

            finally:
                self.conn = None

        self.status = "disconnected"

    # ------------------------------------------------------------------
    # Remote command execution
    # ------------------------------------------------------------------

    async def _exec(self, command, timeout, input=None):
        """
        Run one command on its own channel and ALWAYS release the channel.

        If the caller is cancelled (e.g. the user switched tabs) or the
        timeout fires, the channel is closed explicitly; otherwise it would
        stay open on the server and count against MaxSessions.
        """
        process = None

        async def work():
            nonlocal process
            process = await self.conn.create_process(command, input=input)
            return await process.wait(check=False)

        async with self._channels:
            try:
                return await asyncio.wait_for(work(), timeout=timeout)
            finally:
                if process is not None:
                    try:
                        process.close()
                    except Exception:
                        pass

    @contextlib.asynccontextmanager
    async def _sftp(self):
        """An SFTP session that holds one channel slot while in use."""
        async with self._channels:
            async with self.conn.start_sftp_client() as sftp:
                yield sftp

    async def run_command(self, command, timeout=30):
        """Execute a normal remote command without interactive input."""

        if not self.is_connected():
            raise ConnectionErrorAzmuth("Not connected")

        start = time.monotonic()

        try:
            result = await self._exec(command, timeout)

        except asyncio.TimeoutError as exc:
            raise ConnectionErrorAzmuth(f"Command timed out after {timeout}s") from exc

        except (asyncssh.Error, OSError) as exc:
            raise ConnectionErrorAzmuth(_channel_error(exc)) from exc

        duration = time.monotonic() - start

        return CommandResult(
            # remote output may carry terminal escape sequences
            stdout=clean_text(result.stdout or ""),
            stderr=clean_text(result.stderr or ""),
            exit_code=(result.exit_status if result.exit_status is not None else -1),
            duration=duration,
        )

    async def run_sudo_command(self, command, password, timeout=30):
        """
        Execute a remote command through sudo using a password.

        The password is supplied through SSH stdin using sudo -S.
        It is never inserted into the remote command or its arguments.

        This method does not store or cache the password.

        The caller should first attempt a non-interactive sudo command
        (sudo -n). Only call this method when authentication is required.
        """

        if not self.is_connected():
            raise ConnectionErrorAzmuth("Not connected")

        if not isinstance(command, str) or not command.strip():
            raise ConnectionErrorAzmuth("Invalid sudo command")

        if not isinstance(password, str) or not password:
            raise ConnectionErrorAzmuth("Sudo password cannot be empty")

        if "\n" in password or "\r" in password:
            raise ConnectionErrorAzmuth(
                "Sudo password cannot contain newline characters"
            )

        sudo_command = f"sudo -S -p '' -- {command}"

        start = time.monotonic()

        try:
            result = await self._exec(sudo_command, timeout, input=password + "\n")

        except asyncio.TimeoutError as exc:
            raise ConnectionErrorAzmuth(
                f"Sudo command timed out after {timeout}s"
            ) from exc

        except (asyncssh.Error, OSError) as exc:
            # Never include the password in error messages.
            raise ConnectionErrorAzmuth(
                f"Sudo command execution failed: {_channel_error(exc)}"
            ) from exc

        duration = time.monotonic() - start

        return CommandResult(
            # remote output may carry terminal escape sequences
            stdout=clean_text(result.stdout or ""),
            stderr=clean_text(result.stderr or ""),
            exit_code=(result.exit_status if result.exit_status is not None else -1),
            duration=duration,
        )

    # ------------------------------------------------------------------
    # SFTP error classification
    # ------------------------------------------------------------------

    @staticmethod
    def _classify_sftp_error(operation, path, exc):
        """
        Convert common SFTP errors into specific Azmuth exceptions.

        SFTP v3 status codes:
            2 = No such file
            3 = Permission denied

        Also recognize local OSError errno values where applicable.
        """

        code = getattr(exc, "code", None)
        error_number = getattr(exc, "errno", None)

        try:
            code = int(code)
        except (TypeError, ValueError):
            code = None

        if code == 3 or error_number in (
            errno.EACCES,
            errno.EPERM,
        ):
            return SFTPPermissionDenied(
                operation,
                path,
                original=exc,
            )

        if code == 2 or error_number == errno.ENOENT:
            return SFTPPathNotFound(
                operation,
                path,
                original=exc,
            )

        return ConnectionErrorAzmuth(f"{operation} failed for {path}: {_channel_error(exc)}")

    # ------------------------------------------------------------------
    # SFTP metadata
    # ------------------------------------------------------------------

    @staticmethod
    def _attrs_to_dict(attrs):
        """Convert AsyncSSH SFTP attributes into a consistent dictionary."""

        permissions = attrs.permissions or 0

        return {
            "size": attrs.size or 0,
            "is_dir": stat.S_ISDIR(permissions),
            "is_file": stat.S_ISREG(permissions),
            "is_symlink": stat.S_ISLNK(permissions),
            "modified": int(attrs.mtime or 0),
            "permissions": permissions,
        }

    async def stat(self, remote_path):
        """Return metadata for a remote file or directory."""

        if not self.is_connected():
            raise ConnectionErrorAzmuth("Not connected")

        try:
            async with self._sftp() as sftp:
                attrs = await sftp.stat(remote_path)

            return self._attrs_to_dict(attrs)

        except (asyncssh.Error, OSError) as exc:
            raise self._classify_sftp_error(
                "Stat",
                remote_path,
                exc,
            ) from exc

    async def path_exists(self, remote_path):
        """
        Check whether a remote path exists.

        Returns False only when the server reports that the path
        does not exist. Permission and connection errors are not
        silently treated as a missing path.
        """

        try:
            await self.stat(remote_path)
            return True

        except SFTPPathNotFound:
            return False

    # ------------------------------------------------------------------
    # SFTP directory listing
    # ------------------------------------------------------------------

    async def list_dir(self, path):
        """List the contents of a remote directory."""

        if not self.is_connected():
            raise ConnectionErrorAzmuth("Not connected")

        entries = []

        try:
            async with self._sftp() as sftp:
                items = await sftp.readdir(path)

                for entry in items:
                    # AsyncSSH 2.24.1 returns SFTPName objects.
                    name = entry.filename
                    attrs = entry.attrs

                    if name in (".", "..") or not valid_remote_name(name):
                        continue  # '/' or NUL in a name = malicious server

                    metadata = self._attrs_to_dict(attrs)

                    entries.append(
                        {
                            "name": name,                 # exact, used for operations
                            "display": clean_text(name),  # safe, used for showing
                            "size": metadata["size"],
                            "is_dir": metadata["is_dir"],
                            "modified": metadata["modified"],
                            "permissions": metadata["permissions"],
                        }
                    )

        except (asyncssh.Error, OSError) as exc:
            raise self._classify_sftp_error(
                "List directory",
                path,
                exc,
            ) from exc

        entries.sort(
            key=lambda entry: (
                not entry["is_dir"],
                entry["name"].lower(),
            )
        )

        return entries

    # ------------------------------------------------------------------
    # SFTP upload / download
    # ------------------------------------------------------------------

    async def upload(self, local_path, remote_path):
        """
        Upload a local file to the remote server.

        AsyncSSH transfers the file without loading the complete
        contents into application memory.
        """

        if not self.is_connected():
            raise ConnectionErrorAzmuth("Not connected")

        local_path = os.path.expanduser(str(local_path))

        if not os.path.isfile(local_path):
            raise ConnectionErrorAzmuth(f"Local file not found: {local_path}")

        try:
            async with self._sftp() as sftp:
                await sftp.put(local_path, remote_path)

        except (asyncssh.Error, OSError) as exc:
            raise self._classify_sftp_error(
                "Upload",
                remote_path,
                exc,
            ) from exc

    async def download(self, remote_path, local_path):
        """
        Download a remote file to the local machine.

        AsyncSSH transfers the file without loading the complete
        contents into application memory.
        """

        if not self.is_connected():
            raise ConnectionErrorAzmuth("Not connected")

        local_path = os.path.expanduser(str(local_path))

        try:
            async with self._sftp() as sftp:
                await sftp.get(remote_path, local_path)

        except (asyncssh.Error, OSError) as exc:
            raise self._classify_sftp_error(
                "Download",
                remote_path,
                exc,
            ) from exc

    # ------------------------------------------------------------------
    # SFTP directory creation
    # ------------------------------------------------------------------

    async def make_directory(self, remote_path):
        """Create one remote directory."""

        if not self.is_connected():
            raise ConnectionErrorAzmuth("Not connected")

        try:
            async with self._sftp() as sftp:
                await sftp.mkdir(remote_path)

        except (asyncssh.Error, OSError) as exc:
            raise self._classify_sftp_error(
                "Create directory",
                remote_path,
                exc,
            ) from exc

    # ------------------------------------------------------------------
    # SFTP rename
    # ------------------------------------------------------------------

    async def rename(self, old_path, new_path):
        """
        Rename a remote file or directory.

        Refuses to proceed if the destination already exists.
        The UI/backend should ask the user before any overwrite.
        """

        if not self.is_connected():
            raise ConnectionErrorAzmuth("Not connected")

        try:
            async with self._sftp() as sftp:
                # Do not intentionally overwrite an existing destination.
                try:
                    await sftp.stat(new_path)

                except (asyncssh.SFTPNoSuchFile, asyncssh.SFTPNoSuchPath):
                    pass

                else:
                    raise SFTPPathExists(new_path)

                await sftp.rename(old_path, new_path)

        except SFTPPathExists:
            raise

        except (asyncssh.Error, OSError) as exc:
            raise self._classify_sftp_error(
                "Rename",
                old_path,
                exc,
            ) from exc

    # ------------------------------------------------------------------
    # SFTP deletion
    # ------------------------------------------------------------------

    async def delete_file(self, remote_path):
        """Delete one remote file."""

        if not self.is_connected():
            raise ConnectionErrorAzmuth("Not connected")

        try:
            async with self._sftp() as sftp:
                await sftp.remove(remote_path)

        except (asyncssh.Error, OSError) as exc:
            raise self._classify_sftp_error(
                "Delete file",
                remote_path,
                exc,
            ) from exc

    async def delete_dir(self, remote_path):
        """
        Remove an empty remote directory.

        This uses SFTP rmdir and is deliberately non-recursive.
        A non-empty directory will not be recursively deleted.
        """

        if not self.is_connected():
            raise ConnectionErrorAzmuth("Not connected")

        try:
            async with self._sftp() as sftp:
                await sftp.rmdir(remote_path)

        except (asyncssh.Error, OSError) as exc:
            raise self._classify_sftp_error(
                "Delete directory",
                remote_path,
                exc,
            ) from exc

    # ------------------------------------------------------------------
    # Remote file integrity
    # ------------------------------------------------------------------

    async def sha256_file(self, remote_path, timeout=60):
        """
        Calculate the SHA-256 checksum of a remote file.

        Uses sha256sum through SSH. The path is shell-quoted.
        Returns the hexadecimal digest only.
        """

        if not self.is_connected():
            raise ConnectionErrorAzmuth("Not connected")

        quoted_path = shlex.quote(str(remote_path))
        command = f"sha256sum -- {quoted_path}"

        result = await self.run_command(
            command,
            timeout=timeout,
        )

        if result.exit_code != 0:
            raise ConnectionErrorAzmuth(
                "SHA-256 calculation failed: "
                + (result.stderr.strip() or "remote command failed")
            )

        match = re.match(
            r"^([a-fA-F0-9]{64})\s+",
            result.stdout.strip(),
        )

        if not match:
            raise ConnectionErrorAzmuth("Could not parse remote SHA-256 result")

        return match.group(1).lower()


# ======================================================================
# Public-key installation (ssh-copy-id equivalent)
# ======================================================================

# Runs on the server. The public key arrives on stdin, never on the
# command line, so it cannot be shell-injected or seen in `ps`.
_INSTALL_KEY_SCRIPT = (
    "umask 077; "
    'mkdir -p "$HOME/.ssh" && chmod 700 "$HOME/.ssh" && '
    'f="$HOME/.ssh/authorized_keys"; touch "$f" && chmod 600 "$f" && '
    'IFS= read -r key && [ -n "$key" ] || exit 64; '
    # make sure an existing last line is newline-terminated before appending
    'if [ -s "$f" ] && [ -n "$(tail -c1 "$f")" ]; then echo >> "$f"; fi; '
    'if grep -qxF -- "$key" "$f"; then echo ALREADY_PRESENT; '
    'else printf \'%s\\n\' "$key" >> "$f" && echo INSTALLED; fi; '
    'command -v restorecon >/dev/null 2>&1 && restorecon -F "$HOME/.ssh" "$f" >/dev/null 2>&1; '
    "exit 0"
)


async def install_public_key(
    host,
    port,
    username,
    password,
    expected_fingerprint,
    public_key_line,
    timeout=20,
):
    """
    Append *public_key_line* to the user's ~/.ssh/authorized_keys using
    password authentication — what `ssh-copy-id` does.

    Security:
    - The server must present the already-trusted (pinned) host key;
      the password is never sent to an unverified host.
    - Only password / keyboard-interactive auth is attempted (no agent,
      no default keys), and the password is not stored anywhere.
    - Idempotent: an identical key line is not added twice.

    Returns "INSTALLED" or "ALREADY_PRESENT".
    """
    if not expected_fingerprint:
        raise ConnectionErrorAzmuth("Host key must be trusted before installing a key")

    if not password:
        raise ConnectionErrorAzmuth("Password is required to install the key")

    line = (public_key_line or "").strip()

    if not line.startswith(("ssh-", "ecdsa-", "sk-")) or "\n" in line:
        raise ConnectionErrorAzmuth("Invalid public key")

    client = _PinnedKeyClient(expected_fingerprint)

    try:
        conn = await asyncssh.connect(
            host=host,
            port=int(port),
            username=username,
            password=password,
            known_hosts=asyncssh.import_known_hosts(b"\n"),
            client_factory=lambda: client,
            client_keys=[],
            agent_path=None,
            preferred_auth=("keyboard-interactive", "password"),
            connect_timeout=timeout,
            login_timeout=timeout,
        )

    except asyncssh.HostKeyNotVerifiable as exc:
        presented = client.mismatch or client.presented or "unknown"
        raise HostKeyMismatch(expected_fingerprint, presented) from exc

    except asyncssh.PermissionDenied as exc:
        raise ConnectionErrorAzmuth(
            "Password rejected, or password login is disabled on the server "
            "(PasswordAuthentication no)."
        ) from exc

    except (asyncssh.Error, OSError, asyncio.TimeoutError) as exc:
        raise ConnectionErrorAzmuth(str(exc)) from exc

    try:
        result = await asyncio.wait_for(
            conn.run(_INSTALL_KEY_SCRIPT, input=line + "\n", check=False),
            timeout=timeout,
        )
    except (asyncssh.Error, OSError, asyncio.TimeoutError) as exc:
        raise ConnectionErrorAzmuth(f"Key installation failed: {exc}") from exc
    finally:
        conn.close()
        try:
            await conn.wait_closed()
        except Exception:
            pass

    output = (result.stdout or "").strip()

    if result.exit_status != 0 or output not in ("INSTALLED", "ALREADY_PRESENT"):
        detail = (result.stderr or "").strip() or f"exit {result.exit_status}"
        raise ConnectionErrorAzmuth(f"Key installation failed: {detail}")

    return output


# ======================================================================
# Connection manager
# ======================================================================


class ConnectionManager:
    def __init__(self):
        self.connections = {}
        self._locks = {}  # server name -> asyncio.Lock

    def _lock(self, name):
        lock = self._locks.get(name)
        if lock is None:
            lock = self._locks[name] = asyncio.Lock()
        return lock

    async def connect(
        self,
        name,
        host,
        port,
        username,
        key_path,
        fingerprint,
        client_keys=None,
    ):
        """
        Replace any previous connection object and establish a new one.

        Connects to the same server are serialized with a per-server lock:
        without it, two simultaneous connects (e.g. "c" pressed while
        "connect all" is running) each created an SSH connection, the
        second replaced the first in the table, and the first stayed open
        in the background, invisible and never closed.

        A failed connection will not leave an old connected object
        associated with this server name.
        """
        async with self._lock(name):
            existing = self.connections.get(name)

            # Someone else finished connecting while we waited: reuse it.
            if existing is not None and existing.is_connected():
                return existing

            old = self.connections.pop(name, None)

            if old is not None:
                await old.disconnect()

            conn = ServerConnection(
                host=host,
                port=port,
                username=username,
                key_path=key_path,
            )

            # Keep the new object even if connect() fails so the application
            # can inspect its status/error; the old connection is never kept.
            self.connections[name] = conn
            await conn.connect(fingerprint, client_keys=client_keys)

            # disconnect()/edit/delete may have removed this entry while the
            # handshake was in progress. Then nobody owns this connection:
            # close it instead of leaking it.
            if self.connections.get(name) is not conn:
                await conn.disconnect()
                raise ConnectionErrorAzmuth("Connection cancelled (server was disconnected or removed)")

            return conn

    async def disconnect(self, name):
        """Disconnect and remove one server connection."""

        conn = self.connections.pop(name, None)

        if conn is not None:
            await conn.disconnect()

    async def disconnect_all(self):
        """Disconnect all managed servers."""

        for name in list(self.connections.keys()):
            await self.disconnect(name)

    def get(self, name):
        return self.connections.get(name)

    def is_connected(self, name):
        conn = self.connections.get(name)

        return conn is not None and conn.is_connected()

    def get_status(self, name):
        conn = self.connections.get(name)

        if conn is None:
            return "disconnected"

        return conn.status
