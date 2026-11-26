"""
SFTP file operations with sudo fallback, plus server-to-server transfer.

Rules:
- Never overwrite without an explicit overwrite=True.
- Directory deletion is never recursive (rmdir only).
- Move deletes the source only after SHA-256 verification.
"""

import hashlib
import os
import re
import shlex
import stat as stat_mod
import tempfile
import uuid

from ..core import connection as conn_mod
from .base import BaseManager
from .errors import BackendError, CommandFailed, SudoPasswordRequired

TRANSFER_MODES = ("copy", "move")

# Exit code used by the no-overwrite upload when the destination appeared
# between the existence check and the move (see _upload_with_fallback).
EXIT_DESTINATION_EXISTS = 73
_STAGING_DIR = re.compile(r"^/tmp/\.azmuth-[A-Za-z0-9]{10}$")


def is_permission_error(exc):
    """
    Recognize the typed permission exception from the connection layer.

    The fallback checks common SFTP status attributes so permission errors
    are still recognized if the connection layer wraps the original error.
    """
    if isinstance(exc, conn_mod.SFTPPermissionDenied):
        return True

    code = getattr(exc, "code", None)

    if code is None:
        code = getattr(exc, "sftp_code", None)

    if code in (3, "3", "permission_denied", "FX_PERMISSION_DENIED"):
        return True

    message = str(exc).lower()
    return "permission denied" in message or "permission is denied" in message


def is_path_exists_error(exc):
    if isinstance(exc, conn_mod.SFTPPathExists):
        return True

    code = getattr(exc, "code", None)
    return code in (11, "11", "file_already_exists", "FX_FILE_ALREADY_EXISTS")


def _mv_no_clobber(src, dest):
    """
    Shell snippet: move src to dest without ever overwriting dest.

    `mv -n` changed behaviour between coreutils versions: older ones exit 0
    and silently skip, newer ones (>= 9.2) exit 1 with "not replacing".
    So its exit status is ignored and the outcome is checked directly:
      src gone                   -> moved (exit 0)
      src still there, dest too  -> destination exists (exit 73)
      src still there, no dest   -> some other failure (exit 1)
    Arguments must already be shell-quoted.
    """
    return (
        f"mv -n -- {src} {dest} 2>/dev/null; "
        f"if [ -e {src} ] || [ -L {src} ]; then "
        f"if [ -e {dest} ] || [ -L {dest} ]; then exit {EXIT_DESTINATION_EXISTS}; fi; "
        f"exit 1; fi"
    )


def _remove_quietly(path):
    try:
        if os.path.lexists(path):
            os.remove(path)
    except OSError:
        pass


class FileManager(BaseManager):
    # ------------------------------------------------------------------
    # helpers
    # ------------------------------------------------------------------
    async def _exists(self, name, remote_path, sudo_password=None):
        """
        Does *remote_path* exist?

        SFTP is tried first. If the parent directory is not readable by the
        SSH user (e.g. /root), SFTP answers "permission denied" — that is
        not an answer to the question, so ask again through sudo. This may
        raise SudoPasswordRequired, which makes the UI show the prompt.
        """
        connection = self.ctx.connection(name)

        try:
            return await connection.path_exists(remote_path)
        except conn_mod.ConnectionErrorAzmuth as exc:
            if not is_permission_error(exc):
                raise BackendError(str(exc)) from exc

        quoted = shlex.quote(remote_path)
        # -L as well: a dangling symlink still occupies the name.
        inner = f"if [ -e {quoted} ] || [ -L {quoted} ]; then echo yes; else echo no; fi"
        result = await self.ctx.run_privileged(
            name,
            f"sh -c {shlex.quote(inner)}",
            "check_destination",
            remote_path,
            sudo_password,
        )
        return (result.stdout or "").strip() == "yes"

    async def exists(self, name, remote_path, sudo_password=None):
        return await self._exists(name, remote_path, sudo_password)

    # ------------------------------------------------------------------
    # listing
    # ------------------------------------------------------------------
    async def list_dir(self, name, path):
        """List a remote directory using SFTP."""
        try:
            return await self.ctx.connection(name).list_dir(path)
        except conn_mod.ConnectionErrorAzmuth as exc:
            raise BackendError(str(exc)) from exc

    async def stat(self, name, path):
        try:
            return await self.ctx.connection(name).stat(path)
        except conn_mod.ConnectionErrorAzmuth as exc:
            raise BackendError(str(exc)) from exc

    # ------------------------------------------------------------------
    # create directory
    # ------------------------------------------------------------------
    async def make_dir(self, name, remote_path, sudo_password=None):
        """Create one remote directory, with sudo fallback."""
        connection = self.ctx.connection(name)

        try:
            await connection.make_directory(remote_path)

        except conn_mod.ConnectionErrorAzmuth as exc:
            if is_path_exists_error(exc):
                raise BackendError(
                    f"Directory or file already exists: {remote_path}"
                ) from exc

            if not is_permission_error(exc):
                raise BackendError(str(exc)) from exc

            await self.ctx.run_privileged(
                name,
                f"mkdir -- {shlex.quote(remote_path)}",
                "create_directory",
                remote_path,
                sudo_password,
            )

        self.audit("create_directory", name, "success", remote_path)
        return True

    # ------------------------------------------------------------------
    # rename
    # ------------------------------------------------------------------
    async def rename(self, name, old_path, new_path, sudo_password=None):
        """Rename a remote file or directory without overwriting."""
        connection = self.ctx.connection(name)

        if await self._exists(name, new_path, sudo_password):
            raise BackendError(f"Destination already exists: {new_path}")

        try:
            await connection.rename(old_path, new_path)

        except conn_mod.ConnectionErrorAzmuth as exc:
            if is_path_exists_error(exc):
                raise BackendError(f"Destination already exists: {new_path}") from exc

            if not is_permission_error(exc):
                raise BackendError(str(exc)) from exc

            # Check again immediately before the privileged operation.
            if await self._exists(name, new_path, sudo_password):
                raise BackendError(f"Destination already exists: {new_path}")

            script = _mv_no_clobber(shlex.quote(old_path), shlex.quote(new_path))
            try:
                await self.ctx.run_privileged(
                    name, f"sh -c {shlex.quote(script)}", "rename", old_path, sudo_password
                )
            except CommandFailed as failed:
                if failed.exit_code == EXIT_DESTINATION_EXISTS:
                    raise BackendError(f"Destination already exists: {new_path}") from failed
                raise

        self.audit("rename", name, "success", f"{old_path} -> {new_path}")
        return True

    # ------------------------------------------------------------------
    # private staging directory (for sudo uploads / downloads)
    # ------------------------------------------------------------------
    async def _private_dir(self, name):
        """
        A fresh directory only the SSH user (and root) can enter.

        Staging files directly in /tmp would expose them: /tmp is
        world-listable and the staged file is usually 0644, so any other
        user on the server could read e.g. a config with a password before
        sudo moves it. `mktemp -d` creates the directory with mode 0700.
        """
        res = await self.ctx.run(name, "mktemp -d /tmp/.azmuth-XXXXXXXXXX", timeout=15)
        path = res.stdout.strip()
        if res.exit_code != 0 or not _STAGING_DIR.match(path):
            raise BackendError(f"Could not create a private staging directory: {res.stderr.strip() or path!r}")
        return path

    async def _remove_dir(self, name, path, sudo_password):
        """Best effort. The user owns the 0700 dir, so it can delete what root left in it."""
        if not _STAGING_DIR.match(path or ""):
            return  # never rm -rf anything else
        try:
            res = await self.ctx.run(name, f"rm -rf -- {shlex.quote(path)}", timeout=15)
            if res.exit_code != 0 and sudo_password:
                await self.ctx.run_privileged(
                    name, f"rm -rf -- {shlex.quote(path)}", "staging_cleanup", path, sudo_password
                )
        except Exception:
            pass

    # ------------------------------------------------------------------
    # upload
    # ------------------------------------------------------------------
    async def _upload_with_fallback(
        self, name, local_path, remote_path, sudo_password=None, overwrite=False
    ):
        """
        Upload normally through SFTP.

        If destination permissions prevent the upload, stage the file in a
        private (0700) directory and move it into place through sudo.
        """
        connection = self.ctx.connection(name)
        local_path = os.path.expanduser(str(local_path))

        if not os.path.isfile(local_path):
            raise BackendError(f"Local file not found: {local_path}")

        if not os.access(local_path, os.R_OK):
            raise BackendError(f"Local file is not readable: {local_path}")

        if await self._exists(name, remote_path, sudo_password) and not overwrite:
            raise BackendError(f"Destination already exists: {remote_path}")

        try:
            await connection.upload(local_path, remote_path)
            return

        except conn_mod.ConnectionErrorAzmuth as exc:
            if not is_permission_error(exc):
                raise BackendError(str(exc)) from exc

        staging = await self._private_dir(name)
        temporary_path = f"{staging}/upload"

        try:
            # SFTP writes into the private staging directory.
            await connection.upload(local_path, temporary_path)

            temp = shlex.quote(temporary_path)
            dest = shlex.quote(remote_path)

            # The staged file belongs to the SSH user. Before it replaces
            # anything, give it the right owner and mode — otherwise e.g. a
            # file in /etc/sudoers.d/ would end up owned by the user and
            # sudo would refuse to run.
            #   existing file -> copy owner+mode from the file it replaces
            #   new file      -> root:root 0644, like any file made with sudo
            ownership = (
                f"if [ -e {dest} ]; then "
                f"chown --reference={dest} -- {temp} && chmod --reference={dest} -- {temp}; "
                f"else chown 0:0 -- {temp} && chmod 0644 -- {temp}; fi"
            )

            if overwrite:
                inner = f"{ownership} && mv -f -- {temp} {dest}"
            else:
                # Never overwrite a destination created after the existence
                # check (race); report it with a dedicated exit code.
                inner = f"{ownership} || exit 1; {_mv_no_clobber(temp, dest)}"

            try:
                await self.ctx.run_privileged(
                    name, f"sh -c {shlex.quote(inner)}", "upload", remote_path, sudo_password
                )
            except CommandFailed as exc:
                if exc.exit_code == EXIT_DESTINATION_EXISTS:
                    raise BackendError(f"Destination already exists: {remote_path}") from exc
                raise
        except conn_mod.ConnectionErrorAzmuth as exc:
            raise BackendError(str(exc)) from exc
        finally:
            # Best-effort cleanup; never hides the original error.
            await self._remove_dir(name, staging, sudo_password)

    async def upload(
        self, name, local_path, remote_path, sudo_password=None, overwrite=False
    ):
        """Upload a local file with permission-based sudo fallback."""
        details = f"{local_path} -> {remote_path}"

        try:
            await self._upload_with_fallback(
                name,
                local_path,
                remote_path,
                sudo_password=sudo_password,
                overwrite=overwrite,
            )
        except Exception:
            self.audit("upload", name, "failed", details)
            raise

        self.audit("upload", name, "success", details)
        return True

    # ------------------------------------------------------------------
    # download
    # ------------------------------------------------------------------
    async def _download_with_fallback(
        self, name, remote_path, local_path, sudo_password=None, overwrite=False
    ):
        """
        Download a remote file, safely.

        The data is written to a hidden ".azmuth-part-*" file next to the
        destination and only renamed over it (atomically) once complete.
        So an existing local file is never deleted or half-overwritten:
        if the download fails, is cancelled, or the sudo prompt is
        dismissed, the original stays exactly as it was.

        If the source is protected, a temporary copy is made with sudo,
        handed to the SSH user, downloaded, then removed.
        """
        connection = self.ctx.connection(name)
        local_path = os.path.abspath(os.path.expanduser(str(local_path)))
        parent = os.path.dirname(local_path)

        if not os.path.isdir(parent):
            raise BackendError(f"Local destination directory does not exist: {parent}")

        existed = os.path.exists(local_path)

        if existed and not overwrite:
            raise BackendError(f"Local destination already exists: {local_path}")

        if existed and not os.path.isfile(local_path):
            raise BackendError(f"Local destination is not a regular file: {local_path}")

        part_path = os.path.join(
            parent, f".{os.path.basename(local_path)}.azmuth-part-{uuid.uuid4().hex[:8]}"
        )

        try:
            privileged = False
            try:
                await connection.download(remote_path, part_path)

            except conn_mod.ConnectionErrorAzmuth as exc:
                if not is_permission_error(exc):
                    raise BackendError(str(exc)) from exc
                privileged = True
                _remove_quietly(part_path)
                await self._privileged_download(name, connection, remote_path, part_path, sudo_password)

            # Permissions of the final file:
            # - replacing a file -> keep that file's mode (a private 0600
            #   file must not become world-readable by being re-downloaded)
            # - new file fetched with sudo -> 0600, it was protected remotely
            if existed:
                os.chmod(part_path, stat_mod.S_IMODE(os.stat(local_path).st_mode))
            elif privileged:
                os.chmod(part_path, 0o600)

            os.replace(part_path, local_path)  # atomic on the same filesystem

        finally:
            _remove_quietly(part_path)

    async def _privileged_download(self, name, connection, remote_path, part_path, sudo_password):
        staging = await self._private_dir(name)
        temporary_path = f"{staging}/download"
        quoted_source = shlex.quote(remote_path)
        quoted_temp = shlex.quote(temporary_path)
        # root copies into the user's private 0700 directory, then hands the
        # copy to the SSH user (SUDO_UID/SUDO_GID = the calling user's ids,
        # so no user-name lookup on the server). Wrapped in `sh -c` so all
        # three steps run under sudo, not just cp.
        inner = (
            f"cp -- {quoted_source} {quoted_temp} && "
            'chown -- "${SUDO_UID:?}:${SUDO_GID:?}" ' + quoted_temp + " && "
            f"chmod 600 -- {quoted_temp}"
        )

        try:
            await self.ctx.run_privileged(
                name, f"sh -c {shlex.quote(inner)}", "download", remote_path, sudo_password
            )
            await connection.download(temporary_path, part_path)

        except conn_mod.ConnectionErrorAzmuth as exc:
            raise BackendError(str(exc)) from exc

        finally:
            await self._remove_dir(name, staging, sudo_password)

    async def download(
        self, name, remote_path, local_path, sudo_password=None, overwrite=False
    ):
        """Download a remote file with permission-based sudo fallback."""
        details = f"{remote_path} -> {local_path}"

        try:
            await self._download_with_fallback(
                name,
                remote_path,
                local_path,
                sudo_password=sudo_password,
                overwrite=overwrite,
            )
        except Exception:
            self.audit("download", name, "failed", details)
            raise

        self.audit("download", name, "success", details)
        return True

    # ------------------------------------------------------------------
    # delete
    # ------------------------------------------------------------------
    async def delete_file(self, name, remote_path, sudo_password=None):
        """Delete one remote file. Never recursively deletes directories."""
        await self._delete(
            name,
            remote_path,
            sudo_password,
            sftp_call=lambda c: c.delete_file(remote_path),
            command=f"rm -- {shlex.quote(remote_path)}",
            audit_action="delete_file",
            operation="delete_file",
        )
        return True

    async def delete_dir(self, name, remote_path, sudo_password=None):
        """Delete an empty remote directory (rmdir only, never rm -r)."""
        await self._delete(
            name,
            remote_path,
            sudo_password,
            sftp_call=lambda c: c.delete_dir(remote_path),
            command=f"rmdir -- {shlex.quote(remote_path)}",
            audit_action="delete_dir",
            operation="delete_directory",
        )
        return True

    async def _delete(
        self, name, remote_path, sudo_password, sftp_call, command, audit_action, operation
    ):
        connection = self.ctx.connection(name)

        try:
            await sftp_call(connection)

        except conn_mod.ConnectionErrorAzmuth as exc:
            if not is_permission_error(exc):
                self.audit(audit_action, name, "failed", remote_path)
                raise BackendError(str(exc)) from exc

            try:
                await self.ctx.run_privileged(
                    name, command, operation, remote_path, sudo_password
                )
            except SudoPasswordRequired:
                raise  # not a failure yet: the UI will ask for the password
            except Exception:
                self.audit(audit_action, name, "failed", remote_path)
                raise

        self.audit(audit_action, name, "success", remote_path)

    # ------------------------------------------------------------------
    # SHA-256
    # ------------------------------------------------------------------
    async def sha256(self, name, remote_path, sudo_password=None):
        """Calculate a remote file SHA-256 digest."""
        connection = self.ctx.connection(name)

        try:
            digest = await connection.sha256_file(remote_path)

            if isinstance(digest, str):
                digest = digest.strip().lower()

                if re.fullmatch(r"[a-f0-9]{64}", digest):
                    return digest

            raise BackendError("Connection returned an invalid SHA-256 digest")

        except conn_mod.ConnectionErrorAzmuth as exc:
            if not is_permission_error(exc):
                raise BackendError(str(exc)) from exc

        result = await self.ctx.run_privileged(
            name,
            f"sha256sum -- {shlex.quote(remote_path)}",
            "verify_transfer",
            remote_path,
            sudo_password,
        )

        match = re.match(r"^([a-fA-F0-9]{64})\s+", (result.stdout or "").strip())

        if not match:
            raise BackendError("Could not parse remote SHA-256 result")

        return match.group(1).lower()

    # ------------------------------------------------------------------
    # server-to-server transfer
    # ------------------------------------------------------------------
    async def transfer(
        self,
        source_server,
        source_path,
        destination_server,
        destination_path,
        mode="copy",
        sudo_passwords=None,
        overwrite=False,
        progress=None,
    ):
        """
        Transfer a regular file between two connected servers.

        The management machine is the coordinator:

            Source server -> temporary local file -> Destination server

        mode:
            copy - keep the source file
            move - delete the source only after SHA-256 verification

        sudo_passwords: optional temporary {server_name: password} dict,
        used only for this operation and never saved.

        progress: optional dict owned by the caller and reused across
        retries of the SAME transfer (e.g. after a sudo prompt). Completed
        steps are recorded in it, so a retry resumes where it stopped
        instead of copying again. Without it, a move whose final "delete
        source" step needed sudo would restart, find its own copy at the
        destination and wrongly report "already exists".
        """
        progress = progress if progress is not None else {}
        if mode not in TRANSFER_MODES:
            raise BackendError("Transfer mode must be 'copy' or 'move'")

        if source_server == destination_server:
            raise BackendError("Source and destination servers must be different")

        if not source_path or not destination_path:
            raise BackendError("Source and destination paths are required")

        source_connection = self.ctx.connection(source_server)
        self.ctx.require(destination_server)  # fail early if not connected

        passwords = sudo_passwords if isinstance(sudo_passwords, dict) else {}
        source_password = passwords.get(source_server) or None
        destination_password = passwords.get(destination_server) or None

        details = (
            f"{mode}: {source_server}:{source_path} -> "
            f"{destination_server}:{destination_path}"
        )

        try:
            if not progress.get("verified_digest"):
                progress["verified_digest"] = await self._copy_verified(
                    source_server,
                    source_connection,
                    source_path,
                    source_password,
                    destination_server,
                    destination_path,
                    destination_password,
                    overwrite,
                )

            # Move removes the source only after verification (and only once).
            if mode == "move" and not progress.get("source_deleted"):
                await self.delete_file(
                    source_server,
                    source_path,
                    sudo_password=source_password,
                )
                progress["source_deleted"] = True

        except SudoPasswordRequired:
            raise  # the UI asks for the password and retries with `progress`

        except Exception:
            self.audit("server_transfer", destination_server, "failed", details)
            raise

        local_digest = progress["verified_digest"]

        self.audit(
            "server_transfer",
            destination_server,
            "success",
            f"{details}; SHA-256 verified: {local_digest}",
        )

        return {
            "mode": mode,
            "source_server": source_server,
            "source_path": source_path,
            "destination_server": destination_server,
            "destination_path": destination_path,
            "sha256": local_digest,
            "verified": True,
        }

    async def _copy_verified(
        self,
        source_server,
        source_connection,
        source_path,
        source_password,
        destination_server,
        destination_path,
        destination_password,
        overwrite,
    ):
        """Source -> local staging -> destination, then SHA-256 verify. Returns the digest."""
        if (
            await self._exists(destination_server, destination_path, destination_password)
            and not overwrite
        ):
            raise BackendError(f"Destination already exists: {destination_path}")

        # Confirm that the source is a regular file.
        try:
            source_info = await source_connection.stat(source_path)

        except conn_mod.ConnectionErrorAzmuth as exc:
            if not is_permission_error(exc):
                raise BackendError(str(exc)) from exc

            # A privileged check is needed for protected source files.
            try:
                await self.ctx.run_privileged(
                    source_server,
                    f"test -f {shlex.quote(source_path)}",
                    "transfer_source_check",
                    source_path,
                    source_password,
                )
            except CommandFailed as inner:
                raise BackendError(
                    "Source is not a regular file or cannot be accessed"
                ) from inner
            source_info = {"is_file": True}

        if not source_info.get("is_file", False):
            raise BackendError("Server-to-server transfer supports regular files only")

        with tempfile.TemporaryDirectory(prefix="azmuth-transfer-") as staging_dir:
            staging_path = os.path.join(staging_dir, "transfer-" + uuid.uuid4().hex)

            # Step 1: source server -> management host.
            await self._download_with_fallback(
                source_server,
                source_path,
                staging_path,
                sudo_password=source_password,
                overwrite=False,
            )

            # Step 2: local SHA-256 in chunks.
            digest = hashlib.sha256()
            with open(staging_path, "rb") as staged_file:
                for chunk in iter(lambda: staged_file.read(1024 * 1024), b""):
                    digest.update(chunk)
            local_digest = digest.hexdigest()

            # Step 3: management host -> destination server.
            await self._upload_with_fallback(
                destination_server,
                staging_path,
                destination_path,
                sudo_password=destination_password,
                overwrite=overwrite,
            )

            # Step 4: verify destination contents.
            remote_digest = await self.sha256(
                destination_server,
                destination_path,
                sudo_password=destination_password,
            )

            if remote_digest != local_digest:
                raise BackendError(
                    "Transfer verification failed: SHA-256 mismatch. "
                    "The source file was not deleted."
                )

        return local_digest
