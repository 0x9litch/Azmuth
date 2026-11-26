"""
Managed SSH key: generate, protect with a passphrase, unlock in memory.

Replaces running by hand:
    ssh-keygen -t ed25519 -f ~/.ssh/azmuth_ed25519 -C "azmuth"

Security model
--------------
- The private key is written with mode 0600 (directory ~/.ssh 0700),
  created with O_EXCL so an existing file is never overwritten.
- With a passphrase the file is encrypted in OpenSSH format
  (bcrypt KDF + aes256-ctr), exactly like ssh-keygen does.
- The passphrase is never written anywhere (not the DB, not the audit log).
- "Unlock" decrypts the key into RAM for this session only — the same
  idea as ssh-agent. "Lock" (or quitting) forgets it.
- Only the key *path* is stored, in the settings table.
"""

import asyncio
import importlib.util
import os
import stat

import asyncssh

from . import settings as S
from .base import BaseManager
from .errors import BackendError

DEFAULT_KEY_PATH = "~/.ssh/azmuth_ed25519"
DEFAULT_COMMENT = "azmuth"
MIN_PASSPHRASE_LENGTH = 8


class KeyLocked(BackendError):
    """The key is passphrase-protected and has not been unlocked yet."""

    def __init__(self, path):
        super().__init__(f"SSH key is locked: {path}")
        self.path = path


def normalize(path):
    return os.path.abspath(os.path.expanduser(str(path or "").strip()))


def _bcrypt_available():
    return importlib.util.find_spec("bcrypt") is not None


def _check_passphrase(passphrase):
    if passphrase and len(passphrase) < MIN_PASSPHRASE_LENGTH:
        raise BackendError(
            f"Passphrase must be at least {MIN_PASSPHRASE_LENGTH} characters"
        )
    if passphrase and not _bcrypt_available():
        raise BackendError(
            "Encrypted keys need the 'bcrypt' package: pip install bcrypt"
        )


def _write_exclusive(path, data, mode):
    """Create a new file with *mode*; fail if it already exists."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    try:
        os.write(fd, data)
        os.fsync(fd)
    finally:
        os.close(fd)
    os.chmod(path, mode)  # ignore umask


class KeyManager(BaseManager):
    def __init__(self, ctx, settings):
        super().__init__(ctx)
        self.settings = settings
        self._unlocked = {}  # normalized path -> asyncssh.SSHKey (RAM only)

    # ------------------------------------------------------------------
    # configuration
    # ------------------------------------------------------------------
    def configured_path(self):
        """Managed key path from settings, or None on first run."""
        return self.settings.get(S.KEY_PATH)

    def default_path(self):
        return self.configured_path() or DEFAULT_KEY_PATH

    def use_existing(self, path):
        """Adopt an existing private key as the managed key."""
        real = normalize(path)

        if not os.path.isfile(real):
            raise BackendError(f"Private key not found: {real}")

        self._tighten_permissions(real)
        self._read(real, None, allow_locked=True)  # validates the format
        self.settings.set(S.KEY_PATH, path)
        self.audit("ssh_key_select", None, "success", real)
        return real

    # ------------------------------------------------------------------
    # status
    # ------------------------------------------------------------------
    def status(self, path=None):
        path = path or self.default_path()
        real = normalize(path)
        info = {
            "path": path,
            "real_path": real,
            "exists": os.path.isfile(real),
            "public_exists": os.path.isfile(real + ".pub"),
            "encrypted": False,
            "unlocked": real in self._unlocked,
            "fingerprint": None,
            "comment": None,
            "error": None,
        }

        if not info["exists"]:
            return info

        try:
            key = self._read(real, None, allow_locked=True)
        except BackendError as exc:
            info["error"] = str(exc)
            return info

        info["encrypted"] = key is None

        source = self._unlocked.get(real) or key
        if source is None and info["public_exists"]:
            try:
                source = asyncssh.read_public_key(real + ".pub")
            except (OSError, asyncssh.KeyImportError):
                source = None

        if source is not None:
            info["fingerprint"] = source.get_fingerprint("sha256")
            info["comment"] = source.get_comment()

        return info

    def is_locked(self, path):
        real = normalize(path)
        if real in self._unlocked or not os.path.isfile(real):
            return False
        return self._read(real, None, allow_locked=True) is None

    # ------------------------------------------------------------------
    # generate / passphrase
    # ------------------------------------------------------------------
    async def generate(self, path=None, passphrase=None, comment=DEFAULT_COMMENT):
        """Create a new ed25519 key pair (never overwrites)."""
        path = path or DEFAULT_KEY_PATH
        real = normalize(path)
        _check_passphrase(passphrase)

        if os.path.lexists(real) or os.path.lexists(real + ".pub"):
            raise BackendError(f"{real} already exists — use it or choose another path")

        directory = os.path.dirname(real)
        os.makedirs(directory, mode=0o700, exist_ok=True)

        if os.path.basename(directory) == ".ssh":
            os.chmod(directory, 0o700)

        def work():
            key = asyncssh.generate_private_key("ssh-ed25519", comment=comment)
            private = key.export_private_key(
                "openssh", passphrase=passphrase or None
            )
            public = key.export_public_key("openssh")
            _write_exclusive(real, private, 0o600)
            try:
                _write_exclusive(real + ".pub", public, 0o644)
            except OSError:
                os.unlink(real)
                raise
            return key

        try:
            key = await asyncio.to_thread(work)  # bcrypt KDF is CPU-heavy
        except OSError as exc:
            raise BackendError(f"Cannot write key: {exc}") from exc

        if passphrase:
            self._unlocked[real] = key  # just typed it: start unlocked

        self.settings.set(S.KEY_PATH, path)
        self.audit(
            "ssh_key_generate",
            None,
            "success",
            f"{real} ({'encrypted' if passphrase else 'NO passphrase'})",
        )
        return key.get_fingerprint("sha256")

    async def change_passphrase(self, path, old, new):
        """Like `ssh-keygen -p`: re-encrypt in place (atomic replace)."""
        real = normalize(path)
        _check_passphrase(new)

        # Always prove the OLD passphrase from the file, even if the key is
        # unlocked in memory: someone at an unattended, unlocked session must
        # not be able to re-key (or strip the passphrase from) the key.
        key = await asyncio.to_thread(self._read, real, old or None)

        def work():
            data = key.export_private_key("openssh", passphrase=new or None)
            tmp = f"{real}.tmp-{os.getpid()}"
            try:
                _write_exclusive(tmp, data, 0o600)
                os.replace(tmp, real)
            finally:
                if os.path.exists(tmp):
                    os.unlink(tmp)

        try:
            await asyncio.to_thread(work)
        except OSError as exc:
            raise BackendError(f"Cannot rewrite key: {exc}") from exc

        if new:
            self._unlocked[real] = key
        self.audit(
            "ssh_key_passphrase",
            None,
            "success",
            f"{real} ({'encrypted' if new else 'passphrase removed'})",
        )

    # ------------------------------------------------------------------
    # unlock / lock
    # ------------------------------------------------------------------
    async def unlock(self, path, passphrase):
        real = normalize(path)
        key = await asyncio.to_thread(self._read, real, passphrase)
        self._unlocked[real] = key
        self.audit("ssh_key_unlock", None, "success", real)

    def lock_all(self):
        count = len(self._unlocked)
        self._unlocked.clear()
        if count:
            self.audit("ssh_key_lock", None, "success", f"{count} key(s) forgotten")
        return count

    def unlocked_count(self):
        return len(self._unlocked)

    # ------------------------------------------------------------------
    # used by the connection layer
    # ------------------------------------------------------------------
    def client_keys_for(self, key_path):
        """
        Return the client_keys list for asyncssh, or raise KeyLocked.
        Unencrypted keys are passed by path (unchanged behaviour).
        """
        real = normalize(key_path)

        if real in self._unlocked:
            return [self._unlocked[real]]

        if not os.path.isfile(real):
            raise BackendError(f"Private key not found: {real}")

        if self._read(real, None, allow_locked=True) is None:
            raise KeyLocked(key_path)

        return [real]

    def public_key_line(self, key_path):
        """The one-line public key to install on servers."""
        real = normalize(key_path)
        pub = real + ".pub"

        if os.path.isfile(pub):
            try:
                key = asyncssh.read_public_key(pub)
            except (OSError, asyncssh.KeyImportError) as exc:
                raise BackendError(f"Invalid public key {pub}: {exc}") from exc
        elif real in self._unlocked:
            key = self._unlocked[real]
        else:
            raise BackendError(f"Public key not found: {pub}")

        return key.export_public_key("openssh").decode().strip()

    # ------------------------------------------------------------------
    # internals
    # ------------------------------------------------------------------
    @staticmethod
    def _tighten_permissions(real):
        mode = stat.S_IMODE(os.stat(real).st_mode)
        if mode & 0o077:
            os.chmod(real, 0o600)

    @staticmethod
    def _read(real, passphrase, allow_locked=False):
        """
        Load a private key. With allow_locked=True an encrypted key read
        without a passphrase returns None instead of raising.
        """
        try:
            return asyncssh.read_private_key(real, passphrase)
        except asyncssh.KeyEncryptionError as exc:
            raise BackendError("Incorrect passphrase") from exc
        except asyncssh.KeyImportError as exc:
            message = str(exc).lower()
            if "passphrase" in message:
                if allow_locked:
                    return None
                raise BackendError("Passphrase required") from exc
            if "bcrypt" in message:
                raise BackendError(
                    "Encrypted keys need the 'bcrypt' package: pip install bcrypt"
                ) from exc
            raise BackendError(f"Unsupported or invalid key: {exc}") from exc
        except OSError as exc:
            raise BackendError(f"Cannot read key: {exc}") from exc
