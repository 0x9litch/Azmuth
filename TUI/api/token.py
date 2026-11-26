"""
API token: 256 random bits in a file only the owner can read.

    ~/.config/azmuth/          0700
    ~/.config/azmuth/api-token 0600

The web side reads the same file (same user on the same machine) or the
admin copies it into the ASP.NET configuration. Rotating it invalidates
every client at once.
"""

import os
import secrets
import stat
from pathlib import Path

CONFIG_DIR = Path(os.environ.get("XDG_CONFIG_HOME") or Path.home() / ".config") / "azmuth"
TOKEN_FILE = CONFIG_DIR / "api-token"


class TokenError(Exception):
    pass


def _check_private(path, want):
    mode = stat.S_IMODE(path.stat().st_mode)
    if path.stat().st_uid != os.getuid():
        raise TokenError(f"{path} is not owned by you")
    if mode & 0o077:
        os.chmod(path, want)  # fix over-permissive modes instead of failing


def load_or_create(path=TOKEN_FILE):
    path = Path(path)
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    _check_private(path.parent, 0o700)
    if path.exists():
        if path.is_symlink():
            raise TokenError(f"{path} is a symlink — refusing to use it")
        _check_private(path, 0o600)
        token = path.read_text(encoding="ascii").strip()
        if len(token) >= 32:
            return token
    return rotate(path)


def rotate(path=TOKEN_FILE):
    path = Path(path)
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    token = secrets.token_urlsafe(32)
    tmp = path.with_name(f".{path.name}.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w", encoding="ascii") as fh:
        fh.write(token + "\n")
    os.replace(tmp, path)
    return token
