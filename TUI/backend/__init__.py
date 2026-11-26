"""Application logic layer: one manager per feature, behind a Backend facade."""

from .backend import Backend
from .errors import BackendError, SudoAuthenticationFailed, SudoPasswordRequired
from .key_manager import KeyLocked

__all__ = [
    "Backend",
    "BackendError",
    "KeyLocked",
    "SudoAuthenticationFailed",
    "SudoPasswordRequired",
]
