"""Core layer: persistence (SQLite) and SSH/SFTP transport (AsyncSSH)."""

from .connection import (
    CommandResult,
    ConnectionErrorAzmuth,
    ConnectionManager,
    HostKeyMismatch,
    HostKeyPending,
    ServerConnection,
    SFTPPathExists,
    SFTPPathNotFound,
    SFTPPermissionDenied,
)
from .database import Database, DatabaseError

__all__ = [
    "CommandResult",
    "ConnectionErrorAzmuth",
    "ConnectionManager",
    "Database",
    "DatabaseError",
    "HostKeyMismatch",
    "HostKeyPending",
    "ServerConnection",
    "SFTPPathExists",
    "SFTPPathNotFound",
    "SFTPPermissionDenied",
]
