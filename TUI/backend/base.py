"""
Shared plumbing for backend managers.

Every manager receives the same BackendContext, which owns:
- the Database and ConnectionManager,
- audit recording (never stores credentials),
- "is this server connected?" checks,
- plain and privileged (sudo) remote command execution.
"""

import getpass

from ..core import connection as conn_mod
from ..core import database as db_mod
from .errors import BackendError, CommandFailed, SudoAuthenticationFailed, SudoPasswordRequired
from ..diagnostics.redaction import redact


def _current_user():
    try:
        return getpass.getuser()
    except Exception:
        return "admin"


CURRENT_USER = _current_user()


_PASSWORD_REQUIRED_MARKERS = (
    "a password is required",
    "password is required",
    "interactive authentication is required",
    "a terminal is required",
)

_AUTH_FAILED_MARKERS = (
    "sorry, try again",
    "authentication failure",
    "incorrect password",
    "password is incorrect",
    "authentication failed",
)


class BackendContext:
    def __init__(self, db, conn_mgr):
        self.db = db
        self.conn_mgr = conn_mgr

    # ------------------------------------------------------------------
    # audit
    # ------------------------------------------------------------------
    def audit(self, action, server_name, status, details):
        """
        Record an operation without storing credentials.

        Callers must never pass passwords or private-key contents here.
        Details are redacted anyway (a terminal command can contain a
        password typed by the admin), so no secret reaches the disk.
        """
        try:
            self.db.add_audit(
                CURRENT_USER,
                server_name,
                action,
                status,
                redact(str(details or ""))[:2000],
            )
            return True
        except db_mod.DatabaseError:
            return False

    # ------------------------------------------------------------------
    # connection helpers
    # ------------------------------------------------------------------
    def is_connected(self, name):
        return self.conn_mgr.is_connected(name)

    def require(self, name):
        if not self.conn_mgr.is_connected(name):
            raise BackendError(f"Server '{name}' is not connected")

    def connection(self, name):
        """Return the live ServerConnection for *name* or raise."""
        self.require(name)
        return self.conn_mgr.get(name)

    async def run(self, name, command, timeout=20):
        try:
            return await self.connection(name).run_command(command, timeout=timeout)
        except conn_mod.ConnectionErrorAzmuth as exc:
            raise BackendError(str(exc)) from exc

    async def run_privileged(
        self,
        name,
        command,
        operation,
        target,
        sudo_password=None,
        timeout=60,
    ):
        """
        Run *command* through sudo.

        Without a password, sudo is attempted non-interactively (sudo -n)
        and SudoPasswordRequired is raised only when authentication is
        needed. With a password, it is sent through SSH stdin (sudo -S).

        Raises:
            SudoPasswordRequired      – no password given, sudo needs one
            SudoAuthenticationFailed  – the given password was rejected
            CommandFailed             – the command itself failed (has exit_code)
        """
        connection = self.connection(name)

        if sudo_password is None:
            result = await self.run(name, f"sudo -n -- {command}", timeout=timeout)
        else:
            if not isinstance(sudo_password, str) or not sudo_password:
                raise BackendError("Sudo password cannot be empty")
            try:
                result = await connection.run_sudo_command(
                    command,
                    sudo_password,
                    timeout=timeout,
                )
            except conn_mod.ConnectionErrorAzmuth as exc:
                raise BackendError(str(exc)) from exc

        if result.exit_code == 0:
            return result

        error_text = (result.stderr or "").strip()
        lowered = error_text.lower()

        if "must have a tty" in lowered or "requiretty" in lowered:
            raise CommandFailed(
                f"{operation}: this server's sudo is set to 'requiretty' "
                "(Defaults requiretty in /etc/sudoers). Azmuth runs sudo without a "
                "terminal; remove that line with visudo on the server to use it.",
                exit_code=result.exit_code,
                stderr=error_text,
            )

        password_required = any(m in lowered for m in _PASSWORD_REQUIRED_MARKERS)
        auth_failed = any(m in lowered for m in _AUTH_FAILED_MARKERS)

        if password_required and sudo_password is None:
            raise SudoPasswordRequired(
                f"Sudo password required for {operation}",
                operation=operation,
                server_name=name,
                path=target,
            )

        if auth_failed or (password_required and sudo_password is not None):
            raise SudoAuthenticationFailed(
                "Sudo authentication failed. Check your password.",
                operation=operation,
                server_name=name,
                path=target,
            )

        raise CommandFailed(
            f"{operation} failed: {error_text or result.exit_code}",
            exit_code=result.exit_code,
            stderr=error_text,
        )


class BaseManager:
    """Base class: gives each manager access to the shared context."""

    def __init__(self, ctx):
        self.ctx = ctx

    @property
    def db(self):
        return self.ctx.db

    @property
    def conn_mgr(self):
        return self.ctx.conn_mgr

    def audit(self, action, server_name, status, details):
        return self.ctx.audit(action, server_name, status, details)
