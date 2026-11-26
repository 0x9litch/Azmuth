"""
Remote command execution for the Terminal tab.
"""

from ..core import connection as conn_mod
from .base import BaseManager
from .errors import BackendError


class TerminalManager(BaseManager):
    async def run(self, name, command, timeout=30):
        self.ctx.require(name)

        if not command or not command.strip():
            raise BackendError("Empty command")

        try:
            res = await self.ctx.connection(name).run_command(command, timeout=timeout)

        except conn_mod.ConnectionErrorAzmuth as exc:
            self.audit("exec", name, "failed", f"{command[:200]}  ({exc})")
            raise BackendError(str(exc)) from exc

        self.audit(
            "exec",
            name,
            "success" if res.exit_code == 0 else "failed",
            command[:200],
        )

        return res
