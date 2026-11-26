"""
systemd service listing and control (with interactive sudo support).
"""

from .base import BaseManager
from .errors import BackendError, SudoAuthenticationFailed, SudoPasswordRequired

SERVICE_ACTIONS = ("start", "stop", "restart")


def quote(value):
    """Quote one value for a POSIX shell command."""
    return "'" + str(value).replace("'", "'\\''") + "'"


def is_safe_unit(name):
    """Validate a systemd unit name."""
    allowed = set(
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._@:-"
    )
    # a leading "-" would be read as a systemctl option
    return bool(name) and not name.startswith("-") and all(char in allowed for char in name)


def _parse_units(stdout):
    output = []

    for line in stdout.splitlines():
        line = line.strip()

        if not line:
            continue

        parts = line.split(None, 4)

        if len(parts) < 4:
            continue

        output.append(
            {
                "name": parts[0],
                "load": parts[1],
                "active": parts[2],
                "sub": parts[3],
                "description": parts[4] if len(parts) > 4 else "",
            }
        )

    return output


class ServiceManager(BaseManager):
    async def list(self, name):
        self.ctx.require(name)

        res = await self.ctx.run(
            name,
            "systemctl list-units --type=service --all --no-legend --no-pager --plain",
        )

        if res.exit_code != 0:
            raise BackendError(
                f"systemctl list failed: {res.stderr.strip() or res.exit_code}"
            )

        return _parse_units(res.stdout)

    async def failed(self, name):
        """Return only units in the 'failed' state."""
        self.ctx.require(name)

        res = await self.ctx.run(
            name,
            "systemctl list-units --type=service --state=failed "
            "--no-legend --no-pager --plain",
        )

        if res.exit_code != 0:
            raise BackendError(
                f"systemctl failed-list failed: {res.stderr.strip() or res.exit_code}"
            )

        return _parse_units(res.stdout)

    async def action(self, name, service, action, sudo_password=None):
        """Start, stop, or restart a systemd service."""
        self.ctx.require(name)

        if action not in SERVICE_ACTIONS:
            raise BackendError("Invalid service action")

        if not is_safe_unit(service):
            raise BackendError(f"Unsafe service name: {service}")

        operation = f"service_{action}"

        try:
            await self.ctx.run_privileged(
                name,
                f"systemctl {action} -- {quote(service)}",
                operation,
                service,
                sudo_password=sudo_password,
                timeout=30,
            )

        except SudoPasswordRequired:
            # Not a failure yet: the UI will ask for the password.
            raise

        except SudoAuthenticationFailed:
            self.audit(operation, name, "failed", f"{service}: sudo authentication failed")
            raise

        except BackendError:
            self.audit(operation, name, "failed", service)
            raise

        self.audit(operation, name, "success", service)
        return True
