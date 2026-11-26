"""
Azmuth backend facade.

Coordinates Database (persistence) and ConnectionManager (SSH/SFTP).
The UI never executes SQL or touches AsyncSSH directly; it talks to
one manager per feature area:

    backend.settings     non-secret preferences (key path, theme, mouse)
    backend.keys         managed SSH key: generate, passphrase, unlock
    backend.servers      registry, SSH connect/disconnect, key install, ping
    backend.monitoring   CPU / memory / disk / host info
    backend.services     systemd listing and start/stop/restart
    backend.terminal     remote command execution
    backend.files        SFTP operations and server-to-server transfer
    backend.logs         journalctl and the audit trail
    backend.processes    process list + safe kill
    backend.collector    background data collection (single source for UI/API)
    backend.diagnostics  problem analysis (see the diagnostics package)
    backend.incidents    incident store
    backend.api          read-only HTTP API (off until started)

Security:
- Sudo passwords are never stored or audited.
- Host-key verification is handled by the core connection layer.
- Server-to-server Move deletes the source only after verification.
- Directory deletion is never recursive.
"""

from ..api import DEFAULT_PORT, ApiServer
from ..diagnostics.service import DiagnosticsService
from .base import BackendContext
from .collector import Collector
from .file_manager import FileManager
from .key_manager import KeyManager
from .log_manager import LogManager
from .monitoring import MonitoringManager
from .process_manager import ProcessManager
from .server_manager import ServerManager
from .service_manager import ServiceManager
from .settings import SettingsManager
from .terminal_manager import TerminalManager


class Backend:
    def __init__(self, db, conn_mgr):
        self.ctx = BackendContext(db, conn_mgr)

        self.settings = SettingsManager(self.ctx)
        self.keys = KeyManager(self.ctx, self.settings)
        self.servers = ServerManager(self.ctx, self.keys)
        self.monitoring = MonitoringManager(self.ctx)
        self.services = ServiceManager(self.ctx)
        self.terminal = TerminalManager(self.ctx)
        self.files = FileManager(self.ctx)
        self.logs = LogManager(self.ctx)
        self.processes = ProcessManager(self.ctx)
        self.collector = Collector(self)
        self.diagnostics = DiagnosticsService(self)
        self.incidents = self.diagnostics.store
        self.api = ApiServer(self, port=self._api_port())

    def _api_port(self):
        try:
            port = int(self.settings.get("api_port") or DEFAULT_PORT)
        except (TypeError, ValueError):
            return DEFAULT_PORT
        return port if 1024 <= port <= 65535 else DEFAULT_PORT

    # Convenience shortcuts used all over the UI.
    def is_connected(self, name):
        return self.ctx.is_connected(name)

    def record_audit(self, action, server_name, status, details):
        return self.ctx.audit(action, server_name, status, details)

    async def shutdown(self):
        """Disconnect everything, forget unlocked keys, close the DB (idempotent)."""
        self.keys.lock_all()
        try:
            await self.api.stop()
        except Exception:
            pass
        try:
            await self.collector.stop()
        except Exception:
            pass
        try:
            await self.servers.disconnect_all()
        except Exception:
            pass
        try:
            self.ctx.db.close()
        except Exception:
            pass
