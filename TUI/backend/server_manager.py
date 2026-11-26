"""
Server registry, SSH connection lifecycle and ICMP availability checks.
"""

import asyncio
import re

from ..core import connection as conn_mod
from .base import BaseManager
from .errors import BackendError


# Same rule as the API's /servers/{name} (a name the API cannot address
# would silently disappear from the web).
SERVER_NAME_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
# hostname or IPv4/IPv6; never starting with "-" (option injection)
HOST_RE = re.compile(r"^(?!-)[A-Za-z0-9.:%\[\]-]{1,253}$")
USERNAME_RE = re.compile(r"^(?!-)[A-Za-z0-9._-]{1,32}\$?$")

class ServerManager(BaseManager):
    def __init__(self, ctx, keys):
        super().__init__(ctx)
        self.keys = keys  # KeyManager: unlocked keys + public key line

    # ------------------------------------------------------------------
    # registry
    # ------------------------------------------------------------------
    def list(self):
        return self.db.list_servers()

    def names(self):
        return [s["name"] for s in self.db.list_servers()]

    def get(self, name):
        return self.db.get_server(name)

    def validate(self, name, host, port, username, key_path):
        """Raise BackendError with a user-facing message if invalid."""
        if not name or not str(name).strip():
            raise BackendError("Name is required")
        if not SERVER_NAME_RE.match(str(name)):
            raise BackendError("Name: letters, digits, . _ - only (max 64), e.g. web-srv")

        if not host or not str(host).strip():
            raise BackendError("Host is required")
        if not HOST_RE.match(str(host)):
            raise BackendError("Host must be a hostname or an IP address")

        if not str(port).isdigit():
            raise BackendError("Port must be numeric")

        port_i = int(port)

        if port_i <= 0 or port_i > 65535:
            raise BackendError("Port out of range (1-65535)")

        if not username or not str(username).strip():
            raise BackendError("Username is required")
        if not USERNAME_RE.match(str(username)):
            raise BackendError("Username: letters, digits, . _ - only, not starting with -")

        if not key_path or not str(key_path).strip():
            raise BackendError("Private key path is required")

    def add(self, name, host, port, username, key_path):
        self.validate(name, host, port, username, key_path)
        self.db.add_server(name, host, port, username, key_path)
        self.audit("add_server", name, "success", f"{username}@{host}:{port}")

    async def edit(self, original, name, host, port, username, key_path):
        self.validate(name, host, port, username, key_path)

        await self._drop_connection(original)

        if name != original:
            await self._drop_connection(name)

        self.db.update_server(original, name, host, port, username, key_path)
        self.audit("edit_server", name, "success", f"{username}@{host}:{port}")

    async def delete(self, name):
        await self._drop_connection(name)
        self.db.delete_server(name)
        self.audit("delete_server", name, "success", "removed")

    async def _drop_connection(self, name):
        if name in self.conn_mgr.connections:
            await self.conn_mgr.disconnect(name)

    # ------------------------------------------------------------------
    # connections
    # ------------------------------------------------------------------
    async def connect(self, name):
        srv = self.db.get_server(name)

        if srv is None:
            raise BackendError(f"Unknown server '{name}'")

        target = f"{srv['username']}@{srv['host']}:{srv['port']}"
        fingerprint = srv["host_key_fingerprint"]

        # Raises KeyLocked before any network traffic if the key needs a
        # passphrase. (First contact only fetches the host key: no auth.)
        client_keys = self.keys.client_keys_for(srv["key_path"]) if fingerprint else None

        try:
            await self.conn_mgr.connect(
                name=name,
                host=srv["host"],
                port=srv["port"],
                username=srv["username"],
                key_path=srv["key_path"],
                fingerprint=fingerprint,
                client_keys=client_keys,
            )

        except conn_mod.HostKeyPending as exc:
            self.audit("connect", name, "pending", f"fingerprint {exc.fingerprint}")
            raise

        except conn_mod.HostKeyMismatch as exc:
            self.audit(
                "connect", name, "rejected", f"fingerprint mismatch: {exc.presented}"
            )
            raise

        except conn_mod.ConnectionErrorAzmuth as exc:
            self.audit("connect", name, "failed", str(exc))
            raise BackendError(str(exc)) from exc

        self.audit("connect", name, "success", target)
        return True

    async def confirm_fingerprint(self, name, fingerprint):
        self.db.save_fingerprint(name, fingerprint)
        self.audit("trust_host_key", name, "success", fingerprint)
        return await self.connect(name)

    def trust_fingerprint(self, name, fingerprint):
        """Pin a host key without connecting (used before key install)."""
        self.db.save_fingerprint(name, fingerprint)
        self.audit("trust_host_key", name, "success", fingerprint)

    async def probe_host_key(self, name):
        """First contact only: raises HostKeyPending with the fingerprint."""
        srv = self.db.get_server(name)
        if srv is None:
            raise BackendError(f"Unknown server '{name}'")
        probe = conn_mod.ServerConnection(srv["host"], srv["port"], srv["username"], None)
        try:
            await probe.connect(None)
        except conn_mod.HostKeyPending:
            raise
        except conn_mod.ConnectionErrorAzmuth as exc:
            raise BackendError(str(exc)) from exc

    async def install_key(self, name, password):
        """
        ssh-copy-id equivalent for a registered server.

        Raises HostKeyPending if the server's host key is not trusted yet
        (the password is never sent to an unverified host).
        """
        srv = self.db.get_server(name)
        if srv is None:
            raise BackendError(f"Unknown server '{name}'")

        if not srv["host_key_fingerprint"]:
            await self.probe_host_key(name)  # always raises

        public_line = self.keys.public_key_line(srv["key_path"])
        target = f"{srv['username']}@{srv['host']}:{srv['port']}"

        try:
            outcome = await conn_mod.install_public_key(
                srv["host"],
                srv["port"],
                srv["username"],
                password,
                srv["host_key_fingerprint"],
                public_line,
            )
        except conn_mod.HostKeyMismatch as exc:
            self.audit("install_key", name, "rejected", f"fingerprint mismatch: {exc.presented}")
            raise
        except conn_mod.ConnectionErrorAzmuth as exc:
            self.audit("install_key", name, "failed", f"{target}: {exc}")
            raise BackendError(str(exc)) from exc

        self.audit("install_key", name, "success", f"{target}: {outcome.lower()}")
        return outcome

    def reject_fingerprint(self, name, fingerprint):
        self.audit("connect", name, "rejected", f"user rejected fingerprint {fingerprint}")

    async def disconnect(self, name):
        await self.conn_mgr.disconnect(name)
        self.audit("disconnect", name, "success", "")

    async def disconnect_all(self):
        await self.conn_mgr.disconnect_all()

    def is_connected(self, name):
        return self.conn_mgr.is_connected(name)

    def connected_names(self):
        return [n for n in self.names() if self.conn_mgr.is_connected(n)]

    def status(self, name):
        return self.conn_mgr.get_status(name)

    # ------------------------------------------------------------------
    # availability (ICMP ping)
    # ------------------------------------------------------------------
    async def ping(self, name, timeout=2):
        """
        Check network reachability using ICMP.

        This does not establish or modify an SSH connection.
        """
        srv = self.db.get_server(name)

        if srv is None:
            raise BackendError(f"Unknown server '{name}'")

        if timeout <= 0:
            raise BackendError("Ping timeout must be greater than zero")

        host = srv["host"]
        offline = {"name": name, "host": host, "online": False, "latency_ms": None}

        try:
            process = await asyncio.create_subprocess_exec(
                "ping",
                "-n",
                "-c",
                "1",
                "-W",
                str(timeout),
                "--",  # a host can never be read as a ping option
                host,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )

            try:
                stdout, _ = await asyncio.wait_for(
                    process.communicate(),
                    timeout=timeout + 1,
                )
            except asyncio.TimeoutError:
                try:
                    process.kill()
                except ProcessLookupError:
                    pass
                await process.communicate()
                return offline

        except FileNotFoundError as exc:
            raise BackendError("The ping utility is not installed") from exc

        except OSError as exc:
            raise BackendError(f"Ping failed: {exc}") from exc

        if process.returncode != 0:
            return offline

        output = stdout.decode(errors="replace")
        match = re.search(r"time[=<]([\d.]+)\s*ms", output)
        latency = float(match.group(1)) if match else None

        return {"name": name, "host": host, "online": True, "latency_ms": latency}

    async def ping_all(self, timeout=2, concurrency=10):
        """Check all registered servers concurrently."""
        if concurrency < 1:
            raise BackendError("Ping concurrency must be at least 1")

        servers = self.list()

        if not servers:
            return []

        semaphore = asyncio.Semaphore(concurrency)

        async def check(server):
            async with semaphore:
                return await self.ping(server["name"], timeout=timeout)

        return await asyncio.gather(*(check(s) for s in servers))
