"""
Interactive SSH flows used by the app (mixed into AzmuthApp):

- connect one server: host-key trust → unlock key (passphrase) → connect
- connect ALL servers: unlock each key once, connect in parallel
- install the public key on a server with its password (ssh-copy-id)
- key manager: generate, add/change passphrase, use existing, lock
- first-run key setup

Passwords and passphrases only live in local variables of these
coroutines; they are passed straight to the backend and dropped.
"""

import asyncio
import os

from ..backend.errors import BackendError
from ..backend.key_manager import DEFAULT_KEY_PATH, KeyLocked, normalize
from ..core import connection as conn_mod
from .dialogs import (
    ChangePassphraseDialog,
    FingerprintDialog,
    KeyGenerateDialog,
    KeyManagerDialog,
    PromptDialog,
    SecretDialog,
)

MAX_ATTEMPTS = 3
CONNECT_ALL_CONCURRENCY = 8


class SSHFlowsMixin:
    # ------------------------------------------------------------------
    # unlock
    # ------------------------------------------------------------------
    async def unlock_key(self, key_path):
        """Ask for the passphrase (up to 3 tries). True if unlocked."""
        keys = self.backend.keys
        error = None

        for attempt in range(1, MAX_ATTEMPTS + 1):
            passphrase = await self.ask(
                SecretDialog(
                    "UNLOCK SSH KEY",
                    [
                        f"Key: {normalize(key_path)}",
                        "Unlocked in memory for this session only — never saved.",
                        "Lock it again any time with K → l (quitting also locks it).",
                    ],
                    placeholder="key passphrase",
                    error=error,
                    footer=f"attempt {attempt}/{MAX_ATTEMPTS}",
                )
            )
            if passphrase is None:
                return False

            try:
                with self.busy("unlocking key"):
                    await keys.unlock(key_path, passphrase)
            except BackendError as exc:
                error = f"✗ {exc}"
                continue
            finally:
                passphrase = None

            self.update_topbar()
            return True

        self.notify("Key not unlocked: too many wrong passphrases", severity="error")
        return False

    async def _trust_host_key(self, name, fingerprint):
        accepted = await self.ask(FingerprintDialog(name, fingerprint), timeout=180)
        if accepted:
            self.backend.servers.trust_fingerprint(name, fingerprint)
            return True
        self.backend.servers.reject_fingerprint(name, fingerprint)
        self.notify(f"{name}: host key rejected", severity="warning")
        return False

    # ------------------------------------------------------------------
    # connect one
    # ------------------------------------------------------------------
    async def _connect(self, name, quiet=False):
        """Interactive connect. Returns True when connected."""
        servers = self.backend.servers

        for _ in range(4):  # trust → unlock → connect is at most 3 steps
            try:
                with self.busy(f"connecting to {name}"):
                    await servers.connect(name)
                if not quiet:
                    self.notify(f"{name}: SSH connected")
                break

            except KeyLocked as exc:
                if not await self.unlock_key(exc.path):
                    self.notify(f"{name}: not connected (key still locked)", severity="warning")
                    break

            except conn_mod.HostKeyPending as exc:
                if not await self._trust_host_key(name, exc.fingerprint):
                    break

            except conn_mod.HostKeyMismatch as exc:
                self.notify(
                    f"HOST KEY CHANGED for {name}! expected {exc.expected}, got "
                    f"{exc.presented}. Possible man-in-the-middle — connection refused. "
                    "If you reinstalled this VM, delete it (ctrl+d) and add it again.",
                    severity="error",
                    timeout=15,
                )
                break

            except Exception as exc:
                self.notify(f"{name}: {exc}", severity="error")
                break

        self._after_connection_change(name)
        return self.backend.is_connected(name)

    # ------------------------------------------------------------------
    # connect / disconnect all
    # ------------------------------------------------------------------
    def action_connect_all(self):
        self.spawn(self._connect_all(), group="connect-all", exclusive=True)

    async def _connect_all(self):
        backend = self.backend
        servers = [s for s in backend.servers.list() if not backend.is_connected(s["name"])]

        if not servers:
            self.notify("All servers are already connected")
            return

        # 1. Unlock every distinct locked key ONCE, before going parallel.
        skipped = set()
        for path in sorted({s["key_path"] for s in servers if s["host_key_fingerprint"]}):
            try:
                locked = backend.keys.is_locked(path)
            except BackendError:
                locked = False  # the connect attempt will report the problem
            if locked and not await self.unlock_key(path):
                skipped.add(path)

        ready = [
            s["name"] for s in servers
            if s["host_key_fingerprint"] and s["key_path"] not in skipped
        ]
        first_contact = [s["name"] for s in servers if not s["host_key_fingerprint"]]

        # 2. Known hosts: connect in parallel.
        semaphore = asyncio.Semaphore(CONNECT_ALL_CONCURRENCY)

        async def one(name):
            async with semaphore:
                try:
                    await backend.servers.connect(name)
                    return name, None
                except Exception as exc:
                    return name, exc

        failures = []
        if ready:
            with self.busy(f"connecting {len(ready)} server(s)"):
                results = await asyncio.gather(*(one(n) for n in ready))
            failures = [(n, e) for n, e in results if e is not None]
            self.refresh_server_views()

        # 3. New hosts need a human to verify the fingerprint: one by one.
        for name in first_contact:
            await self._connect(name, quiet=True)

        connected = sum(1 for s in servers if backend.is_connected(s["name"]))
        summary = f"Connected {connected}/{len(servers)} server(s)"
        if skipped:
            summary += f" · {len(servers) - len(ready) - len(first_contact)} skipped (key locked)"
        self.notify(summary, severity="information" if not failures else "warning")

        for name, exc in failures:
            self.notify(f"{name}: {exc}", severity="error", timeout=10)

        self._after_connection_change(self.current)

    def action_disconnect_all(self):
        connected = self.backend.servers.connected_names()
        if not connected:
            self.notify("No connected servers")
            return
        self.spawn(self._disconnect_all(connected))

    async def _disconnect_all(self, names):
        for name in names:
            try:
                await self.backend.servers.disconnect(name)
            except Exception as exc:
                self.notify(f"{name}: {exc}", severity="error")
        self.notify(f"Disconnected {len(names)} server(s)")
        self._after_connection_change(self.current)

    # ------------------------------------------------------------------
    # install public key (ssh-copy-id)
    # ------------------------------------------------------------------
    def action_install_key(self):
        if not self.current:
            self.notify("Select a server first", severity="warning")
            return
        self.spawn(self.install_key_flow(self.current))

    async def install_key_flow(self, name, password=None):
        servers = self.backend.servers
        srv = servers.get(name)
        if srv is None:
            return False

        try:
            servers.keys.public_key_line(srv["key_path"])
        except BackendError as exc:
            self.notify(f"{exc} — create or select a key with K", severity="error")
            return False

        # Verify the host key first, so the admin never types a password
        # for a host they have not confirmed.
        if not srv["host_key_fingerprint"]:
            try:
                with self.busy(f"fetching host key of {name}"):
                    await servers.probe_host_key(name)
            except conn_mod.HostKeyPending as exc:
                if not await self._trust_host_key(name, exc.fingerprint):
                    return False
            except BackendError as exc:
                self.notify(f"{name}: {exc}", severity="error")
                return False

        error = None
        attempts = 0

        try:
            while True:
                if password is None:
                    password = await self.ask(
                        SecretDialog(
                            "INSTALL SSH KEY ON SERVER",
                            [
                                f"Server: {name}   ({srv['username']}@{srv['host']}:{srv['port']})",
                                f"Key:    {normalize(srv['key_path'])}.pub",
                                "Appends it to ~/.ssh/authorized_keys (like ssh-copy-id).",
                                "The password is used once for this and never stored.",
                            ],
                            placeholder=f"password for {srv['username']}",
                            error=error,
                        )
                    )
                    if password is None:
                        self.notify("Key installation cancelled", severity="warning")
                        return False

                try:
                    with self.busy(f"installing key on {name}"):
                        outcome = await servers.install_key(name, password)
                    break

                except conn_mod.HostKeyPending as exc:
                    # Verify the host BEFORE the password is ever sent.
                    if not await self._trust_host_key(name, exc.fingerprint):
                        return False

                except conn_mod.HostKeyMismatch as exc:
                    self.notify(
                        f"HOST KEY CHANGED for {name} (got {exc.presented}). "
                        "Password NOT sent. If you reinstalled this VM, delete it (ctrl+d) "
                        "and add it again.",
                        severity="error",
                        timeout=15,
                    )
                    return False

                except BackendError as exc:
                    attempts += 1
                    if "Password rejected" in str(exc) and attempts < MAX_ATTEMPTS:
                        error, password = f"✗ {exc}", None
                        continue
                    self.notify(f"{name}: {exc}", severity="error", timeout=10)
                    return False
        finally:
            password = None
            self.refresh_audit()

        self.notify(
            f"{name}: public key "
            + ("installed" if outcome == "INSTALLED" else "was already installed")
            + " — verifying key login…"
        )

        # Prove it works: log in with the key (asks the passphrase if locked).
        if await self._connect(name, quiet=True):
            self.notify(f"{name}: key login verified ✓ — password no longer needed")
            return True
        return False

    # ------------------------------------------------------------------
    # key manager
    # ------------------------------------------------------------------
    def action_key_manager(self):
        self.spawn(self._key_manager(), group="key-manager", exclusive=True)

    async def _key_manager(self):
        keys = self.backend.keys

        while True:
            status = keys.status()
            public = None
            if status["exists"]:
                try:
                    public = keys.public_key_line(status["path"])
                except BackendError:
                    public = None

            action = await self.ask(KeyManagerDialog(status, public, keys.unlocked_count()))
            if action is None:
                break

            try:
                await self._key_action(action, status)
            except BackendError as exc:
                self.notify(str(exc), severity="error", timeout=10)

            self.update_topbar()

        self.update_topbar()

    async def _key_action(self, action, status):
        keys = self.backend.keys
        path = status["path"]

        if action == "generate":
            await self.generate_key_flow()

        elif action == "passphrase":
            if not status["exists"]:
                self.notify("No key yet — press g to generate one", severity="warning")
                return
            values = await self.ask(ChangePassphraseDialog(normalize(path), status["encrypted"]))
            if values:
                with self.busy("re-encrypting key"):
                    await keys.change_passphrase(path, values["old"], values["new"])
                self.notify(
                    "Passphrase updated" if values["new"] else "Passphrase removed (key is now unprotected)",
                    severity="information" if values["new"] else "warning",
                )

        elif action == "use":
            chosen = await self.ask(
                PromptDialog("Use an existing private key", initial=path, hint="path to the PRIVATE key (not .pub)")
            )
            if chosen:
                real = keys.use_existing(chosen)
                self.notify(f"Now using {real} for new servers")

        elif action == "unlock":
            if status["exists"] and status["encrypted"]:
                await self.unlock_key(path)

        elif action == "lock":
            count = keys.lock_all()
            self.notify(f"Locked — {count} key(s) removed from memory" if count else "Nothing was unlocked")

    async def generate_key_flow(self, first_run=False):
        keys = self.backend.keys
        values = await self.ask(KeyGenerateDialog(keys.default_path(), first_run=first_run))

        if not values:
            if first_run:
                self.notify("You can create your SSH key later with K", timeout=8)
            return False

        try:
            with self.busy("generating key"):
                fingerprint = await keys.generate(values["path"], values["passphrase"])
        except BackendError as exc:
            self.notify(str(exc), severity="error", timeout=10)
            return False
        finally:
            values = None

        self.notify(
            f"Key created: {fingerprint}\nNext: add a server (a) and type its password "
            "to install the key automatically.",
            timeout=12,
        )
        self.update_topbar()
        return True

    def first_run_key_setup(self):
        """Run once: adopt ~/.ssh/azmuth_ed25519 if it exists, else offer to create it."""
        keys = self.backend.keys
        if keys.configured_path():
            return

        if os.path.isfile(normalize(DEFAULT_KEY_PATH)):
            try:
                keys.use_existing(DEFAULT_KEY_PATH)
            except BackendError as exc:
                self.notify(str(exc), severity="error")
                return
            if not keys.status()["encrypted"]:
                self.notify(
                    f"Using your existing key {DEFAULT_KEY_PATH}. It has NO passphrase — "
                    "press K then p to add one (servers keep working).",
                    severity="warning",
                    timeout=15,
                )
            return

        self.spawn(self.generate_key_flow(first_run=True))
