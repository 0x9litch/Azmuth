"""
E2E for the SSH-key features: first-run key generation with passphrase,
add server + password => key install (ssh-copy-id), passphrase unlock on
connect, connect-all with a single unlock, change passphrase, theme, mouse.
"""

import asyncio
import os
import stat
import sys

exec(open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "e2e.py")).read().split("async def main():")[0])

import asyncssh  # noqa: E402

REMOTE_AK = f"{HOME}/remote/.ssh/authorized_keys"
PASS = "correct horse battery"


async def main():
    setup_fs()
    server, fp = await start_server()

    from TUI.backend import Backend
    from TUI.core.connection import ConnectionManager
    from TUI.core.database import Database
    from TUI.ui import AzmuthApp
    from TUI.ui.dialogs import (
        ChangePassphraseDialog, FingerprintDialog, KeyGenerateDialog,
        KeyManagerDialog, SecretDialog, ServerForm,
    )
    from TUI.ui.styles.theme import P
    from textual.color import Color

    db = Database()
    db.initialize()
    backend = Backend(db, ConnectionManager())
    app = AzmuthApp(backend)
    keypath = f"{HOME}/.ssh/azmuth_ed25519"

    async with app.run_test(size=(170, 50)) as pilot:
        # ---------- first run: generate encrypted key
        await wait_for(pilot, lambda: isinstance(app.screen, KeyGenerateDialog), msg="first-run dialog")
        await type_text(pilot, "short")
        await pilot.press("enter")
        await type_text(pilot, "short")
        await pilot.press("enter")
        await pilot.pause()
        err = str(app.screen.query_one("#key-error").render())
        assert "at least" in err, err
        app.screen.query_one("#new-pass").value = PASS
        app.screen.query_one("#confirm-pass").value = PASS + "x"
        await pilot.press("ctrl+s")
        await pilot.pause()
        assert "match" in str(app.screen.query_one("#key-error").render())
        app.screen.query_one("#confirm-pass").value = PASS
        await pilot.press("ctrl+s")
        await wait_for(pilot, lambda: os.path.exists(keypath + ".pub"), msg="key written")
        mode = stat.S_IMODE(os.stat(keypath).st_mode)
        assert mode == 0o600, oct(mode)
        assert stat.S_IMODE(os.stat(os.path.dirname(keypath)).st_mode) == 0o700
        try:
            asyncssh.read_private_key(keypath)
            raise AssertionError("key should be encrypted")
        except asyncssh.KeyImportError:
            pass
        assert PASS not in open(f"{HOME}/.local/share/azmuth/azmuth.db", "rb").read().decode("latin1")
        await wait_for(pilot, lambda: "key: unlocked" in str(app.query_one("#topbar").render()), msg="topbar")
        print("✓ first run: encrypted ed25519 key, 0600/0700, passphrase not in DB")

        # ---------- lock it (K -> l)
        await pilot.press("K")
        await wait_for(pilot, lambda: isinstance(app.screen, KeyManagerDialog), msg="key manager")
        assert app.screen.public_line.startswith("ssh-ed25519 ") and app.screen.public_line.endswith("azmuth")
        await pilot.press("l")
        await wait_for(pilot, lambda: isinstance(app.screen, KeyManagerDialog), msg="manager reopened")
        await pilot.press("escape")
        await wait_for(pilot, lambda: "key: locked" in str(app.query_one("#topbar").render()), msg="locked")
        print("✓ key manager shows public key; lock works")

        # ---------- add server with password => trust => install => unlock => connect
        await pilot.press("a")
        await wait_for(pilot, lambda: isinstance(app.screen, ServerForm), msg="form")
        f = app.screen
        assert f.query_one("#f-key_path").value == "~/.ssh/azmuth_ed25519"
        f.query_one("#f-name").value = "vm1"
        f.query_one("#f-host").value = "127.0.0.1"
        f.query_one("#f-port").value = str(PORT)
        f.query_one("#f-username").value = "glitch"
        f.query_one("#f-password").value = "wrongpass"
        await pilot.press("ctrl+s")
        await wait_for(pilot, lambda: isinstance(app.screen, FingerprintDialog), msg="fingerprint before password")
        assert app.screen.fingerprint == fp
        await pilot.press("y")
        await wait_for(pilot, lambda: isinstance(app.screen, SecretDialog) and app.screen.error, msg="password re-prompt")
        assert "Password rejected" in app.screen.error
        await type_text(pilot, "serverpass")
        await pilot.press("enter")
        await wait_for(pilot, lambda: isinstance(app.screen, SecretDialog) and "UNLOCK" in app.screen.title_text, msg="unlock prompt")
        await type_text(pilot, "nope-nope")
        await pilot.press("enter")
        await wait_for(pilot, lambda: isinstance(app.screen, SecretDialog) and app.screen.error, msg="wrong passphrase")
        assert "Incorrect passphrase" in app.screen.error, app.screen.error
        await type_text(pilot, PASS)
        await pilot.press("enter")
        await wait_for(pilot, lambda: backend.is_connected("vm1"), msg="connected with key", timeout=15)
        pub = open(keypath + ".pub").read().strip()
        assert open(REMOTE_AK).read().count(pub) == 1
        assert stat.S_IMODE(os.stat(REMOTE_AK).st_mode) == 0o600
        await wait_for(pilot, lambda: any("verified" in m for m in all_notes(app)), msg="verified note")
        print("✓ add server + password: host key verified first, key installed, passphrase unlock, connected")

        # ---------- second server: key already present, no prompts for passphrase (still unlocked)
        backend.servers.add("vm2", "127.0.0.1", PORT, "glitch", "~/.ssh/azmuth_ed25519")
        app.refresh_server_views()
        app.select_server("vm2")
        await pilot.pause()
        await pilot.press("I")
        await wait_for(pilot, lambda: isinstance(app.screen, FingerprintDialog), msg="fp vm2")
        await pilot.press("y")
        await wait_for(pilot, lambda: isinstance(app.screen, SecretDialog), msg="pw vm2")
        await type_text(pilot, "serverpass")
        await pilot.press("enter")
        await wait_for(pilot, lambda: backend.is_connected("vm2"), msg="vm2 connected")
        assert open(REMOTE_AK).read().count(pub) == 1, "key must not be duplicated"
        assert any("already installed" in m for m in all_notes(app))
        print("✓ install key (I) is idempotent")

        # ---------- disconnect all, lock, connect all => one passphrase prompt
        print("  .. X", flush=True)
        await pilot.press("X")
        await wait_for(pilot, lambda: not backend.servers.connected_names(), msg="all disconnected")
        backend.keys.lock_all()
        app.update_topbar()
        prompts = []
        orig_ask = app.ask

        async def counting_ask(screen, timeout=None):
            if isinstance(screen, SecretDialog):
                prompts.append(screen.title_text)
            return await orig_ask(screen, timeout)

        app.ask = counting_ask
        print("  .. C", flush=True)
        await pilot.press("C")
        await wait_for(pilot, lambda: isinstance(app.screen, SecretDialog), msg="single unlock")
        print("  .. unlock prompt", flush=True)
        await type_text(pilot, PASS)
        await pilot.press("enter")
        await wait_for(pilot, lambda: set(backend.servers.connected_names()) == {"vm1", "vm2"}, msg="all connected")
        assert prompts == ["UNLOCK SSH KEY"], prompts
        app.ask = orig_ask
        await wait_for(pilot, lambda: any("Connected 2/2" in m for m in all_notes(app)), msg="summary")
        print("✓ C connects all servers with ONE passphrase prompt")

        # ---------- change passphrase (K -> p)
        fp_before = backend.keys.status()["fingerprint"]
        await pilot.press("K")
        await wait_for(pilot, lambda: isinstance(app.screen, KeyManagerDialog), msg="km")
        await pilot.press("p")
        await wait_for(pilot, lambda: isinstance(app.screen, ChangePassphraseDialog), msg="change dlg")
        app.screen.query_one("#new-pass").value = "another passphrase"
        app.screen.query_one("#confirm-pass").value = "another passphrase"
        # the current passphrase is required even though the key is unlocked
        await pilot.press("ctrl+s")
        await pilot.pause()
        assert isinstance(app.screen, ChangePassphraseDialog), "accepted without the old passphrase"
        assert "current passphrase" in str(app.screen.query_one(".error").render()).lower() if app.screen.query(".error") else True
        app.screen.query_one("#old-pass").value = "wrong old passphrase"
        await pilot.press("ctrl+s")
        await wait_for(pilot, lambda: any("Incorrect passphrase" in n for n in all_notes(app)), msg="wrong old rejected")
        await pilot.press("p")
        await wait_for(pilot, lambda: isinstance(app.screen, ChangePassphraseDialog), msg="change dlg again")
        app.screen.query_one("#old-pass").value = PASS
        app.screen.query_one("#new-pass").value = "another passphrase"
        app.screen.query_one("#confirm-pass").value = "another passphrase"
        await pilot.press("ctrl+s")
        await wait_for(pilot, lambda: isinstance(app.screen, KeyManagerDialog), msg="km back")
        await pilot.press("escape")
        asyncssh.read_private_key(keypath, "another passphrase")
        assert backend.keys.status()["fingerprint"] == fp_before
        assert stat.S_IMODE(os.stat(keypath).st_mode) == 0o600
        print("✓ change passphrase: same key re-encrypted in place, still 0600")

        # ---------- theme applies everywhere + persisted
        old_accent = P.accent
        app.theme = "nord"
        await pilot.pause(0.3)
        assert P.accent != old_accent and P.name == "nord"
        assert db.get_setting("theme") == "nord"
        bg = app.screen.styles.background
        assert bg == Color.parse(app.get_css_variables()["background"]), (bg,)
        sidebar_border = app.query_one("ServerList").styles.border_top[1]
        assert sidebar_border != Color.parse("#005f22")
        await pilot.press("ctrl+t")
        await pilot.pause(0.3)
        assert "CommandPalette" in type(app.screen).__name__, app.screen
        await pilot.press("escape")
        print("✓ theme: whole UI restyled (CSS vars + Python palette), saved; ctrl+t opens picker")

        # ---------- mouse toggle (fake driver to capture escape codes)
        writes = []
        drv = app._driver
        drv._enable_mouse_support = lambda: writes.append("on")
        drv._disable_mouse_support = lambda: writes.append("off")
        await pilot.press("f9")
        await pilot.press("f9")
        assert writes == ["off", "on"], writes
        assert db.get_setting("mouse") == "on"
        print("✓ F9 toggles mouse and saves the preference")

        # Incident toasts are expected (the fake journal contains an OOM kill).
        # expected: incident toasts, and the wrong-old-passphrase error the test caused on purpose
        assert not [n for n in all_notes(app) if n.startswith("error") and "(7 = Incidents)" not in n and n != "error: Incorrect passphrase"], all_notes(app)
        joined = str(backend.logs.audit_records(500))
        for secret in (PASS, "serverpass", "wrongpass", "another passphrase"):
            assert secret not in joined, f"secret leaked into audit: {secret}"
        print("✓ no secrets in the audit log; no error notifications")

    server.close()


asyncio.run(main())
