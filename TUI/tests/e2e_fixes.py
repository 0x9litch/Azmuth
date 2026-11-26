"""
Regression tests for the reviewed bugs (#1-#6, #8, #9).
Each test recreates the reported scenario and checks the corrected behaviour.
"""

import asyncio
import os
import stat
import sys

exec(open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "e2e.py")).read().split("async def main():")[0])

PROT = f"{WORK}/protected"


def mode_of(p):
    return stat.S_IMODE(os.stat(p).st_mode)


async def main():
    setup_fs()
    os.makedirs(f"{WORK}/nodelete", exist_ok=True)
    server, fp = await start_server()

    from TUI.backend import Backend
    from TUI.backend.errors import BackendError, SudoPasswordRequired
    from TUI.core.connection import ConnectionErrorAzmuth, ConnectionManager
    from TUI.core.database import Database
    from TUI.diagnostics.rules import system as system_rules
    from TUI.ui import AzmuthApp
    from TUI.ui.dialogs import ConfirmDialog, PromptDialog, SudoPasswordDialog

    db = Database()
    db.initialize()
    db.set_setting("ssh_key_path", "~/.ssh/id_test")
    backend = Backend(db, ConnectionManager())
    for n in ("srv1", "srv2"):
        backend.servers.add(n, "127.0.0.1", PORT, "glitch", "~/.ssh/id_test")
        db.save_fingerprint(n, fp)
    app = AzmuthApp(backend)

    async with app.run_test(size=(170, 50)) as pilot:
        await backend.servers.connect("srv1")
        await backend.servers.connect("srv2")
        app.refresh_server_views()
        app.select_server("srv1")
        await pilot.press("5")
        ftab = app.tab("files")

        async def answer_sudo(password="secret"):
            await wait_for(pilot, lambda: isinstance(app.screen, SudoPasswordDialog), msg="sudo prompt")
            await type_text(pilot, password)
            await pilot.press("enter")

        # ---------- #1 upload into a folder SFTP cannot even look into
        with open(f"{HOME}/new.txt", "w") as f:
            f.write("brand new\n")
        app.spawn(ftab._upload("srv1", f"{HOME}/new.txt", f"{PROT}/new.txt"))
        await answer_sudo()
        await wait_for(pilot, lambda: os.path.exists(f"{PROT}/new.txt"), msg="#1 uploaded")
        st = os.stat(f"{PROT}/new.txt")
        assert (st.st_uid, st.st_gid, mode_of(f"{PROT}/new.txt")) == (0, 0, 0o644), (st.st_uid, oct(mode_of(f"{PROT}/new.txt")))
        print("✓ #1 upload into protected folder: sudo prompt shown, file created root:root 0644")

        # ---------- #2 overwrite keeps owner and mode (sudoers.d-like file)
        conf = f"{PROT}/90-admins"
        with open(conf, "w") as f:
            f.write("old rules\n")
        os.chown(conf, 1000, 1000)
        os.chmod(conf, 0o440)
        with open(f"{HOME}/90-admins", "w") as f:
            f.write("new rules\n")
        app.spawn(ftab._upload("srv1", f"{HOME}/90-admins", conf))
        await answer_sudo()
        await wait_for(pilot, lambda: isinstance(app.screen, ConfirmDialog), msg="#2 overwrite confirm")
        await pilot.press("y")
        await answer_sudo()
        await wait_for(pilot, lambda: open(conf).read() == "new rules\n", msg="#2 overwritten")
        st = os.stat(conf)
        assert (st.st_uid, st.st_gid, mode_of(conf)) == (1000, 1000, 0o440), (st.st_uid, st.st_gid, oct(mode_of(conf)))
        print("✓ #2 overwrite with sudo: owner 1000:1000 and mode 0440 preserved")

        # ---------- #3 cancelling the sudo prompt keeps the local file
        local = f"{HOME}/secret.txt"
        with open(local, "w") as f:
            f.write("ORIGINAL\n")
        os.chmod(local, 0o600)
        app.spawn(ftab._download("srv1", f"{PROT}/secret.txt", local))
        await wait_for(pilot, lambda: isinstance(app.screen, ConfirmDialog), msg="#3 overwrite local?")
        await pilot.press("y")
        await wait_for(pilot, lambda: isinstance(app.screen, SudoPasswordDialog), msg="#3 sudo")
        await pilot.press("escape")
        await pilot.pause(1.0)
        assert open(local).read() == "ORIGINAL\n", "local file lost!"
        leftovers = [n for n in os.listdir(HOME) if "azmuth-part" in n]
        assert not leftovers, leftovers
        # and when the password IS given, it is replaced and stays private
        app.spawn(ftab._download("srv1", f"{PROT}/secret.txt", local))
        await wait_for(pilot, lambda: isinstance(app.screen, ConfirmDialog), msg="#3 overwrite again")
        await pilot.press("y")
        await answer_sudo()
        await wait_for(pilot, lambda: open(local).read() == "top secret\n", msg="#3 replaced")
        assert mode_of(local) == 0o600, oct(mode_of(local))
        print("✓ #3 download: Esc on sudo keeps original; success replaces atomically, keeps 0600, no temp files")

        # ---------- #4 move where only 'delete source' needs sudo
        src = f"{WORK}/nodelete/m.txt"
        with open(src, "w") as f:
            f.write("move me\n" * 50)
        dst = f"{WORK}/dst/m.txt"
        prompts = []
        real_ask = app.ask

        async def spy_ask(screen, timeout=None):
            prompts.append(type(screen).__name__)
            return await real_ask(screen, timeout)

        app.ask = spy_ask
        app.spawn(ftab._transfer("srv1", src, "srv2", dst, "move"))
        await answer_sudo()
        await wait_for(pilot, lambda: not os.path.exists(src), msg="#4 source deleted")
        await pilot.pause(0.5)
        app.ask = real_ask
        assert os.path.exists(dst) and open(dst).read() == "move me\n" * 50
        assert prompts == ["SudoPasswordDialog"], f"unexpected dialogs: {prompts}"
        assert any("Move completed" in m for m in all_notes(app))
        print("✓ #4 move: one sudo prompt, no false 'already exists', source deleted once")

        # ---------- #5 names with [ ] : no crash, shown literally
        for weird in ("[red]x", "a[b", "[b]bold"):
            open(os.path.join(WORK, weird), "w").close()
        # a path containing "[/]": folder "[" holding a file "]"
        os.makedirs(os.path.join(WORK, "["), exist_ok=True)
        open(os.path.join(WORK, "[", "]"), "w").close()
        ftab.path = WORK
        await ftab.reload()
        names = {e["name"] for e in ftab.entries}
        assert "[red]x" in names
        ftab._redraw(select="[red]x")
        await pilot.pause(0.2)
        cell = ftab.table.get_row("[red]x")[0]
        assert getattr(cell, "plain", str(cell)) == "[red]x", cell
        await pilot.press("d")
        await wait_for(pilot, lambda: isinstance(app.screen, ConfirmDialog), msg="#5 delete dialog")
        app.export_screenshot()  # full render must not raise MarkupError
        assert "[red]x" in app.screen.message
        await pilot.press("y")
        await wait_for(pilot, lambda: not os.path.exists(os.path.join(WORK, "[red]x")), msg="#5 deleted")
        # the exact report case: delete dialog for ".../[/]"
        ftab.path = os.path.join(WORK, "[")
        await ftab.reload()
        ftab._redraw(select="]")
        await pilot.pause(0.2)
        await pilot.press("d")
        await wait_for(pilot, lambda: isinstance(app.screen, ConfirmDialog), msg="#5 [/] dialog")
        app.export_screenshot()
        assert "[/]" in app.screen.message, app.screen.message
        await pilot.press("n")
        ftab.path = WORK
        app.notify("Deleted /tmp/[/]  [red]x", severity="error")
        # Names like this are now refused by validate(); an OLD database could
        # still hold one, so insert it directly and check it is shown safely.
        db.add_server("[b]odd[/b]", "127.0.0.1", PORT, "glitch", "~/.ssh/id_test")
        app.refresh_server_views()
        app.select_server("[b]odd[/b]")
        await pilot.pause(0.3)
        app.export_screenshot()
        sel = str(app.main.query_one("#selection").render())
        assert "[b]odd[/b]" in sel, sel
        app.select_server("srv1")
        print("✓ #5 '[...]' in file/server names: no crash, names shown literally")

        # ---------- #6 two connects at once -> one connection
        await backend.servers.disconnect("srv2")
        mgr = backend.ctx.conn_mgr
        results = await asyncio.gather(
            mgr.connect("srv2", "127.0.0.1", PORT, "glitch", f"{HOME}/.ssh/id_test", fp),
            mgr.connect("srv2", "127.0.0.1", PORT, "glitch", f"{HOME}/.ssh/id_test", fp),
        )
        assert results[0] is results[1] and results[0].is_connected()
        # disconnect while a connect is still in progress -> no orphan
        await mgr.disconnect("srv2")
        # Make the handshake deterministically slow so the disconnect really
        # lands in the middle of it (localhost can finish in < 10 ms).
        from TUI.core.connection import ServerConnection
        real_connect = ServerConnection.connect

        async def slow_connect(self, *a, **kw):
            await asyncio.sleep(0.3)
            return await real_connect(self, *a, **kw)

        ServerConnection.connect = slow_connect
        task = asyncio.create_task(mgr.connect("srv2", "127.0.0.1", PORT, "glitch", f"{HOME}/.ssh/id_test", fp))
        await asyncio.sleep(0.05)
        pending = mgr.connections.get("srv2")
        await mgr.disconnect("srv2")
        try:
            await task
            raise AssertionError("connect should report cancellation")
        except ConnectionErrorAzmuth:
            pass
        ServerConnection.connect = real_connect
        assert pending is not None and pending.conn is None, "orphan SSH connection left open"
        print("✓ #6 simultaneous connects share one connection; disconnect mid-connect closes it")

        # ---------- #8 destination appears between check and move -> overwrite prompt text
        files = backend.files
        real_exists = files._exists

        async def stale_exists(name, path, pw=None):
            return False  # simulate the race: check says "free", file exists

        files._exists = stale_exists
        try:
            await files._upload_with_fallback("srv1", f"{HOME}/new.txt", conf, sudo_password="secret")
            raise AssertionError("expected an error")
        except BackendError as exc:
            assert "Destination already exists" in str(exc), exc
        finally:
            files._exists = real_exists
        assert open(conf).read() == "new rules\n"
        print("✓ #8 race on upload: 'Destination already exists' (overwrite prompt), file untouched")

        # ---------- #9 thermald noise vs real throttling
        healthy = [{"message": "thermald: Using thermal zone x86_pkg_temp", "source": "thermald", "level": "INFO", "ts": ""}]
        real = [{"message": "CPU0: Core temperature above threshold, cpu clock throttled (total events = 1)", "source": "kernel", "level": "WARNING", "ts": ""}]
        assert not [s for s in system_rules.signals(healthy) if s.kind == "thermal"]
        assert [s for s in system_rules.signals(real) if s.kind == "thermal"]
        print("✓ #9 thermal rule: thermald lines ignored, real throttling detected")

        errs = [m for m in all_notes(app) if m.startswith("error") and "[/]" not in m]
        print("unexpected error notifications:", errs)

    server.close()


asyncio.run(main())
