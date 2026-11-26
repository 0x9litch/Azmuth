"""
End-to-end test: real AsyncSSH server on 127.0.0.1 + headless Textual pilot.
Run: python3 e2e.py
"""

import asyncio
import os
import shutil
import sys
import tempfile

HOME = tempfile.mkdtemp(prefix="azhome-")
os.environ["HOME"] = HOME
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..")))

import asyncssh  # noqa: E402

FAKEBIN = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fakebin")
WORK = "/tmp/azt"
PORT = 2299


async def start_server():
    import subprocess
    proc = subprocess.Popen([sys.executable, "-W", "ignore", os.path.join(os.path.dirname(os.path.abspath(__file__)), "sshd_fake.py"), HOME, str(PORT)],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    for _ in range(100):
        if os.path.exists(f"{HOME}/.fp"):
            break
        await asyncio.sleep(0.1)
    class S:
        def close(self): proc.terminate()
    return S(), open(f"{HOME}/.fp").read()


def setup_fs():
    shutil.rmtree(WORK, ignore_errors=True)
    os.makedirs(f"{WORK}/protected", exist_ok=True)
    os.makedirs(f"{WORK}/dst", exist_ok=True)
    with open(f"{WORK}/protected/secret.txt", "w") as f:
        f.write("top secret\n")
    with open(f"{WORK}/hello.txt", "w") as f:
        f.write("hello world\n" * 1000)
    with open(f"{HOME}/upload.txt", "w") as f:
        f.write("uploaded!\n")


def errors_of(app):
    return [n.message for n in app._notifications if n.severity == "error"]


def all_notes(app):
    return [f"{n.severity}: {n.message}" for n in app._notifications]


async def wait_for(pilot, cond, timeout=8.0, msg=""):
    loop = asyncio.get_running_loop()
    end = loop.time() + timeout
    while loop.time() < end:
        await pilot.pause(0.05)
        if cond():
            return
    raise AssertionError(f"timeout waiting for: {msg}\nnotes={all_notes(pilot.app)}")


async def type_text(pilot, text):
    for ch in text:
        await pilot.press(ch if ch != " " else "space")


async def main():
    setup_fs()
    server, fp = await start_server()

    from TUI.backend import Backend
    from TUI.core.connection import ConnectionManager
    from TUI.core.database import Database
    from TUI.ui import AzmuthApp
    from TUI.ui.dialogs import (
        ConfirmDialog, FingerprintDialog, HelpScreen, PromptDialog, ServerForm,
        SudoPasswordDialog, TransferDialog,
    )
    from textual.widgets import DataTable, RichLog, TabbedContent

    db = Database()
    db.initialize()
    db.set_setting("ssh_key_path", "~/.ssh/id_test")
    backend = Backend(db, ConnectionManager())
    app = AzmuthApp(backend)

    async with app.run_test(size=(160, 50)) as pilot:
        await pilot.pause()
        # ---------- add server via form (with a validation error first)
        await pilot.press("a")
        await wait_for(pilot, lambda: isinstance(app.screen, ServerForm), msg="form")
        await type_text(pilot, "srv1")
        await pilot.press("enter")
        await type_text(pilot, "127.0.0.1")
        await pilot.press("enter")
        await pilot.press("ctrl+u")
        await type_text(pilot, "99999")
        await pilot.press("ctrl+s")
        await pilot.pause()
        assert isinstance(app.screen, ServerForm), "form must stay open on invalid port"
        err = str(app.screen.query_one("#form-error").render())
        assert "Port" in err, err
        port_in = app.screen.query_one("#f-port")
        port_in.value = str(PORT)
        app.screen.query_one("#f-username").value = "root"
        app.screen.query_one("#f-key_path").value = "~/.ssh/id_test"
        await pilot.press("ctrl+s")
        await wait_for(pilot, lambda: not isinstance(app.screen, ServerForm), msg="form closed")
        assert app.current == "srv1", app.current
        print("✓ add server (inline validation)")

        # ---------- connect + fingerprint
        await pilot.press("c")
        await wait_for(pilot, lambda: isinstance(app.screen, FingerprintDialog), msg="fp dialog")
        assert app.screen.fingerprint == fp
        await pilot.press("y")
        await wait_for(pilot, lambda: backend.is_connected("srv1"), msg="connected")
        print("✓ connect + fingerprint trust")

        # ---------- dashboard metrics
        data = backend.collector.server("srv1")
        await wait_for(pilot, lambda: data.metrics and data.metrics.get("cpu") is not None, msg="metrics")
        snap = data.metrics
        assert snap["mem"]["total"] > 0 and snap["disk"]["total"] > 0, snap
        assert snap["info"]["cpus"] != "-", snap["info"]
        print("✓ dashboard metrics", {k: (v if k != "info" else v.get("load")) for k, v in snap.items() if k != "mem"})

        # ---------- services: filter + restart with wrong then right password
        await pilot.press("2")
        tc = app.query_one(TabbedContent)
        assert tc.active == "services"
        table = app.query_one("#services-table", DataTable)
        await wait_for(pilot, lambda: table.row_count == 4, msg="services loaded")
        await pilot.press("slash")
        await type_text(pilot, "ngi")
        await wait_for(pilot, lambda: table.row_count == 1, msg="filtered")
        await pilot.press("enter")
        assert app.focused is table, app.focused
        await pilot.press("f")
        await pilot.pause()
        assert table.row_count == 0  # nginx is not failed
        await pilot.press("f")
        await pilot.pause()
        assert table.row_count == 1
        await pilot.press("r")
        await wait_for(pilot, lambda: isinstance(app.screen, ConfirmDialog), msg="confirm restart")
        await pilot.press("y")
        await wait_for(pilot, lambda: isinstance(app.screen, SudoPasswordDialog), msg="sudo dialog")
        await type_text(pilot, "wrong")
        await pilot.press("enter")
        await wait_for(pilot, lambda: isinstance(app.screen, SudoPasswordDialog) and app.screen.error, msg="re-prompt")
        assert app.screen.attempt == 2
        await type_text(pilot, "secret")
        await pilot.press("enter")
        await wait_for(pilot, lambda: any("restart nginx.service: OK" in m for m in all_notes(app)), msg="restart ok")
        assert "restart nginx.service" in open("/tmp/azt-systemctl.log").read()
        await pilot.press("escape")
        await wait_for(pilot, lambda: table.row_count == 4, msg="filter cleared")
        print("✓ services: search, failed filter, confirm, sudo retry")

        # ---------- processes (collector list, sort, search)
        await pilot.press("3")
        assert tc.active == "procs"
        ptab = app.tab("procs")
        ptable = app.query_one("#proc-table", DataTable)
        await wait_for(pilot, lambda: ptable.row_count > 0, msg="processes", timeout=15)
        await pilot.press("o")  # sort by MEM
        await pilot.press("slash")
        await type_text(pilot, "sshd_fake")
        await pilot.press("enter")
        await pilot.pause()
        assert 1 <= ptable.row_count < len(ptab.entries), ptable.row_count
        await pilot.press("escape")
        print(f"✓ processes: {len(ptab.entries)} listed, sort + search")

        # ---------- terminal (markup escaping + history)
        await pilot.press("4")
        cmd = app.query_one("#cmd-input")
        await wait_for(pilot, lambda: app.focused is cmd, msg="prompt focused")
        await type_text(pilot, "echo [b]hi[/b] && false")
        await pilot.press("enter")
        log = app.query_one("#cmd-log", RichLog)
        await wait_for(pilot, lambda: any("exit 1" in str(l.text) for l in log.lines), msg="cmd output")
        text = "\n".join(str(l.text) for l in log.lines)
        assert "[b]hi[/b]" in text, text
        await pilot.press("up")
        assert cmd.value == "echo [b]hi[/b] && false"
        await pilot.press("ctrl+u", "escape")
        assert app.focused is log
        await pilot.press("ctrl+l")
        assert len(log.lines) == 0
        print("✓ terminal: output escaped, history, esc/ctrl+l")

        # ---------- files
        await pilot.press("5")
        ftable = app.query_one("#files-table", DataTable)
        await wait_for(pilot, lambda: ftable.row_count > 0, msg="root listing")
        await pilot.press("p")
        await wait_for(pilot, lambda: isinstance(app.screen, PromptDialog), msg="goto prompt")
        app.screen.query_one("#prompt-input").value = WORK
        await pilot.press("enter")
        ftab = app.tab("files")
        await wait_for(pilot, lambda: ftab.path == WORK and any(e["name"] == "hello.txt" for e in ftab.entries), msg="cd work")

        # upload
        await pilot.press("u")
        await wait_for(pilot, lambda: isinstance(app.screen, PromptDialog), msg="upload prompt")
        await type_text(pilot, "~/upload.txt")
        await pilot.press("enter")
        await wait_for(pilot, lambda: os.path.exists(f"{WORK}/upload.txt"), msg="uploaded")
        # upload again -> overwrite confirm
        await pilot.press("u")
        await wait_for(pilot, lambda: isinstance(app.screen, PromptDialog), msg="upload prompt2")
        await type_text(pilot, "~/upload.txt")
        await pilot.press("enter")
        await wait_for(pilot, lambda: isinstance(app.screen, ConfirmDialog), msg="overwrite confirm")
        await pilot.press("y")
        await wait_for(pilot, lambda: sum("Uploaded to" in m for m in all_notes(app)) == 2, msg="re-upload")

        # mkdir + rename + delete
        await pilot.press("n")
        await wait_for(pilot, lambda: isinstance(app.screen, PromptDialog), msg="mkdir prompt")
        await type_text(pilot, "newdir")
        await pilot.press("enter")
        await wait_for(pilot, lambda: os.path.isdir(f"{WORK}/newdir"), msg="mkdir")
        await wait_for(pilot, lambda: ftab._selected() and ftab._selected()["name"] == "newdir", msg="cursor on new dir")
        await pilot.press("r")
        await wait_for(pilot, lambda: isinstance(app.screen, PromptDialog), msg="rename prompt")
        app.screen.query_one("#prompt-input").value = "renamed"
        await pilot.press("enter")
        await wait_for(pilot, lambda: os.path.isdir(f"{WORK}/renamed"), msg="renamed")
        await wait_for(pilot, lambda: ftab._selected() and ftab._selected()["name"] == "renamed", msg="cursor on renamed")
        await pilot.press("d")
        await wait_for(pilot, lambda: isinstance(app.screen, ConfirmDialog), msg="delete confirm")
        await pilot.press("y")
        await wait_for(pilot, lambda: not os.path.exists(f"{WORK}/renamed"), msg="deleted")

        # protected download via sudo (copy owned by root, chown'd to user)
        await pilot.press("p")
        await wait_for(pilot, lambda: isinstance(app.screen, PromptDialog), msg="goto prompt2")
        app.screen.query_one("#prompt-input").value = "protected-dir/../protected/.."
        await pilot.press("enter")
        await wait_for(pilot, lambda: ftab.path == WORK, msg="normpath")
        local = f"{HOME}/secret-copy.txt"
        await ftab._download("srv1", f"{WORK}/protected/secret.txt", local) if False else None
        app.spawn(ftab._download("srv1", f"{WORK}/protected/secret.txt", local))
        await wait_for(pilot, lambda: isinstance(app.screen, SudoPasswordDialog), msg="sudo for download")
        await type_text(pilot, "secret")
        await pilot.press("enter")
        await wait_for(pilot, lambda: os.path.exists(local), msg="protected downloaded")
        assert open(local).read() == "top secret\n"
        assert not [p for p in os.listdir("/tmp") if p.startswith(".azmuth-download-")], "temp cleanup"
        print("✓ files: goto, upload+overwrite, mkdir, rename, delete, sudo download")

        # ---------- second server + transfer (move)
        backend.servers.add("srv2", "127.0.0.1", PORT, "root", "~/.ssh/id_test")
        app.refresh_server_views()
        backend.ctx.db.save_fingerprint("srv2", fp)
        await backend.servers.connect("srv2")
        app.refresh_server_views()
        # select hello.txt
        ftab._refresh(select="hello.txt")
        await wait_for(pilot, lambda: ftab._selected() and ftab._selected()["name"] == "hello.txt", msg="select hello")
        await pilot.press("t")
        await wait_for(pilot, lambda: isinstance(app.screen, TransferDialog), msg="transfer dialog")
        dlg = app.screen
        dlg.query_one("#transfer-path").value = f"{WORK}/dst/hello.txt"
        await pilot.press("tab", "tab")  # -> radio set
        await pilot.press("down", "enter")  # Move
        await pilot.press("ctrl+s")
        await wait_for(pilot, lambda: any("Move completed" in m for m in all_notes(app)), msg="move done", timeout=15)
        assert os.path.exists(f"{WORK}/dst/hello.txt") and not os.path.exists(f"{WORK}/hello.txt")
        print("✓ transfer: move with SHA-256 verification")

        # ---------- logs (collector buffer, incremental cursor)
        await pilot.press("6")
        logtab = app.tab("logs")
        await wait_for(pilot, lambda: len(logtab.entries) == 4, msg="logs")
        levels = [e["level"] for e in logtab.entries]
        assert levels == ["INFO", "ERROR", "WARNING", "ERROR"], levels
        assert logtab.entries[3]["message"] == "hi"
        await backend.collector.refresh_now("srv1", "logs")  # --after-cursor: nothing new
        assert len(logtab.entries) == 4, "duplicated journal lines"
        await pilot.press("l", "l")  # level >= ERROR
        await pilot.pause()
        assert logtab._shown == 2, logtab._shown
        await pilot.press("slash")
        await type_text(pilot, "memory")
        await pilot.press("enter")
        await pilot.pause()
        assert logtab._shown == 1, logtab._shown
        await pilot.press("escape")
        await pilot.press("z")
        await pilot.pause()
        assert logtab._shown == 4
        print("✓ logs: levels, >= filter, search, reset, no duplicates on refetch")

        # ---------- incidents
        await pilot.press("7")
        assert tc.active == "incidents"
        await pilot.press("d")
        inc_table = app.query_one("#inc-table", DataTable)
        await wait_for(pilot, lambda: inc_table.row_count >= 2, msg="incidents", timeout=20)
        titles = [i["title"] for i in backend.incidents.list()]
        assert any("OOM" in t and "java" in t for t in titles), titles
        assert any("broken.service" in t for t in titles), titles
        await pilot.press("enter")
        from TUI.ui.tabs import IncidentDetail
        await wait_for(pilot, lambda: isinstance(app.screen, IncidentDetail), msg="detail")
        await pilot.press("v")
        await pilot.press("escape")
        await pilot.pause()
        assert any(i["status"] == "investigating" for i in backend.incidents.list()), "status not set"
        first = backend.incidents.list()[0]["id"]
        md = backend.incidents.export_markdown(first)
        assert "## Root cause" in md
        print("✓ incidents:", "; ".join(titles))

        # ---------- activity
        print("  .. press 6", flush=True)
        await pilot.press("8")
        print("  .. pressed 8", flush=True)
        atab = app.tab("activity")
        await pilot.pause()
        atable = app.query_one("#audit-table", DataTable)
        total = atable.row_count
        print("  .. press f", flush=True)
        await pilot.press("f")  # success
        await pilot.pause()
        print("  .. pressed f", flush=True)
        assert 0 < atable.row_count <= total
        joined = " ".join(str(r) for r in atab.records)
        assert "secret" not in joined.replace("secret.txt", "").replace("secret-copy", ""), "password leaked into audit!"
        print(f"✓ activity: {total} records, status filter works, no password in audit")

        # ---------- server switching resets tabs
        await pilot.press("5")
        await pilot.press("right_square_bracket")
        await pilot.pause()
        assert app.current == "srv2" and app.tab("files").path == "/"
        await pilot.press("left_square_bracket")
        await pilot.pause()
        assert app.current == "srv1"
        print("✓ [ / ] server switching")

        # ---------- help + disconnect + quit confirm
        await pilot.press("question_mark")
        await wait_for(pilot, lambda: isinstance(app.screen, HelpScreen), msg="help")
        await pilot.press("escape")
        await pilot.press("x")
        await wait_for(pilot, lambda: not backend.is_connected("srv1"), msg="disconnect")
        await pilot.press("q")
        await wait_for(pilot, lambda: isinstance(app.screen, ConfirmDialog), msg="quit confirm (srv2 connected)")
        await pilot.press("n")
        print("✓ help, disconnect, quit confirmation")

        errs = errors_of(app)
        print("error notifications:", errs)

    server.close()


asyncio.run(main())
