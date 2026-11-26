"""Security: terminal-escape injection, private sudo staging, hostile file names."""
import asyncio, os, stat, subprocess, sys
exec(open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "e2e.py")).read().split("async def main():")[0])

ESC_PAYLOAD = "\x1b]52;c;cm0gLXJmIH4=\x07\x1b]0;PWNED\x07\x1b[2J"
ok = 0
def check(name, cond, info=""):
    global ok
    assert cond, f"{name}: {info!r}"
    ok += 1
    print("✓", name)

def terminal_bytes(app):
    """What Textual would write to the real terminal for the current screen."""
    return str(app.screen._compositor.render_full_update())

async def main():
    setup_fs()
    server, fp = await start_server()
    from TUI.backend import Backend
    from TUI.backend.log_manager import parse_journal_json
    from TUI.core.connection import ConnectionManager
    from TUI.core.database import Database
    from TUI.core.sanitize import clean_text, safe_filename
    from TUI.ui import AzmuthApp
    from TUI.ui.dialogs import SudoPasswordDialog

    # ---- unit level
    import json
    line = json.dumps({"__CURSOR": "x", "__REALTIME_TIMESTAMP": "1", "PRIORITY": "3",
                       "SYSLOG_IDENTIFIER": "evil\x1b[31m", "MESSAGE": "hi" + ESC_PAYLOAD})
    e = parse_journal_json(line)[0]
    check("journal JSON \\u001b decoded then neutralised", "\x1b" not in e["message"] + e["source"] and "^[]52" in e["message"], e)
    check("C1 CSI (0x9b) neutralised", "\x9b" not in clean_text("a\x9b2Jb"))
    check("hostile names -> one safe local component",
          safe_filename("../../.bashrc") == ".._.._.bashrc" and safe_filename("..") == "download" and "/" not in safe_filename("a/b"))

    # ---- fixtures on the "server"
    evil_dir = f"{WORK}/evil{chr(27)}]0;T{chr(7)}dir"
    os.makedirs(evil_dir, exist_ok=True)
    proc = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(120)", "azmuth-evil" + ESC_PAYLOAD])

    db = Database(); db.initialize(); db.set_setting("ssh_key_path", "~/.ssh/id_test")
    backend = Backend(db, ConnectionManager())
    backend.servers.add("srv1", "127.0.0.1", PORT, "glitch", "~/.ssh/id_test"); db.save_fingerprint("srv1", fp)
    app = AzmuthApp(backend)

    async with app.run_test(size=(170, 50)) as pilot:
        await backend.servers.connect("srv1")
        app.refresh_server_views(); app.select_server("srv1")

        # command output (terminal tab path)
        res = await backend.terminal.run("srv1", "printf 'out\\033]52;c;eA==\\007\\033[2Jdone'")
        check("command output neutralised", "\x1b" not in res.stdout and "^[]52" in res.stdout, res.stdout)

        # processes tab: evil argv must not reach the terminal
        await pilot.press("f3")
        await backend.collector.refresh_now("srv1", "processes")
        app.tab("procs")._show_collected()
        await pilot.press("slash"); await type_text(pilot, "azmuth-evil"); await pilot.press("enter")
        await pilot.pause(0.5)
        out = terminal_bytes(app)
        check("Processes tab: escape sequences never reach the terminal",
              app.query_one("#proc-table").row_count == 1 and "\x1b]52" not in out and "\x1b]0;PWNED" not in out and "\x1b[2J" not in out)
        await pilot.press("escape")

        # files tab: evil directory name
        await pilot.press("f5")
        ftab = app.tab("files")
        ftab.path = WORK
        await ftab.reload()
        await pilot.pause(0.5)
        evil = [en for en in ftab.entries if en["name"].startswith("evil")]
        check("SFTP: raw name kept for operations, display cleaned",
              evil and "\x1b" in evil[0]["name"] and "\x1b" not in evil[0]["display"], evil)
        out = terminal_bytes(app)
        check("Files tab: escape sequences never reach the terminal", "\x1b]0;T" not in out)

        # toasts
        app.notify("boom" + ESC_PAYLOAD, severity="error")
        await pilot.pause(0.3)
        check("toast text neutralised", all("\x1b" not in n.message for n in app._notifications))

        # sudo upload: staging is a private 0700 dir, nothing left in /tmp
        seen = {}
        orig = backend.files._private_dir
        async def spy(name):
            path = await orig(name)
            seen["mode"] = stat.S_IMODE(os.stat(path).st_mode)
            seen["path"] = path
            return path
        backend.files._private_dir = spy
        before = {p for p in os.listdir("/tmp") if p.startswith(".azmuth")}
        with open(f"{HOME}/conf.txt", "w") as f:
            f.write("db_password=hunter2\n")
        app.spawn(ftab._upload("srv1", f"{HOME}/conf.txt", f"{WORK}/protected/conf.txt"))
        await wait_for(pilot, lambda: isinstance(app.screen, SudoPasswordDialog), msg="sudo prompt")
        await type_text(pilot, "secret"); await pilot.press("enter")
        await wait_for(pilot, lambda: os.path.exists(f"{WORK}/protected/conf.txt"), msg="uploaded")
        await pilot.pause(0.5)
        check("sudo upload staged in a 0700 directory", seen.get("mode") == 0o700, seen)
        after = {p for p in os.listdir("/tmp") if p.startswith(".azmuth")}
        check("staging directory removed afterwards", after == before, after - before)

        # sudo download goes through the same private dir
        seen.clear()
        local = f"{HOME}/dl-secret.txt"
        app.spawn(ftab._download("srv1", f"{WORK}/protected/secret.txt", local))
        await wait_for(pilot, lambda: isinstance(app.screen, SudoPasswordDialog), msg="sudo prompt 2")
        await type_text(pilot, "secret"); await pilot.press("enter")
        await wait_for(pilot, lambda: os.path.exists(local), msg="downloaded")
        await pilot.pause(0.5)
        check("sudo download staged in a 0700 directory, then removed",
              seen.get("mode") == 0o700 and {p for p in os.listdir("/tmp") if p.startswith(".azmuth")} == before, seen)
        check("downloaded protected file is 0600", stat.S_IMODE(os.stat(local).st_mode) == 0o600)

        # audit has no secrets from the terminal
        await backend.terminal.run("srv1", "echo mysql -u root -pS3cretX >/dev/null")
        rows = str([tuple(r) for r in db.conn.execute("SELECT details FROM audit_logs").fetchall()])
        check("terminal command stored redacted in audit", "S3cretX" not in rows, rows[-200:])

    proc.kill()
    server.close()
    print(f"\n{ok} security checks passed")

asyncio.run(main())
