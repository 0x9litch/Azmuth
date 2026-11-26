import asyncio, os, sys, tempfile
os.environ["HOME"] = tempfile.mkdtemp()
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..")))
from TUI.backend import Backend
from TUI.core.connection import ConnectionManager
from TUI.core.database import Database
from TUI.ui import AzmuthApp
from TUI.ui.styles.theme import P

async def main():
    db = Database(); db.initialize(); db.set_setting("ssh_key_path", "~/.ssh/none")
    b = Backend(db, ConnectionManager())
    for n in ("db-srv", "mgmt-srv"):
        b.servers.add(n, "192.168.122.10", 22, "glitch", "~/.ssh/none")
    app = AzmuthApp(b)
    bad = []
    async with app.run_test(size=(150, 45)) as pilot:
        await pilot.pause(0.3)
        for t in sorted(app.available_themes):
            try:
                app.theme = t
                await pilot.pause(0.15)
                for k in "12345678":
                    await pilot.press(k)
                await pilot.pause(0.1)
                app.export_screenshot()          # forces a full render
            except Exception as exc:
                bad.append((t, f"{type(exc).__name__}: {exc}"[:90]))
            if app._exit_renderables or getattr(app, "_exit", False):
                bad.append((t, "app exited")); break
        print("themes tested:", len(app.available_themes), "| palette now:", P.accent, P.dim)
    print("FAILED:" if bad else "ALL OK", bad)
asyncio.run(main())
