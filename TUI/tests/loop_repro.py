import asyncio, os, sys, tempfile
os.environ["HOME"] = tempfile.mkdtemp()
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..")))
from TUI.backend import Backend
from TUI.core.connection import ConnectionManager
from TUI.core.database import Database
from TUI.ui import AzmuthApp

async def main():
    db = Database(); db.initialize(); db.set_setting("ssh_key_path", "~/.ssh/none")
    b = Backend(db, ConnectionManager())
    for n, ip in (("db-srv", "10.0.0.12"), ("mgmt-srv", "10.0.0.10"), ("web-srv", "10.0.0.11")):
        b.servers.add(n, ip, 22, "glitch", "~/.ssh/none")
    app = AzmuthApp(b)
    calls = []
    orig = app.select_server
    def spy(name):
        calls.append(name); return orig(name)
    app.select_server = spy
    async with app.run_test() as pilot:
        await pilot.pause(0.3)
        app.select_server("mgmt-srv")
        await pilot.pause(0.3)
        calls.clear()
        # same tick: refresh (highlights old) then select another (highlights new)
        app.refresh_server_views()
        orig("web-srv")
        await pilot.pause(2.0)
        print("current:", app.current, "| spontaneous select_server calls:", len(calls), calls[:8])
asyncio.run(main())
