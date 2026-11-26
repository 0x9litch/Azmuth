"""
Regression test for the bug in the user's screenshot:
servers switching by themselves + "open failed" (sshd MaxSessions).
Fake server refuses channels above 10, like OpenSSH.
"""

import asyncio
import os
import sys

exec(open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "e2e.py")).read().split("async def main():")[0])


def server_channels():
    try:
        now, peak = open(f"{HOME}/.channels").read().split()
        return int(now), int(peak)
    except (OSError, ValueError):
        return 0, 0


async def main():
    setup_fs()
    server, fp = await start_server()

    from TUI.backend import Backend
    from TUI.core.connection import ConnectionManager, MAX_CHANNELS_PER_CONNECTION
    from TUI.core.database import Database
    from TUI.ui import AzmuthApp
    from TUI.ui.dialogs import FingerprintDialog, KeyGenerateDialog, SecretDialog, ServerForm

    db = Database()
    db.initialize()
    backend = Backend(db, ConnectionManager())
    app = AzmuthApp(backend)

    switches = []
    real_select = app.select_server

    def spy(name):
        switches.append(name)
        return real_select(name)

    async with app.run_test(size=(160, 50)) as pilot:
        # first run: key without passphrase to keep the test short
        await wait_for(pilot, lambda: isinstance(app.screen, KeyGenerateDialog), msg="keygen")
        await pilot.press("ctrl+s")
        await pilot.press("ctrl+s")  # confirm "no passphrase"
        await wait_for(pilot, lambda: not isinstance(app.screen, KeyGenerateDialog), msg="keygen done")

        # two existing servers, the selected one NOT first (the user's case)
        for n in ("db-srv", "mgmt-srv"):
            backend.servers.add(n, "127.0.0.1", PORT, "glitch", "~/.ssh/azmuth_ed25519")
        app.refresh_server_views()
        real_select("mgmt-srv")
        await pilot.pause(0.3)
        app.select_server = spy

        # ---------- add a third server via the form, with password
        await pilot.press("a")
        await wait_for(pilot, lambda: isinstance(app.screen, ServerForm), msg="form")
        f = app.screen
        f.query_one("#f-name").value = "web-srv"
        f.query_one("#f-host").value = "127.0.0.1"
        f.query_one("#f-port").value = str(PORT)
        f.query_one("#f-username").value = "glitch"
        f.query_one("#f-password").value = "serverpass"
        await pilot.press("ctrl+s")
        await wait_for(pilot, lambda: isinstance(app.screen, FingerprintDialog), msg="fp")
        await pilot.press("y")
        await wait_for(pilot, lambda: backend.is_connected("web-srv"), msg="web-srv connected", timeout=15)
        await pilot.pause(3)  # let any loop show itself
        assert switches == ["web-srv"], f"servers switched by themselves: {len(switches)} {switches[:6]}"
        print(f"✓ add server: exactly 1 switch (was hundreds), current={app.current}")

        # ---------- connect the others, flip between servers and tabs fast
        await pilot.press("C")
        await wait_for(pilot, lambda: isinstance(app.screen, FingerprintDialog), msg="fp db", timeout=15)
        await pilot.press("y")
        await wait_for(pilot, lambda: isinstance(app.screen, FingerprintDialog), msg="fp mgmt", timeout=15)
        await pilot.press("y")
        await wait_for(pilot, lambda: len(backend.servers.connected_names()) == 3, msg="all 3", timeout=20)
        # F-keys work from every tab; after the Terminal (f4) the prompt has
        # focus and would swallow letters, so leave it with esc first.
        for key in ["f1", "f2", "f3", "right_square_bracket", "f5", "f6", "left_square_bracket", "f4", "escape", "f7",
                    "right_square_bracket", "f2", "f3", "f1", "right_square_bracket", "f6", "f5", "f4", "escape", "f8", "f1"] * 3:
            await pilot.press(key)
            await pilot.pause(0.05)
        await pilot.pause(4)
        refusals = [m for m in all_notes(app) if "refused" in m or "open failed" in m]
        assert not refusals, refusals
        _, peak = server_channels()
        print(f"✓ fast server/tab switching: no refused channels (server peak {peak} ≤ 10)")

        # ---------- 30 parallel commands on ONE connection stay under the cap
        conn = backend.ctx.connection("web-srv")
        results = await asyncio.gather(*(conn.run_command("sleep 0.3; echo ok") for _ in range(30)))
        assert all(r.stdout.strip() == "ok" for r in results)
        print(f"✓ 30 parallel commands all succeed (client cap {MAX_CHANNELS_PER_CONNECTION} channels/server)")

        # ---------- cancelled commands release their channels
        tasks = [asyncio.create_task(conn.run_command("sleep 5")) for _ in range(6)]
        await asyncio.sleep(0.7)
        for t in tasks:
            t.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        await pilot.pause(0.5)
        open_channels = len(conn.conn._channels)
        assert open_channels == 0, f"{open_channels} channels leaked after cancel"
        r = await conn.run_command("echo still-fine")
        assert r.stdout.strip() == "still-fine"
        print("✓ cancelled commands close their channels (0 leaked)")

        # ---------- wrong address: fails cleanly, no loop, no flood
        backend.servers.add("bad-ip", "127.0.0.1", 1, "glitch", "~/.ssh/azmuth_ed25519")
        app.refresh_server_views()
        switches.clear()
        app.select_server("bad-ip")
        await pilot.press("c")
        await wait_for(pilot, lambda: any("bad-ip" in m and "error" in m for m in all_notes(app)), msg="bad-ip error")
        await pilot.pause(3)
        assert switches == ["bad-ip", "bad-ip"] or switches == ["bad-ip"], switches
        assert app.current == "bad-ip"
        errors = [m for m in all_notes(app) if m.startswith("error")]
        assert len(errors) <= 2, errors
        print(f"✓ wrong IP/port: one clear error, no switching ({errors[0][:70]})")

        # ---------- server dies: UI notices
        real_select("web-srv")
        await pilot.pause(0.3)
        server.close()
        await wait_for(pilot, lambda: not backend.is_connected("web-srv"), msg="drop detected", timeout=20)
        await wait_for(pilot, lambda: any("connection lost" in m for m in all_notes(app)), msg="lost toast", timeout=8)
        assert "DISCONNECTED" in str(app.main.query_one("#status").render())
        print("✓ server shutdown: 'connection lost' shown, status updated")


asyncio.run(main())
