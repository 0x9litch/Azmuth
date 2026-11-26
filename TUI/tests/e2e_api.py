"""Read-only API: security properties + data, and saves real responses for docs/API.md."""
import asyncio, json, os, stat, subprocess, sys
exec(open("e2e.py").read().split("async def main():")[0])
import aiohttp

API_PORT = 18765
EXAMPLES = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "docs", "examples")
ok = 0
def check(name, cond, info=""):
    global ok
    assert cond, f"{name}: {info}"
    ok += 1
    print("✓", name)

async def main():
    setup_fs()
    server, fp = await start_server()
    from TUI.backend import Backend
    from TUI.core.connection import ConnectionManager
    from TUI.core.database import Database
    from TUI.ui import AzmuthApp

    # a process whose command line carries a secret (must be redacted by the API)
    secret_proc = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(120)", "--db-password=hunter2"])
    # a process whose command line tries to write the admin's clipboard (OSC 52)
    evil_proc = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(120)", "\x1b]52;c;cHduZWQ=\x07evil"])

    db = Database(); db.initialize(); db.set_setting("ssh_key_path", "~/.ssh/id_test"); db.set_setting("api_port", str(API_PORT))
    backend = Backend(db, ConnectionManager())
    for n in ("web-srv", "db-srv"):
        backend.servers.add(n, "127.0.0.1", PORT, "glitch", "~/.ssh/id_test"); db.save_fingerprint(n, fp)
    backend.record_audit("demo", "web-srv", "success", "mysql -u root -pS3cretPass dump; token=abc123")
    app = AzmuthApp(backend)
    os.makedirs(EXAMPLES, exist_ok=True)

    async with app.run_test(size=(160, 46)) as pilot:
        await backend.servers.connect("web-srv"); await backend.servers.connect("db-srv")
        app.refresh_server_views(); app._after_connection_change("web-srv")
        for kind in ("metrics", "processes", "services", "logs"):
            await backend.collector.refresh_now("web-srv", kind)
        await backend.diagnostics.analyze_and_store("web-srv")

        # ---- off by default, A turns it on
        check("API is off at start", not backend.api.running)
        await pilot.press("A")
        await wait_for(pilot, lambda: backend.api.running, msg="api on")
        topbar = str(app.main.query_one("#topbar").render())
        check("A starts it; top bar shows it", f"api: ON :{API_PORT}" in topbar, topbar)

        tok_path = backend.api.token_path
        check("token file 0600, dir 0700",
              stat.S_IMODE(os.stat(tok_path).st_mode) == 0o600 and stat.S_IMODE(os.stat(tok_path.parent).st_mode) == 0o700)
        token = tok_path.read_text().strip()
        H = {"Authorization": f"Bearer {token}"}
        base = f"http://127.0.0.1:{API_PORT}/api/v1"

        async with aiohttp.ClientSession() as http:
            async def get(path, headers=H, save=None, **kw):
                async with http.get(base + path, headers=headers, **kw) as r:
                    body = await r.text()
                    data = json.loads(body) if r.content_type == "application/json" else body
                    if save:
                        with open(f"{EXAMPLES}/{save}", "w") as f:
                            f.write(json.dumps(data, indent=2) if not isinstance(data, str) else data)
                    return r.status, data, r.headers

            # ---- security
            s, d, h = await get("/health", headers={}, save="health.json")
            check("health is public, reveals nothing", s == 200 and set(d) == {"status", "api_version", "time"}, d)
            check("security headers, no CORS, no version in Server",
                  h.get("X-Content-Type-Options") == "nosniff" and h.get("Cache-Control") == "no-store"
                  and "Access-Control-Allow-Origin" not in h and h.get("Server") == "azmuth", dict(h))
            s, d, _ = await get("/servers", headers={})
            check("no token -> 401 JSON", s == 401 and d["error"]["code"] == "unauthorized", d)
            with open(f"{EXAMPLES}/error-401.json", "w") as f: json.dump(d, f, indent=2)
            s, d, _ = await get("/servers", headers={"Authorization": "Bearer " + "x" * 43})
            check("wrong token -> 401", s == 401)
            async with http.post(base + "/servers", headers=H) as r:
                check("POST -> 405 (read-only)", r.status == 405, r.status)
            s, d, _ = await get("/servers", headers={**H, "Host": "evil.example:8765"})
            check("foreign Host header -> 421 (DNS rebinding)", s == 421, s)
            s, d, _ = await get("/servers/nope")
            check("unknown server -> 404 JSON", s == 404 and d["error"]["code"] == "not_found", d)
            s, d, _ = await get("/servers/web-srv/metrics/history?minutes=abc")
            check("bad parameter -> 400", s == 400 and "minutes" in d["error"]["message"], d)
            s, d, _ = await get("/servers/web-srv/../../etc/passwd")
            check("path tricks -> 404", s == 404, s)

            # ---- data
            s, d, _ = await get("/servers", save="servers.json")
            names = [x["name"] for x in d["servers"]]
            check("/servers", s == 200 and names == ["db-srv", "web-srv"] and "key_path" not in json.dumps(d), d)
            s, d, _ = await get("/servers/web-srv", save="server.json")
            check("/servers/{name} has metrics + failed services", d["metrics"]["cpu_percent"] is not None and d["failed_services"] == ["broken.service"], d)
            s, d, _ = await get("/servers/web-srv/metrics", save="metrics.json")
            check("/metrics", d["metrics"]["memory"]["total_bytes"] > 0)
            s, d, _ = await get("/servers/web-srv/metrics/history?minutes=10", save="metrics-history.json")
            check("/metrics/history", s == 200 and len(d["samples"]) >= 1, d)
            s, d, _ = await get("/servers/web-srv/processes?sort=mem&limit=5")  # docs example is hand-written: the test host's own processes must not leak into it
            check("/processes sort+limit", s == 200 and len(d["processes"]) == 5)
            s, d, _ = await get("/servers/web-srv/processes?limit=500")
            joined = json.dumps(d)
            check("process command lines redacted", "--db-password=[REDACTED]" in joined and "hunter2" not in joined)
            raw_procs = backend.collector.server("web-srv").processes
            evil = [p for p in raw_procs if "evil" in p["command"]]
            # ps already prints control characters as '.', our layer is the backup
            check("escape sequences never reach the TUI or the API (ps)",
                  evil and "\x1b" not in evil[0]["command"] and "\\u001b" not in joined and "\x1b" not in joined, evil)
            s, d, _ = await get("/servers/web-srv/services?state=failed", save="services-failed.json")
            check("/services?state=failed", [x["name"] for x in d["services"]] == ["broken.service"], d)
            s, d, _ = await get("/servers/web-srv/logs?level=ERROR", save="logs.json")
            check("/logs?level=ERROR (>=)", d["count"] == 2, d)
            last = d["entries"][-1]["epoch"]
            s, d, _ = await get(f"/servers/web-srv/logs?since={last}")
            check("/logs?since=<last epoch> -> only newer", d["count"] == 0, d)
            s, d, _ = await get("/alerts", save="alerts.json")
            check("/alerts", s == 200 and any(a["title"] == "broken.service failed" for a in d["alerts"]), d)
            s, d, _ = await get("/incidents", save="incidents.json")
            check("/incidents", s == 200 and len(d["incidents"]) >= 2, d)
            check("/incidents carries root_cause + created_at (for Telegram)",
                  all(i["root_cause"] and i["created_at"] for i in d["incidents"]), d)
            mark = d["now"]
            s2, d2, _ = await get(f"/incidents?status=all&created_since={mark}")
            check("created_since=<now from last call> -> nothing new (no duplicate alerts)", s2 == 200 and d2["incidents"] == [], d2)
            s2, d2, _ = await get("/incidents?status=all&created_since=0")
            check("created_since=0 -> everything", len(d2["incidents"]) == len(d["incidents"]), d2)
            s2, d2, _ = await get(f"/incidents?status=all&seen_since={mark - 86400}", save="incidents-report.json")
            check("seen_since (daily report window)", len(d2["incidents"]) >= 1, d2)
            s2, d2, _ = await get("/incidents?created_since=abc")
            check("created_since validated", s2 == 400, d2)
            iid = next(i["id"] for i in d["incidents"] if "OOM" in i["title"])
            s, d, _ = await get(f"/incidents/{iid}", save="incident.json")
            check("/incidents/{id} with evidence", d["evidence"] and d["checks"], d)
            s, d, h = await get(f"/incidents/{iid}/export?format=markdown&mask_ips=1", save="incident-export.md")
            check("/export markdown", s == 200 and d.startswith(f"# {iid}") and "text/markdown" in h["Content-Type"])
            s, d, _ = await get("/incidents/INC-9999")
            check("unknown incident -> 404", s == 404)
            s, d, _ = await get("/audit?limit=50", save="audit.json")
            joined = json.dumps(d)
            check("audit details redacted", "S3cretPass" not in joined and "abc123" not in joined and "[REDACTED]" in joined, joined[:300])
            check("failed logins are audited", any(r["action"] == "api_auth_failed" for r in d["audit"]))

            # ---- a flood of bad tokens is throttled but never locks out the real token
            bad = []
            for _ in range(15):
                async with http.get(base + "/servers", headers={"Authorization": "Bearer wrong"}) as r:
                    bad.append(r.status)
            check("bad-token flood -> 429 after 10", bad.count(401) <= 10 and 429 in bad, bad)
            s, d, _ = await get("/servers")
            check("valid token still works during a bad-token flood", s == 200, s)
            audited = [r for r in (await get("/audit?limit=1000"))[1]["audit"] if r["action"] == "api_auth_failed"]
            check("audit not flooded (<= 10 failed-login rows per minute + earlier ones)", len(audited) <= 12, len(audited))

            # ---- global rate limit (runaway loops)
            statuses = []
            for _ in range(620):
                async with http.get(base + "/health") as r:
                    statuses.append(r.status)
            check("rate limit -> 429 after 600/min", 429 in statuses and statuses.count(200) <= 600, statuses[-3:])

        # ---- rotate + stop
        old = token
        backend.api.rotate_token()
        check("rotate writes a new token", tok_path.read_text().strip() != old)
        await pilot.press("A")
        await wait_for(pilot, lambda: not backend.api.running, msg="api off")
        try:
            async with aiohttp.ClientSession() as http:
                async with http.get(base + "/health", timeout=aiohttp.ClientTimeout(total=2)):
                    pass
            stopped = False
        except aiohttp.ClientError:
            stopped = True
        check("A stops it: port closed", stopped)

    secret_proc.kill()
    evil_proc.kill()
    server.close()
    print(f"\n{ok} API checks passed")

asyncio.run(main())
