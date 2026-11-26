import sys, time, tempfile, os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..")))
from collections import deque
from TUI.diagnostics.engine import DiagnosticsEngine
from TUI.diagnostics.incidents import IncidentStore
from TUI.diagnostics.redaction import redact
from TUI.diagnostics.models import Severity
from TUI.core.database import Database

NOW = time.time()
def ev(dt, source, msg, unit=None, prio=6):
    return {"epoch": NOW - dt, "source": source, "message": msg, "unit": unit, "priority": prio}

class Data:
    def __init__(self, logs=(), services=(), updates=None, metrics=None, history=(), access="full"):
        self.logs = deque(logs); self.services = list(services); self.updates = updates
        self.metrics = metrics; self.history = deque(history); self.journal_access = access; self.errors = {}
    @property
    def failed_services(self): return [s for s in self.services if s.get("active") == "failed"]

E = DiagnosticsEngine()
ok = fail = 0
def check(name, cond, info=""):
    global ok, fail
    ok += bool(cond); fail += (not cond)
    print(("PASS " if cond else "FAIL ") + name + ("" if cond else f"  -> {info}"))

def run(data, **kw): return E.analyze("t", data, **kw).findings
def find(fs, key): return next((f for f in fs if f.key.startswith(key)), None)

# 1 OOM -> service
fs = run(Data([
    ev(100, "kernel", "Out of memory: Killed process 4242 (mysqld) total-vm:2000kB", prio=3),
    ev(99, "systemd", "mysql.service: A process of this unit has been killed by the OOM killer.", unit="mysql.service", prio=4),
    ev(99, "systemd", "mysql.service: Main process exited, code=killed, status=9/KILL", unit="mysql.service", prio=5),
    ev(98, "systemd", "mysql.service: Failed with result 'oom-kill'.", unit="mysql.service", prio=4),
]))
f = find(fs, "oom:")
check("OOM linked to mysql.service, high, critical", f and f.affected == ["mysql.service"] and f.confidence == "high" and f.severity == Severity.CRITICAL, fs)
check("OOM: no separate svc finding", not find(fs, "svc:mysql"), [x.key for x in fs])

# 2 disk full -> services
fs = run(Data([
    ev(300, "nginx", "open() \"/var/log/nginx/access.log\" failed (28: No space left on device)", unit="nginx.service", prio=3),
    ev(200, "systemd", "postgresql.service: Failed with result 'exit-code'.", unit="postgresql.service", prio=4),
], metrics={"disk": {"percent": 99.0}, "info": {}}))
f = find(fs, "disk:full")
check("disk full affects postgresql", f and "postgresql.service" in f.affected and f.confidence == "high", fs)

# 3 dependency
fs = run(Data([
    ev(50, "systemd", "var-data.mount: Failed with result 'exit-code'.", unit="var-data.mount", prio=4),
    ev(49, "systemd", "Dependency failed for app.service - My App.", unit="app.service", prio=3),
]))
f = find(fs, "dep:var-data.mount")
check("dependency root = var-data.mount", f and f.confidence == "high", [x.key for x in fs])

# 4 restart loop with cause line
logs = [ev(400, "myapp", "Error: cannot connect to redis at 127.0.0.1:6379", unit="myapp.service", prio=3)]
for n in range(1, 6):
    logs.append(ev(390 - n * 10, "systemd", f"myapp.service: Scheduled restart job, restart counter is at {n}.", unit="myapp.service", prio=6))
logs.append(ev(300, "systemd", "myapp.service: Start request repeated too quickly.", unit="myapp.service", prio=4))
fs = run(Data(logs))
f = find(fs, "loop:myapp")
check("restart loop with redis cause", f and "redis" in f.root_cause and f.count == 5, fs)

# 5 upgrade -> service failure (name match)
fs = run(Data(
    [ev(600, "systemd", "nginx.service: Failed with result 'exit-code'.", unit="nginx.service", prio=4)],
    updates={"packages": [{"epoch": NOW - 900, "action": "upgrade", "package": "nginx", "old": "1.24.0-2", "new": "1.24.0-3"}]},
))
f = find(fs, "update:nginx")
check("upgrade nginx -> nginx.service high", f and f.confidence == "high" and "1.24.0-2" in f.root_cause, fs)

# 6 kernel change + module error
fs = run(Data(
    [ev(60, "kernel", "nvidia: Unknown symbol drm_open (err -2)", prio=3)],
    updates={"kernel": "6.8.0-50-generic", "prev_kernel": "6.8.0-45-generic", "packages": []},
    metrics={"info": {"uptime": "120"}},
))
f = find(fs, "kernel:")
check("kernel change + module error critical", f and f.severity == Severity.CRITICAL and "nvidia" in f.affected, fs)

# 7 ssh brute force
logs = [ev(500 - i, "sshd", f"Failed password for invalid user u{i % 4} from 203.0.113.9 port 4{i} ssh2", unit="ssh.service", prio=6) for i in range(30)]
fs = run(Data(logs))
f = find(fs, "ssh:203.0.113.9")
check("ssh brute force warning high", f and f.severity == Severity.WARNING and f.confidence == "high" and f.count == 30, fs)

# 8 unclassified + limited journal + thermal false positive guard
logs = [ev(100 - i, "weirdd", f"weird thing {i}", unit="weirdd.service", prio=3) for i in range(6)]
logs.append(ev(10, "thermald", "thermald: Started thermal daemon", prio=6))
fs = run(Data(logs, access="limited"))
check("unclassified errors grouped", find(fs, "errors:weirdd.service"), [x.key for x in fs])
check("limited journal warning", find(fs, "journal-access"), [x.key for x in fs])
check("thermald start is not thermal", not find(fs, "thermal"), [x.key for x in fs])

# 9 failed state with no logs -> low confidence
fs = run(Data(services=[{"name": "old.service", "active": "failed"}]))
f = find(fs, "svc:old.service")
check("failed state only -> low", f and f.confidence == "low", fs)

# server clock 3 h ahead of ours: its log lines must still be analysed
skew = Data([{"epoch": NOW + 3 * 3600 - 60, "source": "kernel", "message": "Out of memory: Killed process 77 (java)", "unit": None, "priority": 3}])
skew.clock_offset = 3 * 3600
fs = E.analyze("t", skew, now=NOW).findings
f = find(fs, "oom:")
check("clock skew: server-time logs analysed, stored in local time", f and abs(f.last_ts - (NOW - 60)) < 1, fs)

# metric history falls back to the database after a restart (empty memory)
from TUI.backend.collector import Collector
class _B: pass
class _Ctx: pass
tmpd = tempfile.mkdtemp(dir=os.path.expanduser("~")); hdb = Database(os.path.join(tmpd, "h.db")); hdb.initialize()
for i in range(10):
    hdb.add_metric_sample("srv", int(NOW) - 1800 + i * 30, {"cpu": 10.0 + i, "mem_percent": 5.0, "mem_used": 1, "mem_total": 2,
                                                            "disk_percent": 1.0, "disk_used": 1, "disk_total": 2, "load1": 0.1, "load5": 0.1, "load15": 0.1})
b = _B(); b.ctx = _Ctx(); b.ctx.db = hdb
c = Collector(b)
check("history after restart comes from the database", len(c.history("srv", 60)) == 10, c.history("srv", 60))

# redaction
s = redact("mysql -u root -pS3cret db; password=hunter2 Authorization: Bearer abc.def token: xyz https://bob:pw@example.com AKIAABCDEFGHIJKLMNOP")
check("redaction", all(x not in s for x in ("S3cret", "hunter2", "abc.def", "xyz", ":pw@", "AKIAABCDEFGHIJKLMNOP")), s)

cases = {
 "PGPASSWORD=abc psql -h db": "abc", "DB_PASSWORD: s3cr3t": "s3cr3t", "mysql --password hunter2 db": "hunter2",
 "sshpass -p Pa55 ssh root@x": "Pa55", "MYSQL_PWD=x1y mysql": "x1y", "curl -u admin:Pw123 http://x": "Pw123",
 "export API_TOKEN=tok123": "tok123", "redis-cli -a RedisPass ping": "RedisPass", 'mysql --password="q w" db': "q w"}
leaks = [k for k, v in cases.items() if v in redact(k)]
check("redaction: env vars, flags, sshpass, redis, curl", not leaks, leaks)
keep = "Failed password for invalid user admin from 1.2.3.4 port 22 ssh2"
check("redaction keeps normal auth lines readable", redact(keep) == keep, redact(keep))

# incident lifecycle
tmp = tempfile.mkdtemp(dir=os.path.expanduser("~")); db = Database(os.path.join(tmp, "t.db")); db.initialize()
store = IncidentStore(db)
data = Data(services=[{"name": "old.service", "active": "failed"}])
new = store.sync("t", run(data))
check("first sync creates incident", len(new) == 1 and new[0]["id"] == "INC-0001", new)
again = store.sync("t", run(data))
check("second sync dedupes", again == [] and len(store.list("t")) == 1, store.list("t"))
store.sync("t", [])
inc = store.get("INC-0001")
check("vanished -> cleared", inc["cleared"], inc)
store.set_status("INC-0001", "resolved")
new = store.sync("t", run(data))
check("recurrence new incident", new and new[0]["recurring"] == 1 and new[0]["previous_id"] == "INC-0001", new)
md = store.export_markdown(new[0]["id"])
check("markdown export", md and "Root cause" in md and "old.service" in md, md)

# resolving a log-based incident must not recreate it from the same old lines
oom = Data([ev(100, "kernel", "Out of memory: Killed process 4242 (mysqld)", prio=3)])
created = store.sync("t", run(oom))
store.set_status(created[0]["id"], "resolved")
check("resolved + same old log lines -> no new incident", store.sync("t", run(oom)) == [])
time.sleep(1.1)
oom.logs.append({"epoch": time.time(), "source": "kernel", "message": "Out of memory: Killed process 5555 (mysqld)", "unit": None, "priority": 3})
again = store.sync("t", run(oom))
check("resolved + NEW event after resolution -> recurring incident", again and again[0]["recurring"] == 1, again)

# ids compare as numbers ("INC-9999" < "INC-10000")
for i in ("INC-9999", "INC-10000"):
    db.conn.execute("INSERT INTO incidents (id, server, fingerprint, category, severity, status, title, first_seen, last_seen, created_at, updated_at) "
                    "VALUES (?, 't', ?, 'c', 'info', 'resolved', 't', 'a', 'a', 'a', 'a')", (i, i))
db.conn.commit()
check("next incident id after INC-10000 is INC-10001", store._next_id() == "INC-10001", store._next_id())

# secrets are redacted BEFORE storage (raw DB rows)
leaky = Data([
    ev(50, "myapp", "connect failed: mysql -u root -pTopSecret1 password=hunter2", unit="myapp.service", prio=3),
    ev(40, "systemd", "myapp.service: Failed with result 'exit-code'.", unit="myapp.service", prio=4),
])
store.sync("t", run(leaky))
raw = " ".join(str(tuple(r)) for r in db.conn.execute("SELECT * FROM incidents").fetchall())
raw += " ".join(str(tuple(r)) for r in db.conn.execute("SELECT * FROM incident_evidence").fetchall())
check("no secrets in incidents tables", "TopSecret1" not in raw and "hunter2" not in raw and "[REDACTED]" in raw, raw[:300])
from TUI.backend.base import BackendContext
ctx = BackendContext.__new__(BackendContext); ctx.db = db
ctx.audit("exec", "t", "success", "mysql -u root -pS3cret -e 'select 1'")
raw = str([tuple(r) for r in db.conn.execute("SELECT details FROM audit_logs").fetchall()])
check("no secrets in audit table", "S3cret" not in raw and "[REDACTED]" in raw, raw)

# a resolved problem is NOT reopened by the same old log lines …
oom_logs = [ev(300, "kernel", "Out of memory: Killed process 777 (worker)", prio=3)]
created = store.sync("t", run(Data(oom_logs)))
oom_id = next(i["id"] for i in created if "worker" in i["title"])
store.set_status(oom_id, "resolved")
db.conn.execute("UPDATE incidents SET updated_at = ? WHERE id = ?",
                (time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(NOW - 60)), oom_id)); db.conn.commit()
again = store.sync("t", run(Data(oom_logs)))
check("resolved + same old logs -> no false recurrence", not [i for i in again if "worker" in i["title"]], again)
# … but a NEW kill after the resolution is a real recurrence
newer = oom_logs + [ev(10, "kernel", "Out of memory: Killed process 888 (worker)", prio=3)]
again = store.sync("t", run(Data(newer)))
back = [i for i in again if "worker" in i["title"]]
check("new evidence after resolution -> recurrence", back and back[0]["recurring"] >= 1 and back[0]["previous_id"] == oom_id, again)
# … and a unit that is STILL failed comes back even with old logs only
store.set_status(next(i["id"] for i in store.list("t") if i["title"] == "old.service failed"), "resolved")
again = store.sync("t", run(Data(services=[{"name": "old.service", "active": "failed"}])))
check("still failed (ongoing) -> reopened", any(i["title"] == "old.service failed" for i in again), again)

# the case the external review caught: still failed AND old log lines present
logs_fail = [ev(600, "svcx", "fatal: bad config", unit="stuck.service", prio=3),
             ev(599, "systemd", "stuck.service: Failed with result 'exit-code'.", unit="stuck.service", prio=4)]
state = [{"name": "stuck.service", "active": "failed"}]
store.sync("t", run(Data(logs_fail, services=state)))
sid = next(i["id"] for i in store.list("t") if i["title"].startswith("stuck.service"))
store.set_status(sid, "resolved")
again = store.sync("t", run(Data(logs_fail, services=state)))
check("still failed WITH old logs -> reopened (ongoing wins)", any(i["title"].startswith("stuck.service") for i in again), again)
store.set_status(next(i["id"] for i in store.list("t") if i["title"].startswith("stuck.service")), "resolved")
again = store.sync("t", run(Data(logs_fail, services=[])))
check("fixed (no longer failed), same old logs -> stays resolved", not any(i["title"].startswith("stuck.service") for i in again), again)

# input validation (option injection / names the API can address)
from TUI.backend.server_manager import ServerManager
from TUI.backend.service_manager import is_safe_unit
from TUI.backend.errors import BackendError
v = ServerManager.validate
def rejects(*a):
    try:
        v(None, *a); return False
    except BackendError:
        return True
check("host starting with '-' rejected", rejects("ok", "-oProxyCommand=x", 22, "glitch", "~/.ssh/k"))
check("name with space rejected", rejects("my server", "10.0.0.1", 22, "glitch", "~/.ssh/k"))
check("username starting with '-' rejected", rejects("ok", "10.0.0.1", 22, "-x", "~/.ssh/k"))
check("normal server accepted", not rejects("web-srv", "192.168.122.11", 22, "glitch", "~/.ssh/k")
      and not rejects("v6", "fe80::1%virbr0", 22, "glitch", "~/.ssh/k"))
check("unit starting with '-' rejected", not is_safe_unit("--now") and is_safe_unit("nginx.service"))

# server clock 3 h BEHIND: a line 30 s old on the server looks 3 h old to us
skew = Data([ev(3 * 3600 + 30, "kernel", "Out of memory: Killed process 1 (skewproc)", prio=3)])
skew.clock_offset = 0.0
check("without the offset the fresh line is dropped (shows the risk)", not find(run(skew), "oom:skewproc"), "")
skew.clock_offset = -3 * 3600.0
check("with the server clock offset it is analysed", find(run(skew), "oom:skewproc"), "dropped")

# journal JSON: "\u001b" becomes a real ESC only after json decoding
from TUI.backend.log_manager import parse_journal_json
line = '{"__REALTIME_TIMESTAMP":"1700000000000000","PRIORITY":"3","SYSLOG_IDENTIFIER":"x\\u001b]0;T\\u0007","MESSAGE":"hi \\u001b]52;c;cHduZWQ=\\u0007 there \\u009b31m"}'
e = parse_journal_json(line)[0]
check("journal escape sequences neutralised", "\x1b" not in e["message"] + e["source"] and "\x9b" not in e["message"] and "^[" in e["message"], e)

# secrets never reach the database file
logs = [ev(50, "myapp", "connect failed: password=Hunter2Secret token=tok_ABCDEF123", unit="leaky.service", prio=3),
        ev(49, "systemd", "leaky.service: Failed with result 'exit-code'.", unit="leaky.service", prio=4)]
store.sync("t", run(Data(logs)))
db.add_audit("me", "t", "exec", "success", "mysql -u root -pS3cretPass -e 'show databases'")
db.conn.commit()
raw = open(db.db_path, "rb").read() + (open(str(db.db_path) + "-wal", "rb").read() if os.path.exists(str(db.db_path) + "-wal") else b"")
check("no secrets in the sqlite file", all(x not in raw for x in (b"Hunter2Secret", b"tok_ABCDEF123", b"S3cretPass")), "secret found on disk")
leaky = next(i for i in store.list("t") if "leaky" in i["title"])
check("redacted text still readable", "[REDACTED]" in leaky["root_cause"] and "connect failed" in leaky["root_cause"], leaky["root_cause"])

print(f"\n{ok} passed, {fail} failed")
sys.exit(1 if fail else 0)
