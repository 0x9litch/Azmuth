"""
Background collector: the ONE place that gathers data from servers.

Every consumer — TUI tabs, the read-only API, the diagnostics engine —
reads from this cache instead of running its own SSH commands. So the load
on the servers is fixed (one schedule per server) no matter how many
screens or web clients are looking.

Schedule per connected server (seconds):
    metrics 5 · processes 5 · services 30 · logs 15 (incremental, by
    journal cursor) · updates 300 · analyze 60 (diagnostics → incidents)
Plus a ping of every registered server every 30 s.

History: the last hour of 5-second metric samples stays in memory; one
30-second average per server goes to SQLite for longer charts (7 days).
"""

import asyncio
import time
from collections import deque
from datetime import datetime, timedelta, timezone

INTERVALS = {
    "metrics": 5,
    "processes": 5,
    "services": 30,
    "logs": 15,
    "updates": 300,
    "analyze": 60,
}
PING_INTERVAL = 30
PERSIST_INTERVAL = 30
PRUNE_INTERVAL = 3600
METRIC_RETENTION_DAYS = 7
RESOLVED_INCIDENT_RETENTION_DAYS = 90
MEMORY_HISTORY = 720          # 1 hour of 5-second samples
LOG_BUFFER = 5000             # journal entries kept per server
FIRST_LOG_WINDOW_MINUTES = 60


def _now_iso():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _sample(snapshot, ts):
    """Flatten a monitoring snapshot into one numeric sample."""
    mem = snapshot.get("mem") or {}
    disk = snapshot.get("disk") or {}
    info = snapshot.get("info") or {}
    loads = [None, None, None]
    try:
        loads = [float(x) for x in str(info.get("load", "")).split()[:3]] + [None] * 3
    except ValueError:
        pass
    return {
        "ts": int(ts),
        "cpu": snapshot.get("cpu"),
        "mem_percent": mem.get("percent"),
        "mem_used": mem.get("used"),
        "mem_total": mem.get("total"),
        "disk_percent": disk.get("percent"),
        "disk_used": disk.get("used"),
        "disk_total": disk.get("total"),
        "load1": loads[0],
        "load5": loads[1],
        "load15": loads[2],
    }


def _average(samples):
    out = {}
    for key in samples[-1]:
        if key == "ts":
            continue
        values = [s[key] for s in samples if isinstance(s.get(key), (int, float))]
        if not values:
            out[key] = None
        elif key in ("mem_used", "mem_total", "disk_used", "disk_total"):
            out[key] = int(sum(values) / len(values))
        else:
            out[key] = round(sum(values) / len(values), 2)
    return out


class ServerData:
    """Everything known about one server, refreshed by the collector."""

    def __init__(self):
        self.metrics = None
        self.history = deque(maxlen=MEMORY_HISTORY)
        self.processes = []
        self.services = []
        self.logs = deque(maxlen=LOG_BUFFER)
        self.logs_cursor = None
        self.updates = None
        self.journal_access = None
        self.collected_at = {}     # kind -> epoch seconds of last success
        # server clock minus local clock (s). Journal timestamps use the
        # server's clock; diagnostics compare them with "now".
        self.clock_offset = 0.0
        self.errors = {}           # kind -> last error message
        self.last_run = {}         # kind -> monotonic time of last attempt
        self.running = set()
        self._pending = []         # samples waiting to be averaged into SQLite
        self._last_persist = time.monotonic()

    @property
    def failed_services(self):
        return [s for s in self.services if s.get("active") == "failed"]


class Collector:
    def __init__(self, backend):
        self.backend = backend
        self.data = {}
        self.ping_results = {}
        self.ping_at = None
        self._listeners = []
        self._task = None
        self._tasks = set()
        self._wake = None
        self._ping_running = False
        self.ping_error = None
        self.loop_errors = 0       # unexpected errors survived by the loop

    # ------------------------------------------------------------------
    # lifecycle
    # ------------------------------------------------------------------
    @property
    def running(self):
        return self._task is not None and not self._task.done()

    def start(self):
        """Start the schedule (must be called from the running event loop)."""
        if self.running:
            return
        self._wake = asyncio.Event()
        self._task = asyncio.create_task(self._loop(), name="azmuth-collector")

    async def stop(self):
        tasks = [t for t in (self._task, *self._tasks) if t is not None and not t.done()]
        for t in tasks:
            t.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        self._task = None
        self._tasks.clear()

    # ------------------------------------------------------------------
    # access for consumers
    # ------------------------------------------------------------------
    def subscribe(self, callback):
        """callback(server_name_or_None, kind) after each collection."""
        self._listeners.append(callback)

    def server(self, name):
        data = self.data.get(name)
        if data is None:
            data = self.data[name] = ServerData()
        return data

    def forget(self, name):
        self.data.pop(name, None)
        self.ping_results.pop(name, None)

    def request(self, name, *kinds):
        """
        Ask for an early refresh (next loop tick, ~immediately).
        With no kinds = a (re)connection: everything is refreshed and facts
        that only change on a new login (journal group membership) are
        re-checked.
        """
        data = self.server(name)
        if not kinds:
            data.journal_access = None
        for kind in kinds or INTERVALS:
            data.last_run.pop(kind, None)
        if self._wake is not None:
            self._wake.set()

    def ping_now(self):
        """Ping every registered server now (key p on the dashboard)."""
        self._spawn(self._ping())

    async def refresh_now(self, name, kind, timeout=60):
        """Collect *kind* right now and wait for the result."""
        data = self.server(name)
        deadline = time.monotonic() + timeout
        while kind in data.running and time.monotonic() < deadline:
            await asyncio.sleep(0.05)
        await self._collect(name, kind)
        if kind in data.errors:
            raise RuntimeError(data.errors[kind])

    def history(self, name, minutes):
        """
        Metric samples for the last *minutes*: 5-second samples from memory,
        and 30-second averages from SQLite for whatever memory does not
        cover (longer ranges, or right after Azmuth was restarted).
        """
        since = time.time() - minutes * 60
        memory = [s for s in self.server(name).history if s["ts"] >= since]
        if memory and memory[0]["ts"] <= since + 30:
            return memory
        until = memory[0]["ts"] if memory else float("inf")
        try:
            stored = [s for s in self.backend.ctx.db.metric_history(name, since) if s["ts"] < until]
        except Exception:
            stored = []
        return stored + memory

    # ------------------------------------------------------------------
    # schedule
    # ------------------------------------------------------------------
    async def _loop(self):
        last_ping = last_prune = float("-inf")
        while True:
            try:
                last_ping, last_prune = self._tick(last_ping, last_prune)
            except asyncio.CancelledError:
                raise
            except Exception:
                # One bad tick (e.g. a DB error) must not stop collection
                # for every server for the rest of the session.
                self.loop_errors += 1

            try:
                await asyncio.wait_for(self._wake.wait(), timeout=1.0)
            except asyncio.TimeoutError:
                pass
            self._wake.clear()

    def _tick(self, last_ping, last_prune):
        """Start whatever is due. Returns the updated ping/prune clocks."""
        now = time.monotonic()
        if now - last_ping >= PING_INTERVAL:
            last_ping = now
            self._spawn(self._ping())

        if now - last_prune >= PRUNE_INTERVAL:
            last_prune = now
            self._prune()

        for name in self.backend.servers.connected_names():
            data = self.server(name)
            for kind, interval in INTERVALS.items():
                if kind in data.running:
                    continue
                if kind == "analyze" and "logs" not in data.collected_at and "logs" not in data.errors:
                    # wait for the first log fetch — but if it FAILED, analyse
                    # anyway: disk, CPU, failed units don't need the journal
                    continue
                if now - data.last_run.get(kind, float("-inf")) >= interval:
                    data.last_run[kind] = now
                    self._spawn(self._collect(name, kind))
        return last_ping, last_prune

    def _spawn(self, coro):
        task = asyncio.create_task(coro)
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)

    def _emit(self, name, kind):
        for callback in list(self._listeners):
            try:
                callback(name, kind)
            except Exception:
                pass

    # ------------------------------------------------------------------
    # collection
    # ------------------------------------------------------------------
    async def _collect(self, name, kind):
        data = self.server(name)
        data.running.add(kind)
        data.last_run[kind] = time.monotonic()
        backend = self.backend

        try:
            if not backend.is_connected(name):
                return

            if kind == "metrics":
                snap = await backend.monitoring.snapshot(name)
                errors = snap.pop("errors", [])
                previous = data.metrics or {}
                # keep the last good value of a metric that failed this time
                data.metrics = {k: snap[k] if snap.get(k) is not None else previous.get(k) for k in snap}
                sample = _sample(data.metrics, time.time())
                data.history.append(sample)
                self._persist(name, data, sample)
                if errors:
                    raise RuntimeError("; ".join(errors))

            elif kind == "processes":
                data.processes = await backend.processes.list(name)
                if data.processes:
                    # start = server_now - elapsed, so start + elapsed = server_now
                    server_now = max(p["start"] + p["elapsed"] for p in data.processes)
                    offset = server_now - time.time()
                    data.clock_offset = offset if abs(offset) >= 5 else 0.0  # ignore jitter

            elif kind == "services":
                data.services = await backend.services.list(name)

            elif kind == "logs":
                if data.journal_access is None:
                    data.journal_access = await backend.logs.journal_access(name)
                entries, cursor = await backend.logs.fetch_new(
                    name, data.logs_cursor, since_minutes=FIRST_LOG_WINDOW_MINUTES
                )
                data.logs.extend(entries)
                data.logs_cursor = cursor

            elif kind == "updates":
                data.updates = await backend.monitoring.updates_info(name)

            elif kind == "analyze":
                await backend.diagnostics.analyze_and_store(name)

            data.collected_at[kind] = time.time()
            data.errors.pop(kind, None)

        except asyncio.CancelledError:
            raise
        except Exception as exc:
            data.errors[kind] = str(exc)
            if kind == "metrics":
                data.collected_at[kind] = time.time()  # partial data still arrived
        finally:
            data.running.discard(kind)

        self._emit(name, kind)

    async def _ping(self):
        if self._ping_running:  # a slow round is still going: don't stack them
            return
        self._ping_running = True
        try:
            results = await self.backend.servers.ping_all(timeout=2)
        except Exception as exc:
            # keep the last known results; just record why this round failed
            self.ping_error = str(exc)
        else:
            self.ping_error = None
            self.ping_results = {
                r["name"]: {"online": bool(r.get("online")), "latency_ms": r.get("latency_ms")}
                for r in results
                if r.get("name") is not None
            }
        finally:
            self._ping_running = False
        self.ping_at = time.time()
        self._emit(None, "ping")

    def _persist(self, name, data, sample):
        data._pending.append(sample)
        if time.monotonic() - data._last_persist < PERSIST_INTERVAL:
            return
        averaged = _average(data._pending)
        data._pending = []
        data._last_persist = time.monotonic()
        try:
            self.backend.ctx.db.add_metric_sample(name, int(sample["ts"]), averaged)
        except Exception:
            pass  # history is best-effort; live data is unaffected

    def _prune(self):
        db = self.backend.ctx.db
        try:
            db.prune_metric_samples(time.time() - METRIC_RETENTION_DAYS * 86400)
            cutoff = datetime.now(timezone.utc) - timedelta(days=RESOLVED_INCIDENT_RETENTION_DAYS)
            db.prune_resolved_incidents(cutoff.strftime("%Y-%m-%dT%H:%M:%SZ"))
        except Exception:
            pass
