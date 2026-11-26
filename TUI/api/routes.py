"""
GET endpoints. All data comes from memory (collector) or SQLite (incidents,
history, audit): a request never opens an SSH channel, so the web side can
poll freely without touching the servers.

Every free-text field that may contain secrets (process command lines,
log messages, audit details, incident evidence) is redacted here.
"""

import re
import time
from datetime import datetime, timezone

from aiohttp import web

from ..diagnostics.incidents import STATUSES
from ..diagnostics.redaction import IpMasker, redact, redact_obj
from .security import error

API_VERSION = "1"
MAX_HISTORY_MINUTES = 7 * 24 * 60
_NAME = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
_INCIDENT = re.compile(r"^INC-\d{4,}$")
SEVERITIES = ("critical", "error", "warning", "info")
LOG_LEVELS = ("INFO", "WARNING", "ERROR", "CRITICAL")


# ----------------------------------------------------------------------
# helpers
# ----------------------------------------------------------------------
class BadRequest(Exception):
    pass


def _int(request, key, default, lo, hi):
    raw = request.query.get(key)
    if raw is None or raw == "":
        return default
    try:
        value = int(raw)
    except ValueError:
        raise BadRequest(f"'{key}' must be an integer")
    if not lo <= value <= hi:
        raise BadRequest(f"'{key}' must be between {lo} and {hi}")
    return value


def _number(request, key, default, lo, hi):
    """Like _int but accepts fractions (epochs are returned as floats)."""
    raw = request.query.get(key)
    if raw is None or raw == "":
        return default
    try:
        value = float(raw)
    except ValueError:
        raise BadRequest(f"'{key}' must be a number")
    if not lo <= value <= hi:
        raise BadRequest(f"'{key}' must be between {lo} and {hi}")
    return value


def _choice(request, key, choices, default=None):
    value = request.query.get(key, default)
    if value is not None and value not in choices:
        raise BadRequest(f"'{key}' must be one of: {', '.join(choices)}")
    return value


def _iso(epoch):
    if epoch is None:
        return None
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(epoch))


def _resolution(samples):
    if len(samples) < 2:
        return None
    gaps = sorted(b["ts"] - a["ts"] for a, b in zip(samples, samples[1:]))
    return 5 if gaps[len(gaps) // 2] < 15 else 30


def _round(value):
    return round(value, 1) if isinstance(value, float) else value


def _ok(data):
    return web.json_response(data)


def handle_bad_requests(handler):
    async def wrapper(request):
        try:
            return await handler(request)
        except BadRequest as exc:
            return error(400, "bad_request", str(exc))
    return wrapper


class Routes:
    def __init__(self, backend):
        self.backend = backend

    @property
    def collector(self):
        return self.backend.collector

    def _server(self, request):
        name = request.match_info["name"]
        if not _NAME.match(name) or self.backend.servers.get(name) is None:
            raise web.HTTPNotFound(reason="Server not found")
        return name

    # ------------------------------------------------------------------
    # routing table
    # ------------------------------------------------------------------
    def register(self, app):
        r = app.router
        p = "/api/v1"
        for path, handler in (
            ("/health", self.health),
            ("/servers", self.servers),
            ("/servers/{name}", self.server),
            ("/servers/{name}/metrics", self.metrics),
            ("/servers/{name}/metrics/history", self.history),
            ("/servers/{name}/processes", self.processes),
            ("/servers/{name}/services", self.services),
            ("/servers/{name}/logs", self.logs),
            ("/alerts", self.alerts),
            ("/incidents", self.incidents),
            ("/incidents/{id}", self.incident),
            ("/incidents/{id}/export", self.export),
            ("/audit", self.audit),
        ):
            r.add_get(p + path, handle_bad_requests(handler))

    # ------------------------------------------------------------------
    # endpoints
    # ------------------------------------------------------------------
    async def health(self, request):
        return _ok({"status": "ok", "api_version": API_VERSION, "time": _iso(time.time())})

    def _server_summary(self, s):
        name = s["name"]
        data = self.collector.data.get(name)
        ping = self.collector.ping_results.get(name)
        active = self.backend.incidents.list(server=name, status="active", limit=1000)
        worst = None
        for sev in SEVERITIES:
            if any(i["severity"] == sev for i in active):
                worst = sev
                break
        return {
            "name": name,
            "host": s["host"],
            "port": s["port"],
            "connected": self.backend.is_connected(name),
            "ping": None if ping is None else {"online": ping["online"], "latency_ms": ping["latency_ms"]},
            "active_incidents": len(active),
            "worst_severity": worst,
            "last_collected": {k: _iso(v) for k, v in (data.collected_at.items() if data else [])},
            "collection_errors": dict(data.errors) if data else {},
        }

    async def servers(self, request):
        return _ok({"servers": [self._server_summary(s) for s in self.backend.servers.list()]})

    async def server(self, request):
        name = self._server(request)
        summary = self._server_summary(self.backend.servers.get(name))
        data = self.collector.data.get(name)
        summary["metrics"] = _metrics(data)
        summary["failed_services"] = [s["name"] for s in data.failed_services] if data else []
        summary["journal_access"] = data.journal_access if data else None
        return _ok(summary)

    async def metrics(self, request):
        name = self._server(request)
        return _ok({"server": name, "metrics": _metrics(self.collector.data.get(name))})

    async def history(self, request):
        name = self._server(request)
        minutes = _int(request, "minutes", 60, 1, MAX_HISTORY_MINUTES)
        samples = self.collector.history(name, minutes)
        keys = ("cpu", "mem_percent", "disk_percent", "load1", "load5", "load15", "mem_used", "mem_total")
        return _ok({
            "server": name,
            "minutes": minutes,
            # 5 s from memory, 30 s averages from the database (longer
            # ranges, or right after a restart): report what was returned
            "resolution_seconds": _resolution(samples),
            "samples": [{"ts": _iso(s["ts"]), **{k: _round(s.get(k)) for k in keys}} for s in samples],
        })

    async def processes(self, request):
        name = self._server(request)
        sort = _choice(request, "sort", ("cpu", "mem", "rss", "pid"), "cpu")
        limit = _int(request, "limit", 50, 1, 500)
        data = self.collector.data.get(name)
        procs = [p for p in (data.processes if data else []) if not p["kernel_thread"]]
        procs = sorted(procs, key=lambda p: p[sort], reverse=sort != "pid")[:limit]
        return _ok({
            "server": name,
            "collected_at": _iso(data.collected_at.get("processes")) if data else None,
            "total": len(data.processes) if data else 0,
            "processes": [
                {
                    "pid": p["pid"], "ppid": p["ppid"], "user": p["user"], "cpu": p["cpu"],
                    "mem": p["mem"], "rss_bytes": p["rss"], "elapsed_seconds": p["elapsed"],
                    "state": p["stat"], "name": p["name"], "command": redact(p["command"]),
                }
                for p in procs
            ],
        })

    async def services(self, request):
        name = self._server(request)
        state = _choice(request, "state", ("all", "failed", "active", "inactive"), "all")
        data = self.collector.data.get(name)
        rows = data.services if data else []
        if state != "all":
            rows = [s for s in rows if s["active"] == state]
        return _ok({
            "server": name,
            "collected_at": _iso(data.collected_at.get("services")) if data else None,
            "services": [
                {"name": s["name"], "load": s["load"], "active": s["active"], "sub": s["sub"], "description": s["description"]}
                for s in rows
            ],
        })

    async def logs(self, request):
        name = self._server(request)
        since = _number(request, "since", 0, 0, 2**32)
        limit = _int(request, "limit", 200, 1, 1000)
        level = _choice(request, "level", LOG_LEVELS)
        unit = request.query.get("unit")
        q = (request.query.get("q") or "").casefold()
        rank = {lvl: i for i, lvl in enumerate(LOG_LEVELS)}
        data = self.collector.data.get(name)
        out = []
        for e in (data.logs if data else []):
            if since and (e.get("epoch") or 0) <= since:
                continue
            if level and rank.get(e["level"], 0) < rank[level]:
                continue
            if unit and e.get("unit") != unit:
                continue
            if q and q not in e["message"].casefold():
                continue
            out.append(e)
        out = out[-limit:]
        return _ok({
            "server": name,
            "journal_access": data.journal_access if data else None,
            "count": len(out),
            # pass the last 'epoch' back as ?since= to get only newer lines
            "entries": [
                {
                    "ts": _iso(e.get("epoch")), "epoch": e.get("epoch"), "level": e["level"],
                    "source": e["source"], "unit": e.get("unit"), "pid": e.get("pid"),
                    "message": redact(e["message"]),
                }
                for e in out
            ],
        })

    async def alerts(self, request):
        findings = self.backend.diagnostics.engine.quick_alerts(
            self.backend.servers.names(), self.collector.ping_results, self.collector
        )
        return _ok({"alerts": [
            {"server": f.server, "severity": f.severity.key, "category": f.category, "title": f.title}
            for f in findings
        ]})

    async def incidents(self, request):
        server = request.query.get("server")
        if server is not None and not _NAME.match(server):
            raise BadRequest("invalid server name")
        status = _choice(request, "status", (*STATUSES, "active", "all"), "active")
        severity = _choice(request, "severity", SEVERITIES)
        limit = _int(request, "limit", 100, 1, 500)
        # For n8n: "what was OPENED since my last run" (alerts) and
        # "what was SEEN since yesterday" (daily report) — epoch seconds.
        created_since = _number(request, "created_since", None, 0, 2**32)
        seen_since = _number(request, "seen_since", None, 0, 2**32)
        rows = self.backend.incidents.list(
            server=server, status=None if status == "all" else status, severity=severity,
            limit=500 if (created_since or seen_since) else limit,
        )
        if created_since is not None:
            rows = [r for r in rows if (_epoch(r.get("created_at")) or 0) > created_since]
        if seen_since is not None:
            rows = [r for r in rows if (_epoch(r.get("last_seen")) or 0) >= seen_since]
        return _ok({
            "now": time.time(),   # pass back as created_since next time: nothing is missed
            "incidents": [redact_obj(_incident_summary(r)) for r in rows[:limit]],
        })

    def _incident_id(self, request):
        incident_id = request.match_info["id"]
        if not _INCIDENT.match(incident_id) or self.backend.incidents.get(incident_id) is None:
            raise web.HTTPNotFound(reason="Incident not found")
        return incident_id

    async def incident(self, request):
        return _ok(self.backend.incidents.export(self._incident_id(request)))

    async def export(self, request):
        """What n8n sends to the AI: redacted, optionally with private IPs masked."""
        incident_id = self._incident_id(request)
        fmt = _choice(request, "format", ("json", "markdown"), "json")
        mask = request.query.get("mask_ips", "0") in ("1", "true", "yes")
        if fmt == "markdown":
            return web.Response(
                text=self.backend.incidents.export_markdown(incident_id, mask_ips=mask),
                content_type="text/markdown",
            )
        return _ok(self.backend.incidents.export(incident_id, mask_ips=mask))

    async def audit(self, request):
        limit = _int(request, "limit", 100, 1, 1000)
        masker = IpMasker() if request.query.get("mask_ips") in ("1", "true") else None
        rows = self.backend.logs.audit_records(limit)
        return _ok({"audit": [
            {
                "id": r["id"], "time": r["created_at"], "user": r["user"], "server": r["server_name"],
                "action": r["action"], "status": r["status"],
                "details": redact_obj(r["details"] or "", masker),
            }
            for r in rows
        ]})


def _metrics(data):
    if data is None or data.metrics is None:
        return None
    m = data.metrics
    info = m.get("info") or {}
    mem, disk = m.get("mem") or {}, m.get("disk") or {}
    loads = (info.get("load") or "").split()
    return {
        "collected_at": _iso(data.collected_at.get("metrics")),
        "cpu_percent": m.get("cpu"),
        "memory": {"percent": _round(mem.get("percent")), "used_bytes": mem.get("used"), "total_bytes": mem.get("total")},
        "disk_root": {"percent": disk.get("percent"), "used_bytes": disk.get("used"), "total_bytes": disk.get("total")},
        "load": [float(x) for x in loads[:3]] if len(loads) >= 3 else None,
        "cpus": int(info["cpus"]) if str(info.get("cpus", "")).isdigit() else None,
        "uptime_seconds": int(info["uptime"]) if str(info.get("uptime", "")).isdigit() else None,
        "hostname": info.get("hostname"),
        "os": info.get("os"),
        "kernel": info.get("kernel"),
    }


def _incident_summary(r):
    return {
        "id": r["id"], "server": r["server"], "severity": r["severity"], "status": r["status"],
        "cleared": r["cleared"], "category": r["category"], "title": r["title"],
        "root_cause": r["root_cause"], "confidence": r["confidence"],
        "created_at": r.get("created_at"), "first_seen": r["first_seen"], "last_seen": r["last_seen"],
        "event_count": r["event_count"], "recurring": r["recurring"],
    }


def _epoch(iso):
    try:
        return datetime.strptime(iso, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc).timestamp()
    except (TypeError, ValueError):
        return None
