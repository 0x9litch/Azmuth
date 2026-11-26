"""
Diagnostics engine — pure and synchronous (no SSH, no DB).

    analyze(server, data, ping)  -> Report   full analysis of one server
    quick_alerts(...)            -> [Finding] cheap dashboard alerts

`data` is the collector's ServerData (or anything with the same fields),
so the engine can be tested with plain objects and fake log lines.
"""

import time
from datetime import datetime

from . import correlator, rules
from .models import Finding, Report, Severity
from .rules import THRESHOLDS, resources, services, updates

# Only analyse a recent window: older problems are already incidents.
ANALYSIS_WINDOW = 2 * 3600


def _boot_ts(metrics, now):
    try:
        return now - int((metrics or {}).get("info", {}).get("uptime"))
    except (TypeError, ValueError):
        return 0


class DiagnosticsEngine:
    def analyze(self, server, data, ping=None, now=None):
        local_now = now or time.time()
        offset = getattr(data, "clock_offset", 0.0) or 0.0
        # log timestamps come from the server's clock: compare in that clock
        now = local_now + offset
        events = [e for e in data.logs if (e.get("epoch") or 0) >= now - ANALYSIS_WINDOW]

        signals, matched = rules.log_signals(events)
        signals += services.failed_state_signals(data.failed_services, now)
        signals += updates.signals(data.updates)
        # metric history is stamped with the local clock
        signals += resources.signals(data.metrics, list(data.history), THRESHOLDS, local_now)

        unmatched = [
            e for e in events
            if id(e) not in matched and e.get("priority") is not None and e["priority"] <= 3
        ]
        ctx = {
            "now": now,
            "journal_access": data.journal_access,
            "ping": ping,
            "unmatched_errors": unmatched,
            "boot_ts": _boot_ts(data.metrics, now),  # server clock, compared with log times
        }
        findings = correlator.correlate(server, signals, events, ctx)
        if offset:
            # store incident times in the local clock, like everything else
            for f in findings:
                f.first_ts = f.first_ts - offset if f.first_ts else f.first_ts
                f.last_ts = f.last_ts - offset if f.last_ts else f.last_ts
        return Report(
            server=server,
            findings=findings,
            errors=[f"{k}: {v}" for k, v in data.errors.items()],
            collected_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        )

    def quick_alerts(self, servers, ping_results, collector=None):
        """Ping state of every server + live metric thresholds. No remote calls."""
        out = []
        for name in servers:
            ping = ping_results.get(name)
            if ping is not None and not ping.get("online"):
                out.append(Finding(Severity.CRITICAL, name, "network", "server unreachable (no ping reply)"))
            data = collector.data.get(name) if collector else None
            m = data.metrics if data else None
            if not m:
                continue
            for label, value, key in (
                ("CPU", m.get("cpu"), "cpu"),
                ("memory", (m.get("mem") or {}).get("percent"), "mem"),
                ("disk /", (m.get("disk") or {}).get("percent"), "disk"),
            ):
                if value is None:
                    continue
                if value >= THRESHOLDS[f"{key}_critical"]:
                    out.append(Finding(Severity.CRITICAL, name, "resources", f"{label} at {value:.0f}%"))
                elif value >= THRESHOLDS[f"{key}_warning"]:
                    out.append(Finding(Severity.WARNING, name, "resources", f"{label} at {value:.0f}%"))
            for svc in data.failed_services[:3]:
                out.append(Finding(Severity.ERROR, name, "services", f"{svc['name']} failed"))
        out.sort(key=lambda f: -int(f.severity))
        return out
