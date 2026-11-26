"""Resource pressure from metrics: sustained CPU/memory, load, disk usage."""

from ..models import Signal


def signals(metrics, history, thresholds, now):
    out = []
    if not metrics:
        return out

    window = [s for s in history if s["ts"] >= now - thresholds["sustained_seconds"]]
    # need at least ~2 minutes of samples before calling anything "sustained"
    if len(window) >= 24:
        for key, metric in (("cpu", "cpu"), ("mem_percent", "mem")):
            values = [s[key] for s in window if s.get(key) is not None]
            limit = thresholds[f"sustained_{metric}"]
            if values and min(values) >= limit:
                out.append(Signal(f"sustained_{metric}", now, {"min": min(values), "max": max(values), "minutes": round((window[-1]["ts"] - window[0]["ts"]) / 60, 1)}))

    disk = (metrics.get("disk") or {}).get("percent")
    if disk is not None and disk >= thresholds["disk_warning"]:
        out.append(Signal("disk_usage", now, {"percent": disk, "mount": "/"}))

    info = metrics.get("info") or {}
    try:
        load1 = float(str(info.get("load", "")).split()[0])
        cpus = int(info.get("cpus"))
    except (TypeError, ValueError, IndexError):
        load1 = cpus = None
    if load1 is not None and cpus and load1 / cpus >= thresholds["load_per_cpu_warning"]:
        out.append(Signal("load_high", now, {"load1": load1, "cpus": cpus}))
    return out
