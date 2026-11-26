"""
Detection rules. Each module turns raw evidence into Signals:

    auth.py      SSH login failures
    memory.py    OOM killer
    disk.py      disk full, I/O errors, read-only remounts
    services.py  failed units, restart loops, dependency failures
    system.py    thermal throttling, segfaults, kernel module / firmware errors
    updates.py   package upgrades and kernel changes (from dpkg.log)
    resources.py sustained CPU / memory / load / disk usage (from metrics)

Adding a problem type = adding a function here; the engine and the
correlator do not need to change for a standalone signal.
"""

from . import auth, disk, memory, resources, services, system, updates

# Thresholds in percent unless noted. Change them here only.
THRESHOLDS = {
    "cpu_warning": 85.0,
    "cpu_critical": 95.0,
    "mem_warning": 80.0,
    "mem_critical": 90.0,
    "disk_warning": 85.0,
    "disk_critical": 95.0,
    "load_per_cpu_warning": 2.0,
    "sustained_cpu": 90.0,          # % for SUSTAINED_SECONDS -> finding
    "sustained_mem": 90.0,
    "sustained_seconds": 300,
    "auth_failures_warning": 10,    # failed SSH attempts from one IP in the window
    "auth_failures_error": 100,
    "unclassified_errors": 5,       # error lines from one source with no rule
}

LOG_RULES = (auth.signals, memory.signals, disk.signals, services.signals, system.signals)


def log_signals(events):
    """Run every log rule. Returns (signals, ids_of_events_that_matched)."""
    out = []
    for rule in LOG_RULES:
        out.extend(rule(events))
    matched = {id(s.event) for s in out if s.event is not None}
    return out, matched

__all__ = ["THRESHOLDS", "log_signals", "auth", "disk", "memory", "resources", "services", "system", "updates"]
