"""
Data types of the diagnostics pipeline.

    log entry (dict) ──rules──▶ Signal ──correlator──▶ Finding ──store──▶ Incident (SQLite)

- Signal: one rule matched one piece of evidence ("OOM killed pid 1234").
- Finding: a diagnosed problem built from one or more related signals,
  with a root cause, a confidence level and the evidence behind it.
- Incident: a Finding persisted and tracked over time (see incidents.py).
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import IntEnum


class Severity(IntEnum):
    INFO = 1
    WARNING = 2
    ERROR = 3
    CRITICAL = 4

    @property
    def label(self):
        return {1: "INFO", 2: "WARN", 3: "ERR", 4: "CRIT"}[int(self)]

    @property
    def key(self):
        return self.name.lower()

    @classmethod
    def from_key(cls, key):
        return cls[str(key).upper()]


# Confidence is a label with a reason, never a fake percentage.
HIGH, MEDIUM, LOW = "high", "medium", "low"


def iso_utc(epoch):
    if epoch is None:
        return None
    return datetime.fromtimestamp(epoch, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


@dataclass
class Signal:
    kind: str                 # e.g. "oom_kill", "service_failed", "ssh_auth_fail"
    ts: float                 # epoch seconds
    entities: dict            # what the rule extracted: unit, pid, process, ip, ...
    event: dict | None = None # the log entry it came from (None for metric/state signals)


@dataclass
class Finding:
    severity: Severity
    server: str
    category: str             # memory | disk | services | security | updates | system | resources | network | logs
    title: str
    key: str = ""             # stable identity of the problem -> incident fingerprint
    root_cause: str = ""
    confidence: str = MEDIUM
    confidence_reason: str = ""
    impact: str = ""
    affected: list = field(default_factory=list)
    evidence: list = field(default_factory=list)   # [{ts, source, unit, role, message}]
    checks: list = field(default_factory=list)     # [{title, command}]
    first_ts: float | None = None
    last_ts: float | None = None
    count: int = 1
    # True when the problem is a CURRENT state (unit failed right now, disk
    # full now), not only old log lines: a resolved incident is reopened
    # only if the problem is ongoing or has evidence newer than the resolution.
    ongoing: bool = False

    # Short forms used by the dashboard alert list.
    @property
    def detail(self):
        return self.root_cause

    @property
    def suggestion(self):
        return self.checks[0]["title"] if self.checks else ""

    def short(self):
        return f"{self.server}: {self.title}"


@dataclass
class Report:
    server: str
    findings: list = field(default_factory=list)
    errors: list = field(default_factory=list)   # data that could not be collected
    collected_at: str = ""

    @property
    def worst(self):
        return max((f.severity for f in self.findings), default=None)

    def count(self, severity):
        return sum(1 for f in self.findings if f.severity == severity)


def evidence_from_event(event, role="observed"):
    return {
        "ts": iso_utc(event.get("epoch")) or event.get("ts") or "",
        "source": event.get("source") or "",
        "unit": event.get("unit") or "",
        "role": role,
        "message": (event.get("message") or "")[:500],
    }
