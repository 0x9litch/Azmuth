"""systemd unit failures, restart loops and dependency failures."""

import re

from ..models import Signal

FAILED_RESULT = re.compile(r"^(?P<unit>\S+?): Failed with result '(?P<result>[^']+)'")
MAIN_EXIT = re.compile(r"^(?P<unit>\S+?): Main process exited, code=(?P<code>\w+), status=(?P<status>\S+)")
FAILED_START = re.compile(r"^Failed to start (?P<what>.+?)\.?$")
RESTART = re.compile(r"^(?P<unit>\S+?): Scheduled restart job, restart counter is at (?P<n>\d+)")
START_LIMIT = re.compile(r"^(?P<unit>\S+?): Start request repeated too quickly")
DEPENDENCY = re.compile(r"^Dependency failed for (?P<what>.+?)\.?$")
DEP_JOB = re.compile(r"^(?P<unit>\S+?): Job \S+ failed with result 'dependency'")

_UNIT_SUFFIXES = (".service", ".socket", ".mount", ".timer", ".target", ".path", ".scope")


def _unit_of(event, match_unit=None):
    """Unit from the message, else the journal UNIT= field (systemd's own messages)."""
    for candidate in (match_unit, event.get("unit")):
        if candidate and candidate.endswith(_UNIT_SUFFIXES) and candidate != "init.scope":
            return candidate
    return None


def signals(events):
    out = []
    for e in events:
        if e.get("source") not in ("systemd", "init") and not (e.get("unit") or "").endswith(_UNIT_SUFFIXES):
            continue
        msg = e.get("message", "")
        ts = e.get("epoch") or 0

        m = FAILED_RESULT.search(msg)
        if m:
            unit = _unit_of(e, m["unit"])
            if unit:
                out.append(Signal("service_failed", ts, {"unit": unit, "result": m["result"]}, e))
            continue
        m = MAIN_EXIT.search(msg)
        if m:
            unit = _unit_of(e, m["unit"])
            if unit and m["status"] not in ("0/SUCCESS",):
                out.append(Signal("main_exit", ts, {"unit": unit, "code": m["code"], "status": m["status"]}, e))
            continue
        m = RESTART.search(msg)
        if m:
            unit = _unit_of(e, m["unit"])
            if unit:
                out.append(Signal("restart", ts, {"unit": unit, "n": int(m["n"])}, e))
            continue
        m = START_LIMIT.search(msg)
        if m:
            unit = _unit_of(e, m["unit"])
            if unit:
                out.append(Signal("start_limit", ts, {"unit": unit}, e))
            continue
        m = DEP_JOB.search(msg)
        if m:
            unit = _unit_of(e, m["unit"])
            if unit:
                out.append(Signal("dependency_failed", ts, {"unit": unit}, e))
            continue
        m = DEPENDENCY.search(msg) or FAILED_START.search(msg)
        if m:
            unit = _unit_of(e)
            if unit:
                kind = "dependency_failed" if msg.startswith("Dependency") else "start_failed"
                out.append(Signal(kind, ts, {"unit": unit}, e))
    return out


def failed_state_signals(failed_units, now):
    """Units systemd currently reports as failed (may have failed long ago)."""
    return [Signal("service_failed_state", now, {"unit": u["name"]}) for u in failed_units]
