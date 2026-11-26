"""Out-of-memory killer activity."""

import re

from ..models import Signal

OOM_KILLED = re.compile(r"Out of memory: Killed process (?P<pid>\d+) \((?P<proc>[^)]+)\)")
OOM_TASK = re.compile(r"oom-kill:.*\btask=(?P<proc>[^,]+),pid=(?P<pid>\d+)")
UNIT_OOM = re.compile(r"^(?P<unit>\S+?): A process of this unit has been killed by the OOM killer")


def signals(events):
    out = []
    for e in events:
        msg = e.get("message", "")
        ts = e.get("epoch") or 0
        m = OOM_KILLED.search(msg) or OOM_TASK.search(msg)
        if m:
            out.append(Signal("oom_kill", ts, {"pid": int(m["pid"]), "process": m["proc"].strip()}, e))
            continue
        m = UNIT_OOM.search(msg)
        if m:
            out.append(Signal("unit_oom", ts, {"unit": m["unit"]}, e))
    return out
