"""Thermal throttling, crashes (segfaults), kernel module and firmware load errors."""

import re

from ..models import Signal

# Real kernel throttling/overheating messages. The bare word "thermal"
# is NOT used: it matched healthy thermald output.
THERMAL = re.compile(
    r"temperature above threshold|cpu clock throttled|critical temperature reached|"
    r"thermal_zone\d+: critical",
    re.I,
)
SEGFAULT = re.compile(r"(?P<proc>[\w.@:+-]+)\[(?P<pid>\d+)\]: segfault at")
MODULE = re.compile(
    r"Failed to insert module '(?P<a>[^']+)'|"
    r"^(?P<b>\w+): (?:Unknown symbol|disagrees about version of symbol)"
)
FIRMWARE = re.compile(r"Direct firmware load for (?P<fw>\S+) failed")


def signals(events):
    out = []
    for e in events:
        msg = e.get("message", "")
        ts = e.get("epoch") or 0
        if THERMAL.search(msg):
            out.append(Signal("thermal", ts, {}, e))
            continue
        m = SEGFAULT.search(msg)
        if m:
            out.append(Signal("segfault", ts, {"process": m["proc"], "pid": int(m["pid"])}, e))
            continue
        m = MODULE.search(msg)
        if m:
            out.append(Signal("module_error", ts, {"module": m["a"] or m["b"]}, e))
            continue
        m = FIRMWARE.search(msg)
        if m:
            out.append(Signal("firmware_error", ts, {"firmware": m["fw"]}, e))
    return out
