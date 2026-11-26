"""Disk full, storage I/O errors, filesystem switched to read-only."""

import re

from ..models import Signal

NO_SPACE = re.compile(r"No space left on device", re.I)
IO_ERROR = re.compile(
    r"I/O error,? dev (?P<a>[\w-]+)|Buffer I/O error on dev(?:ice)? (?P<b>[\w-]+)|"
    r"EXT4-fs error \(device (?P<c>[\w-]+)\)|XFS \((?P<d>[\w-]+)\):.*(?:error|corrupt)",
    re.I,
)
READ_ONLY = re.compile(r"(?:\((?P<dev>[\w-]+)\): )?Remounting filesystem read-only", re.I)


def signals(events):
    out = []
    for e in events:
        msg = e.get("message", "")
        ts = e.get("epoch") or 0
        if NO_SPACE.search(msg):
            out.append(Signal("disk_full_log", ts, {"unit": e.get("unit") or e.get("source")}, e))
            continue
        m = READ_ONLY.search(msg)
        if m:
            out.append(Signal("readonly_remount", ts, {"device": m["dev"] or "?"}, e))
            continue
        m = IO_ERROR.search(msg)
        if m:
            dev = next((g for g in m.groups() if g), "?")
            out.append(Signal("io_error", ts, {"device": dev}, e))
    return out
