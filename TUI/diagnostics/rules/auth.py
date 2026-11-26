"""SSH authentication failures (possible brute force)."""

import re

from ..models import Signal

FAILED = re.compile(
    r"Failed (?:password|publickey|keyboard-interactive\S*) for (?:invalid user )?(?P<user>\S+) "
    r"from (?P<ip>[0-9a-fA-F:.]+)"
)
INVALID = re.compile(r"Invalid user (?P<user>\S*) from (?P<ip>[0-9a-fA-F:.]+)")
# OpenSSH >= 9.8 logs from "sshd-session" instead of "sshd".
SOURCES = ("sshd", "sshd-session")


def signals(events):
    out = []
    for e in events:
        if e.get("source") not in SOURCES and "ssh" not in (e.get("unit") or ""):
            continue
        msg = e.get("message", "")
        m = FAILED.search(msg) or INVALID.search(msg)
        if m:
            out.append(Signal("ssh_auth_fail", e.get("epoch") or 0, {"ip": m["ip"], "user": m["user"]}, e))
    return out
