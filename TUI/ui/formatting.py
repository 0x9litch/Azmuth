"""Pure formatting helpers used by tabs and widgets."""

import stat as stat_mod
from datetime import datetime


def fmt_bytes(n):
    if n is None:
        return "—"
    try:
        n = float(n)
    except (TypeError, ValueError, OverflowError):
        return "—"

    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            return f"{n:.1f} {unit}"
        n /= 1024

    return "—"


def fmt_uptime(seconds):
    if seconds is None:
        return "—"
    try:
        s = int(seconds)
    except (TypeError, ValueError, OverflowError):
        return "—"

    days, rem = divmod(s, 86400)
    hours, rem = divmod(rem, 3600)
    mins, _ = divmod(rem, 60)
    return f"{days}d {hours}h {mins}m"


def fmt_mode(permissions):
    """0o100644 -> '-rw-r--r--' (like ls -l)."""
    try:
        return stat_mod.filemode(int(permissions))
    except (TypeError, ValueError):
        return "?"


def fmt_mtime(epoch):
    try:
        epoch = int(epoch)
    except (TypeError, ValueError):
        return ""
    if epoch <= 0:
        return ""
    return datetime.fromtimestamp(epoch).strftime("%Y-%m-%d %H:%M")


def bar(percent, width=20):
    """Text gauge: '██████░░░░░░' for a 0..100 value."""
    try:
        p = max(0.0, min(100.0, float(percent)))
    except (TypeError, ValueError):
        return "░" * width
    filled = round(p / 100 * width)
    return "█" * filled + "░" * (width - filled)
