"""
System logs (journalctl) and the local audit trail.
"""

import json
import shlex
from datetime import datetime

from .base import BaseManager
from .errors import BackendError
from ..core.sanitize import clean_text

LOG_LEVELS = ("ALL", "CRITICAL", "ERROR", "WARNING", "INFO")
MAX_LOG_LINES = 5000


def _level_from_priority(priority):
    # syslog priorities: 0 emerg, 1 alert, 2 crit, 3 err, 4 warning, 5+ notice/info/debug
    if priority is None:
        return "INFO"
    if priority <= 2:
        return "CRITICAL"
    if priority == 3:
        return "ERROR"
    if priority == 4:
        return "WARNING"
    return "INFO"


def _decode_message(value):
    if value is None:
        return ""
    if isinstance(value, list):  # binary messages are arrays of byte values
        try:
            return bytes(value).decode("utf-8", errors="replace")
        except (TypeError, ValueError):
            return str(value)
    return str(value)


def _parse_json_line(line):
    record = json.loads(line)

    try:
        priority = int(record.get("PRIORITY"))
    except (TypeError, ValueError):
        priority = None

    ts = ""
    epoch = None
    raw_ts = record.get("__REALTIME_TIMESTAMP")
    if raw_ts:
        try:
            epoch = int(raw_ts) / 1_000_000
            ts = datetime.fromtimestamp(epoch).strftime("%Y-%m-%d %H:%M:%S")
        except (TypeError, ValueError, OverflowError, OSError):
            ts, epoch = "", None

    source = record.get("SYSLOG_IDENTIFIER") or record.get("_COMM") or ""

    # For systemd's own messages about a unit, UNIT= names the unit the
    # message is about (_SYSTEMD_UNIT would be init.scope). For a service's
    # own output, _SYSTEMD_UNIT is that service.
    unit = record.get("UNIT") or record.get("USER_UNIT") or record.get("_SYSTEMD_UNIT") or ""

    try:
        pid = int(record.get("_PID")) if record.get("_PID") is not None else None
    except (TypeError, ValueError):
        pid = None

    return {
        "ts": ts,
        "epoch": epoch,
        "source": str(source),
        "unit": str(unit),
        "pid": pid,
        "level": _level_from_priority(priority),
        "priority": priority,
        "message": _decode_message(record.get("MESSAGE")).rstrip(),
        "cursor": record.get("__CURSOR"),
        "boot_id": record.get("_BOOT_ID"),
    }


def _parse_text_line(line):
    """Fallback for plain-text journal lines (heuristic level)."""
    upper = line.upper()

    if " ERROR " in upper or "PRIORITY=3" in upper:
        level = "ERROR"
    elif " WARN" in upper or "PRIORITY=4" in upper:
        level = "WARNING"
    else:
        level = "INFO"

    parts = line.split(None, 2)

    return {
        "ts": parts[0] if parts else "",
        "epoch": None,
        "source": parts[1] if len(parts) > 1 else "",
        "unit": "",
        "pid": None,
        "level": level,
        "priority": None,
        "message": parts[2] if len(parts) > 2 else line,
        "cursor": None,
        "boot_id": None,
    }


def parse_journal_json(stdout):
    entries = []
    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            entry = _parse_json_line(line)
        except (ValueError, AttributeError):
            entry = _parse_text_line(line)
        # json.loads turns "\u001b" into a real ESC: clean AFTER decoding
        for key in ("message", "source", "unit"):
            if isinstance(entry.get(key), str):
                entry[key] = clean_text(entry[key])
        entries.append(entry)
    return entries


class LogManager(BaseManager):
    async def recent(self, name, lines=300):
        """
        Return the last *lines* journal entries, oldest first.

        Uses journalctl's JSON output so the level comes from the real
        syslog PRIORITY field instead of guessing from the text.
        """
        self.ctx.require(name)

        lines = int(lines)

        if lines < 1:
            raise BackendError("Log line count must be at least 1")

        if lines > MAX_LOG_LINES:
            raise BackendError(f"Log line count cannot exceed {MAX_LOG_LINES}")

        res = await self.ctx.run(
            name,
            f"journalctl --no-pager --output=json -n {lines}",
            timeout=20,
        )

        if res.exit_code != 0:
            raise BackendError(f"journalctl failed: {res.stderr.strip() or res.exit_code}")

        return parse_journal_json(res.stdout)

    async def fetch_new(self, name, cursor=None, since_minutes=60, limit=3000):
        """
        Incremental collection: entries after *cursor* (or the last
        *since_minutes* on the first call). Returns (entries, last_cursor).
        Only new lines travel over SSH each time.
        """
        self.ctx.require(name)
        limit = max(1, min(int(limit), MAX_LOG_LINES))

        if cursor:
            where = f"--after-cursor={shlex.quote(cursor)}"
        else:
            where = f"--since={shlex.quote(f'-{int(since_minutes)}min')}"

        res = await self.ctx.run(
            name,
            f"journalctl --no-pager --output=json {where} -n {limit}",
            timeout=30,
        )

        if res.exit_code != 0:
            raise BackendError(f"journalctl failed: {res.stderr.strip() or res.exit_code}")

        entries = parse_journal_json(res.stdout)
        last_cursor = next((e["cursor"] for e in reversed(entries) if e.get("cursor")), cursor)
        return entries, last_cursor

    async def journal_access(self, name):
        """
        'full' if this SSH user can read the system journal, else 'limited'.
        On Ubuntu that needs root or membership in systemd-journal / adm;
        without it journalctl silently shows only the user's own logs.
        """
        res = await self.ctx.run(name, "id -u; id -nG", timeout=10)
        lines = (res.stdout or "").split("\n")
        uid = lines[0].strip() if lines else ""
        groups = set(lines[1].split()) if len(lines) > 1 else set()
        if uid == "0" or groups & {"systemd-journal", "adm", "wheel"}:
            return "full"
        return "limited"

    # ------------------------------------------------------------------
    # audit trail
    # ------------------------------------------------------------------
    def audit_records(self, limit=200):
        return self.db.list_audit(limit)
