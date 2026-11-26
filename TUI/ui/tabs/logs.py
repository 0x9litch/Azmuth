"""
Logs: live journal viewer with filters.

The collector fetches new journal lines every 15 s (incrementally, using
the journal cursor) into a per-server buffer; this tab only filters and
draws that buffer. New lines are appended without redrawing everything,
so the scroll position is kept while reading.

Problem analysis lives in the Incidents tab (7).
"""

import time

from rich.markup import escape
from textual.binding import Binding
from textual.markup import escape as esc
from textual.widgets import Input, RichLog, Static

from ..styles.theme import P
from ..widgets import SearchBar
from .base import BaseTab

MAX_DRAWN = 1500
# "at least" levels: WARNING shows warning + error + critical
LEVELS = ("ALL", "WARNING", "ERROR", "CRITICAL")
_RANK = {"INFO": 0, "WARNING": 1, "ERROR": 2, "CRITICAL": 3}
RANGES = ((0, "all"), (5, "5 min"), (15, "15 min"), (60, "1 h"))


class LogsTab(BaseTab):
    TAB_ID = "logs"
    TITLE = "6 Logs"

    BINDINGS = [
        Binding("r", "refresh_logs", "fetch now"),
        Binding("l", "cycle_level", "level ≥"),
        Binding("t", "cycle_range", "time range"),
        Binding("u", "cycle_unit", "unit"),
        Binding("v", "cycle_source", "source"),
        Binding("slash", "search", "search text", key_display="/"),
        Binding("z", "clear_filters", "reset filters"),
        Binding("escape", "clear_filter", show=False),
    ]

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.level = "ALL"
        self.range_idx = 0
        self.unit = "ALL"
        self.source = "ALL"
        self._last_drawn = None   # last entry written to the RichLog
        self._shown = 0

    def compose(self):
        yield Static("No server connected", id="log-status", classes="subline")
        yield SearchBar(placeholder="Search log messages…  (enter = keep, esc = clear)", id="log-search")
        yield RichLog(id="log-log", wrap=True, markup=True, max_lines=MAX_DRAWN)

    def on_mount(self):
        self.query_one("#log-log").border_title = "JOURNAL"

    @property
    def search(self):
        return self.query_one("#log-search", SearchBar)

    @property
    def log_widget(self):
        return self.query_one("#log-log", RichLog)

    def focus_primary(self):
        self.log_widget.focus()

    @property
    def entries(self):
        return self.backend.collector.server(self.current).logs if self.current else ()

    # ------------------------------------------------------------------
    # hooks
    # ------------------------------------------------------------------
    def restyle(self):
        self.render_logs()

    def on_server_changed(self):
        self.unit = self.source = "ALL"
        self.render_logs()

    async def reload(self):
        self.render_logs()

    def on_collected(self, name, kind):
        if kind == "logs" and name == self.current:
            self._append_new()

    # ------------------------------------------------------------------
    # filtering / drawing
    # ------------------------------------------------------------------
    def _passes(self, e, q, since):
        if self.level != "ALL" and _RANK.get(e["level"], 0) < _RANK[self.level]:
            return False
        if since and (e.get("epoch") or 0) < since:
            return False
        if self.unit != "ALL" and e.get("unit") != self.unit:
            return False
        if self.source != "ALL" and e["source"] != self.source:
            return False
        if q and q not in e["message"].casefold() and q not in e["source"].casefold():
            return False
        return True

    def _filter_args(self):
        minutes = RANGES[self.range_idx][0]
        return self.search.query_text, (time.time() - minutes * 60) if minutes else 0

    def _write(self, e):
        color = P.severity(e["level"]) if e["level"] != "INFO" else P.accent
        self.log_widget.write(
            f"[dim]{escape(e['ts'])}[/dim] [{color}]{e['level']:<8}[/{color}] "
            f"{escape(e['source'][:16]):<16} {escape(e['message'])}"
        )

    def render_logs(self):
        log_w = self.log_widget
        log_w.clear()
        entries = list(self.entries)
        q, since = self._filter_args()
        shown = [e for e in entries if self._passes(e, q, since)][-MAX_DRAWN:]
        for e in shown:
            self._write(e)
        self._shown = len(shown)
        self._last_drawn = entries[-1] if entries else None
        self._status()

    def _append_new(self):
        entries = self.entries
        if not entries:
            return
        # Find where we stopped; if it fell out of the buffer, redraw.
        start = None
        if self._last_drawn is not None:
            for i in range(len(entries) - 1, -1, -1):
                if entries[i] is self._last_drawn:
                    start = i + 1
                    break
        if start is None:
            self.render_logs()
            return
        q, since = self._filter_args()
        for i in range(start, len(entries)):
            if self._passes(entries[i], q, since):
                self._write(entries[i])
                self._shown += 1
        self._last_drawn = entries[-1]
        self._status()

    def _status(self):
        if not self.current:
            self.query_one("#log-status", Static).update("No server selected")
            return
        data = self.backend.collector.server(self.current)
        q = self.search.value.strip()
        extra = ""
        if data.journal_access == "limited":
            extra = f"   [{P.warning}]partial journal (user not in systemd-journal/adm)[/]"
        if data.errors.get("logs"):
            extra += f"   [{P.error}]{esc(data.errors['logs'][:80])}[/]"
        self.query_one("#log-status", Static).update(
            f"[b]{esc(self.current)}[/b]   level≥{self.level}   range={RANGES[self.range_idx][1]}   "
            f"unit={esc(self.unit)}   source={esc(self.source)}"
            + (f"   search='{esc(q)}'" if q else "")
            + f"   shown={min(self._shown, MAX_DRAWN)}/{len(self.entries)}" + extra
        )

    # ------------------------------------------------------------------
    # actions
    # ------------------------------------------------------------------
    def on_input_changed(self, ev: Input.Changed):
        if ev.input.id == "log-search":
            self.render_logs()

    def on_search_bar_closed(self, ev):
        self.focus_primary()

    def action_search(self):
        if self.entries:
            self.search.open()

    def action_clear_filter(self):
        if self.search.value:
            self.search.clear_filter()

    def action_clear_filters(self):
        self.level, self.range_idx, self.unit, self.source = "ALL", 0, "ALL", "ALL"
        if self.search.value:
            self.search.clear_filter()  # triggers a redraw
        else:
            self.render_logs()

    def action_refresh_logs(self):
        if self.require_connection():
            self.app.spawn(self._fetch(self.current), group="reload-logs", exclusive=True)

    async def _fetch(self, name):
        try:
            await self.backend.collector.refresh_now(name, "logs")
        except Exception as exc:
            self.notify(f"Logs: {exc}", severity="error")

    def action_cycle_level(self):
        self.level = LEVELS[(LEVELS.index(self.level) + 1) % len(LEVELS)]
        self.render_logs()

    def action_cycle_range(self):
        self.range_idx = (self.range_idx + 1) % len(RANGES)
        self.render_logs()

    def _cycle(self, attr, field):
        values = sorted({e.get(field) for e in self.entries if e.get(field)})
        if not values:
            return
        order = ["ALL"] + values
        current = getattr(self, attr)
        idx = order.index(current) if current in order else 0
        setattr(self, attr, order[(idx + 1) % len(order)])
        self.render_logs()

    def action_cycle_unit(self):
        self._cycle("unit", "unit")

    def action_cycle_source(self):
        self._cycle("source", "source")
