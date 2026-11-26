"""Activity / Audit: local audit trail with search and status filter."""

from rich.text import Text
from textual.markup import escape as esc
from textual.binding import Binding
from textual.widgets import DataTable, Input, Static

from ..styles.theme import P
from ..widgets import SearchBar
from .base import BaseTab

STATUS_FILTERS = ("ALL", "success", "failed", "pending", "rejected")
AUDIT_LIMIT = 500


class ActivityTab(BaseTab):
    TAB_ID = "activity"
    TITLE = "8 Activity / Audit"
    NEEDS_CONNECTION = False

    BINDINGS = [
        Binding("r", "reload_records", "refresh"),
        Binding("f", "cycle_status", "status filter"),
        Binding("slash", "search", "search", key_display="/"),
        Binding("escape", "clear_filter", show=False),
    ]

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.records = []
        self.status_filter = "ALL"

    def compose(self):
        yield Static("", id="audit-summary", classes="subline")
        yield SearchBar(placeholder="Search server, action, details…", id="audit-search")
        yield DataTable(id="audit-table", cursor_type="row")

    def on_mount(self):
        self.table.add_columns("Time (UTC)", "User", "Server", "Action", "Status", "Details")

    @property
    def table(self):
        return self.query_one("#audit-table", DataTable)

    @property
    def search(self):
        return self.query_one("#audit-search", SearchBar)

    def focus_primary(self):
        self.table.focus()

    async def reload(self):
        self.refresh_records()

    def restyle(self):
        self.render_rows()

    def refresh_records(self):
        """Synchronous: the audit trail is a local SQLite query."""
        try:
            self.records = self.backend.logs.audit_records(AUDIT_LIMIT)
        except Exception as exc:
            self.notify(f"Audit: {exc}", severity="error")
            return
        self.render_rows()

    def render_rows(self):
        q = self.search.query_text
        table = self.table
        table.clear()
        shown = 0

        for r in self.records:
            if self.status_filter != "ALL" and r["status"] != self.status_filter:
                continue
            haystack = f"{r['server_name'] or ''} {r['action']} {r['details'] or ''}".casefold()
            if q and q not in haystack:
                continue
            shown += 1
            table.add_row(
                Text(r["created_at"]),
                Text(r["user"]),
                Text(r["server_name"] or "-"),
                Text(r["action"]),
                Text(r["status"], style={"success": P.accent, "pending": P.warning}.get(r["status"], P.error)),
                Text((r["details"] or "")[:120]),
            )

        filt = []
        if self.status_filter != "ALL":
            filt.append(f"status={self.status_filter}")
        if q:
            filt.append(f"search='{esc(self.search.value.strip())}'")
        self.query_one("#audit-summary", Static).update(
            f"{shown} of {len(self.records)} most recent records"
            + (f"   filter: {', '.join(filt)}" if filt else "")
        )

    def on_input_changed(self, ev: Input.Changed):
        if ev.input.id == "audit-search":
            self.render_rows()

    def on_search_bar_closed(self, ev):
        self.table.focus()

    def action_reload_records(self):
        self.refresh_records()

    def action_cycle_status(self):
        i = STATUS_FILTERS.index(self.status_filter)
        self.status_filter = STATUS_FILTERS[(i + 1) % len(STATUS_FILTERS)]
        self.render_rows()

    def action_search(self):
        self.search.open()

    def action_clear_filter(self):
        if self.search.value:
            self.search.clear_filter()
