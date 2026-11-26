"""Services: list systemd units, filter, start/stop/restart."""

from rich.text import Text
from textual.markup import escape as esc
from textual.binding import Binding
from textual.widgets import DataTable, Input, Static

from ..dialogs import ConfirmDialog
from ..styles.theme import P
from ..widgets import SearchBar
from .base import CANCELLED, BaseTab



def _active_style(state):
    return {"active": f"bold {P.accent}", "failed": f"bold {P.error}", "activating": P.warning}.get(state, P.dim)


class ServicesTab(BaseTab):
    TAB_ID = "services"
    TITLE = "2 Services"

    BINDINGS = [
        Binding("slash", "search", "search", key_display="/"),
        Binding("f", "toggle_failed", "failed only"),
        Binding("s", "service('start')", "start"),
        Binding("t", "service('stop')", "stop"),
        Binding("r", "service('restart')", "restart"),
        Binding("R", "reload_list", "reload", key_display="R"),
        Binding("escape", "clear_filter", show=False),
    ]

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.entries = []
        self.failed_only = False

    def compose(self):
        yield Static("No server connected", id="services-summary", classes="subline")
        yield SearchBar(placeholder="Filter services…  (enter = keep, esc = clear)", id="services-search")
        yield DataTable(id="services-table", cursor_type="row")

    def on_mount(self):
        self.query_one(DataTable).add_columns("Service", "Load", "Active", "Sub", "Description")

    @property
    def table(self):
        return self.query_one("#services-table", DataTable)

    @property
    def search(self):
        return self.query_one("#services-search", SearchBar)

    def focus_primary(self):
        self.table.focus()

    def on_server_changed(self):
        self.entries = []
        self.table.clear()
        self._summary()

    def restyle(self):
        if self.entries:
            self.render_rows()

    async def reload(self):
        """Show what the collector has now and ask it for a fresh list."""
        self._show_collected()
        self.backend.collector.request(self.current, "services")

    async def refresh_now(self):
        name = self.current
        try:
            await self.backend.collector.refresh_now(name, "services")
        except Exception as exc:
            self.notify(f"Services: {exc}", severity="error")
        if name == self.current:
            self._show_collected()

    def on_collected(self, name, kind):
        if kind == "services" and name == self.current:
            self._show_collected()

    def _show_collected(self):
        services = self.backend.collector.server(self.current).services if self.current else []
        if services is not self.entries:
            self.entries = services
            self.render_rows()

    # ------------------------------------------------------------------
    # rendering / filtering
    # ------------------------------------------------------------------
    def _visible(self):
        q = self.search.query_text
        rows = self.entries
        if self.failed_only:
            rows = [s for s in rows if s["active"] == "failed"]
        if q:
            rows = [s for s in rows if q in s["name"].casefold() or q in s["description"].casefold()]
        return rows

    def _summary(self, shown=None):
        if not self.entries:
            self.query_one("#services-summary", Static).update(
                "No services loaded" if self.current else "No server selected"
            )
            return
        running = sum(1 for s in self.entries if s["sub"] == "running")
        failed = sum(1 for s in self.entries if s["active"] == "failed")
        filt = []
        if self.failed_only:
            filt.append("failed only")
        if self.search.query_text:
            filt.append(f"'{esc(self.search.value.strip())}'")
        self.query_one("#services-summary", Static).update(
            f"{esc(self.current)}: [b]{len(self.entries)}[/b] units   "
            f"running [b {P.accent}]{running}[/]   failed [b {P.error}]{failed}[/]   "
            f"showing {shown if shown is not None else len(self.entries)}"
            + (f"   filter: {', '.join(filt)}" if filt else "")
        )

    def render_rows(self):
        table = self.table
        prev = None
        if table.row_count:
            try:
                prev = table.coordinate_to_cell_key(table.cursor_coordinate).row_key.value
            except Exception:
                prev = None

        rows = self._visible()
        table.clear()

        for s in rows:
            table.add_row(
                Text(s["name"]),
                Text(s["load"]),
                Text(s["active"], style=_active_style(s["active"])),
                Text(s["sub"]),
                Text(s["description"]),
                key=s["name"],
            )

        if prev is not None:
            try:
                table.move_cursor(row=table.get_row_index(prev))
            except Exception:
                pass

        self._summary(len(rows))

    def on_input_changed(self, ev: Input.Changed):
        if ev.input.id == "services-search":
            self.render_rows()

    def on_search_bar_closed(self, ev):
        self.table.focus()

    # ------------------------------------------------------------------
    # actions
    # ------------------------------------------------------------------
    def action_search(self):
        if self.require_connection():
            self.search.open()

    def action_clear_filter(self):
        if self.search.value:
            self.search.clear_filter()

    def action_toggle_failed(self):
        self.failed_only = not self.failed_only
        self.render_rows()

    def action_reload_list(self):
        if self.require_connection():
            self.app.spawn(self.refresh_now(), group="reload-services", exclusive=True)

    def on_data_table_row_selected(self, ev):
        ev.stop()
        self.notify("Press s / t / r to start / stop / restart this service")

    def action_service(self, action):
        if not self.require_connection():
            return

        if self.table.row_count == 0:
            self.notify("No services loaded", severity="warning")
            return

        try:
            service = self.table.coordinate_to_cell_key(self.table.cursor_coordinate).row_key.value
        except Exception:
            return

        self.app.spawn(self._run_action(self.current, service, action))

    async def _run_action(self, server, service, action):
        if action in ("stop", "restart"):
            ok = await self.app.ask(
                ConfirmDialog(
                    f"{action} service",
                    f"{action.capitalize()} {service} on {server}?"
                    + ("\n⚠ Stopping ssh/sshd can lock you out." if "ssh" in service and action == "stop" else ""),
                )
            )
            if not ok:
                return

        try:
            with self.app.busy(f"{action} {service}"):
                result = await self.run_with_sudo(
                    f"service_{action}",
                    lambda pw: self.backend.services.action(
                        server, service, action, sudo_password=pw.get(server)
                    ),
                )
            if result is not CANCELLED:
                self.notify(f"{action} {service}: OK")
        except Exception as exc:
            self.notify(f"{action} {service} failed: {exc}", severity="error")

        if server == self.current:
            await self.refresh_now()
        self.app.refresh_audit()
