"""
Processes: live process list (from the collector, every 5 s) + safe kill.

Kill safety, in layers:
  1. UI refuses PID 1 and kernel threads, and always asks for confirmation
     (SIGKILL and sshd get an extra warning).
  2. The backend re-checks on the server that the PID still has the SAME
     start time it had in the list — so a PID reused by a new process is
     never killed by mistake (exit 67 "different process").
  3. Someone else's process needs sudo: the password prompt is shown and the
     password is kept only for this one operation.
  4. Every attempt is written to the audit log.
"""

from rich.text import Text
from textual.binding import Binding
from textual.markup import escape as esc
from textual.widgets import DataTable, Input, Static

from ..dialogs import ConfirmDialog
from ..formatting import fmt_bytes
from ..styles.theme import P
from ..widgets import SearchBar
from .base import CANCELLED, BaseTab

SORTS = (("cpu", "CPU%"), ("mem", "MEM%"), ("rss", "RSS"), ("elapsed", "TIME"), ("pid", "PID"))
MAX_ROWS = 400


def fmt_elapsed(seconds):
    seconds = int(seconds or 0)
    d, rem = divmod(seconds, 86400)
    h, rem = divmod(rem, 3600)
    m, s = divmod(rem, 60)
    if d:
        return f"{d}d{h:02d}h"
    if h:
        return f"{h}h{m:02d}m"
    return f"{m}m{s:02d}s"


class ProcessesTab(BaseTab):
    TAB_ID = "procs"
    TITLE = "3 Processes"

    BINDINGS = [
        Binding("slash", "search", "search", key_display="/"),
        Binding("o", "cycle_sort", "sort"),
        Binding("h", "toggle_kernel", "kernel threads"),
        Binding("k", "kill('TERM')", "terminate (TERM)"),
        Binding("ctrl+k", "kill('KILL')", "force kill (KILL)", key_display="^k"),
        Binding("R", "refresh_now", "refresh", key_display="R"),
        Binding("escape", "clear_filter", show=False),
    ]

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.entries = []
        self.sort_idx = 0
        self.show_kernel = False

    def compose(self):
        yield Static("No server connected", id="proc-summary", classes="subline")
        yield SearchBar(placeholder="Filter by command / user / PID…  (enter = keep, esc = clear)", id="proc-search")
        yield DataTable(id="proc-table", cursor_type="row", zebra_stripes=True)

    def on_mount(self):
        for label, key in (("PID", "pid"), ("User", "user"), ("CPU%", "cpu"), ("MEM%", "mem"),
                           ("RSS", "rss"), ("Time", "elapsed"), ("Stat", "stat"), ("Command", "command")):
            self.table.add_column(label, key=key)

    @property
    def table(self):
        return self.query_one("#proc-table", DataTable)

    @property
    def search(self):
        return self.query_one("#proc-search", SearchBar)

    def focus_primary(self):
        self.table.focus()

    # ------------------------------------------------------------------
    # hooks
    # ------------------------------------------------------------------
    def on_server_changed(self):
        self.entries = []
        self.table.clear()
        self._summary(0)

    def restyle(self):
        self.render_rows()

    async def reload(self):
        self._show_collected()
        self.backend.collector.request(self.current, "processes")

    def on_collected(self, name, kind):
        # Redraw only while the tab is visible: 5 s updates for a hidden tab
        # would just burn CPU.
        if kind == "processes" and name == self.current and self.app.active_tab() is self:
            self._show_collected()

    def _show_collected(self):
        self.entries = self.backend.collector.server(self.current).processes if self.current else []
        self.render_rows()

    # ------------------------------------------------------------------
    # rendering
    # ------------------------------------------------------------------
    def _visible(self):
        rows = self.entries if self.show_kernel else [p for p in self.entries if not p["kernel_thread"]]
        q = self.search.query_text
        if q:
            rows = [p for p in rows if q in p["command"].casefold() or q in p["user"].casefold() or q == str(p["pid"])]
        key = SORTS[self.sort_idx][0]
        return sorted(rows, key=lambda p: p[key], reverse=key != "pid")

    def _summary(self, shown):
        if not self.current or not self.entries:
            data = self.backend.collector.server(self.current) if self.current else None
            err = data.errors.get("processes") if data else None
            self.query_one("#proc-summary", Static).update(
                f"[{P.error}]{esc(err)}[/]" if err else ("Collecting…" if self.current else "No server selected")
            )
            return
        cpu = sum(p["cpu"] for p in self.entries)
        users = len({p["user"] for p in self.entries})
        q = self.search.value.strip()
        self.query_one("#proc-summary", Static).update(
            f"{esc(self.current)}: [b]{len(self.entries)}[/b] processes   {users} users   "
            f"total cpu {cpu:.0f}%   sort={SORTS[self.sort_idx][1]}   "
            f"kernel threads {'shown' if self.show_kernel else 'hidden'}   showing {shown}"
            + (f"   filter '{esc(q)}'" if q else "")
        )

    def render_rows(self):
        table = self.table
        prev = self._selected_key()
        rows = self._visible()[:MAX_ROWS]
        table.clear()
        for p in rows:
            hot = p["cpu"] >= 50 or p["mem"] >= 30
            style = P.dim if p["kernel_thread"] else (f"bold {P.warning}" if hot else "")
            table.add_row(
                Text(str(p["pid"]), style=style),
                Text(p["user"][:16]),
                Text(f"{p['cpu']:.1f}", style=style),
                Text(f"{p['mem']:.1f}", style=style),
                Text(fmt_bytes(p["rss"])),
                Text(fmt_elapsed(p["elapsed"])),
                Text(p["stat"]),
                Text(p["command"][:200], style=style),
                key=str(p["pid"]),
            )
        if prev is not None:
            try:
                table.move_cursor(row=table.get_row_index(prev), animate=False)
            except Exception:
                pass
        self._summary(len(rows))

    def _selected_key(self):
        if not self.table.row_count:
            return None
        try:
            return self.table.coordinate_to_cell_key(self.table.cursor_coordinate).row_key.value
        except Exception:
            return None

    def _selected(self):
        key = self._selected_key()
        return next((p for p in self.entries if str(p["pid"]) == key), None)

    # ------------------------------------------------------------------
    # actions
    # ------------------------------------------------------------------
    def on_input_changed(self, ev: Input.Changed):
        if ev.input.id == "proc-search":
            self.render_rows()

    def on_search_bar_closed(self, ev):
        self.table.focus()

    def on_data_table_row_selected(self, ev):
        ev.stop()
        self.notify("k = terminate (TERM)   ctrl+k = force kill (KILL)")

    def action_search(self):
        if self.require_connection():
            self.search.open()

    def action_clear_filter(self):
        if self.search.value:
            self.search.clear_filter()

    def action_cycle_sort(self):
        self.sort_idx = (self.sort_idx + 1) % len(SORTS)
        self.render_rows()

    def action_toggle_kernel(self):
        self.show_kernel = not self.show_kernel
        self.render_rows()

    def action_refresh_now(self):
        if self.require_connection():
            self.app.spawn(self._refresh(self.current), group="reload-procs", exclusive=True)

    async def _refresh(self, name):
        try:
            await self.backend.collector.refresh_now(name, "processes")
        except Exception as exc:
            self.notify(f"Processes: {exc}", severity="error")
        if name == self.current:
            self._show_collected()

    def action_kill(self, signal):
        if not self.require_connection():
            return
        proc = self._selected()
        if proc is None:
            self.notify("No process selected", severity="warning")
            return
        if proc["pid"] <= 1 or proc["kernel_thread"]:
            self.notify("Refusing: PID 1 and kernel threads cannot be signalled", severity="warning")
            return
        self.app.spawn(self._kill(self.current, proc, signal))

    async def _kill(self, server, proc, signal):
        warn = ""
        if signal == "KILL":
            warn += "\n⚠ SIGKILL cannot be caught: the process gets no chance to save data or clean up."
        if proc["name"].startswith("sshd") or "sshd" in proc["command"].split(" ", 1)[0]:
            warn += "\n⚠ This is an SSH process: killing it may drop your own connection."
        ssh_user = (self.backend.servers.get(server) or {}).get("username")
        if ssh_user != "root" and proc["user"] != ssh_user:
            warn += f"\nOwned by {proc['user']}: sudo will be needed."

        ok = await self.app.ask(ConfirmDialog(
            f"Send SIG{signal}",
            f"Send SIG{signal} to PID {proc['pid']} on {server}?\n"
            f"user: {proc['user']}   cpu {proc['cpu']:.1f}%   mem {proc['mem']:.1f}%\n"
            f"{proc['command'][:300]}" + warn,
        ))
        if not ok:
            return

        try:
            with self.app.busy(f"SIG{signal} {proc['pid']}"):
                result = await self.run_with_sudo(
                    f"kill_{signal.lower()}",
                    lambda pw: self.backend.processes.kill(
                        server, proc["pid"], proc["start"], signal=signal,
                        command=proc["command"], sudo_password=pw.get(server),
                    ),
                )
            if result is not CANCELLED:
                self.notify(f"SIG{signal} sent to {proc['pid']} ({proc['name']})")
        except Exception as exc:
            self.notify(f"SIG{signal} {proc['pid']}: {exc}", severity="error")

        self.app.refresh_audit()
        if server == self.current:
            await self._refresh(server)
