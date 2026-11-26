"""
Incidents: problems found by the diagnostics engine, tracked over time.

The collector analyses every connected server once a minute; each problem
becomes an incident (or updates the existing one). This tab lists them,
shows the details (root cause, confidence, evidence, checks) and lets the
admin move them through open → investigating → resolved.
"""

import os
from pathlib import Path

from rich.text import Text
from textual.binding import Binding
from textual.containers import Vertical, VerticalScroll
from textual.markup import escape as esc
from textual.screen import ModalScreen
from textual.widgets import DataTable, Input, Static

from ...diagnostics import Severity
from ..styles.theme import P
from ..widgets import SearchBar
from .base import BaseTab

STATUS_FILTERS = ("active", "open", "investigating", "resolved", "all")
SEVERITY_FILTERS = (None, "critical", "error", "warning", "info")
EXPORT_DIR = Path.home() / "azmuth-exports"


def export_markdown(store, incident_id):
    """Write the redacted report to ~/azmuth-exports/<id>.md (0600). Returns the path."""
    text = store.export_markdown(incident_id)
    if text is None:
        raise ValueError(f"{incident_id} not found")
    EXPORT_DIR.mkdir(mode=0o700, exist_ok=True)
    os.chmod(EXPORT_DIR, 0o700)  # mkdir keeps the mode of an existing folder
    path = EXPORT_DIR / f"{incident_id}.md"
    # O_NOFOLLOW: never write through a planted symlink
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    os.fchmod(fd, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(text)
    return path


def _status_text(inc):
    if inc["status"] == "resolved":
        return Text("resolved", style=P.dim)
    if inc["cleared"]:
        return Text(f"{inc['status']} (cleared)", style=P.accent)
    style = f"bold {P.warning}" if inc["status"] == "investigating" else "bold"
    return Text(inc["status"], style=style)


def _short_ts(iso):
    return (iso or "")[5:16].replace("T", " ")  # MM-DD HH:MM (UTC)


class IncidentsTab(BaseTab):
    TAB_ID = "incidents"
    TITLE = "7 Incidents"
    NEEDS_CONNECTION = False

    EXTRA_KEYS = [("enter", "details")]
    BINDINGS = [
        Binding("d", "analyze", "analyse now"),
        Binding("v", "set_status('investigating')", "investigating"),
        Binding("z", "set_status('resolved')", "resolve"),
        Binding("o", "set_status('open')", "reopen"),
        Binding("w", "export", "export .md"),
        Binding("f", "cycle_status", "status filter"),
        Binding("l", "cycle_severity", "severity"),
        Binding("g", "toggle_scope", "this/all servers"),
        Binding("slash", "search", "search", key_display="/"),
        Binding("escape", "clear_filter", show=False),
    ]

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.status_idx = 0
        self.severity_idx = 0
        self.all_servers = True
        self.rows = []

    def compose(self):
        yield Static(id="inc-summary", classes="subline")
        yield SearchBar(placeholder="Search incidents…  (enter = keep, esc = clear)", id="inc-search")
        yield DataTable(id="inc-table", cursor_type="row", zebra_stripes=True)

    def on_mount(self):
        for label in ("ID", "Sev", "Status", "Server", "Category", "Title", "Last seen (UTC)", "Events", "Confidence"):
            self.table.add_column(label, key=label)

    @property
    def table(self):
        return self.query_one("#inc-table", DataTable)

    @property
    def search(self):
        return self.query_one("#inc-search", SearchBar)

    @property
    def store(self):
        return self.backend.incidents

    def focus_primary(self):
        self.table.focus()

    # ------------------------------------------------------------------
    # hooks
    # ------------------------------------------------------------------
    async def reload(self):
        self.render_rows()

    def restyle(self):
        self.render_rows()

    def on_server_changed(self):
        if not self.all_servers:
            self.render_rows()

    def on_collected(self, name, kind):
        if kind in ("analyze", "incidents"):
            self.render_rows()

    # ------------------------------------------------------------------
    # rendering
    # ------------------------------------------------------------------
    def _load(self):
        status = STATUS_FILTERS[self.status_idx]
        rows = self.store.list(
            server=None if self.all_servers else self.current,
            status=None if status == "all" else status,
            severity=SEVERITY_FILTERS[self.severity_idx],
            limit=500,
        )
        q = self.search.query_text
        if q:
            rows = [
                r for r in rows
                if q in r["title"].casefold() or q in r["root_cause"].casefold()
                or q in r["id"].casefold() or any(q in str(a).casefold() for a in r["affected"])
            ]
        # active before resolved, worst first, newest first inside a severity
        rows.sort(key=lambda r: r["last_seen"] or "", reverse=True)
        rows.sort(key=lambda r: (r["status"] == "resolved", -int(Severity.from_key(r["severity"]))))
        return rows

    def render_rows(self):
        prev = self._selected_id()
        self.rows = self._load()
        table = self.table
        table.clear()
        for r in self.rows:
            color = P.severity(r["severity_label"])
            dim = r["status"] == "resolved"
            table.add_row(
                Text(r["id"], style=P.dim if dim else "bold"),
                Text(r["severity_label"], style=P.dim if dim else f"bold {color}"),
                _status_text(r),
                Text(r["server"]),
                Text(r["category"], style=P.dim),
                Text(r["title"][:90] + (f"  ↻{r['recurring']}" if r["recurring"] else ""), style=P.dim if dim else ""),
                Text(_short_ts(r["last_seen"])),
                Text(str(r["event_count"])),
                Text(r["confidence"], style=P.accent if r["confidence"] == "high" else P.dim),
                key=r["id"],
            )
        if prev:
            try:
                table.move_cursor(row=table.get_row_index(prev), animate=False)
            except Exception:
                pass
        self._summary()

    def _summary(self):
        active = self.store.list(server=None if self.all_servers else self.current, status="active", limit=1000)
        counts = {s: 0 for s in ("critical", "error", "warning", "info")}
        for r in active:
            counts[r["severity"]] = counts.get(r["severity"], 0) + 1
        scope = "all servers" if self.all_servers else (self.current or "-")
        sev = SEVERITY_FILTERS[self.severity_idx] or "any"
        q = self.search.value.strip()
        self.query_one("#inc-summary", Static).update(
            f"[b]{esc(scope)}[/b]   active: "
            f"[b {P.error}]{counts['critical']} crit[/]  [b {P.error}]{counts['error']} err[/]  "
            f"[b {P.warning}]{counts['warning']} warn[/]  {counts['info']} info   "
            f"filter status={STATUS_FILTERS[self.status_idx]} severity={sev}"
            + (f" search='{esc(q)}'" if q else "")
            + f"   showing {len(self.rows)}   (analysed every 60 s, d = now)"
        )

    def _selected_id(self):
        if not self.table.row_count:
            return None
        try:
            return self.table.coordinate_to_cell_key(self.table.cursor_coordinate).row_key.value
        except Exception:
            return None

    # ------------------------------------------------------------------
    # actions
    # ------------------------------------------------------------------
    def on_input_changed(self, ev: Input.Changed):
        if ev.input.id == "inc-search":
            self.render_rows()

    def on_search_bar_closed(self, ev):
        self.table.focus()

    def action_search(self):
        self.search.open()

    def action_clear_filter(self):
        if self.search.value:
            self.search.clear_filter()

    def action_cycle_status(self):
        self.status_idx = (self.status_idx + 1) % len(STATUS_FILTERS)
        self.render_rows()

    def action_cycle_severity(self):
        self.severity_idx = (self.severity_idx + 1) % len(SEVERITY_FILTERS)
        self.render_rows()

    def action_toggle_scope(self):
        self.all_servers = not self.all_servers
        self.render_rows()

    def on_data_table_row_selected(self, ev):
        ev.stop()
        incident_id = ev.row_key.value
        if incident_id:
            self.app.push_screen(IncidentDetail(incident_id), lambda _: self.render_rows())

    def action_set_status(self, status):
        incident_id = self._selected_id()
        if not incident_id:
            return
        set_incident_status(self.app, incident_id, status)
        self.render_rows()

    def action_export(self):
        incident_id = self._selected_id()
        if incident_id:
            try:
                path = export_markdown(self.store, incident_id)
                self.notify(f"Exported (secrets redacted) to {path}")
            except Exception as exc:
                self.notify(f"Export failed: {exc}", severity="error")

    def action_analyze(self):
        if self.require_connection():
            self.app.spawn(self._analyze(self.current), group="diagnostics", exclusive=True)

    async def _analyze(self, name):
        try:
            with self.app.busy(f"analysing {name}"):
                report = await self.backend.diagnostics.analyze_now(name)
        except Exception as exc:
            self.notify(f"Analysis failed: {exc}", severity="error")
            return
        n = len(report.findings)
        self.notify(f"{name}: {n} problem(s) found" if n else f"{name}: no problems detected")
        for err in report.errors:
            self.notify(f"{name}: could not collect {err}", severity="warning")
        self.render_rows()


def set_incident_status(app, incident_id, status):
    app.backend.incidents.set_status(incident_id, status)
    inc = app.backend.incidents.get(incident_id) or {}
    app.backend.record_audit(f"incident_{status}", inc.get("server", "-"), "success", incident_id)
    app.refresh_audit()
    app.notify(f"{incident_id}: {status}")


class IncidentDetail(ModalScreen):
    """Full view of one incident."""

    BINDINGS = [
        Binding("escape", "dismiss", "close"),
        Binding("q", "dismiss", show=False),
        Binding("v", "status('investigating')", "investigating"),
        Binding("z", "status('resolved')", "resolve"),
        Binding("o", "status('open')", "reopen"),
        Binding("w", "export", "export .md"),
    ]

    def __init__(self, incident_id):
        super().__init__()
        self.incident_id = incident_id

    def compose(self):
        with Vertical(id="inc-detail"):
            yield Static(id="inc-detail-title")
            with VerticalScroll():
                yield Static(id="inc-detail-body")
            yield Static("v investigating   z resolve   o reopen   w export (redacted)   esc close", id="inc-detail-hints")

    def on_mount(self):
        self.render_incident()

    def render_incident(self):
        store = self.app.backend.incidents
        inc = store.get(self.incident_id)
        if inc is None:
            self.dismiss(None)
            return
        color = P.severity(inc["severity_label"])
        title = Text()
        title.append(f"{inc['id']}  ", style="bold")
        title.append(f"[{inc['severity_label']}] ", style=f"bold {color}")
        title.append(inc["title"], style=f"bold {color}")
        self.query_one("#inc-detail-title", Static).update(title)

        t = Text()

        def head(label):
            t.append(f"\n{label}\n", style=f"bold {P.accent}")

        t.append(f"server {inc['server']}   category {inc['category']}   status ", style=P.dim)
        t.append_text(_status_text(inc))
        t.append(f"\nfirst seen {inc['first_seen']}   last seen {inc['last_seen']}   events {inc['event_count']}", style=P.dim)
        if inc["recurring"]:
            t.append(f"\n↻ happened {inc['recurring']} time(s) before (previous: {inc['previous_id']})", style=P.warning)
        if inc["cleared"]:
            t.append(f"\n✓ not detected since {inc['condition_cleared_at']} — resolve it if it is fixed", style=P.accent)

        head("ROOT CAUSE")
        t.append(inc["root_cause"] + "\n")
        t.append(f"confidence: {inc['confidence']}", style="bold")
        t.append(f" — {inc['confidence_reason']}", style=P.dim)

        head("IMPACT")
        t.append(inc["impact"] or "-")

        if inc["affected"]:
            head("AFFECTED")
            t.append(", ".join(inc["affected"]))

        if inc["checks"]:
            head("CHECKS  (run them in the Terminal tab — nothing runs automatically)")
            for c in inc["checks"]:
                change = c["title"].lower().startswith("change")
                t.append(f"• {c['title']}\n", style=P.warning if change else "")
                t.append(f"    {c['command']}\n", style=P.accent)

        evidence = store.evidence(self.incident_id)
        if evidence:
            head(f"EVIDENCE  ({len(evidence)} lines, newest kept)")
            for e in evidence:
                role_color = {"cause": P.error, "effect": P.warning}.get(e["role"], P.dim)
                t.append(f"{(e['ts'] or '')[11:19]} ", style=P.dim)
                t.append(f"{e['role']:<8}", style=role_color)
                t.append(f"{(e['source'] or e['unit'] or '')[:16]:<16} ", style=P.dim)
                t.append(f"{e['message']}\n")

        self.query_one("#inc-detail-body", Static).update(t)

    def action_status(self, status):
        set_incident_status(self.app, self.incident_id, status)
        self.render_incident()

    def action_export(self):
        try:
            path = export_markdown(self.app.backend.incidents, self.incident_id)
            self.app.notify(f"Exported (secrets redacted) to {path}")
        except Exception as exc:
            self.app.notify(f"Export failed: {exc}", severity="error")
