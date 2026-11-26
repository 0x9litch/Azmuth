"""
Dashboard: all-server overview, live metrics + 10-minute trend, alerts.

No SSH calls here: everything comes from the collector (backend.collector),
which refreshes metrics every 5 s and pings every 30 s. The tab only
redraws when the collector says new data arrived.
"""

import time

from rich.text import Text
from textual.binding import Binding
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.markup import escape as esc
from textual.widgets import DataTable, Static

from ...diagnostics import Severity
from ..formatting import fmt_bytes, fmt_uptime
from ..styles.theme import P
from ...diagnostics import THRESHOLDS
from ..widgets import MetricCard, StatTile, TrendChart
from .base import BaseTab

TREND_MINUTES = 10


class DashboardTab(BaseTab):
    TAB_ID = "dash"
    TITLE = "1 Dashboard"
    NEEDS_CONNECTION = False

    EXTRA_KEYS = [("↑/↓ enter", "pick server from table")]
    BINDINGS = [
        Binding("r", "refresh", "refresh now"),
        Binding("p", "ping", "ping all now"),
    ]

    def compose(self):
        with VerticalScroll(id="dash-scroll"):
            with Horizontal(id="dash-tiles"):
                yield StatTile("SERVERS", id="tile-servers")
                yield StatTile("REACHABLE", id="tile-reach")
                yield StatTile("SSH", id="tile-ssh")
                yield StatTile("INCIDENTS (7)", id="tile-inc")
            with Horizontal(id="dash-top"):
                yield DataTable(id="overview", cursor_type="row")
                yield Static(id="alerts")
            with Vertical(id="dash-server"):
                yield Static("No server connected", id="dash-info")
                with Horizontal(id="dash-metrics"):
                    yield MetricCard("CPU", "cpu", id="card-cpu")
                    yield MetricCard("MEMORY", "mem", id="card-ram")
                    yield MetricCard("DISK /", "disk", id="card-disk")
                    # load per CPU: 100% = every CPU busy, 200% = twice the work it can do
                    yield MetricCard("LOAD / CPU", limits=(100.0, 200.0), id="card-load")
                with Horizontal(id="dash-trend"):
                    with Vertical(classes="trend"):
                        yield Static("CPU %", id="trend-cpu-label", classes="trend-label")
                        yield TrendChart((THRESHOLDS["cpu_warning"], THRESHOLDS["cpu_critical"]), id="trend-cpu")
                    with Vertical(classes="trend"):
                        yield Static("MEM %", id="trend-mem-label", classes="trend-label")
                        yield TrendChart((THRESHOLDS["mem_warning"], THRESHOLDS["mem_critical"]), id="trend-mem")

    def on_mount(self):
        table = self.query_one("#overview", DataTable)
        table.border_title = "SERVERS"
        for col in ("Server", "Host/IP", "Ping", "Latency", "SSH", "Incidents"):
            table.add_column(col, key=col)  # explicit keys for update_cell()
        alerts = self.query_one("#alerts", Static)
        alerts.border_title = "ALERTS"
        alerts.update(Text("✓ No active alerts", style=P.accent))
        self.query_one("#dash-server").border_title = "SELECTED SERVER"

    def focus_primary(self):
        self.query_one("#overview", DataTable).focus()

    @property
    def collector(self):
        return self.backend.collector

    # ------------------------------------------------------------------
    # actions / hooks
    # ------------------------------------------------------------------
    def action_refresh(self):
        if self.current and self.backend.is_connected(self.current):
            self.collector.request(self.current, "metrics")
        self.collector.ping_now()

    def action_ping(self):
        self.collector.ping_now()
        self.notify("Pinging all servers…")

    def on_data_table_row_selected(self, ev):
        if ev.data_table.id == "overview":
            ev.stop()
            self.app.select_server(ev.row_key.value)

    def on_server_changed(self):
        self.render_selected()

    def restyle(self):
        # Cells hold Rich Text with baked colours: rebuild them.
        self.query_one("#overview", DataTable).clear()
        self.rebuild_overview()
        self.render_selected()

    async def reload(self):
        self.rebuild_overview()
        self.render_selected()

    def on_collected(self, name, kind):
        """Called by the app for every collector update."""
        if kind == "ping" or kind == "incidents":
            self.rebuild_overview()
        elif name == self.current and kind in ("metrics", "services"):
            self.render_selected()

    # ------------------------------------------------------------------
    # overview table
    # ------------------------------------------------------------------
    def _ping_cells(self, name):
        r = self.collector.ping_results.get(name)
        if r is None:
            return Text("?", style=P.dim), Text("-", style=P.dim)
        if r.get("online"):
            ms = r.get("latency_ms")
            return Text("ONLINE", style=f"bold {P.accent}"), Text(f"{ms:.1f} ms" if ms is not None else "-", style=P.accent)
        return Text("UNREACHABLE", style=f"bold {P.error}"), Text("-", style=P.dim)

    def _ssh_cell(self, name):
        if self.backend.is_connected(name):
            return Text("CONNECTED", style=f"bold {P.accent}")
        return Text("—", style=P.dim)

    def _incident_cell(self, name):
        active = self.backend.incidents.list(server=name, status="active", limit=500)
        if not active:
            return Text("0", style=P.dim)
        worst = max(Severity.from_key(i["severity"]) for i in active)
        return Text(f"{len(active)} {worst.label}", style=f"bold {P.severity(worst.label)}")

    def rebuild_overview(self):
        table = self.query_one("#overview", DataTable)
        servers = self.backend.servers.list()
        keys = [s["name"] for s in servers]

        if [row.value for row in table.rows] == keys:
            # Same rows: update cells in place so the cursor never jumps.
            for s in servers:
                ping, lat = self._ping_cells(s["name"])
                table.update_cell(s["name"], "Ping", ping, update_width=True)
                table.update_cell(s["name"], "Latency", lat, update_width=True)
                table.update_cell(s["name"], "SSH", self._ssh_cell(s["name"]), update_width=True)
                table.update_cell(s["name"], "Incidents", self._incident_cell(s["name"]), update_width=True)
        else:
            table.clear()
            for s in servers:
                table.add_row(
                    Text(s["name"], style="bold"),
                    Text(s["host"]),
                    *self._ping_cells(s["name"]),
                    self._ssh_cell(s["name"]),
                    self._incident_cell(s["name"]),
                    key=s["name"],
                )

        if self.current in keys:
            table.move_cursor(row=keys.index(self.current))

        self._update_summary(servers)
        self.render_alerts()

    def _update_summary(self, servers):
        pings = self.collector.ping_results
        total = len(servers)
        online = sum(1 for s in servers if (pings.get(s["name"]) or {}).get("online"))
        known = sum(1 for s in servers if s["name"] in pings)
        ssh_conn = sum(1 for s in servers if self.backend.is_connected(s["name"]))
        active = self.backend.incidents.list(status="active", limit=1000)
        # adjust the table/alerts row to the number of servers
        self.query_one("#dash-top").styles.height = max(7, min(14, total + 4))

        self.query_one("#tile-servers", StatTile).set(total, "registered", "ok" if total else "muted")
        if not known:
            self.query_one("#tile-reach", StatTile).set("?", "no ping yet", "muted")
        else:
            self.query_one("#tile-reach", StatTile).set(
                f"{online} / {known}", "ping", "ok" if online == known else ("bad" if online == 0 else "warn")
            )
        self.query_one("#tile-ssh", StatTile).set(
            f"{ssh_conn} / {total}", "sessions", "ok" if ssh_conn and ssh_conn == total else ("muted" if not ssh_conn else "warn")
        )
        if active:
            worst = max(Severity.from_key(i["severity"]) for i in active)
            crit = sum(1 for i in active if i["severity"] in ("critical", "error"))
            state = "bad" if worst >= Severity.ERROR else "warn"
            self.query_one("#tile-inc", StatTile).set(len(active), f"{crit} serious" if crit else worst.label.lower(), state)
        else:
            self.query_one("#tile-inc", StatTile).set(0, "all clear", "ok")

    # ------------------------------------------------------------------
    # alerts (live thresholds, no remote calls)
    # ------------------------------------------------------------------
    def render_alerts(self):
        findings = self.backend.diagnostics.engine.quick_alerts(
            self.backend.servers.names(), self.collector.ping_results, self.collector
        )
        widget = self.query_one("#alerts", Static)
        widget.border_title = f"ALERTS ({len(findings)})" if findings else "ALERTS"
        widget.set_class(bool(findings), "has-alerts")
        if not findings:
            widget.update(Text("✓ No active alerts", style=P.accent))
            return
        room = max(1, (widget.size.height or 8) - 2)
        shown = findings if len(findings) <= room else findings[: room - 1]
        t = Text(no_wrap=True, overflow="ellipsis")
        for i, f in enumerate(shown):
            if i:
                t.append("\n")
            color = P.severity(f.severity.label)
            t.append(f"{f.severity.label:<4} ", style=f"bold {color}")
            t.append(f"{f.server} ", style="bold")
            t.append(f.title, style=color)
        if len(shown) < len(findings):
            t.append(f"\n+{len(findings) - len(shown)} more", style=P.dim)
        widget.update(t)

    # ------------------------------------------------------------------
    # selected server
    # ------------------------------------------------------------------
    def render_selected(self):
        info_w = self.query_one("#dash-info", Static)
        panel = self.query_one("#dash-server")
        cur = self.current

        if not cur:
            panel.border_title, panel.border_subtitle = "SELECTED SERVER", ""
            info_w.update(Text("No server selected — press a to add one", style=P.dim))
            self._paint(None)
            self._trend(None)
            self.render_alerts()
            return

        data = self.collector.server(cur)
        m = data.metrics
        info = (m or {}).get("info") or {}
        panel.border_title = f"{cur}  ·  {info.get('hostname') or '-'}" if info.get("hostname") else cur
        # os / kernel come from the remote server: escape markup
        panel.border_subtitle = esc(" · ".join(x for x in (info.get("os"), info.get("kernel")) if x))
        connected = self.backend.is_connected(cur)
        panel.set_class(connected, "connected")

        if not connected:
            info_w.update(Text(
                "Not SSH-connected — press c to connect. Last known values below (ping is independent).",
                style=P.warning,
            ))
        elif m is None:
            info_w.update(Text("Collecting…", style=P.dim))
        else:
            error = data.errors.get("metrics")
            line = Text()
            for label, value in (
                ("uptime", fmt_uptime(info.get("uptime"))),
                ("load", info.get("load") or "-"),
                ("cpus", info.get("cpus") or "-"),
                ("updated", self._age(data.collected_at.get("metrics"))),
            ):
                line.append(f"{label} ", style=P.dim)
                line.append(f"{value}    ", style="bold")
            if error:
                line.append(f"partial data: {error}", style=P.warning)
            info_w.update(line)
        self._paint(m, loading=connected and m is None)
        self._trend(cur)
        self.render_alerts()

    @staticmethod
    def _age(ts):
        if not ts:
            return "-"
        seconds = max(0, int(time.time() - ts))
        return f"{seconds}s ago" if seconds < 120 else f"{seconds // 60}m ago"

    def _trend(self, name):
        samples = self.collector.history(name, TREND_MINUTES) if name else []
        for key, metric in (("cpu", "cpu"), ("mem", "mem_percent")):
            values = [s[metric] for s in samples if s.get(metric) is not None]
            self.query_one(f"#trend-{key}", TrendChart).set_values(values)
            label = f"{key.upper()} %  · last {TREND_MINUTES} min"
            if values:
                label += f"   now {values[-1]:.0f}   min {min(values):.0f}   max {max(values):.0f}"
            self.query_one(f"#trend-{key}-label", Static).update(label)

    def _paint(self, snap, loading=False):
        cards = {
            "cpu": self.query_one("#card-cpu", MetricCard),
            "ram": self.query_one("#card-ram", MetricCard),
            "disk": self.query_one("#card-disk", MetricCard),
            "load": self.query_one("#card-load", MetricCard),
        }
        if snap is None:
            for c in cards.values():
                c.set_text("Loading…" if loading else "—", dim=True)
            return

        cpu = snap.get("cpu")
        if cpu is not None:
            cards["cpu"].set_percent(float(cpu))
        else:
            cards["cpu"].set_text("—", dim=True)

        for key, card in (("mem", cards["ram"]), ("disk", cards["disk"])):
            m = snap.get(key) or {}
            if m.get("percent") is not None and m.get("total") is not None:
                card.set_percent(float(m["percent"]), f"{fmt_bytes(m.get('used'))} / {fmt_bytes(m.get('total'))}")
            else:
                card.set_text("—", dim=True)

        info = snap.get("info") or {}
        try:
            loads = str(info.get("load", "")).split()
            load1, cpus = float(loads[0]), int(info.get("cpus"))
            cards["load"].set_percent(load1 / cpus * 100, " ".join(loads[:3]), label=f"{load1 / cpus * 100:.0f}%")
        except (TypeError, ValueError, IndexError, ZeroDivisionError):
            cards["load"].set_text("—", dim=True)
