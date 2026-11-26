"""
Azmuth TUI application shell (Textual 8.x).

The app owns only what is shared between tabs:
- the selected server (self.current),
- ping results and the per-server metric cache,
- global keys (tabs, server CRUD, connect, help, quit, theme, mouse),
- helpers used by every tab: spawn(), ask(), busy(), refresh_audit().

Everything tab-specific lives in ui/tabs/<tab>.py; interactive SSH
flows (unlock key, connect all, install key) live in ui/ssh_flows.py.
"""

import asyncio
import inspect
import time
from contextlib import contextmanager

from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.widgets import OptionList, Static, TabbedContent, TabPane, Tabs
from textual.worker import WorkerState

from ..backend import settings as S
from .commands import AzmuthCommands
from .dialogs import ConfirmDialog, HelpScreen, ServerForm
from .ssh_flows import SSHFlowsMixin
from .styles import STYLESHEET
from .styles.theme import AZMUTH_THEME, P
from .tabs import TAB_CLASSES, BaseTab
from .widgets import KeyHints, ServerList, StatusBar, binding_pairs
from ..core.sanitize import clean_text

# Only local work now (lost-connection check, status bar): data comes
# from backend.collector, which pushes updates to the tabs.
WATCH_SECONDS = 3.0
MAX_INCIDENT_TOASTS = 3
TOAST_DEDUPE_SECONDS = 6.0

GLOBAL_HINT = (
    "1-8 tabs  a/e/^d server  c/C connect/all  x/X disconnect/all  I install key  "
    "K key  A api  [ ] switch  ^p palette  ^t theme  F9 mouse  ? help  q quit"
)


class AzmuthApp(SSHFlowsMixin, App):
    CSS_PATH = STYLESHEET
    TITLE = "Azmuth"
    COMMANDS = App.COMMANDS | {AzmuthCommands}

    BINDINGS = [
        *[
            Binding(f"f{i}", f"goto('{cls.TAB_ID}')", show=False)
            for i, cls in enumerate(TAB_CLASSES, start=1)
        ],
        *[
            Binding(str(i), f"goto('{cls.TAB_ID}')", show=False)
            for i, cls in enumerate(TAB_CLASSES, start=1)
        ],
        Binding("a", "add_server", "add server"),
        Binding("e", "edit_server", "edit server"),
        Binding("ctrl+d", "delete_server", "delete server", key_display="ctrl+d"),
        Binding("c", "connect_server", "connect (SSH)"),
        Binding("C", "connect_all", "connect ALL servers", key_display="C"),
        Binding("x", "disconnect_server", "disconnect"),
        Binding("X", "disconnect_all", "disconnect ALL", key_display="X"),
        Binding("I", "install_key", "install SSH key on server (password)", key_display="I"),
        Binding("K", "key_manager", "SSH key: generate / passphrase / lock", key_display="K"),
        Binding("ctrl+t", "change_theme", "theme picker", key_display="ctrl+t"),
        Binding("f9", "toggle_mouse", "mouse on/off", key_display="F9"),
        Binding("A", "toggle_api", "read-only API on/off (for the web)", key_display="A"),
        Binding("right_square_bracket", "shift_server(1)", "next server", key_display="]"),
        Binding("left_square_bracket", "shift_server(-1)", "previous server", key_display="["),
        Binding("question_mark", "help", "keyboard help", key_display="?"),
        Binding("q", "quit_app", "quit"),
    ]

    def __init__(self, backend, mouse_enabled=True):
        super().__init__()
        self.backend = backend
        self.mouse_enabled = mouse_enabled
        self.current = None
        self.ready = False

        self._pending_coros = {}
        self._recent_toasts = {}
        self._known_connected = set()

    # ------------------------------------------------------------------
    # layout
    # ------------------------------------------------------------------
    def compose(self) -> ComposeResult:
        yield Static("AZMUTH  —  System Administration TUI", id="topbar")

        with Horizontal():
            yield ServerList(id="sidebar")

            with Vertical(id="main"):
                yield StatusBar(id="status")

                with TabbedContent(id="tabs", initial=TAB_CLASSES[0].TAB_ID):
                    for cls in TAB_CLASSES:
                        with TabPane(cls.TITLE, id=cls.TAB_ID):
                            yield cls(id=f"tab-{cls.TAB_ID}")

        yield KeyHints(id="hints")

    def on_mount(self):
        self.register_theme(AZMUTH_THEME)
        saved_theme = self.backend.settings.get(S.THEME)
        self.theme = saved_theme if saved_theme in self.available_themes else AZMUTH_THEME.name
        P.update(self)
        self.theme_changed_signal.subscribe(self, self._on_theme_changed)

        if not self.mouse_enabled:
            self._set_mouse(False)

        # Tabs are switched with F-keys / numbers; keeping the tab strip
        # out of the focus chain means Tab/Shift+Tab only visit content.
        for tabs in self.main.query(Tabs):
            tabs.can_focus = False

        servers = self.backend.servers.names()
        self.current = servers[0] if servers else None

        self.refresh_server_views()
        self.refresh_audit()
        self._update_hints()

        self.ready = True
        self.update_topbar()
        self.active_tab().activated()
        self.first_run_key_setup()

        # Background collection: one schedule feeds every tab (and the API).
        self.backend.collector.subscribe(self._on_collected)
        self.backend.diagnostics.subscribe(self._on_new_incidents)
        self.backend.collector.start()
        self.set_interval(WATCH_SECONDS, self.periodic_watch)

    async def on_unmount(self):
        # Workers queued but never started at exit: close their coroutines
        # (avoids "coroutine was never awaited" warnings).
        for coro in list(self._pending_coros.values()):
            if inspect.getcoroutinestate(coro) == inspect.CORO_CREATED:
                coro.close()
        self._pending_coros.clear()
        await self.backend.shutdown()

    # ------------------------------------------------------------------
    # helpers used by tabs
    # ------------------------------------------------------------------
    def notify(self, message, **kwargs):
        """
        Show a toast, but drop an identical warning/error shown in the last
        few seconds (a server that is down must not flood the screen).
        """
        # Messages carry file paths, server names and remote output, which
        # may contain "[...]": show them literally, never as markup.
        kwargs.setdefault("markup", False)
        # ...and may carry terminal escape sequences (server error texts)
        message = clean_text(str(message))
        severity = kwargs.get("severity", "information")
        if severity not in ("warning", "error"):
            super().notify(message, **kwargs)  # successes always show
            return
        key = (str(message), severity)
        now = time.monotonic()
        if now - self._recent_toasts.get(key, -1e9) < TOAST_DEDUPE_SECONDS:
            return
        self._recent_toasts[key] = now
        if len(self._recent_toasts) > 200:
            self._recent_toasts = {
                k: t for k, t in self._recent_toasts.items() if now - t < TOAST_DEDUPE_SECONDS
            }
        super().notify(message, **kwargs)

    @property
    def main(self):
        """
        The base screen holding the sidebar and tabs.

        App.query_one() searches the screen on TOP of the stack, which is a
        dialog whenever one is open; background work (connect-all, ping,
        theme preview) must still reach the main widgets.
        """
        return self.screen_stack[0]

    @property
    def alive(self):
        """False while shutting down (late events must be ignored)."""
        return bool(self.screen_stack) and not getattr(self, "_exit", False)

    def tabs(self):
        return list(self.main.query(BaseTab))

    def tab(self, tab_id):
        return self.main.query_one(f"#tab-{tab_id}", BaseTab)

    def active_tab(self):
        return self.tab(self.main.query_one(TabbedContent).active)

    def spawn(self, coro, group="default", exclusive=False):
        """
        Run a coroutine in a worker. Unexpected exceptions become an error
        notification instead of crashing the whole application.
        """

        async def guarded():
            try:
                return await coro
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                self.notify(f"Unexpected error: {exc}", severity="error", timeout=8)
                return None

        # Passing the function (not a coroutine object) means nothing is
        # created if an exclusive worker is cancelled before it starts.
        worker = self.run_worker(guarded, group=group, exclusive=exclusive, exit_on_error=False)
        self._pending_coros[worker] = coro
        return worker

    def on_worker_state_changed(self, event):
        if event.state in (WorkerState.CANCELLED, WorkerState.SUCCESS, WorkerState.ERROR):
            coro = self._pending_coros.pop(event.worker, None)
            if coro is not None and inspect.getcoroutinestate(coro) == inspect.CORO_CREATED:
                coro.close()  # cancelled before it ran: avoid "never awaited"

    async def ask(self, screen, timeout=None):
        """Show a modal and await its dismiss value."""
        future = asyncio.get_running_loop().create_future()

        def done(result):
            if not future.done():
                future.set_result(result)

        self.push_screen(screen, done)

        if timeout is None:
            return await future

        try:
            return await asyncio.wait_for(future, timeout=timeout)
        except asyncio.TimeoutError:
            if self.screen is screen:
                screen.dismiss(None)
            return None

    @contextmanager
    def busy(self, label):
        """Show '⟳ label…' in the status bar while a long operation runs."""
        status = self.main.query_one(StatusBar)
        token = status.start_busy(label)
        try:
            yield
        finally:
            status.stop_busy(token)

    @property
    def ping_results(self):
        return self.backend.collector.ping_results

    def refresh_audit(self):
        try:
            self.tab("activity").refresh_records()
        except Exception:
            pass

    # ------------------------------------------------------------------
    # chrome
    # ------------------------------------------------------------------
    def _update_hints(self):
        self.main.query_one(KeyHints).show(GLOBAL_HINT, self.active_tab().key_pairs())

    def update_status_bar(self):
        if not self.alive:
            return
        status = self.main.query_one(StatusBar)
        cur = self.current

        if cur and self.backend.is_connected(cur):
            s = self.backend.servers.get(cur) or {}
            status.set_connection(
                f"SSH: CONNECTED   {s.get('username')}@{s.get('host')}:{s.get('port')}  [{cur}]",
                connected=True,
            )
        elif cur:
            status.set_connection(f"SSH: DISCONNECTED   [{cur}]   (press c to connect)")
        else:
            status.set_connection("No servers configured — press a to add one")

    def refresh_server_views(self):
        """Sidebar, status bar and dashboard overview after any server change."""
        if not self.alive:
            return
        servers = self.backend.servers.list()
        names = [s["name"] for s in servers]

        if self.current not in names:
            self.current = names[0] if names else None

        self.main.query_one(ServerList).render_servers(servers, self.current, self.backend.is_connected)
        self.update_status_bar()
        self.tab("dash").rebuild_overview()

    # ------------------------------------------------------------------
    # tabs
    # ------------------------------------------------------------------
    def action_goto(self, tab_id):
        tabbed = self.main.query_one(TabbedContent)
        if tabbed.active == tab_id:
            self.tab(tab_id).focus_primary()
        else:
            # Drop focus first: otherwise, when the old pane hides, Textual
            # moves focus to another widget in that pane, and TabbedContent
            # re-activates the pane holding focus (tabs bounce back and forth).
            self.set_focus(None)
            tabbed.active = tab_id

    def on_tabbed_content_tab_activated(self, ev):
        if not self.ready:
            return
        self._update_hints()
        self.tab(ev.pane.id).activated()

    # ------------------------------------------------------------------
    # server selection
    # ------------------------------------------------------------------
    def select_server(self, name):
        if not self.alive:
            return
        if name == self.current or name not in self.backend.servers.names():
            return

        self.current = name
        self.refresh_server_views()

        for tab in self.tabs():
            tab.on_server_changed()

        self.active_tab().activated()

    def action_shift_server(self, delta):
        names = self.backend.servers.names()
        if not names:
            return
        idx = names.index(self.current) if self.current in names else 0
        self.select_server(names[(idx + delta) % len(names)])

    def on_option_list_option_selected(self, ev: OptionList.OptionSelected):
        """
        A server was picked in the sidebar (mouse click).

        Only OptionSelected — a real user action — switches servers.
        OptionHighlighted must NOT: the sidebar re-highlights the current
        server every time it is redrawn, and reacting to that made two
        redraws trigger each other forever (servers switching by themselves,
        hundreds of reloads, and sshd refusing channels with "open failed").
        """
        if not self.ready or ev.option_list.id != "servers":
            return
        ev.stop()
        names = self.backend.servers.names()
        if ev.option_index is not None and ev.option_index < len(names):
            self.select_server(names[ev.option_index])

    # ------------------------------------------------------------------
    # server CRUD
    # ------------------------------------------------------------------
    def _form_validator(self, values):
        self.backend.servers.validate(
            values["name"], values["host"], values["port"], values["username"], values["key_path"]
        )
        if values.get("password"):
            # Installing needs the .pub next to the private key.
            self.backend.keys.public_key_line(values["key_path"])

    def action_add_server(self):
        def done(values):
            if not values:
                return
            password = values.pop("password", "") or None
            try:
                self.backend.servers.add(
                    values["name"], values["host"], int(values["port"]),
                    values["username"], values["key_path"],
                )
            except Exception as exc:
                self.notify(str(exc), severity="error")
                return

            self.notify(
                f"Server '{values['name']}' added"
                + ("" if values.get("key_path") and password else " — press c to connect, or I to install your key")
            )
            if not self.current:
                self.current = values["name"]
            self.refresh_server_views()
            self.select_server(values["name"])
            self.refresh_audit()
            self.periodic_ping()

            if password:
                self.spawn(self.install_key_flow(values["name"], password))
            password = None

        self.push_screen(
            ServerForm(
                validator=self._form_validator,
                default_key_path=self.backend.keys.default_path(),
            ),
            done,
        )

    def action_edit_server(self):
        if not self.current:
            self.notify("Select a server first", severity="warning")
            return

        srv = self.backend.servers.get(self.current)
        if not srv:
            return

        def done(values):
            if values:
                self.spawn(self._edit_server(srv["name"], values))

        self.push_screen(
            ServerForm(existing_data=srv, editing_name=self.current, validator=self._form_validator),
            done,
        )

    async def _edit_server(self, original, values):
        try:
            await self.backend.servers.edit(
                original, values["name"], values["host"], int(values["port"]),
                values["username"], values["key_path"],
            )
        except Exception as exc:
            self.notify(str(exc), severity="error")
            return

        for key in (original, values["name"]):
            self.backend.collector.forget(key)  # data belonged to the old entry

        self._remember_connected()  # edit closed the session on purpose
        self.current = values["name"]
        self.notify("Server updated")
        self.refresh_server_views()
        for tab in self.tabs():
            tab.on_server_changed()
        self.refresh_audit()
        self.periodic_ping()

    def action_delete_server(self):
        if not self.current:
            self.notify("Select a server first", severity="warning")
            return

        name = self.current

        def done(ok):
            if ok:
                self.spawn(self._delete_server(name))

        self.push_screen(
            ConfirmDialog("Delete server", f"Remove '{name}' from the database?\n(Its SSH session is closed.)"),
            done,
        )

    async def _delete_server(self, name):
        try:
            await self.backend.servers.delete(name)
        except Exception as exc:
            self.notify(str(exc), severity="error")
            return

        self._remember_connected()
        self.notify(f"Server '{name}' deleted")
        self.backend.collector.forget(name)

        self.current = None
        self.refresh_server_views()
        for tab in self.tabs():
            tab.on_server_changed()
        self.refresh_audit()
        self.active_tab().activated()

    # ------------------------------------------------------------------
    # connect / disconnect
    # ------------------------------------------------------------------
    def action_connect_server(self):
        if not self.current:
            self.notify("Select a server first", severity="warning")
            return
        self.connect(self.current)

    def connect(self, name):
        self.select_server(name)
        if self.backend.is_connected(name):
            self.notify("Already connected")
            return
        self.spawn(self._connect(name), group=f"connect-{name}", exclusive=True)


    def action_disconnect_server(self):
        if not self.current:
            return
        if not self.backend.is_connected(self.current):
            self.notify("Not connected")
            return
        self.disconnect(self.current)

    def disconnect(self, name):
        self.spawn(self._disconnect(name))

    async def _disconnect(self, name):
        try:
            await self.backend.servers.disconnect(name)
            self.notify(f"{name}: disconnected")
        except Exception as exc:
            self.notify(str(exc), severity="error")
        self._after_connection_change(name)

    def _after_connection_change(self, name):
        if not self.alive:
            return
        self._remember_connected()
        if name and self.backend.is_connected(name):
            self.backend.collector.request(name)  # collect everything now
        self.refresh_server_views()
        self.refresh_audit()
        if name == self.current:
            for tab in self.tabs():
                tab.on_server_changed()
            self.active_tab().activated()

    # ------------------------------------------------------------------
    # periodic work
    # ------------------------------------------------------------------
    def periodic_watch(self):
        if not self.alive:
            return
        self._detect_lost_connections()
        self.update_status_bar()

    def _on_collected(self, name, kind):
        """Collector finished one collection: let every tab decide whether to redraw."""
        if not self.alive or not self.ready:
            return
        if self.screen.is_modal and kind not in ("ping", "analyze", "incidents"):
            return  # a dialog is open: skip cosmetic redraws behind it
        for tab in self.tabs():
            handler = getattr(tab, "on_collected", None)
            if handler is None:
                continue
            try:
                handler(name, kind)
            except Exception:
                pass  # a tab drawing problem must not stop the collector

    def _on_new_incidents(self, incidents):
        if not self.alive:
            return
        loud = [i for i in incidents if i["severity"] in ("critical", "error", "warning")]
        for inc in loud[:MAX_INCIDENT_TOASTS]:
            self.notify(
                f"{inc['id']} {inc['server']}: {inc['title']}   (7 = Incidents)",
                title=f"New incident [{inc['severity_label']}]",
                severity="error" if inc["severity"] in ("critical", "error") else "warning",
                timeout=10,
            )
        if len(loud) > MAX_INCIDENT_TOASTS:
            self.notify(f"+{len(loud) - MAX_INCIDENT_TOASTS} more new incidents (tab 7)", severity="warning")
        self.refresh_audit()
        self._on_collected(None, "incidents")

    def _detect_lost_connections(self):
        """Notice sessions that dropped (VM shut down, network lost)."""
        now = set(self.backend.servers.connected_names())
        lost = self._known_connected - now
        self._known_connected = now

        if not lost:
            return

        for name in sorted(lost):
            if name in self.backend.servers.names():
                self.notify(f"{name}: SSH connection lost — press c to reconnect", severity="warning")
        self.refresh_server_views()
        if self.current in lost:
            for tab in self.tabs():
                tab.on_server_changed()

    def _remember_connected(self):
        self._known_connected = set(self.backend.servers.connected_names())

    def periodic_ping(self):
        """Ping all servers now (results arrive through the collector)."""
        self.backend.collector.ping_now()

    # ------------------------------------------------------------------
    # top bar, theme, mouse
    # ------------------------------------------------------------------
    def update_topbar(self):
        if not self.alive:
            return
        keys = self.backend.keys
        try:
            st = keys.status()
            if not st["exists"]:
                key = "key: none (K)"
            elif not st["encrypted"]:
                key = "key: NO passphrase"
            else:
                key = "key: unlocked" if keys.unlocked_count() else "key: locked"
        except Exception:
            key = "key: ?"

        api = self.backend.api
        api_state = f"api: ON :{api.port}" if api.running else "api: off (A)"
        self.main.query_one("#topbar", Static).update(
            f"AZMUTH  —  System Administration TUI"
            f"        {key}  ·  {api_state}  ·  mouse: {'on' if self.mouse_enabled else 'off'} (F9)"
            f"  ·  theme: {self.theme} (^t)"
        )

    def _on_theme_changed(self, theme):
        P.update(self)
        if not self.ready:
            return
        self.backend.settings.set(S.THEME, self.theme)
        self.refresh_server_views()
        self.update_status_bar()
        for tab in self.tabs():
            try:
                tab.restyle()
            except Exception:
                pass
        self.update_topbar()

    def _set_mouse(self, enabled):
        driver = self._driver
        method = getattr(driver, "_enable_mouse_support" if enabled else "_disable_mouse_support", None)
        if method is None:
            return False
        method()
        if hasattr(driver, "flush"):
            driver.flush()
        return True

    def action_toggle_mouse(self):
        enabled = not self.mouse_enabled
        if not self._set_mouse(enabled):
            self.notify("This terminal driver cannot toggle the mouse", severity="warning")
            return
        self.mouse_enabled = enabled
        self.backend.settings.set(S.MOUSE, "on" if enabled else "off")
        self.update_topbar()
        self.notify(
            "Mouse ON" if enabled else "Mouse OFF — select & copy text with your terminal"
        )

    # ------------------------------------------------------------------
    # read-only API (for the web dashboard)
    # ------------------------------------------------------------------
    def action_toggle_api(self):
        self.spawn(self._toggle_api(), group="api", exclusive=True)

    async def _toggle_api(self):
        api = self.backend.api
        try:
            if api.running:
                await api.stop()
                self.notify("API stopped")
            else:
                await api.start()
                self.notify(
                    f"API on {api.url} (localhost only, read-only)\n"
                    f"token: {api.token_path}",
                    timeout=10,
                )
        except Exception as exc:
            self.notify(f"API: {exc}", severity="error")
        self.update_topbar()
        self.refresh_audit()

    def action_rotate_api_token(self):
        def done(ok):
            if not ok:
                return
            try:
                path = self.backend.api.rotate_token()
            except Exception as exc:
                self.notify(f"Token rotation failed: {exc}", severity="error")
                return
            self.notify(f"New API token written to {path} — update the web config", timeout=10)
            self.refresh_audit()

        self.push_screen(
            ConfirmDialog("Rotate API token", "Create a new API token?\nThe web dashboard stops working until it uses the new one."),
            done,
        )

    # ------------------------------------------------------------------
    # misc global actions
    # ------------------------------------------------------------------
    def action_diagnose_current(self):
        self.action_goto("incidents")
        self.call_after_refresh(self.tab("incidents").action_analyze)

    def action_help(self):
        sections = [
            ("Global", binding_pairs(self.BINDINGS) + [
                ("F1-F8 / 1-8", "switch tab"),
                ("shift+drag", "select text even with mouse on (most terminals)"),
                ("ctrl+p", "command palette (servers, tabs, actions)"),
                ("tab / shift+tab", "move focus inside a tab or dialog"),
            ]),
        ]
        sections += [(t.TITLE[2:], t.key_pairs()) for t in self.tabs()]
        sections.append(("Dialogs", [
            ("y / n", "confirm / cancel"),
            ("enter", "next field / submit"),
            ("ctrl+s", "save form / start transfer"),
            ("esc", "cancel"),
        ]))
        self.push_screen(HelpScreen(sections))

    def action_quit_app(self):
        connected = self.backend.servers.connected_names()
        if not connected:
            self.exit()
            return

        def done(ok):
            if ok:
                self.exit()

        self.push_screen(
            ConfirmDialog("Quit Azmuth", f"Close {len(connected)} SSH session(s) and quit?"),
            done,
        )
