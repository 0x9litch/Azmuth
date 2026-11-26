"""Terminal: run one-shot remote commands with history."""

from rich.markup import escape
from rich.text import Text
from textual.markup import escape as esc
from textual.binding import Binding
from textual.containers import Horizontal
from textual.widgets import RichLog, Static

from ..widgets import HistoryInput
from ..styles.theme import P
from .base import BaseTab


class TerminalTab(BaseTab):
    TAB_ID = "terminal"
    TITLE = "4 Terminal"

    EXTRA_KEYS = [("enter", "run"), ("↑/↓", "history")]
    BINDINGS = [
        Binding("ctrl+l", "clear", "clear", key_display="ctrl+l"),
        Binding("escape", "leave_prompt", "scroll output / use shortcuts", key_display="esc"),
        Binding("i", "enter_prompt", "back to prompt"),
    ]

    def compose(self):
        yield Static("No server connected", id="term-target", classes="subline")
        with Horizontal(id="prompt-row"):
            yield Static("$", id="prompt-sign")
            yield HistoryInput(placeholder="type a command and press Enter", id="cmd-input")
        yield RichLog(id="cmd-log", wrap=True, markup=True)

    @property
    def prompt(self):
        return self.query_one("#cmd-input", HistoryInput)

    @property
    def log_view(self):
        return self.query_one("#cmd-log", RichLog)

    def focus_primary(self):
        self.prompt.focus()

    def on_server_changed(self):
        self._update_target()

    async def reload(self):
        self._update_target()

    def activated(self):
        self._update_target()
        self.take_focus()

    def _update_target(self):
        cur = self.current
        target = self.query_one("#term-target", Static)
        sign = self.query_one("#prompt-sign", Static)

        if not cur:
            target.update("No server selected")
            sign.update("$")
            return

        srv = self.backend.servers.get(cur) or {}
        connected = self.backend.is_connected(cur)
        target.update(
            f"{esc(cur)}  ({esc(str(srv.get('username', '?')))}@{esc(str(srv.get('host', '?')))})  "
            + ("[b]connected[/b]" if connected else "not connected — press esc then c")
            + "   · non-interactive: each command runs on its own, timeout 30s"
        )
        sign.update(Text(f"{srv.get('username', '')}@{cur} $"))

    # ------------------------------------------------------------------
    # actions
    # ------------------------------------------------------------------
    def action_clear(self):
        self.log_view.clear()

    def action_leave_prompt(self):
        self.log_view.focus()

    def action_enter_prompt(self):
        self.prompt.focus()

    def on_input_submitted(self, ev):
        if ev.input.id != "cmd-input":
            return
        ev.stop()

        cmd = ev.value.strip()
        ev.input.value = ""

        if not cmd or not self.require_connection():
            return

        self.prompt.remember(cmd)
        self.app.spawn(self._run(self.current, cmd))

    async def _run(self, server, cmd):
        log = self.log_view
        log.write(f"[bold]{escape(server)}:~$[/bold] {escape(cmd)}")

        try:
            with self.app.busy(f"running: {cmd[:30]}"):
                res = await self.backend.terminal.run(server, cmd)
        except Exception as exc:
            log.write(f"[{P.error}]error: {escape(str(exc))}[/]")
            self.app.refresh_audit()
            return

        if res.stdout:
            log.write(escape(res.stdout.rstrip()))
        if res.stderr:
            log.write(f"[{P.error}]{escape(res.stderr.rstrip())}[/]")

        color = P.accent if res.exit_code == 0 else P.error
        log.write(f"[{color}]exit {res.exit_code}[/]  ({res.duration:.2f}s)")
        self.app.refresh_audit()
