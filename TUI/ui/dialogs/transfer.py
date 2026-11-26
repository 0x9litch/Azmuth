"""Server-to-server transfer: pick destination, path and mode by keyboard."""

from rich.text import Text
from textual.binding import Binding
from textual.containers import Vertical
from textual.screen import ModalScreen
from textual.widgets import Input, Label, OptionList, RadioButton, RadioSet

from ..styles.theme import P


class TransferDialog(ModalScreen):
    BINDINGS = [
        Binding("ctrl+s", "save", "Start transfer"),
        Binding("escape", "cancel", "Cancel"),
    ]

    def __init__(self, source_server, source_path, candidates):
        """
        candidates: list of (server_name, is_connected) excluding the source.
        """
        super().__init__()
        self.source_server = source_server
        self.source_path = source_path
        self.candidates = candidates

    def compose(self):
        with Vertical(classes="dialog"):
            yield Label("SERVER-TO-SERVER TRANSFER", classes="title")
            yield Label(f"Source: {self.source_server}:{self.source_path}", markup=False)

            yield Label("Destination server  (↑/↓, ● = connected)", classes="keys")
            options = []
            for name, connected in self.candidates:
                t = Text()
                t.append("● " if connected else "○ ", style=P.accent if connected else P.dim)
                t.append(name, style="bold" if connected else P.dim)
                if not connected:
                    t.append("  (not connected)", style=P.dim)
                options.append(t)
            yield OptionList(*options, id="transfer-server")

            yield Label("Destination path", classes="keys")
            yield Input(value=self.source_path, id="transfer-path")

            yield Label("Mode  (←/→ or ↑/↓, space to pick)", classes="keys")
            with RadioSet(id="transfer-mode"):
                yield RadioButton("Copy — keep source", value=True)
                yield RadioButton("Move — delete source after SHA-256 verify")

            yield Label("", id="transfer-error", classes="error", markup=False)
            yield Label("start(ctrl+s)  next(tab)  cancel(esc)", classes="keys")

    def on_mount(self):
        self.query_one("#transfer-error", Label).display = False
        ol = self.query_one("#transfer-server", OptionList)
        # Preselect the first connected candidate.
        for i, (_, connected) in enumerate(self.candidates):
            if connected:
                ol.highlighted = i
                break
        else:
            if self.candidates:
                ol.highlighted = 0
        ol.focus()

    def on_option_list_option_highlighted(self, ev):
        ev.stop()  # never let this list change the app's selected server

    def on_option_list_option_selected(self, ev):
        ev.stop()
        self.query_one("#transfer-path", Input).focus()

    def on_input_submitted(self, ev):
        ev.stop()
        self.action_save()

    def _error(self, message):
        err = self.query_one("#transfer-error", Label)
        err.update(f"✗ {message}")
        err.display = True

    def action_save(self):
        ol = self.query_one("#transfer-server", OptionList)
        idx = ol.highlighted

        if idx is None or not self.candidates:
            self._error("Choose a destination server")
            return

        name, connected = self.candidates[idx]

        if not connected:
            self._error(f"'{name}' is not connected. Close (esc), select it, press c.")
            return

        path = self.query_one("#transfer-path", Input).value.strip()

        if not path.startswith("/"):
            self._error("Destination path must be absolute (start with /)")
            return

        radio = self.query_one("#transfer-mode", RadioSet)
        mode = "move" if radio.pressed_index == 1 else "copy"

        self.dismiss({"destination_server": name, "destination_path": path, "mode": mode})

    def action_cancel(self):
        self.dismiss(None)
