"""Yes/No confirmation and single-line text prompt."""

from textual.binding import Binding
from textual.containers import Vertical
from textual.screen import ModalScreen
from textual.widgets import Input, Label


class ConfirmDialog(ModalScreen):
    BINDINGS = [
        Binding("y", "yes", "Yes"),
        Binding("n,escape", "no", "No"),
    ]

    def __init__(self, title, message, danger=False):
        super().__init__()
        self.title_text = title
        self.message = message
        self.danger = danger

    def compose(self):
        with Vertical(classes="dialog"):
            yield Label(self.title_text.upper(), classes="title", markup=False)
            yield Label(self.message, markup=False)
            yield Label("confirm(y)  cancel(n / esc)", classes="keys")

    def action_yes(self):
        self.dismiss(True)

    def action_no(self):
        self.dismiss(False)


class PromptDialog(ModalScreen):
    BINDINGS = [Binding("escape", "cancel", "Cancel")]

    def __init__(self, title, initial="", placeholder="", hint=""):
        super().__init__()
        self.title_text = title
        self.initial = initial
        self.placeholder = placeholder
        self.hint = hint

    def compose(self):
        with Vertical(classes="dialog"):
            yield Label(self.title_text, classes="title", markup=False)
            if self.hint:
                yield Label(self.hint, classes="keys", markup=False)
            yield Input(self.initial, placeholder=self.placeholder, id="prompt-input")
            yield Label("ok(enter)  cancel(esc)", classes="keys")

    def on_mount(self):
        inp = self.query_one("#prompt-input", Input)
        inp.focus()
        inp.cursor_position = len(inp.value)

    def on_input_submitted(self, ev):
        ev.stop()
        self.dismiss(ev.value.strip())

    def action_cancel(self):
        self.dismiss(None)
