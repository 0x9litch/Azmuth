"""Sudo password prompt (characters are never displayed)."""

from textual.binding import Binding
from textual.containers import Vertical
from textual.screen import ModalScreen
from textual.widgets import Input, Label


class SudoPasswordDialog(ModalScreen):
    BINDINGS = [Binding("escape", "cancel", "Cancel")]

    def __init__(self, server_name, operation, path, error=None, attempt=1, max_attempts=3):
        super().__init__()
        self.server_name = server_name
        self.operation = operation or "-"
        self.path = path or "-"
        self.error = error
        self.attempt = attempt
        self.max_attempts = max_attempts

    def compose(self):
        operation = self.operation.replace("_", " ").upper()

        with Vertical(classes="dialog"):
            yield Label("SUDO AUTHENTICATION REQUIRED", classes="title")
            yield Label(
                f"Server:    {self.server_name}\n"
                f"Operation: {operation}\n"
                f"Target:    {self.path}",
                markup=False,
            )
            if self.error:
                yield Label(
                    f"{self.error}  (attempt {self.attempt}/{self.max_attempts})",
                    classes="error",
                    markup=False,
                )
            yield Input(
                placeholder="sudo password",
                password=True,
                id="sudo-password-input",
            )
            yield Label(
                "continue(enter)  cancel(esc)   · used once, never stored",
                classes="keys",
            )

    def on_mount(self):
        self.query_one("#sudo-password-input", Input).focus()

    def on_input_submitted(self, ev):
        ev.stop()
        # Do not strip the password: spaces may be valid.
        self.dismiss(ev.value if ev.value else None)

    def action_cancel(self):
        self.dismiss(None)
