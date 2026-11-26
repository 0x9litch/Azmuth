"""Full keyboard reference ('?')."""

from rich.table import Table
from rich.text import Text
from textual.binding import Binding
from textual.containers import Vertical, VerticalScroll
from textual.screen import ModalScreen
from textual.widgets import Label, Static

from ..styles.theme import P


class HelpScreen(ModalScreen):
    BINDINGS = [Binding("escape,question_mark,q", "close", "Close")]

    def __init__(self, sections):
        """sections: list of (title, [(key, description), ...])."""
        super().__init__()
        self.sections = sections

    def compose(self):
        table = Table.grid(padding=(0, 2))
        table.add_column(style=f"bold {P.accent}", no_wrap=True)
        table.add_column(style=P.dim)

        for i, (title, pairs) in enumerate(self.sections):
            if i:
                table.add_row("", "")
            table.add_row(title.upper(), "")
            for key, desc in pairs:
                table.add_row(Text(f"  {key}"), Text(desc))

        with Vertical(classes="dialog"):
            yield Label("KEYBOARD REFERENCE", classes="title")
            with VerticalScroll(id="help-body"):
                yield Static(table)
            yield Label("close(esc / ?)   scroll(↑/↓ PgUp/PgDn)", classes="keys")

    def on_mount(self):
        self.query_one("#help-body").focus()

    def action_close(self):
        self.dismiss(None)
