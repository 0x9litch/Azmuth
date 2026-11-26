"""
Hidden filter input: '/' opens it, typing filters live,
Enter keeps the filter and returns focus, Esc clears it.
"""

from textual.binding import Binding
from textual.message import Message
from textual.widgets import Input


class SearchBar(Input):
    BINDINGS = [Binding("escape", "cancel", show=False)]

    class Closed(Message):
        """Posted when the bar hides, so the owner can refocus its table."""

        def __init__(self, bar):
            super().__init__()
            self.bar = bar

    def on_mount(self):
        self.display = False

    @property
    def query_text(self):
        return self.value.strip().casefold()

    def open(self):
        self.display = True
        self.focus()
        self.cursor_position = len(self.value)

    def action_cancel(self):
        self.clear_filter()

    def clear_filter(self):
        self.value = ""  # posts Input.Changed -> owner re-filters
        self._close()

    def on_input_submitted(self, event):
        event.stop()
        self._close()

    def _close(self):
        self.display = False
        self.post_message(self.Closed(self))
