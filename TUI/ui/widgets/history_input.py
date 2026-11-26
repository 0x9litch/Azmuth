"""Input with shell-like Up/Down history."""

from textual.binding import Binding
from textual.widgets import Input


class HistoryInput(Input):
    BINDINGS = [
        Binding("up", "history(-1)", show=False),
        Binding("down", "history(1)", show=False),
    ]

    def __init__(self, *args, max_history=500, **kwargs):
        super().__init__(*args, **kwargs)
        self.history = []
        self._index = 0
        self._max = max_history

    def remember(self, value):
        if value and (not self.history or self.history[-1] != value):
            self.history.append(value)
            del self.history[: -self._max]
        self._index = len(self.history)

    def action_history(self, delta):
        if not self.history:
            return
        self._index = max(0, min(len(self.history), self._index + delta))
        self.value = self.history[self._index] if self._index < len(self.history) else ""
        self.cursor_position = len(self.value)
