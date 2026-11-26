"""One-line status: SSH state of the selected server + busy indicator."""

from rich.text import Text
from textual.widgets import Static

from ..styles.theme import P


class StatusBar(Static):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self._connection = ("", False)
        self._busy = {}  # token -> label
        self._token = 0

    def set_connection(self, text, connected=False):
        self._connection = (text, connected)
        self._redraw()

    def start_busy(self, label):
        self._token += 1
        self._busy[self._token] = label
        self._redraw()
        return self._token

    def stop_busy(self, token):
        self._busy.pop(token, None)
        self._redraw()

    def _redraw(self):
        text, connected = self._connection
        t = Text(text, style=f"bold {P.accent}" if connected else P.dim)
        if self._busy:
            labels = list(self._busy.values())
            extra = f" (+{len(labels) - 1})" if len(labels) > 1 else ""
            t.append(f"     ⟳ {labels[-1]}…{extra}", style=f"bold {P.warning}")
        self.update(t)
