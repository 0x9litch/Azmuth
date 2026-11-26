"""
Dashboard widgets.

MetricCard  bordered gauge: value + detail on line 1, a bar that fills the
            card's width on line 2 (redrawn on resize).
StatTile    small bordered tile with one big number; its border colour
            shows the state (ok / warn / bad / muted).
"""

from rich.text import Text
from textual.widgets import Static

from ...diagnostics.rules import THRESHOLDS
from ..formatting import bar
from ..styles.theme import P


class MetricCard(Static):
    def __init__(self, title, threshold_key=None, limits=None, **kwargs):
        super().__init__(**kwargs)
        self.card_title = title
        # colour limits: (warning, critical) in percent
        if limits is None and threshold_key:
            limits = (THRESHOLDS[f"{threshold_key}_warning"], THRESHOLDS[f"{threshold_key}_critical"])
        self.limits = limits
        self._state = ("text", "—", True)

    def on_mount(self):
        self.border_title = self.card_title

    def on_resize(self, event):
        self._draw()

    def _color(self, percent):
        if self.limits:
            warning, critical = self.limits
            if percent >= critical:
                return P.error
            if percent >= warning:
                return P.warning
        return P.accent

    def set_percent(self, percent, detail="", label=None):
        self._state = ("percent", float(percent), detail, label)
        self._draw()

    def set_text(self, text, dim=False):
        self._state = ("text", text, dim)
        self._draw()

    def restyle(self):
        self._draw()

    def _draw(self):
        if self._state[0] == "text":
            _, text, dim = self._state
            self.update(Text(text, style=P.dim if dim else f"bold {P.accent}"))
            return
        _, percent, detail, label = self._state
        width = max(8, self.content_region.width or 20)
        color = self._color(percent)
        value = label or f"{percent:.1f}%"
        t = Text(no_wrap=True, overflow="crop")
        t.append(value, style=f"bold {color}")
        # the detail only appears when it fits: wrapping would push the bar out
        if detail and len(value) + 2 + len(detail) <= width:
            t.append(" " * (width - len(value) - len(detail)) + detail, style=P.dim)
        t.append("\n")
        t.append(bar(min(percent, 100.0), width), style=color)
        self.update(t)


class StatTile(Static):
    STATES = ("ok", "warn", "bad", "muted")

    def __init__(self, title, **kwargs):
        super().__init__("—", **kwargs)
        self.tile_title = title

    def on_mount(self):
        self.border_title = self.tile_title

    def set(self, value, sub="", state="ok"):
        t = Text(justify="center", no_wrap=True, overflow="ellipsis")
        color = {"ok": P.accent, "warn": P.warning, "bad": P.error}.get(state, P.dim)
        t.append(str(value), style=f"bold {color}")
        if sub:
            t.append(f"  {sub}", style=P.dim)
        self.update(t)
        for s in self.STATES:
            self.set_class(s == state, f"tile-{s}")
