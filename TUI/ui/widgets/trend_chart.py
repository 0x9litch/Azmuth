"""
TrendChart: small percent chart with a FIXED 0–100 scale.

Textual's Sparkline scales from the data's min to max, so CPU moving
between 4% and 14% fills the whole height and looks like an emergency.
Here the height always means 0–100 %, with a y-axis, and each column is
coloured by the same thresholds as the gauges.

Drawing: each column is one sample (resampled to the width); each row is
filled with eighth-blocks ▁▂▃▄▅▆▇█ so the resolution is height × 8 steps.
"""

from rich.text import Text
from textual.widgets import Static

from ..styles.theme import P

BLOCKS = " ▁▂▃▄▅▆▇█"
AXIS_WIDTH = 5  # "100┤"


def resample(values, width):
    """Fit values into `width` columns (average when there are more)."""
    if not values or width <= 0:
        return []
    if len(values) <= width:
        return list(values)
    step = len(values) / width
    out = []
    for i in range(width):
        chunk = values[int(i * step): max(int((i + 1) * step), int(i * step) + 1)]
        out.append(sum(chunk) / len(chunk))
    return out


class TrendChart(Static):
    def __init__(self, limits=(80.0, 90.0), **kwargs):
        super().__init__(**kwargs)
        self.limits = limits
        self.values = []

    def set_values(self, values):
        self.values = [max(0.0, min(100.0, float(v))) for v in values if v is not None]
        self._draw()

    def on_resize(self, event):
        self._draw()

    def restyle(self):
        self._draw()

    def _color(self, value):
        warning, critical = self.limits
        if value >= critical:
            return P.error
        if value >= warning:
            return P.warning
        return P.accent

    def _draw(self):
        height = max(2, self.content_region.height or 4)
        width = max(4, (self.content_region.width or 40) - AXIS_WIDTH)
        cols = resample(self.values, width)
        pad = width - len(cols)  # newest samples on the right

        t = Text(no_wrap=True, overflow="crop")
        for row in range(height):  # row 0 = top
            top = height - row
            label = {0: "100", height // 2: " 50", height - 1: "  0"}.get(row, "   ")
            t.append(f"{label:>3} ┤" if label.strip() else "    │", style=P.dim)
            t.append(" " * pad)
            for v in cols:
                level = v / 100 * height     # in rows
                fill = level - (top - 1)      # how much of this row is filled
                if fill >= 1:
                    ch = "█"
                elif fill <= 0:
                    ch = "·" if row == height - 1 and v == 0 else " "
                else:
                    ch = BLOCKS[max(1, round(fill * 8))]
                t.append(ch, style=self._color(v))
            if row < height - 1:
                t.append("\n")
        if not self.values:
            t = Text("no data yet", style=P.dim)
        self.update(t)
