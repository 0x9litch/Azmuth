"""
Colours.

- AZMUTH_THEME is the default Textual theme (terminal green).
- azmuth.tcss only uses Textual theme variables ($primary, $foreground,
  $error, ...), so ANY theme chosen with Ctrl+T restyles the whole UI.
- P (the palette) gives the same colours to Python code that builds Rich
  Text (tables, status lines, gauges). It is refreshed from the active
  theme on every theme change, so always read P.accent etc. at render
  time — never copy them into module-level constants.
"""

from rich.color import Color as RichColor
from textual.color import Color
from textual.theme import Theme

BLACK = "#000000"
GREEN = "#00ff5f"
GREEN_DIM = "#00aa44"
GREEN_BG = "#001a0a"
RED = "#ff5f5f"
YELLOW = "#ffd75f"

AZMUTH_THEME = Theme(
    name="azmuth",
    primary=GREEN,
    secondary=GREEN_DIM,
    accent=GREEN,
    foreground=GREEN,
    background=BLACK,
    surface=BLACK,
    panel=GREEN_BG,
    success=GREEN,
    warning=YELLOW,
    error=RED,
    dark=True,
)


def _is_ansi(color):
    return getattr(color, "ansi", None) is not None


def rich_color(color, fallback):
    """
    Convert a Textual Color to a colour name Rich understands.

    Most themes use RGB, but terminal-palette themes such as "textual-ansi"
    use names like "ansi_default" / "ansi_bright_green", which Rich does not
    parse ("default" / "bright_green" are its names). An unparseable colour
    in a Rich style crashes rendering, so every value is validated here.
    """
    candidates = []
    if _is_ansi(color):
        text = str(color.css if hasattr(color, "css") else color)
        candidates.append(text.removeprefix("ansi_"))
    candidates += [getattr(color, "hex", None), fallback]

    for candidate in candidates:
        if not candidate:
            continue
        try:
            RichColor.parse(candidate)
            return candidate
        except Exception:
            continue
    return fallback


class Palette:
    """Theme-derived colours for Rich styles (hex strings)."""

    def __init__(self):
        self.accent = GREEN      # primary text / OK states
        self.dim = GREEN_DIM     # secondary text
        self.error = RED
        self.warning = YELLOW
        self.success = GREEN
        self.name = AZMUTH_THEME.name

    def update(self, app):
        variables = app.get_css_variables()

        def pick(name, fallback):
            try:
                return Color.parse(variables[name])
            except Exception:
                return Color.parse(fallback)

        background = pick("background", BLACK)
        foreground = pick("foreground", GREEN)

        self.accent = rich_color(pick("primary", GREEN), GREEN)
        self.error = rich_color(pick("error", RED), RED)
        self.warning = rich_color(pick("warning", YELLOW), YELLOW)
        self.success = rich_color(pick("success", GREEN), GREEN)

        if _is_ansi(background) or _is_ansi(foreground):
            # Terminal-palette themes (e.g. textual-ansi) have no RGB value
            # to blend, so use the terminal's own grey for secondary text.
            self.dim = "bright_black"
        else:
            self.dim = background.blend(foreground, 0.6).hex

        self.name = app.theme

    def severity(self, label):
        """'CRIT' / 'ERR' / 'WARN' / 'INFO' (or ERROR/WARNING/CRITICAL) -> colour."""
        return {
            "CRIT": self.error, "CRITICAL": self.error,
            "ERR": self.error, "ERROR": self.error,
            "WARN": self.warning, "WARNING": self.warning,
        }.get(str(label).upper(), self.dim)


P = Palette()
