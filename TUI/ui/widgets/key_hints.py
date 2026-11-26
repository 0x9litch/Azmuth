"""Bottom bar listing the keys available right now."""

from rich.text import Text
from textual.widgets import Static


def binding_pairs(bindings):
    """Binding objects -> [(key_display, description)] (described ones only)."""
    pairs = []
    for b in bindings:
        if b.description:
            pairs.append((b.key_display or b.key.split(",")[0], b.description))
    return pairs


def describe(pairs):
    return "  ".join(f"{desc}({key})" for key, desc in pairs)


class KeyHints(Static):
    def show(self, global_hint, pairs):
        # Plain Text: hints contain "[ ]" (the server-switch keys).
        self.update(Text(f"{global_hint}\n{describe(pairs)}"))
