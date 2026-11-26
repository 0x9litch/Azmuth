"""Sidebar listing registered servers with their SSH state."""

from rich.text import Text
from textual.markup import escape as esc
from textual.containers import Vertical
from textual.widgets import OptionList, Static

from ..styles.theme import P


class ServerList(Vertical):
    def compose(self):
        yield Static("SERVERS", classes="brand")
        yield OptionList(id="servers")
        yield Static("No server selected", id="selection")

    def on_mount(self):
        # Keyboard users switch servers with [ / ] or Ctrl+P, so the list
        # never steals focus from the active tab.
        self.option_list.can_focus = False

    @property
    def option_list(self):
        return self.query_one("#servers", OptionList)

    def render_servers(self, servers, current, is_connected):
        ol = self.option_list
        ol.clear_options()

        if not servers:
            ol.add_option(Text("(no servers — press a)", style=P.dim))
            self.query_one("#selection", Static).update("No server selected")
            return

        names = []
        for s in servers:
            connected = is_connected(s["name"])
            label = Text()
            label.append("● " if connected else "○ ", style=f"bold {P.accent}" if connected else P.dim)
            label.append(s["name"], style="bold")
            label.append(f"\n  {s['username']}@{s['host']}:{s['port']}", style=P.dim)
            ol.add_option(label)
            names.append(s["name"])

        if current in names:
            ol.highlighted = names.index(current)
            s = servers[names.index(current)]
            self.query_one("#selection", Static).update(
                f"selected: [b]{esc(s['name'])}[/b]\n{esc(s['username'])}@{esc(s['host'])}"
            )
