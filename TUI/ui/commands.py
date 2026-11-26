"""
Command palette (Ctrl+P): fuzzy-search servers and actions by keyboard.
"""

from functools import partial

from textual.command import DiscoveryHit, Hit, Provider


class AzmuthCommands(Provider):
    def _commands(self):
        app = self.app
        backend = app.backend
        out = []

        for name in backend.servers.names():
            connected = backend.is_connected(name)
            out.append((f"Server: switch to {name}", partial(app.select_server, name), "select in sidebar"))
            if connected:
                out.append((f"Server: disconnect {name}", partial(app.disconnect, name), "close SSH session"))
            else:
                out.append((f"Server: connect {name}", partial(app.connect, name), "open SSH session"))

        out.append(("Server: add new", app.action_add_server, "open the add-server form"))
        out.append(("Server: connect ALL", app.action_connect_all, "C — asks the key passphrase once"))
        out.append(("Server: disconnect ALL", app.action_disconnect_all, "X"))
        if app.current:
            out.append(
                (f"SSH key: install on {app.current} (password)", app.action_install_key, "I — like ssh-copy-id")
            )
        out.append(("SSH key: manager (generate / passphrase / lock)", app.action_key_manager, "K"))
        out.append(("Mouse: toggle on/off", app.action_toggle_mouse, "F9"))
        out.append(("Theme: change", app.action_change_theme, "ctrl+t — applies to the whole UI"))

        for tab in app.tabs():
            out.append((f"Go to: {tab.TITLE[2:]}", partial(app.action_goto, tab.TAB_ID), tab.TITLE))

        if app.current:
            out.append(
                (f"Diagnostics: analyse {app.current}", app.action_diagnose_current, "Incidents tab — d")
            )
            out.append(("Ping all servers", app.periodic_ping, "ICMP reachability"))

        api = app.backend.api
        out.append((
            "API: stop" if api.running else "API: start (read-only, localhost)",
            app.action_toggle_api,
            f"A — {api.url}",
        ))
        out.append(("API: rotate token", app.action_rotate_api_token, str(api.token_path)))
        out.append(("Help: keyboard reference", app.action_help, "?"))
        return out

    async def discover(self):
        for text, callback, help_text in self._commands():
            yield DiscoveryHit(text, callback, help=help_text)

    async def search(self, query):
        matcher = self.matcher(query)
        for text, callback, help_text in self._commands():
            score = matcher.match(text)
            if score > 0:
                yield Hit(score, matcher.highlight(text), callback, help=help_text)
