"""
Common behaviour for every tab.

A tab is a self-contained widget that owns:
- its layout (compose),
- its key bindings (active while focus is inside the tab),
- its per-server state, reset in on_server_changed(),
- an async reload() that fetches data for the selected server.
"""

from textual.containers import Vertical

from ...backend.errors import SudoAuthenticationFailed, SudoPasswordRequired
from ..dialogs import SudoPasswordDialog
from ..widgets import binding_pairs

# Returned by run_with_sudo() when the user cancels the password prompt.
CANCELLED = object()

MAX_SUDO_ATTEMPTS = 3


class BaseTab(Vertical):
    TAB_ID = ""
    TITLE = ""
    NEEDS_CONNECTION = True
    # Keys handled by child widgets (documentation only): [(key, description)]
    EXTRA_KEYS = []

    # ------------------------------------------------------------------
    # shortcuts
    # ------------------------------------------------------------------
    @property
    def backend(self):
        return self.app.backend

    @property
    def current(self):
        return self.app.current

    def key_pairs(self):
        return list(self.EXTRA_KEYS) + binding_pairs(self.BINDINGS)

    def require_connection(self):
        if not self.current:
            self.notify("No server selected", severity="warning")
            return False
        if not self.backend.is_connected(self.current):
            self.notify("Server is not connected (press c)", severity="warning")
            return False
        return True

    # ------------------------------------------------------------------
    # lifecycle hooks (override in subclasses)
    # ------------------------------------------------------------------
    def focus_primary(self):
        """Give keyboard focus to the tab's main widget."""

    def on_server_changed(self):
        """Clear anything that belongs to the previously selected server."""

    async def reload(self):
        """Fetch fresh data for the selected server."""

    def restyle(self):
        """Re-render from cached data after a theme change (no network)."""

    def owns_focus(self):
        focused = self.app.focused
        return focused is not None and self in focused.ancestors_with_self

    def take_focus(self):
        """
        Focus the primary widget unless focus is already inside this tab.

        TabbedContent activates whichever pane contains the focused widget,
        so unconditional focusing from two tabs could bounce between them.
        """
        if not self.owns_focus():
            self.focus_primary()

    def activated(self):
        """Called when the tab becomes visible or the server changes."""
        self.take_focus()
        if not self.NEEDS_CONNECTION or (
            self.current and self.backend.is_connected(self.current)
        ):
            self.app.spawn(self.reload(), group=f"reload-{self.TAB_ID}", exclusive=True)

    # ------------------------------------------------------------------
    # sudo flow shared by Services and Files
    # ------------------------------------------------------------------
    async def run_with_sudo(self, label, callback):
        """
        Run callback(passwords) and handle sudo prompts.

        *passwords* is a temporary {server_name: password} dict that lives
        only for this operation; it is never persisted or audited.
        A rejected password re-prompts (up to MAX_SUDO_ATTEMPTS).

        Returns the callback result, or CANCELLED if the user pressed Esc.
        """
        passwords = {}
        attempts = {}

        try:
            while True:
                try:
                    return await callback(passwords)

                except SudoPasswordRequired as exc:
                    request, error = exc, None

                except SudoAuthenticationFailed as exc:
                    server = exc.server_name or self.current
                    attempts[server] = attempts.get(server, 1) + 1
                    passwords.pop(server, None)

                    if attempts[server] > MAX_SUDO_ATTEMPTS:
                        raise

                    request, error = exc, "Incorrect password"

                server = request.server_name or self.current
                password = await self.app.ask(
                    SudoPasswordDialog(
                        server,
                        request.operation or label,
                        request.path,
                        error=error,
                        attempt=attempts.get(server, 1),
                        max_attempts=MAX_SUDO_ATTEMPTS,
                    )
                )

                if password is None:
                    self.notify(f"{label}: cancelled", severity="warning")
                    return CANCELLED

                passwords[server] = password

        finally:
            # Python strings cannot be securely zeroed; drop references.
            passwords.clear()
