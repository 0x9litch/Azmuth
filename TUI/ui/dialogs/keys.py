"""
SSH key dialogs: key manager, generate, change passphrase, secret prompt.

Secrets typed here (passphrases, server passwords) are returned to the
caller once and never stored by the dialogs.
"""

from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.screen import ModalScreen
from textual.widgets import Input, Label, Static

from ...backend.key_manager import DEFAULT_KEY_PATH, MIN_PASSPHRASE_LENGTH


class SecretDialog(ModalScreen):
    """One hidden input (passphrase or password). Dismisses str or None."""

    BINDINGS = [Binding("escape", "cancel", "Cancel")]

    def __init__(self, title, lines=(), placeholder="", error=None, footer=""):
        super().__init__()
        self.title_text = title
        self.lines = lines
        self.placeholder = placeholder
        self.error = error
        self.footer = footer

    def compose(self):
        with Vertical(classes="dialog"):
            yield Label(self.title_text, classes="title", markup=False)
            for line in self.lines:
                yield Label(line, markup=False)
            if self.error:
                yield Label(self.error, classes="error", markup=False)
            yield Input(placeholder=self.placeholder, password=True, id="secret-input")
            yield Label(
                "continue(enter)  cancel(esc)" + (f"   · {self.footer}" if self.footer else ""),
                classes="keys",
            )

    def on_mount(self):
        self.query_one("#secret-input", Input).focus()

    def on_input_submitted(self, ev):
        ev.stop()
        self.dismiss(ev.value if ev.value else None)  # never strip secrets

    def action_cancel(self):
        self.dismiss(None)


class _PassphraseForm(ModalScreen):
    """Shared validation for 'new passphrase + confirm' forms."""

    BINDINGS = [
        Binding("ctrl+s", "save", "Save"),
        Binding("escape", "cancel", "Cancel"),
    ]

    def __init__(self):
        super().__init__()
        self._empty_confirmed = False

    def _error(self, message, warn=False):
        err = self.query_one("#key-error", Label)
        err.set_classes("warn" if warn else "error")
        err.update(message)
        err.display = True

    def _check_new(self):
        new = self.query_one("#new-pass", Input).value
        confirm = self.query_one("#confirm-pass", Input).value

        if new != confirm:
            self._error("✗ Passphrases do not match")
            return None

        if new and len(new) < MIN_PASSPHRASE_LENGTH:
            self._error(f"✗ Use at least {MIN_PASSPHRASE_LENGTH} characters")
            return None

        if not new and not self._empty_confirmed:
            self._empty_confirmed = True
            self._error(
                "⚠ No passphrase: anyone who copies the key file can log in to "
                "your servers. Press ctrl+s again to continue anyway.",
                warn=True,
            )
            return None

        return new

    def on_input_submitted(self, ev):
        ev.stop()
        if ev.input.id == "confirm-pass":
            self.action_save()
        else:
            self.focus_next()

    def action_cancel(self):
        self.dismiss(None)


class KeyGenerateDialog(_PassphraseForm):
    def __init__(self, default_path=DEFAULT_KEY_PATH, first_run=False):
        super().__init__()
        self.default_path = default_path
        self.first_run = first_run

    def compose(self):
        with Vertical(classes="dialog"):
            yield Label(
                "WELCOME — CREATE YOUR AZMUTH SSH KEY" if self.first_run else "GENERATE SSH KEY",
                classes="title",
            )
            yield Label(
                "Creates an ed25519 key pair (like ssh-keygen -t ed25519 -C azmuth).\n"
                "With a passphrase the private key file is encrypted; you type the\n"
                "passphrase once per session to unlock it (kept in memory only).",
                classes="note",
            )
            with Horizontal(classes="row"):
                yield Label("Key path", classes="field-label")
                yield Input(self.default_path, id="key-path")
            with Horizontal(classes="row"):
                yield Label("Passphrase", classes="field-label")
                yield Input(password=True, placeholder=f"min {MIN_PASSPHRASE_LENGTH} chars (recommended)", id="new-pass")
            with Horizontal(classes="row"):
                yield Label("Confirm passphrase", classes="field-label")
                yield Input(password=True, id="confirm-pass")
            yield Label("", id="key-error", classes="error", markup=False)
            yield Label(
                "generate(ctrl+s)  next(enter/tab)  "
                + ("later(esc — press K any time)" if self.first_run else "cancel(esc)"),
                classes="keys",
            )

    def on_mount(self):
        self.query_one("#key-error", Label).display = False
        self.query_one("#new-pass", Input).focus()

    def action_save(self):
        path = self.query_one("#key-path", Input).value.strip()
        if not path:
            self._error("✗ Key path is required")
            return
        new = self._check_new()
        if new is None:
            return
        self.dismiss({"path": path, "passphrase": new})


class ChangePassphraseDialog(_PassphraseForm):
    def __init__(self, path, encrypted):
        super().__init__()
        self.path = path
        self.encrypted = encrypted

    def compose(self):
        with Vertical(classes="dialog"):
            yield Label(
                "CHANGE KEY PASSPHRASE" if self.encrypted else "ADD A PASSPHRASE TO THE KEY",
                classes="title",
            )
            yield Label(
                f"{self.path}\nLike ssh-keygen -p: the same key is re-encrypted in place,\n"
                "so servers that already trust it keep working.",
                classes="note",
            )
            if self.encrypted:
                with Horizontal(classes="row"):
                    yield Label("Current passphrase", classes="field-label")
                    yield Input(password=True, placeholder="required, even if the key is unlocked", id="old-pass")
            with Horizontal(classes="row"):
                yield Label("New passphrase", classes="field-label")
                yield Input(password=True, placeholder=f"min {MIN_PASSPHRASE_LENGTH} chars; empty = remove", id="new-pass")
            with Horizontal(classes="row"):
                yield Label("Confirm", classes="field-label")
                yield Input(password=True, id="confirm-pass")
            yield Label("", id="key-error", classes="error", markup=False)
            yield Label("save(ctrl+s)  next(enter/tab)  cancel(esc)", classes="keys")

    def on_mount(self):
        self.query_one("#key-error", Label).display = False
        first = "#old-pass" if self.encrypted else "#new-pass"
        self.query_one(first, Input).focus()

    def action_save(self):
        new = self._check_new()
        if new is None:
            return
        old = self.query_one("#old-pass", Input).value if self.encrypted else None
        if self.encrypted and not old:
            # proves it is really you, not someone at an unlocked session
            self._error("✗ Enter the current passphrase")
            self.query_one("#old-pass", Input).focus()
            return
        self.dismiss({"old": old or None, "new": new})


class KeyManagerDialog(ModalScreen):
    """
    Shows the managed key and dismisses with the chosen action:
    generate | passphrase | use | unlock | lock | None.
    """

    BINDINGS = [
        Binding("g", "pick('generate')", "generate new key"),
        Binding("p", "pick('passphrase')", "set / change passphrase"),
        Binding("o", "pick('use')", "use another existing key"),
        Binding("u", "pick('unlock')", "unlock now"),
        Binding("l", "pick('lock')", "lock (forget unlocked keys)"),
        Binding("escape,k", "pick(None)", "close"),
    ]

    def __init__(self, status, public_line=None, unlocked_count=0):
        super().__init__()
        self.status = status
        self.public_line = public_line
        self.unlocked_count = unlocked_count

    def compose(self):
        s = self.status

        with Vertical(classes="dialog"):
            yield Label("SSH KEY", classes="title")

            if not s["exists"]:
                yield Label(f"No key at {s['real_path']}", classes="warn", markup=False)
                yield Label("Press g to generate one, or o to use an existing key.", classes="note")
            else:
                if s["error"]:
                    state, cls = f"unreadable: {s['error']}", "error"
                elif not s["encrypted"]:
                    state, cls = "NOT protected by a passphrase (press p to add one)", "warn"
                elif s["unlocked"]:
                    state, cls = "encrypted · unlocked for this session", "ok"
                else:
                    state, cls = "encrypted · locked (asked on connect)", "ok"

                yield Label(f"Path:        {s['real_path']}", markup=False)
                yield Label(f"Fingerprint: {s['fingerprint'] or '-'}", markup=False)
                yield Label(f"Comment:     {s['comment'] or '-'}", markup=False)
                yield Label(f"State:       {state}", classes=cls, markup=False)
                if self.public_line:
                    yield Label("Public key (what gets installed on servers):", classes="note")
                    yield Static(self.public_line, classes="mono", markup=False)
                    yield Label("Tip: turn the mouse off (F9) to select & copy it with your terminal.", classes="note")

            if self.unlocked_count:
                yield Label(f"{self.unlocked_count} key(s) unlocked in memory.", classes="note")

            keys = []
            if not s["exists"]:
                keys.append("generate(g)")
            else:
                keys.append("passphrase(p)")
                if s["encrypted"] and not s["unlocked"]:
                    keys.append("unlock(u)")
            keys += ["use existing(o)", "lock(l)", "close(esc)"]
            yield Label("  ".join(keys), classes="keys")

    def action_pick(self, action):
        self.dismiss(action)
