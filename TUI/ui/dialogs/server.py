"""Add/Edit server form and host-key fingerprint confirmation."""

from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.screen import ModalScreen
from textual.widgets import Input, Label


class ServerForm(ModalScreen):
    """
    Collects server fields. If a *validator* is given it is called on
    save; a raised exception is shown inline and the form stays open,
    so the user never loses what they typed.
    """

    BINDINGS = [
        Binding("ctrl+s", "save", "Save"),
        Binding("escape", "cancel", "Cancel"),
    ]

    FIELDS = [
        ("name", "Name", "e.g. web-01"),
        ("host", "Host/IP", "e.g. 192.168.1.10"),
        ("port", "Port", "22"),
        ("username", "Username", "e.g. admin"),
        ("key_path", "Private key path", "~/.ssh/id_ed25519"),
    ]

    def __init__(self, existing_data=None, editing_name=None, validator=None, default_key_path=""):
        super().__init__()
        self.existing_data = existing_data or {}
        self.editing_name = editing_name
        self.validator = validator
        self.default_key_path = default_key_path

    def compose(self):
        d = self.existing_data

        with Vertical(classes="dialog"):
            yield Label("EDIT SERVER" if self.editing_name else "ADD SERVER", classes="title")

            for fid, label, placeholder in self.FIELDS:
                if fid == "name":
                    val = self.editing_name or d.get("name", "")
                elif fid == "port":
                    val = str(d.get("port", 22))
                elif fid == "key_path" and not d.get("key_path"):
                    val = self.default_key_path
                else:
                    val = str(d.get(fid, ""))

                with Horizontal(classes="row"):
                    yield Label(label, classes="field-label")
                    yield Input(val, placeholder=placeholder, id=f"f-{fid}")

            if not self.editing_name:
                with Horizontal(classes="row"):
                    yield Label("Server password", classes="field-label")
                    yield Input(
                        placeholder="optional — installs your public key (ssh-copy-id)",
                        password=True,
                        id="f-password",
                    )
                yield Label(
                    "With a password, Azmuth verifies the host key with you, logs in once\n"
                    "with the password, appends your public key to ~/.ssh/authorized_keys,\n"
                    "then connects with the key. The password is used once and never stored.",
                    classes="note",
                )

            yield Label("", id="form-error", classes="error", markup=False)
            yield Label("save(ctrl+s)  next field(enter / tab)  cancel(esc)", classes="keys")

    def on_mount(self):
        self.query_one("#form-error", Label).display = False
        self.query_one("#f-name", Input).focus()

    def on_input_submitted(self, ev):
        ev.stop()
        last = "f-key_path" if self.editing_name else "f-password"
        if ev.input.id == last:
            self.action_save()
        else:
            self.focus_next()

    def _values(self):
        values = {fid: self.query_one(f"#f-{fid}", Input).value.strip() for fid, _, _ in self.FIELDS}
        values["port"] = values["port"] or "22"
        if not self.editing_name:
            values["password"] = self.query_one("#f-password", Input).value  # not stripped
        return values

    def action_save(self):
        values = self._values()

        if self.validator is not None:
            try:
                self.validator(values)
            except Exception as exc:
                err = self.query_one("#form-error", Label)
                err.update(f"✗ {exc}")
                err.display = True
                return

        self.dismiss(values)

    def action_cancel(self):
        self.dismiss(None)


class FingerprintDialog(ModalScreen):
    BINDINGS = [
        Binding("y", "accept", "Accept"),
        Binding("n,escape", "reject", "Reject"),
    ]

    def __init__(self, server_name, fingerprint):
        super().__init__()
        self.server_name = server_name
        self.fingerprint = fingerprint

    def compose(self):
        with Vertical(classes="dialog"):
            yield Label("UNKNOWN HOST KEY", classes="title")
            yield Label(f"Server: {self.server_name}", markup=False)
            yield Label(f"Fingerprint (SHA256): {self.fingerprint}", markup=False)
            yield Label(
                "Verify this fingerprint out-of-band before trusting it\n"
                "(on the server: ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub).",
                classes="keys",
            )
            yield Label("trust(y)  reject(n / esc)", classes="keys")

    def action_accept(self):
        self.dismiss(True)

    def action_reject(self):
        self.dismiss(False)
