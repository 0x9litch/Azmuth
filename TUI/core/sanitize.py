"""
Neutralise text that comes from a server before it is shown or stored.

Why: Textual/Rich print control characters as they are. A line written to
the journal by ANY user on a server (e.g. `logger $'\\e]52;c;…\\a'`), a
process name, or a file name could then send escape sequences to the
admin's terminal: write the clipboard (OSC 52 — dangerous if pasted),
change the title, clear or fake the screen.

Applied where remote data ENTERS Azmuth (command output, journal fields,
SFTP names), so no display path can be forgotten.
"""

import re

# C0 controls except \t and \n, DEL, and C1 controls (0x80–0x9f; 0x9b is a
# one-byte CSI some terminals honour).
_CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f\x80-\x9f]")


def _visible(match):
    ch = match.group(0)
    code = ord(ch)
    if code < 0x20:
        return "^" + chr(code + 64)   # ESC -> ^[ , BEL -> ^G (caret notation)
    return "�"


def clean_text(text):
    """Make remote text safe to display: control characters become visible."""
    if not text:
        return text
    if not isinstance(text, str):
        text = str(text)
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    return _CONTROL.sub(_visible, text)


def safe_filename(name):
    """A remote file name turned into ONE safe local path component."""
    name = _CONTROL.sub("_", str(name)).replace("/", "_").replace("\\", "_").strip()
    if name in ("", ".", ".."):
        name = "download"
    return name[:255]


def valid_remote_name(name):
    """SFTP names never contain '/' or NUL; a server that sends them is lying."""
    return bool(name) and "/" not in name and "\x00" not in name
