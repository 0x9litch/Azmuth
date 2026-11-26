# Azmuth

Keyboard-only Linux system administration TUI (Python, Textual, AsyncSSH), with a read-only local API for the web dashboard.

- Full documentation: [TUI/README.md](TUI/README.md)
- API contract for the web team: [TUI/docs/API.md](TUI/docs/API.md)

Run from the repository root:

    python -m venv .venv
    .venv/bin/pip install -r TUI/requirements.txt
    .venv/bin/python -m TUI
