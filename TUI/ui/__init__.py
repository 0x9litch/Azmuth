"""
Textual user interface.

    app.py       application shell (shared state + global keys)
    commands.py  Ctrl+P command palette provider
    formatting.py
    tabs/        one widget per tab
    dialogs/     modal screens
    widgets/     reusable widgets
    styles/      theme colours + azmuth.tcss
"""

from .app import AzmuthApp

__all__ = ["AzmuthApp"]
