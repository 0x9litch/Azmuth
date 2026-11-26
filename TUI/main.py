"""
Azmuth entry point.

Startup:
  1. Database.initialize()
  2. ConnectionManager()
  3. Backend(db, conn_mgr)
  4. AzmuthApp(backend).run()

Shutdown is owned by AzmuthApp.on_unmount() → Backend.shutdown().
This module's try/finally is a safety net:
  - disconnect_all() is idempotent (pops entries from the manager)
  - db.close() is idempotent (sets conn=None)
so double-call is safe.
"""

import asyncio
import importlib
import os
import sys

# Allow `python main.py` from inside the folder as well as `python -m TUI`:
# when run as a plain script, register the parent folder as a package so
# the relative imports below resolve.
if __name__ == "__main__" and not __package__:
    _pkg_dir = os.path.dirname(os.path.abspath(__file__))
    sys.path.insert(0, os.path.dirname(_pkg_dir))
    __package__ = os.path.basename(_pkg_dir)
    importlib.import_module(__package__)

from .backend import Backend
from .backend.settings import MOUSE as SETTING_MOUSE
from .core.connection import ConnectionManager
from .core.database import Database, DatabaseError
from .ui import AzmuthApp


def main():
    # 1. Database
    db = Database()
    try:
        db.initialize()
    except DatabaseError as exc:
        print(f"FATAL: database initialization failed: {exc}", file=sys.stderr)
        sys.exit(1)

    # 2. Connection manager
    conn_mgr = ConnectionManager()

    # 3. Backend
    backend = Backend(db, conn_mgr)

    # 4. Run the TUI. The driver always starts with mouse support so it can
    #    be toggled at runtime (F9); the saved preference is applied on mount.
    mouse_enabled = backend.settings.get_bool(SETTING_MOUSE, True)
    app = AzmuthApp(backend, mouse_enabled=mouse_enabled)
    try:
        app.run(mouse=True)
    finally:
        # on_unmount should have run; these are idempotent fallbacks.
        try:
            asyncio.run(conn_mgr.disconnect_all())
        except Exception:
            pass
        try:
            db.close()
        except Exception:
            pass


if __name__ == "__main__":
    main()
