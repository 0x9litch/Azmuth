"""
Non-secret user preferences stored in the local database.

Never put passwords, passphrases or key contents here.
"""

from ..core import database as db_mod
from .base import BaseManager

KEY_PATH = "ssh_key_path"
THEME = "theme"
MOUSE = "mouse"


class SettingsManager(BaseManager):
    def get(self, key, default=None):
        try:
            return self.db.get_setting(key, default)
        except db_mod.DatabaseError:
            return default

    def set(self, key, value):
        try:
            self.db.set_setting(key, value)
            return True
        except db_mod.DatabaseError:
            return False

    def get_bool(self, key, default=True):
        value = self.get(key)
        if value is None:
            return default
        return str(value).lower() in ("1", "true", "on", "yes")
