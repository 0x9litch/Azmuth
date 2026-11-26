"""
Azmuth database layer.

Stores server metadata and audit records in SQLite at:
    ~/.local/share/azmuth/azmuth.db

Security rules:
- Application directory permissions 700, file permissions 600 (enforced).
- Refuse symlinked database paths and paths outside $HOME.
- Never store passwords, passphrases, or private key contents.
  (The settings table only holds non-secret preferences such as the
  managed SSH key *path*, the theme name and the mouse on/off flag.)
- Audit records are append-only through the application API.

Monitoring data (written only by Azmuth's collector / diagnostics):
- metric_samples: one averaged sample per server every 30 s (charts).
- incidents + incident_evidence: diagnosed problems and their log lines.
Old rows are pruned (see prune_* methods). Nothing here is a secret.

Fingerprint policy:
- Changing the server's host or port clears the stored fingerprint,
  forcing re-approval on the next connection.
- Changing only the display name preserves the fingerprint.
"""

import os
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from .redaction import redact


DEFAULT_APP_DIR = Path.home() / ".local" / "share" / "azmuth"
DEFAULT_DB_PATH = DEFAULT_APP_DIR / "azmuth.db"


class DatabaseError(Exception):
    """Raised for any database-level problem."""


class Database:
    def __init__(self, db_path=None):
        self.db_path = Path(db_path).expanduser() if db_path else DEFAULT_DB_PATH
        self.conn = None

    # ------------------------------------------------------------------
    # initialization
    # ------------------------------------------------------------------
    def initialize(self):
        app_dir = self.db_path.parent
        self._prepare_directory(app_dir)
        self._refuse_unsafe_path()
        try:
            self.conn = sqlite3.connect(str(self.db_path), timeout=10)
        except sqlite3.Error as exc:
            raise DatabaseError(f"Cannot open database: {exc}") from exc
        self.conn.row_factory = sqlite3.Row
        try:
            self.conn.execute("PRAGMA foreign_keys = ON")
            self.conn.execute("PRAGMA journal_mode = WAL")
        except sqlite3.Error as exc:
            self.conn.close()
            self.conn = None
            raise DatabaseError(f"PRAGMA failed: {exc}") from exc
        self._secure_file()
        try:
            self._create_tables()
        except Exception:
            # do not leave an open connection on failure
            self.close()
            raise

    def _prepare_directory(self, app_dir):
        try:
            app_dir.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            raise DatabaseError(f"Cannot create {app_dir}: {exc}") from exc
        try:
            os.chmod(app_dir, 0o700)
        except OSError as exc:
            raise DatabaseError(
                f"Cannot restrict permissions on {app_dir}: {exc}"
            ) from exc

    def _refuse_unsafe_path(self):
        if self.db_path.is_symlink():
            raise DatabaseError(
                f"Refusing to use symlinked database path: {self.db_path}"
            )
        try:
            real = self.db_path.resolve()
            home = Path.home().resolve()
        except OSError as exc:
            raise DatabaseError(f"Cannot resolve database path: {exc}") from exc
        # proper component check, not string prefix
        try:
            real.relative_to(home)
        except ValueError:
            raise DatabaseError(f"Database path must stay under $HOME (got {real})")

    def _secure_file(self):
        if not self.db_path.exists():
            return
        try:
            os.chmod(self.db_path, 0o600)
        except OSError as exc:
            raise DatabaseError(
                f"Cannot restrict permissions on {self.db_path}: {exc}"
            ) from exc

    def _create_tables(self):
        try:
            with self.conn:
                self.conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS servers (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        name TEXT NOT NULL UNIQUE,
                        host TEXT NOT NULL,
                        port INTEGER NOT NULL,
                        username TEXT NOT NULL,
                        key_path TEXT NOT NULL,
                        host_key_fingerprint TEXT,
                        created_at TEXT NOT NULL,
                        updated_at TEXT NOT NULL
                    )
                    """
                )
                self.conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS audit_logs (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        user TEXT NOT NULL,
                        server_name TEXT,
                        action TEXT NOT NULL,
                        status TEXT NOT NULL,
                        details TEXT,
                        created_at TEXT NOT NULL
                    )
                    """
                )
                self.conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS settings (
                        key TEXT PRIMARY KEY,
                        value TEXT NOT NULL,
                        updated_at TEXT NOT NULL
                    )
                    """
                )
                self.conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS metric_samples (
                        server TEXT NOT NULL,
                        ts INTEGER NOT NULL,
                        cpu REAL,
                        mem_percent REAL,
                        mem_used INTEGER,
                        mem_total INTEGER,
                        disk_percent REAL,
                        disk_used INTEGER,
                        disk_total INTEGER,
                        load1 REAL,
                        load5 REAL,
                        load15 REAL,
                        PRIMARY KEY (server, ts)
                    )
                    """
                )
                self.conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS incidents (
                        id TEXT PRIMARY KEY,
                        server TEXT NOT NULL,
                        fingerprint TEXT NOT NULL,
                        category TEXT NOT NULL,
                        severity TEXT NOT NULL,
                        status TEXT NOT NULL,
                        title TEXT NOT NULL,
                        root_cause TEXT,
                        confidence TEXT,
                        confidence_reason TEXT,
                        impact TEXT,
                        affected TEXT,
                        checks TEXT,
                        first_seen TEXT NOT NULL,
                        last_seen TEXT NOT NULL,
                        event_count INTEGER NOT NULL DEFAULT 0,
                        recurring INTEGER NOT NULL DEFAULT 0,
                        previous_id TEXT,
                        condition_cleared_at TEXT,
                        created_at TEXT NOT NULL,
                        updated_at TEXT NOT NULL
                    )
                    """
                )
                self.conn.execute(
                    "CREATE INDEX IF NOT EXISTS idx_incidents_fp ON incidents(fingerprint, status)"
                )
                self.conn.execute(
                    "CREATE INDEX IF NOT EXISTS idx_incidents_seen ON incidents(last_seen)"
                )
                self.conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS incident_evidence (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        incident_id TEXT NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
                        ts TEXT NOT NULL,
                        source TEXT,
                        unit TEXT,
                        role TEXT,
                        message TEXT NOT NULL,
                        UNIQUE (incident_id, ts, message)
                    )
                    """
                )
        except sqlite3.Error as exc:
            raise DatabaseError(f"Table creation failed: {exc}") from exc

    def close(self):
        if self.conn is not None:
            try:
                self.conn.close()
            except sqlite3.Error:
                pass
            finally:
                self.conn = None

    # ------------------------------------------------------------------
    # servers
    # ------------------------------------------------------------------
    def list_servers(self):
        rows = self._query(
            "SELECT id, name, host, port, username, key_path, "
            "host_key_fingerprint, created_at, updated_at "
            "FROM servers ORDER BY name COLLATE NOCASE"
        )
        return [dict(row) for row in rows]

    def get_server(self, name):
        rows = self._query(
            "SELECT id, name, host, port, username, key_path, "
            "host_key_fingerprint, created_at, updated_at "
            "FROM servers WHERE name = ?",
            (name,),
        )
        return dict(rows[0]) if rows else None

    def add_server(self, name, host, port, username, key_path):
        now = _now()
        try:
            with self.conn:
                cur = self.conn.execute(
                    "INSERT INTO servers "
                    "(name, host, port, username, key_path, "
                    "host_key_fingerprint, created_at, updated_at) "
                    "VALUES (?, ?, ?, ?, ?, NULL, ?, ?)",
                    (name, host, int(port), username, key_path, now, now),
                )
            return cur.lastrowid
        except sqlite3.IntegrityError as exc:
            raise DatabaseError(f"Server '{name}' already exists") from exc
        except sqlite3.Error as exc:
            raise DatabaseError(f"Insert failed: {exc}") from exc

    def update_server(self, original_name, name, host, port, username, key_path):
        """
        Update a server row.
        If host or port changes, clear the stored host key fingerprint.
        A name-only change preserves the fingerprint.
        """
        existing = self.get_server(original_name)
        if existing is None:
            raise DatabaseError(f"Server '{original_name}' not found")

        connection_changed = existing["host"] != host or int(existing["port"]) != int(
            port
        )
        new_fingerprint = (
            None if connection_changed else existing["host_key_fingerprint"]
        )
        now = _now()

        try:
            with self.conn:
                cur = self.conn.execute(
                    "UPDATE servers SET name = ?, host = ?, port = ?, "
                    "username = ?, key_path = ?, host_key_fingerprint = ?, "
                    "updated_at = ? WHERE name = ?",
                    (
                        name,
                        host,
                        int(port),
                        username,
                        key_path,
                        new_fingerprint,
                        now,
                        original_name,
                    ),
                )
            if cur.rowcount == 0:
                raise DatabaseError(f"Server '{original_name}' not found")
        except sqlite3.IntegrityError as exc:
            raise DatabaseError(f"Server name '{name}' is already used") from exc
        except sqlite3.Error as exc:
            raise DatabaseError(f"Update failed: {exc}") from exc

    def delete_server(self, name):
        try:
            with self.conn:
                cur = self.conn.execute("DELETE FROM servers WHERE name = ?", (name,))
            if cur.rowcount == 0:
                raise DatabaseError(f"Server '{name}' not found")
        except sqlite3.Error as exc:
            raise DatabaseError(f"Delete failed: {exc}") from exc

    def save_fingerprint(self, name, fingerprint):
        now = _now()
        try:
            with self.conn:
                cur = self.conn.execute(
                    "UPDATE servers SET host_key_fingerprint = ?, updated_at = ? "
                    "WHERE name = ?",
                    (fingerprint, now, name),
                )
            if cur.rowcount == 0:
                raise DatabaseError(f"Server '{name}' not found")
        except sqlite3.Error as exc:
            raise DatabaseError(f"Fingerprint save failed: {exc}") from exc

    def get_fingerprint(self, name):
        rows = self._query(
            "SELECT host_key_fingerprint FROM servers WHERE name = ?", (name,)
        )
        if not rows:
            return None
        return rows[0]["host_key_fingerprint"]

    # ------------------------------------------------------------------
    # audit
    # ------------------------------------------------------------------
    def add_audit(self, user, server_name, action, status, details):
        # details can hold terminal commands ("mysql -pSECRET") or error text:
        # secrets never reach the disk.
        details = redact(details) if isinstance(details, str) else details
        now = _now()
        try:
            with self.conn:
                self.conn.execute(
                    "INSERT INTO audit_logs "
                    "(user, server_name, action, status, details, created_at) "
                    "VALUES (?, ?, ?, ?, ?, ?)",
                    (user, server_name, action, status, details, now),
                )
        except sqlite3.Error as exc:
            raise DatabaseError(f"Audit insert failed: {exc}") from exc

    def list_audit(self, limit=200):
        rows = self._query(
            "SELECT id, user, server_name, action, status, details, created_at "
            "FROM audit_logs ORDER BY id DESC LIMIT ?",
            (int(limit),),
        )
        return [dict(row) for row in rows]

    # ------------------------------------------------------------------
    # settings (non-secret preferences only)
    # ------------------------------------------------------------------
    def get_setting(self, key, default=None):
        rows = self._query("SELECT value FROM settings WHERE key = ?", (key,))
        return rows[0]["value"] if rows else default

    def set_setting(self, key, value):
        if self.conn is None:
            raise DatabaseError("Database not initialized")
        try:
            with self.conn:
                self.conn.execute(
                    "INSERT INTO settings (key, value, updated_at) VALUES (?, ?, ?) "
                    "ON CONFLICT(key) DO UPDATE SET value = excluded.value, "
                    "updated_at = excluded.updated_at",
                    (key, str(value), _now()),
                )
        except sqlite3.Error as exc:
            raise DatabaseError(f"Setting save failed: {exc}") from exc

    # ------------------------------------------------------------------
    # metric history
    # ------------------------------------------------------------------
    METRIC_COLUMNS = (
        "cpu", "mem_percent", "mem_used", "mem_total", "disk_percent",
        "disk_used", "disk_total", "load1", "load5", "load15",
    )

    def add_metric_sample(self, server, ts, values):
        cols = ", ".join(self.METRIC_COLUMNS)
        marks = ", ".join("?" for _ in self.METRIC_COLUMNS)
        self._write(
            f"INSERT OR REPLACE INTO metric_samples (server, ts, {cols}) VALUES (?, ?, {marks})",
            (server, int(ts), *[values.get(c) for c in self.METRIC_COLUMNS]),
        )

    def metric_history(self, server, since_ts):
        rows = self._query(
            f"SELECT ts, {', '.join(self.METRIC_COLUMNS)} FROM metric_samples "
            "WHERE server = ? AND ts >= ? ORDER BY ts",
            (server, int(since_ts)),
        )
        return [dict(r) for r in rows]

    def prune_metric_samples(self, before_ts):
        return self._write("DELETE FROM metric_samples WHERE ts < ?", (int(before_ts),))

    # ------------------------------------------------------------------
    # incidents
    # ------------------------------------------------------------------
    INCIDENT_FIELDS = (
        "id", "server", "fingerprint", "category", "severity", "status", "title",
        "root_cause", "confidence", "confidence_reason", "impact", "affected", "checks",
        "first_seen", "last_seen", "event_count", "recurring", "previous_id",
        "condition_cleared_at", "created_at", "updated_at",
    )

    # free text that may quote log lines; affected/checks are JSON built by
    # the playbooks (not raw logs) and redacting them could break the JSON
    INCIDENT_TEXT_FIELDS = ("title", "root_cause", "confidence_reason", "impact")

    def _redact_incident(self, fields):
        return {
            k: redact(v) if k in self.INCIDENT_TEXT_FIELDS and isinstance(v, str) else v
            for k, v in fields.items()
        }

    def insert_incident(self, record):
        record = self._redact_incident(record)
        cols = ", ".join(self.INCIDENT_FIELDS)
        marks = ", ".join("?" for _ in self.INCIDENT_FIELDS)
        self._write(
            f"INSERT INTO incidents ({cols}) VALUES ({marks})",
            tuple(record.get(f) for f in self.INCIDENT_FIELDS),
        )

    def update_incident(self, incident_id, fields):
        fields = self._redact_incident(fields)
        allowed = [f for f in fields if f in self.INCIDENT_FIELDS and f != "id"]
        if not allowed:
            return 0
        assignments = ", ".join(f"{f} = ?" for f in allowed)
        return self._write(
            f"UPDATE incidents SET {assignments} WHERE id = ?",
            (*[fields[f] for f in allowed], incident_id),
        )

    def get_incident(self, incident_id):
        rows = self._query("SELECT * FROM incidents WHERE id = ?", (incident_id,))
        return dict(rows[0]) if rows else None

    def find_incident(self, fingerprint, active=True):
        """Latest incident with this fingerprint (active = not resolved)."""
        status_clause = "status != 'resolved'" if active else "status = 'resolved'"
        rows = self._query(
            f"SELECT * FROM incidents WHERE fingerprint = ? AND {status_clause} "
            "ORDER BY updated_at DESC, created_at DESC LIMIT 1",
            (fingerprint,),
        )
        return dict(rows[0]) if rows else None

    def list_incidents(self, server=None, status=None, severity=None, limit=200):
        clauses, params = [], []
        if server:
            clauses.append("server = ?")
            params.append(server)
        if status == "active":
            clauses.append("status != 'resolved'")
        elif status:
            clauses.append("status = ?")
            params.append(status)
        if severity:
            clauses.append("severity = ?")
            params.append(severity)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        rows = self._query(
            f"SELECT * FROM incidents {where} ORDER BY last_seen DESC LIMIT ?",
            (*params, int(limit)),
        )
        return [dict(r) for r in rows]

    def add_evidence(self, incident_id, rows, keep=30):
        """Insert evidence lines (duplicates ignored); keep only the newest *keep*. Returns new rows."""
        added = 0
        try:
            with self.conn:
                for r in rows:
                    cur = self.conn.execute(
                        "INSERT OR IGNORE INTO incident_evidence "
                        "(incident_id, ts, source, unit, role, message) VALUES (?, ?, ?, ?, ?, ?)",
                        (incident_id, r["ts"], r.get("source"), r.get("unit"), r.get("role"), redact(r["message"] or "")),
                    )
                    added += cur.rowcount
                self.conn.execute(
                    "DELETE FROM incident_evidence WHERE incident_id = ? AND id NOT IN ("
                    "SELECT id FROM incident_evidence WHERE incident_id = ? ORDER BY ts DESC, id DESC LIMIT ?)",
                    (incident_id, incident_id, int(keep)),
                )
        except sqlite3.Error as exc:
            raise DatabaseError(f"Evidence insert failed: {exc}") from exc
        return added

    def incident_evidence(self, incident_id):
        rows = self._query(
            "SELECT ts, source, unit, role, message FROM incident_evidence "
            "WHERE incident_id = ? ORDER BY ts, id",
            (incident_id,),
        )
        return [dict(r) for r in rows]

    def incident_count(self):
        # numeric max: as text "INC-9999" > "INC-10000"
        rows = self._query(
            "SELECT COUNT(*) AS n, MAX(CAST(SUBSTR(id, 5) AS INTEGER)) AS last FROM incidents"
        )
        return dict(rows[0]) if rows else {"n": 0, "last": None}

    def prune_resolved_incidents(self, before_iso):
        return self._write(
            "DELETE FROM incidents WHERE status = 'resolved' AND last_seen < ?", (before_iso,)
        )

    # ------------------------------------------------------------------
    # helpers
    # ------------------------------------------------------------------
    def _write(self, sql, params=()):
        if self.conn is None:
            raise DatabaseError("Database not initialized")
        try:
            with self.conn:
                return self.conn.execute(sql, params).rowcount
        except sqlite3.Error as exc:
            raise DatabaseError(f"Write failed: {exc}") from exc

    def _query(self, sql, params=()):
        if self.conn is None:
            raise DatabaseError("Database not initialized")
        try:
            return self.conn.execute(sql, params).fetchall()
        except sqlite3.Error as exc:
            raise DatabaseError(f"Query failed: {exc}") from exc


def _now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
