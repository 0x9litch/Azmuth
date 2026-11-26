"""
Incident store: Findings become tracked Incidents in SQLite.

Lifecycle
    new finding                  -> incident OPEN
    same problem seen again      -> same incident: last_seen, count, evidence updated
    problem not detected anymore -> condition_cleared_at set ("cleared", still open)
    cleared for AUTO_RESOLVE     -> RESOLVED automatically
    admin: v / z / o             -> INVESTIGATING / RESOLVED / reopened
    resolved problem comes back  -> NEW incident, recurring = n, previous_id = old one

Identity (fingerprint) = sha1(server | category | finding.key)[:16], so the
same problem keeps the same incident across analyses and restarts.
"""

import hashlib
import json
import time
from datetime import datetime, timezone

from .models import Severity, iso_utc
from .redaction import IpMasker, redact, redact_obj

STATUSES = ("open", "investigating", "resolved")
AUTO_RESOLVE_SECONDS = 24 * 3600
EVIDENCE_KEEP = 30


def _now_iso():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse_iso(value):
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc).timestamp()
    except (TypeError, ValueError):
        return None


def fingerprint(server, category, key):
    return hashlib.sha1(f"{server}|{category}|{key}".encode()).hexdigest()[:16]


def _decode(row):
    if row is None:
        return None
    row = dict(row)
    for field in ("affected", "checks"):
        try:
            row[field] = json.loads(row[field] or "[]")
        except (TypeError, ValueError):
            row[field] = []
    row["severity_label"] = Severity.from_key(row["severity"]).label if row.get("severity") else "?"
    row["cleared"] = row.get("condition_cleared_at") is not None and row.get("status") != "resolved"
    return row


class IncidentStore:
    def __init__(self, db):
        self.db = db

    # ------------------------------------------------------------------
    # sync with an analysis
    # ------------------------------------------------------------------
    def sync(self, server, findings, now=None):
        """Upsert every finding, mark vanished problems cleared. Returns new incidents."""
        now = now or time.time()
        new, seen = [], set()
        for f in findings:
            incident, created = self._upsert(server, f)
            if incident is None:
                continue  # resolved, and nothing new happened since
            seen.add(incident["fingerprint"])
            if created:
                new.append(incident)

        for inc in self.db.list_incidents(server=server, status="active", limit=1000):
            if inc["fingerprint"] in seen:
                continue
            cleared = _parse_iso(inc["condition_cleared_at"])
            if cleared is None:
                self.db.update_incident(inc["id"], {"condition_cleared_at": _now_iso(), "updated_at": _now_iso()})
            elif now - cleared >= AUTO_RESOLVE_SECONDS and inc["status"] == "open":
                self.db.update_incident(inc["id"], {"status": "resolved", "updated_at": _now_iso()})
        return new

    def _upsert(self, server, f):
        # Secrets never reach the disk: evidence lines and texts quoting log
        # messages are redacted BEFORE they are stored (not only on export).
        f.title, f.root_cause = redact(f.title), redact(f.root_cause)
        f.evidence = redact_obj(f.evidence)
        f.affected = redact_obj(f.affected)
        fp = fingerprint(server, f.category, f.key)
        stamp = _now_iso()
        first = iso_utc(f.first_ts) if f.first_ts else stamp
        last = iso_utc(f.last_ts) if f.last_ts else stamp
        active = self.db.find_incident(fp, active=True)

        if active:
            added = self.db.add_evidence(active["id"], f.evidence, keep=EVIDENCE_KEEP)
            fields = {
                "last_seen": max(active["last_seen"] or last, last),
                "severity": max(Severity.from_key(active["severity"]), f.severity).key,
                # never below what the current analysis window counts
                "event_count": max((active["event_count"] or 1) + added, f.count),
                "condition_cleared_at": None,
                "updated_at": stamp,
            }
            # a better explanation replaces a weaker one
            rank = {"low": 0, "medium": 1, "high": 2}
            if rank.get(f.confidence, 0) >= rank.get(active["confidence"], 0):
                fields.update(
                    title=f.title, root_cause=f.root_cause, confidence=f.confidence,
                    confidence_reason=f.confidence_reason, impact=f.impact,
                    affected=json.dumps(f.affected), checks=json.dumps(f.checks),
                )
            self.db.update_incident(active["id"], fields)
            return self.get(active["id"]), False

        previous = self.db.find_incident(fp, active=False)
        if previous and not self._came_back(f, previous):
            # Resolved by the admin, and the only evidence is the same old log
            # lines still inside the 2 h analysis window: not a recurrence.
            return None, False
        record = {
            "id": self._next_id(),
            "server": server, "fingerprint": fp, "category": f.category,
            "severity": f.severity.key, "status": "open", "title": f.title,
            "root_cause": f.root_cause, "confidence": f.confidence,
            "confidence_reason": f.confidence_reason, "impact": f.impact,
            "affected": json.dumps(f.affected), "checks": json.dumps(f.checks),
            "first_seen": first, "last_seen": last, "event_count": max(1, f.count),
            "recurring": (previous["recurring"] or 0) + 1 if previous else 0,
            "previous_id": previous["id"] if previous else None,
            "condition_cleared_at": None, "created_at": stamp, "updated_at": stamp,
        }
        self.db.insert_incident(record)
        self.db.add_evidence(record["id"], f.evidence, keep=EVIDENCE_KEEP)
        return self.get(record["id"]), True

    @staticmethod
    def _came_back(finding, previous):
        """Is a resolved problem really back?"""
        if finding.ongoing or finding.last_ts is None:
            return True  # a current state (unit failed now, disk full now…)
        resolved_at = _parse_iso(previous.get("updated_at"))
        return resolved_at is None or finding.last_ts > resolved_at

    def _next_id(self):
        last = self.db.incident_count().get("last")
        try:
            n = int(last) + 1
        except (ValueError, TypeError):
            n = 1
        return f"INC-{n:04d}"

    # ------------------------------------------------------------------
    # queries / admin actions
    # ------------------------------------------------------------------
    def get(self, incident_id):
        return _decode(self.db.get_incident(incident_id))

    def list(self, server=None, status="active", severity=None, limit=200):
        return [_decode(r) for r in self.db.list_incidents(server, status, severity, limit)]

    def evidence(self, incident_id):
        return self.db.incident_evidence(incident_id)

    def set_status(self, incident_id, status):
        if status not in STATUSES:
            raise ValueError(f"unknown status {status!r}")
        fields = {"status": status, "updated_at": _now_iso()}
        if status != "resolved":
            fields["condition_cleared_at"] = None
        return self.db.update_incident(incident_id, fields)

    def prune(self, days):
        cutoff = iso_utc(time.time() - days * 86400)
        return self.db.prune_resolved_incidents(cutoff)

    # ------------------------------------------------------------------
    # export (always redacted — this is what goes to n8n / AI)
    # ------------------------------------------------------------------
    def export(self, incident_id, mask_ips=False):
        inc = self.get(incident_id)
        if inc is None:
            return None
        data = {
            k: inc[k] for k in (
                "id", "server", "category", "severity", "status", "title", "root_cause",
                "confidence", "confidence_reason", "impact", "affected", "checks",
                "first_seen", "last_seen", "event_count", "recurring", "previous_id",
            )
        }
        data["cleared"] = inc["cleared"]
        data["evidence"] = self.evidence(incident_id)
        return redact_obj(data, IpMasker() if mask_ips else None)

    def export_markdown(self, incident_id, mask_ips=False):
        d = self.export(incident_id, mask_ips)
        if d is None:
            return None
        lines = [
            f"# {d['id']} — {d['title']}", "",
            f"- Server: {d['server']}",
            f"- Severity: {d['severity']}   Status: {d['status']}{' (condition cleared)' if d['cleared'] else ''}",
            f"- Category: {d['category']}",
            f"- First seen: {d['first_seen']}   Last seen: {d['last_seen']}   Events: {d['event_count']}",
        ]
        if d["recurring"]:
            lines.append(f"- Recurring: {d['recurring']} time(s) before (previous: {d['previous_id']})")
        lines += ["", "## Root cause", d["root_cause"],
                  f"Confidence: {d['confidence']} — {d['confidence_reason']}", "",
                  "## Impact", d["impact"] or "-"]
        if d["affected"]:
            lines += ["", "## Affected", *[f"- {a}" for a in d["affected"]]]
        if d["checks"]:
            lines += ["", "## Checks"]
            for c in d["checks"]:
                lines += [f"- {c['title']}", f"  `{c['command']}`"]
        if d["evidence"]:
            lines += ["", "## Evidence", "```"]
            lines += [f"{e['ts']} [{e['role']}] {e['source'] or e['unit']}: {e['message']}" for e in d["evidence"]]
            lines.append("```")
        lines += ["", "_Generated by Azmuth (rule-based). Secrets redacted._", ""]
        return "\n".join(lines)
