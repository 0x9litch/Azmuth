"""
Diagnostics: rule-based problem analysis and incident tracking.

    models.py      Severity, Signal, Finding, Report
    rules/         detection rules (one module per problem type) + THRESHOLDS
    correlator.py  joins signals into findings with a root cause + confidence
    playbooks.py   impact text and read-only checks per problem type
    engine.py      DiagnosticsEngine.analyze / quick_alerts (pure)
    incidents.py   IncidentStore (SQLite lifecycle, export)
    redaction.py   secret removal before anything leaves Azmuth
    service.py     DiagnosticsService (collector -> engine -> store)
"""

from .engine import DiagnosticsEngine
from .incidents import IncidentStore
from .models import Finding, Report, Severity, Signal
from .rules import THRESHOLDS

__all__ = ["DiagnosticsEngine", "Finding", "IncidentStore", "Report", "Severity", "Signal", "THRESHOLDS"]
