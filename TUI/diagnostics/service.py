"""
DiagnosticsService: glue between the collector, the engine and the store.

The collector calls analyze_and_store(name) every 60 s per server.
Listeners (the app) are told about NEW incidents so they can show a toast.
"""

from .engine import DiagnosticsEngine
from .incidents import IncidentStore


class DiagnosticsService:
    def __init__(self, backend):
        self.backend = backend
        self.engine = DiagnosticsEngine()
        self.store = IncidentStore(backend.ctx.db)
        self.reports = {}          # server -> last Report
        self._listeners = []

    def subscribe(self, callback):
        """callback(list_of_new_incidents) — called from the event loop."""
        self._listeners.append(callback)

    async def analyze_and_store(self, name):
        collector = self.backend.collector
        data = collector.server(name)
        report = self.engine.analyze(name, data, ping=collector.ping_results.get(name))
        self.reports[name] = report
        new = self.store.sync(name, report.findings)
        if new:
            self.backend.record_audit("incident_new", name, "INFO", ", ".join(i["id"] for i in new))
            for cb in list(self._listeners):
                try:
                    cb(new)
                except Exception:
                    pass
        return report

    async def analyze_now(self, name):
        """Fresh logs + state first, then analyse (key `d` in the Incidents tab)."""
        collector = self.backend.collector
        for kind in ("logs", "services", "metrics"):
            try:
                await collector.refresh_now(name, kind)
            except Exception:
                pass
        return await self.analyze_and_store(name)
