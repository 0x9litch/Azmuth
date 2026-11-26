"""
Read-only HTTP API for the web dashboard (ASP.NET + n8n).

    token.py      bearer token file (~/.config/azmuth/api-token, 0600)
    security.py   middlewares: Host check, auth, method, rate limit, headers
    routes.py     GET endpoints (data comes from the collector + incident store)
    server.py     ApiServer: start/stop inside the TUI's event loop

Off by default; the admin turns it on with key A in the TUI.
Contract for the web team: docs/API.md
"""

from .server import DEFAULT_PORT, ApiServer

__all__ = ["ApiServer", "DEFAULT_PORT"]
