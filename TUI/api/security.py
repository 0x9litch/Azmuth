"""
Security middlewares (order matters, outermost first):

1. headers     – every response: nosniff, no-store, no framing, no referrer,
                 restrictive CSP. No CORS headers at all: browsers cannot call
                 the API directly, only the ASP.NET server can.
2. host_check  – Host header must be localhost/127.0.0.1/[::1] (+ port):
                 blocks DNS-rebinding attacks from web pages.
3. method      – GET / HEAD only. The API cannot change anything.
4. rate_limit  – per client address, sliding 60 s window.
5. auth        – Authorization: Bearer <token>, compared in constant time.
                 Only /api/v1/health is public (it reveals nothing).
"""

import hmac
import time
from collections import defaultdict, deque

from aiohttp import web

PUBLIC_PATHS = {"/api/v1/health"}
ALLOWED_HOSTS = {"127.0.0.1", "localhost", "[::1]"}
# Everything comes from 127.0.0.1, so the limit is shared by ASP.NET and
# n8n together: it only stops runaway loops, normal polling stays far below.
RATE_LIMIT_PER_MINUTE = 600
FAILED_AUTH_LIMIT = 10      # bad tokens per minute; more are refused without auditing

SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "Cache-Control": "no-store",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'",
    "Cross-Origin-Resource-Policy": "same-origin",
}


def error(status, code, message):
    return web.json_response({"error": {"code": code, "message": message}}, status=status)


def make_middlewares(get_token, audit=None):
    hits = defaultdict(deque)
    failures = defaultdict(deque)

    def _window(q, now, limit):
        while q and q[0] <= now - 60:
            q.popleft()
        return len(q) >= limit

    @web.middleware
    async def headers(request, handler):
        try:
            response = await handler(request)
        except web.HTTPException as exc:
            code = {400: "bad_request", 404: "not_found", 405: "method_not_allowed"}.get(exc.status, "http_error")
            response = error(exc.status, code, exc.reason)
        except Exception:
            # never leak tracebacks or internal paths to the client
            response = error(500, "internal_error", "Internal error")
        response.headers.update(SECURITY_HEADERS)
        return response

    @web.middleware
    async def host_check(request, handler):
        host = (request.host or "").lower()
        bare = host.rsplit(":", 1)[0] if not host.startswith("[") else host.split("]")[0] + "]"
        if bare not in ALLOWED_HOSTS:
            return error(421, "bad_host", "Host header not allowed")
        return await handler(request)

    @web.middleware
    async def method(request, handler):
        if request.method not in ("GET", "HEAD"):
            return error(405, "method_not_allowed", "The API is read-only (GET only)")
        return await handler(request)

    @web.middleware
    async def rate_limit(request, handler):
        now = time.monotonic()
        peer = request.remote or "?"
        if _window(hits[peer], now, RATE_LIMIT_PER_MINUTE):
            return error(429, "rate_limited", "Too many requests, slow down")
        hits[peer].append(now)
        return await handler(request)

    @web.middleware
    async def auth(request, handler):
        if request.path in PUBLIC_PATHS:
            return await handler(request)
        header = request.headers.get("Authorization", "")
        scheme, _, given = header.partition(" ")
        expected = get_token()
        if scheme.lower() != "bearer" or not expected or not hmac.compare_digest(given.strip().encode(), expected.encode()):
            # Bad tokens are throttled separately: a local process spamming
            # wrong tokens must not lock out the real dashboard (same IP)
            # nor flood the audit log.
            peer, now = request.remote or "?", time.monotonic()
            if _window(failures[peer], now, FAILED_AUTH_LIMIT):
                return error(429, "rate_limited", "Too many failed logins, wait a minute")
            failures[peer].append(now)
            if audit:
                audit("api_auth_failed", "-", "failed", f"{request.method} {request.path[:100]} from {peer}")
            return error(401, "unauthorized", "Missing or invalid bearer token")
        return await handler(request)

    return [headers, host_check, method, rate_limit, auth]
