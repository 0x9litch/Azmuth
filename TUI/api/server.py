"""
ApiServer: aiohttp running inside the TUI's own event loop.

- Binds to 127.0.0.1 only (never 0.0.0.0): reachable from this machine
  only. The ASP.NET server runs on the same machine and calls it.
- Off until the admin starts it (key A); never auto-started on launch.
- Access logging is disabled: aiohttp would print to the terminal and
  corrupt the TUI (requests are rate-limited and failed auth is audited).
"""

from aiohttp import web

from . import token as token_file
from .routes import Routes
from .security import make_middlewares

HOST = "127.0.0.1"
DEFAULT_PORT = 8765


async def _hide_versions(request, response):
    # aiohttp would send "Server: Python/3.x aiohttp/3.x": don't advertise versions.
    response.headers["Server"] = "azmuth"


class ApiServer:
    def __init__(self, backend, port=DEFAULT_PORT, token_path=None):
        self.backend = backend
        self.port = int(port)
        self.token_path = token_path or token_file.TOKEN_FILE
        self._token = None
        self._runner = None

    @property
    def running(self):
        return self._runner is not None

    @property
    def url(self):
        return f"http://{HOST}:{self.port}/api/v1"

    def _audit(self, action, server, status, details):
        try:
            self.backend.record_audit(action, server, status, details)
        except Exception:
            pass

    def build_app(self):
        app = web.Application(middlewares=make_middlewares(lambda: self._token, self._audit))
        Routes(self.backend).register(app)
        app.on_response_prepare.append(_hide_versions)
        return app

    async def start(self):
        if self.running:
            return
        self._token = token_file.load_or_create(self.token_path)
        runner = web.AppRunner(self.build_app(), access_log=None, handle_signals=False)
        await runner.setup()
        try:
            await web.TCPSite(runner, HOST, self.port, reuse_address=True).start()
        except OSError as exc:
            await runner.cleanup()
            raise RuntimeError(f"cannot listen on {HOST}:{self.port}: {exc.strerror or exc}") from exc
        self._runner = runner
        self._audit("api_start", "-", "success", f"{HOST}:{self.port}")

    async def stop(self):
        if not self.running:
            return
        runner, self._runner = self._runner, None
        await runner.cleanup()
        self._token = None
        self._audit("api_stop", "-", "success", f"{HOST}:{self.port}")

    def rotate_token(self):
        """New token; clients using the old one get 401 immediately."""
        self._token = token_file.rotate(self.token_path)
        self._audit("api_token_rotate", "-", "success", str(self.token_path))
        return self.token_path
