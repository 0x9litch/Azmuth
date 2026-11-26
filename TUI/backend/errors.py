"""Backend exception types shared by every manager and by the UI."""


class BackendError(Exception):
    """General backend error."""


class SudoPasswordRequired(BackendError):
    """Raised when an operation requires interactive sudo authentication."""

    def __init__(self, message, operation=None, server_name=None, path=None):
        super().__init__(message)
        self.operation = operation
        self.server_name = server_name
        self.path = path


class SudoAuthenticationFailed(BackendError):
    """
    Raised when a supplied sudo password was rejected.

    Subclass of BackendError so existing ``except BackendError`` handlers
    keep working; the UI catches it specifically to re-prompt.
    """

    def __init__(self, message, operation=None, server_name=None, path=None):
        super().__init__(message)
        self.operation = operation
        self.server_name = server_name
        self.path = path


class CommandFailed(BackendError):
    """
    A privileged command ran but exited non-zero (not an auth problem).

    Carries the exit code so callers can react to specific codes instead
    of parsing the message text.
    """

    def __init__(self, message, exit_code=None, stderr=""):
        super().__init__(message)
        self.exit_code = exit_code
        self.stderr = stderr
