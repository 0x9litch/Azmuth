"""Kept for imports inside diagnostics; the implementation lives in core.redaction
(the database layer uses it too, and core must not depend on diagnostics)."""

from ..core.redaction import MASK, IpMasker, redact, redact_obj

__all__ = ["MASK", "IpMasker", "redact", "redact_obj"]
