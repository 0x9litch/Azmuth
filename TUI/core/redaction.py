"""
Remove secrets from text before it leaves Azmuth (API export → n8n → AI).

Applied to: incident export, audit details in the API. Never trust the
web side to do this — it happens here, once, in Python.
"""

import ipaddress
import re

MASK = "[REDACTED]"

_SECRET_WORDS = r"(?:password|passwd|pwd|pass|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|credentials?)"
_VALUE = r"(\"[^\"]*\"|'[^']*'|\S+)"

_PATTERNS = [
    # private keys (whole block)
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.S), MASK),
    # Authorization: Bearer xxx / Basic xxx
    (re.compile(r"(?i)\b(authorization\s*[:=]\s*)(?:bearer|basic|token)?\s*\S+"), r"\1" + MASK),
    # --password VALUE / --password=VALUE / --token VALUE (flag before key=value)
    (re.compile(r"(?i)(--(?:password|passwd|pass|token|secret|api-key|access-key)(?:=|\s+))" + _VALUE), r"\1" + MASK),
    # KEY=VALUE / key: value, including prefixed names (PGPASSWORD, DB_PASSWORD, MYSQL_PWD, API_TOKEN)
    (re.compile(r"(?i)\b(\w*" + _SECRET_WORDS + r"\w*\s*[=:]\s*)" + _VALUE), r"\1" + MASK),
    # mysql -pSECRET (value glued to -p; "-p" alone prompts and is harmless)
    (re.compile(r"(\b(?:mysql|mysqldump|mysqladmin|mariadb)\b[^\n]*?\s-p)([^\s-]\S*)"), r"\1" + MASK),
    # sshpass -p SECRET, redis-cli -a SECRET
    (re.compile(r"(\bsshpass\s+-p\s*)(\S+)"), r"\1" + MASK),
    # echo SECRET | sudo -S …  /  printf 'SECRET\n' | sudo -S …  (password piped to sudo)
    (re.compile(r"(?i)\b((?:echo|printf)\s+(?:-[ne]+\s+)?)(\"[^\"]*\"|'[^']*'|\S+)(\s*\|\s*sudo\b)"), r"\1" + MASK + r"\3"),
    (re.compile(r"(\bredis-cli\b[^\n]*?\s-a\s+)(\S+)"), r"\1" + MASK),
    # curl -u user:SECRET / --user user:SECRET
    (re.compile(r"((?:\s-u|--user)\s+[^\s:]+:)(\S+)"), r"\1" + MASK),
    # credentials inside URLs: scheme://user:pass@host
    (re.compile(r"(\b[a-z][a-z0-9+.-]*://[^\s:/@]+:)([^\s@/]+)(@)", re.I), r"\1" + MASK + r"\3"),
    # AWS access key ids
    (re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), MASK),
    # JWTs
    (re.compile(r"\beyJ[\w-]{8,}\.[\w-]{8,}\.[\w-]{8,}\b"), MASK),
    # GitHub / Slack style tokens
    (re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{20,}|xox[abpr]-[A-Za-z0-9-]{10,})\b"), MASK),
]

_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def redact(text):
    if not text:
        return text
    for pattern, repl in _PATTERNS:
        text = pattern.sub(repl, text)
    return text


class IpMasker:
    """Optional: replace private IPs with stable placeholders (host-1, host-2…)."""

    def __init__(self):
        self.mapping = {}

    def __call__(self, text):
        def sub(m):
            try:
                ip = ipaddress.ip_address(m.group(0))
            except ValueError:
                return m.group(0)
            if not ip.is_private:
                return m.group(0)
            return self.mapping.setdefault(m.group(0), f"host-{len(self.mapping) + 1}")
        return _IPV4.sub(sub, text) if text else text


def redact_obj(obj, mask_ips=None):
    """Redact every string inside dicts/lists (returns a new object)."""
    if isinstance(obj, str):
        out = redact(obj)
        return mask_ips(out) if mask_ips else out
    if isinstance(obj, dict):
        return {k: redact_obj(v, mask_ips) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [redact_obj(v, mask_ips) for v in obj]
    return obj
