from __future__ import annotations

import base64
import hashlib
import json
import re
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

SENSITIVE_KEY = re.compile(
    r"authorization|proxy-authorization|cookie|set-cookie|token|secret|password|csrf|api[-_]?key|"
    r"access_token|refresh_token|id_token|sessionid|jwt|private[_-]?key",
    re.I,
)
SECRET_CONTAINER = re.compile(r"^(request_b64|response_b64|raw_capture|capture|raw)$", re.I)
BEARER = re.compile(r"(?i)bearer\s+[A-Za-z0-9._~+/=-]+")
BASIC = re.compile(r"(?i)basic\s+[A-Za-z0-9+/=]+")
JWT = re.compile(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+")
COOKIE_PAIR = re.compile(r"(?i)((?:^|;)\s*[A-Za-z0-9_*-]+=)[^;]*")
QUERY_SECRET = re.compile(r"^(access_token|refresh_token|id_token|token|code|key|api_key|password|secret|auth|session)$", re.I)
SECRET_HINT = re.compile(r"(?i)(?:bearer|basic)[\s]+|eyJ[A-Za-z0-9_-]{4,}\.|://|@")
JSON_PREFIX = re.compile(rb"^\s*[\[{]")
PLACEHOLDER = "[REDACTED]"


class RedactionStats:
    __slots__ = ("count",)

    def __init__(self) -> None:
        self.count = 0

    def hit(self) -> str:
        self.count += 1
        return PLACEHOLDER


def _redact_url(value: str, stats: RedactionStats) -> str:
    try:
        parts = urlsplit(value)
    except ValueError:
        return value
    changed = False
    netloc = parts.netloc
    if "@" in netloc:
        host = netloc.rsplit("@", 1)[-1]
        netloc = f"{PLACEHOLDER}@{host}"
        stats.hit()
        changed = True
    query_pairs = []
    for key, val in parse_qsl(parts.query, keep_blank_values=True):
        if QUERY_SECRET.match(key) or SENSITIVE_KEY.search(key):
            query_pairs.append((key, stats.hit()))
            changed = True
        else:
            query_pairs.append((key, _redact_text(val, stats)))
    query = urlencode(query_pairs) if parts.query else parts.query
    if changed or query != parts.query:
        return urlunsplit((parts.scheme, netloc, parts.path, query, parts.fragment))
    return value


def _redact_text(value: str, stats: RedactionStats) -> str:
    # Skip only when the whole string lacks characters that secrets use.
    # Never skip based on a prefix: a Bearer/JWT can sit after the first bytes.
    if "b" not in value and "B" not in value and "@" not in value and ":" not in value and "e" not in value:
        return value
    if not SECRET_HINT.search(value):
        return value
    if BEARER.search(value):
        value = BEARER.sub(lambda _m: "Bearer " + stats.hit(), value)
    if BASIC.search(value):
        value = BASIC.sub(lambda _m: "Basic " + stats.hit(), value)
    if JWT.search(value):
        value = JWT.sub(lambda _m: stats.hit(), value)
    if "://" in value or "@" in value:
        value = _redact_url(value, stats)
    return value


def _looks_base64(value: str) -> bool:
    if len(value) < 16 or len(value) % 4 != 0:
        return False
    try:
        base64.b64decode(value, validate=True)
        return True
    except Exception:
        return False


def _redact_form(value: str, stats: RedactionStats) -> str:
    pairs = []
    changed = False
    for key, val in parse_qsl(value, keep_blank_values=True):
        if SENSITIVE_KEY.search(key) or QUERY_SECRET.match(key):
            pairs.append((key, stats.hit()))
            changed = True
        else:
            pairs.append((key, _redact_text(val, stats) if isinstance(val, str) else val))
            if pairs[-1][1] != val:
                changed = True
    return urlencode(pairs) if changed else value


def _redact_json_string_body(value: str, stats: RedactionStats) -> str:
    prefix = value.lstrip()[:1]
    if prefix not in "{[":
        if "=" in value and "&" in value or (value.count("=") == 1 and "&" not in value and len(value) < 4096):
            return _redact_form(value, stats)
        return _redact_text(value, stats)
    try:
        parsed = json.loads(value)
    except json.JSONDecodeError:
        return _redact_text(value, stats)
    redacted = _walk(parsed, stats)
    return json.dumps(redacted, separators=(",", ":"))


def _walk(value: Any, stats: RedactionStats, key: str = "") -> Any:
    if SECRET_CONTAINER.match(key):
        stats.hit()
        if isinstance(value, str):
            digest = hashlib.sha256(value.encode("utf-8", "replace")).hexdigest()[:12]
            return f"{PLACEHOLDER}:{len(value)}:{digest}"
        return PLACEHOLDER
    if key.lower() in {"cookie", "set-cookie"} or (isinstance(key, str) and key.lower().endswith("cookie")):
        if isinstance(value, str):
            stats.hit()
            return COOKIE_PAIR.sub(lambda m: m.group(1) + PLACEHOLDER, value)
        return stats.hit()
    if SENSITIVE_KEY.search(key):
        return stats.hit()
    if isinstance(value, dict):
        # GraphQL variables ride under common keys and must still be walked.
        return {k: _walk(v, stats, str(k)) for k, v in value.items()}
    if isinstance(value, list):
        return [_walk(item, stats) for item in value]
    if isinstance(value, str):
        if key.lower() in {"body", "request_body", "response_body", "query"}:
            return _redact_json_string_body(value, stats)
        return _redact_text(value, stats)
    return value


def redact(value: Any, key: str = "") -> Any:
    stats = RedactionStats()
    return _walk(value, stats, key)


def redact_with_stats(value: Any) -> tuple[Any, int]:
    stats = RedactionStats()
    return _walk(value, stats), stats.count


def redact_http_body(body: str, content_type: str = "") -> tuple[str, int]:
    stats = RedactionStats()
    lowered = content_type.lower()
    if "json" in lowered or "graphql" in lowered:
        try:
            parsed = json.loads(body)
            out = json.dumps(_walk(parsed, stats), separators=(",", ":"))
            return out, stats.count
        except json.JSONDecodeError:
            pass
    if "x-www-form-urlencoded" in lowered:
        return _redact_form(body, stats), stats.count
    return _redact_json_string_body(body, stats), stats.count


def looks_like_json_bytes(prefix: bytes) -> bool:
    return bool(JSON_PREFIX.match(prefix[:32]))
