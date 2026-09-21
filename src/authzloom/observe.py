"""Opt-in structured logs. Never emit headers, bodies, URLs with query, captures, or tokens."""
from __future__ import annotations

import json
import os
import sys
from typing import Any

_ALLOWED = {
    "event", "run_id", "case", "request_id", "kind", "status", "duration_ms",
    "limiter_wait_ms", "bytes", "truncated", "transport", "queue_delay_ms",
    "state", "cleanup", "error", "count",
}


def enabled() -> bool:
    return os.environ.get("AUTHZLOOM_LOG", "").strip() not in {"", "0", "false", "no"}


def log(event: str, **fields: Any) -> None:
    if not enabled():
        return
    record = {"event": event}
    for key, value in fields.items():
        if key in _ALLOWED and value is not None:
            record[key] = value
    print(json.dumps(record, separators=(",", ":")), file=sys.stderr, flush=True)
