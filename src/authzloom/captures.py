from __future__ import annotations

import hashlib
import json
import threading
import time
from dataclasses import dataclass, field
from typing import Any

from .errors import CaptureError, LimitExceeded
from .limits import Limits


HANDLE_PREFIX = "cap_"


def new_handle() -> str:
    import secrets
    return HANDLE_PREFIX + secrets.token_hex(12)


@dataclass(slots=True)
class CaptureMeta:
    handle: str
    host: str
    method: str
    path: str
    session_owner: str | None
    expires_at: float
    created_at: float
    byte_length: int | None = None


class CaptureRegistry:
    """Python-side metadata only. Live request bytes stay in the Burp bridge."""

    def __init__(self, limits: Limits | None = None):
        self.limits = limits or Limits()
        self._items: dict[str, CaptureMeta] = {}
        self._lock = threading.Lock()
        self._order: list[str] = []

    def register(self, meta: CaptureMeta) -> CaptureMeta:
        now = time.time()
        with self._lock:
            self._purge_locked(now)
            if len(self._items) >= self.limits.max_ingested_captures:
                oldest = self._order.pop(0)
                self._items.pop(oldest, None)
            self._items[meta.handle] = meta
            if meta.handle in self._order:
                self._order.remove(meta.handle)
            self._order.append(meta.handle)
        return meta

    def get(self, handle: str, *, host: str | None = None, session_owner: str | None = None) -> CaptureMeta:
        now = time.time()
        with self._lock:
            self._purge_locked(now)
            meta = self._items.get(handle)
            if meta is None or meta.expires_at <= now:
                raise CaptureError("capture handle is stale, unknown, or identity-mismatched")
            if host is not None and meta.host.lower() != host.lower():
                raise CaptureError("capture handle is stale, unknown, or identity-mismatched")
            if session_owner is not None and meta.session_owner and meta.session_owner != session_owner:
                raise CaptureError("capture handle is stale, unknown, or identity-mismatched")
            return meta

    def evict(self, handle: str) -> None:
        with self._lock:
            self._items.pop(handle, None)
            if handle in self._order:
                self._order.remove(handle)

    def _purge_locked(self, now: float) -> None:
        expired = [handle for handle, meta in self._items.items() if meta.expires_at <= now]
        for handle in expired:
            self._items.pop(handle, None)
            if handle in self._order:
                self._order.remove(handle)

    def ingest_document(self, document: dict[str, Any]) -> dict[str, Any]:
        if any(key in document for key in ("request_b64", "response_b64", "raw", "raw_capture")):
            raise LimitExceeded("captures must remain in the Burp bridge; send a handle")
        handle = str(document.get("handle") or new_handle())
        host = str(document.get("host") or "")
        method = str(document.get("method") or "GET").upper()
        path = str(document.get("path") or "/")
        if not host:
            raise CaptureError("capture metadata must include host")
        now = time.time()
        meta = CaptureMeta(
            handle=handle,
            host=host.lower(),
            method=method,
            path=path,
            session_owner=str(document["session_owner"]) if document.get("session_owner") else None,
            expires_at=now + self.limits.ingest_ttl_seconds,
            created_at=now,
            byte_length=int(document["byte_length"]) if document.get("byte_length") else None,
        )
        self.register(meta)
        return {
            "handle": meta.handle,
            "host": meta.host,
            "method": meta.method,
            "path": meta.path,
            "expires_at": int(meta.expires_at),
        }
