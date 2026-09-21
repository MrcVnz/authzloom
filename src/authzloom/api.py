from __future__ import annotations

import json
import os
import signal
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

from . import __version__
from .captures import CaptureRegistry
from .errors import AuthzLoomError, LimitExceeded, RunInProgress, RunNotFound, public_error
from .executor import run
from .limits import Limits
from .models import Scenario
from .planner import plan
from .redact import redact
from .store import Store


class AuthzLoomService:
    def __init__(self, root: Path, token: str, limits: Limits | None = None):
        self.limits = limits or Limits.from_env()
        self.store, self.token = Store(root, self.limits), token
        self.captures = CaptureRegistry(self.limits)
        self._run_lock = threading.Lock()
        self._running = False
        self._cancel = threading.Event()
        self.ingested: list[dict[str, Any]] = []

    def close(self) -> None:
        self.store.close()

    def handler(self):
        service = self

        class Handler(BaseHTTPRequestHandler):
            def _json(self, status: int, value: Any):
                data = json.dumps(value).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def _authorized(self) -> bool:
                return bool(service.token) and self.headers.get("Authorization") == f"Bearer {service.token}"

            def _body(self):
                length = int(self.headers.get("Content-Length", 0) or 0)
                if length > service.limits.max_api_body_bytes:
                    raise LimitExceeded("input or output exceeds configured limits")
                if length < 0:
                    raise LimitExceeded("input or output exceeds configured limits")
                raw = self.rfile.read(length) if length else b"{}"
                if len(raw) > service.limits.max_api_body_bytes:
                    raise LimitExceeded("input or output exceeds configured limits")
                return json.loads(raw or b"{}")

            def _discard_body(self):
                length = int(self.headers.get("Content-Length", 0) or 0)
                if length <= 0:
                    return
                remaining = min(length, service.limits.max_api_body_bytes)
                while remaining > 0:
                    chunk = self.rfile.read(min(65_536, remaining))
                    if not chunk:
                        break
                    remaining -= len(chunk)

            def do_GET(self):
                parsed = urlparse(self.path)
                if parsed.path == "/health":
                    return self._json(200, {"ok": True, "service": "authzloom"})
                if parsed.path == "/version":
                    return self._json(200, {"name": "authzloom", "version": __version__})
                if parsed.path == "/ready":
                    try:
                        service.store.list(limit=1)
                    except Exception:
                        return self._json(503, {"ok": False, "service": "authzloom"})
                    return self._json(200, {"ok": True, "service": "authzloom"})
                if not self._authorized():
                    return self._json(401, {"error": "unauthorized"})
                if parsed.path == "/status":
                    query = parse_qs(parsed.query)
                    limit = int((query.get("limit") or ["50"])[0])
                    offset = int((query.get("offset") or ["0"])[0])
                    return self._json(200, service.store.list(limit=limit, offset=offset))
                if parsed.path.startswith("/export/"):
                    try:
                        return self._json(200, redact(service.store.get(parsed.path.rsplit("/", 1)[-1])))
                    except RunNotFound:
                        return self._json(404, {"error": "unknown run"})
                    except AuthzLoomError as exc:
                        return self._json(exc.http_status, exc.to_dict())
                self._json(404, {"error": "not found"})

            def do_POST(self):
                if not self._authorized():
                    return self._json(401, {"error": "unauthorized"})
                parsed = urlparse(self.path)
                try:
                    if parsed.path == "/cancel":
                        self._discard_body()
                        service._cancel.set()
                        return self._json(202, {"ok": True, "state": "cancelled"})
                    body = self._body()
                    if parsed.path == "/ingest":
                        if any(key in body for key in ("request_b64", "response_b64", "raw", "raw_capture")):
                            raise LimitExceeded("captures must remain in the Burp bridge; send a handle")
                        meta = None
                        if body.get("handle") and body.get("host"):
                            meta = service.captures.ingest_document(body)
                        clean = redact(body)
                        service.ingested.append(clean)
                        if len(service.ingested) > service.limits.max_ingested_captures:
                            service.ingested.pop(0)
                        payload = {"ingest_id": len(service.ingested) - 1, "capture": clean}
                        if meta:
                            payload.update(meta)
                        return self._json(202, payload)
                    if parsed.path == "/plan":
                        scenario = Scenario.from_dict(body)
                        return self._json(200, {"cases": [vars_case(x) for x in plan(scenario)]})
                    if parsed.path == "/run":
                        scenario = Scenario.from_dict(body)
                        if not service._run_lock.acquire(blocking=False):
                            raise RunInProgress("another run is already active")
                        service._running = True
                        service._cancel.clear()
                        try:
                            result = run(
                                scenario,
                                burp_token=os.environ.get("AUTHZLOOM_TOKEN", service.token),
                                cancel=service._cancel,
                            )
                            run_id = service.store.save(result)
                            return self._json(200, {"run_id": run_id, "result": redact(result)})
                        finally:
                            service._running = False
                            service._run_lock.release()
                    return self._json(404, {"error": "not found"})
                except AuthzLoomError as exc:
                    return self._json(exc.http_status, exc.to_dict())
                except Exception:
                    return self._json(400, public_error(Exception()))

            def log_message(self, *_):
                pass

        return Handler


def vars_case(case):
    return {"name": case.name, "session": case.session, "object_owner": case.object_owner}


def serve(host: str, port: int, root: Path, token: str) -> None:
    if host not in {"127.0.0.1", "::1", "localhost"}:
        raise ValueError("AuthzLoom API must bind to loopback")
    service = AuthzLoomService(root, token)
    server = ThreadingHTTPServer((host, port), service.handler())
    print(f"AuthzLoom listening on http://{host}:{port}")

    def _stop(*_):
        threading.Thread(target=server.shutdown, daemon=True).start()

    try:
        signal.signal(signal.SIGINT, _stop)
        signal.signal(signal.SIGTERM, _stop)
    except (ValueError, OSError):
        pass
    try:
        server.serve_forever()
    finally:
        server.server_close()
        service.close()
