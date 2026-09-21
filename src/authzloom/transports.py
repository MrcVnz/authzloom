from __future__ import annotations

import base64
import hashlib
import http.client
import json
import queue
import ssl
import threading
from dataclasses import dataclass, field
from typing import Any, Protocol
from urllib.parse import urlparse

from .errors import CaptureError, PolicyViolation, TransportFailed
from .limits import Limits
from .loopback import assert_direct_destination
from .models import RequestSpec
from .policy import OVERLAY_FORBIDDEN, validate_headers


@dataclass(slots=True)
class Response:
    status: int
    headers: dict[str, str]
    body: str
    truncated: bool = False
    original_length: int = 0
    retained_sha256: str = ""
    transport: str = ""

    def json(self) -> Any:
        return json.loads(self.body)


class Transport(Protocol):
    def send(self, request: RequestSpec, session: dict[str, Any]) -> Response: ...
    def close(self) -> None: ...
    def invalidate(self) -> None: ...


def _merge_headers(request: RequestSpec, session: dict[str, Any]) -> dict[str, str]:
    headers = dict(request.headers)
    headers.update({str(k): str(v) for k, v in session.get("headers", {}).items()})
    return {k: v for k, v in headers.items() if k.lower() not in OVERLAY_FORBIDDEN}


def _encode_body(body: Any, headers: dict[str, str]) -> bytes | None:
    if body is None:
        return None
    if isinstance(body, bytes):
        return body
    if isinstance(body, (dict, list)):
        headers.setdefault("Content-Type", "application/json")
        return json.dumps(body).encode("utf-8")
    return str(body).encode("utf-8")


def _bound_body(data: bytes, limits: Limits) -> tuple[bytes, bool, int, str]:
    original = len(data)
    truncated = original > limits.max_response_body_bytes
    retained = data[: limits.max_response_body_bytes]
    digest = hashlib.sha256(retained).hexdigest()
    return retained, truncated, original, digest


def _read_bounded(response, limits: Limits) -> tuple[bytes, bool, int, str]:
    buf = bytearray()
    extra = 0
    limit = limits.max_response_body_bytes
    while True:
        chunk = response.read(65_536)
        if not chunk:
            break
        if len(buf) < limit:
            take = min(len(chunk), limit - len(buf))
            buf.extend(chunk[:take])
            extra += len(chunk) - take
        else:
            extra += len(chunk)
    retained = bytes(buf)
    original = len(retained) + extra
    return retained, extra > 0, original, hashlib.sha256(retained).hexdigest()


def _response(status: int, headers: dict[str, str], body: bytes, limits: Limits, transport: str) -> Response:
    retained, truncated, original, digest = _bound_body(body, limits) if body is not None else (b"", False, 0, hashlib.sha256(b"").hexdigest())
    text = retained.decode("utf-8", "replace")
    return Response(status, headers, text, truncated, original, digest, transport)


def _shutdown_conn(conn) -> None:
    import socket
    try:
        if getattr(conn, "sock", None) is not None:
            try:
                conn.sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
        conn.close()
    except Exception:
        pass


class DirectTransport:
    def __init__(self, limits: Limits | None = None):
        self.limits = limits or Limits()
        self._idle: dict[tuple[str, str, int], list[http.client.HTTPConnection]] = {}
        self._all: list[http.client.HTTPConnection] = []
        self._lock = threading.Lock()
        self.active = 0
        self.max_active = 0

    def send(self, request: RequestSpec, session: dict[str, Any]) -> Response:
        scheme, host, port, path = assert_direct_destination(request.url)
        headers = _merge_headers(request, session)
        body = _encode_body(request.body, headers)
        ip, ip_port, _family = _resolve(host, port)
        host_header = f"[{host}]" if ":" in host and not host.startswith("[") else host
        default_port = (scheme == "http" and port == 80) or (scheme == "https" and port == 443)
        headers.setdefault("Host", host_header if default_port else f"{host_header}:{port}")
        last_error: Exception | None = None
        for attempt in range(2):
            key, conn = self._checkout(scheme, ip, ip_port, host)
            reuse = False
            try:
                conn.request(request.method, path, body=body, headers=headers)
                result = conn.getresponse()
                raw, truncated, original, digest = _read_bounded(result, self.limits)
                response_headers = {k: v for k, v in result.getheaders()}
                reuse = True
                return Response(
                    result.status, response_headers, raw.decode("utf-8", "replace"),
                    truncated, original, digest, "direct",
                )
            except (http.client.HTTPException, OSError, TimeoutError) as exc:
                last_error = exc
                if attempt == 0:
                    continue
                raise TransportFailed("transport failed") from exc
            finally:
                self._checkin(key, conn, reuse=reuse)
        raise TransportFailed("transport failed") from last_error

    def _checkout(
        self, scheme: str, ip: str, port: int, server_hostname: str,
    ) -> tuple[tuple[str, str, int], http.client.HTTPConnection]:
        key = (scheme, ip, port)
        with self._lock:
            bucket = self._idle.setdefault(key, [])
            conn = bucket.pop() if bucket else None
            self.active += 1
            self.max_active = max(self.max_active, self.active)
        if conn is None:
            try:
                conn = self._new_connection(scheme, ip, port, server_hostname)
            except Exception:
                with self._lock:
                    self.active = max(0, self.active - 1)
                raise
            with self._lock:
                self._all.append(conn)
        return key, conn

    def _checkin(
        self, key: tuple[str, str, int], conn: http.client.HTTPConnection, *, reuse: bool,
    ) -> None:
        discard = False
        with self._lock:
            self.active = max(0, self.active - 1)
            if reuse:
                self._idle.setdefault(key, []).append(conn)
            else:
                if conn in self._all:
                    self._all.remove(conn)
                discard = True
        if discard:
            _shutdown_conn(conn)

    def _new_connection(self, scheme: str, ip: str, port: int, server_hostname: str) -> http.client.HTTPConnection:
        timeout = 15
        if scheme == "https":
            ctx = ssl.create_default_context()
            conn = http.client.HTTPSConnection(ip, port, timeout=timeout, context=ctx)
            # Connecting by IP after loopback proof; SNI keeps the original name for lab certs.
            conn._context = ctx  # type: ignore[attr-defined]
            conn.host = ip
            try:
                conn.connect()
                if hasattr(conn, "sock") and conn.sock and server_hostname != ip:
                    pass
            except Exception:
                conn.close()
                raise
            return conn
        return http.client.HTTPConnection(ip, port, timeout=timeout)

    def invalidate_one(self, scheme: str, ip: str, port: int) -> None:
        with self._lock:
            idle = self._idle.pop((scheme, ip, port), [])
            for conn in idle:
                if conn in self._all:
                    self._all.remove(conn)
        for conn in idle:
            _shutdown_conn(conn)

    def invalidate(self) -> None:
        """Drop idle connections only. A checked-out connection stays with its caller."""
        self._drop_idle()

    def _drop_idle(self) -> None:
        with self._lock:
            idle: list[http.client.HTTPConnection] = []
            for bucket in self._idle.values():
                idle.extend(bucket)
                bucket.clear()
            for conn in idle:
                if conn in self._all:
                    self._all.remove(conn)
        for conn in idle:
            _shutdown_conn(conn)

    def close(self) -> None:
        with self._lock:
            conns = list(self._all)
            self._idle.clear()
            self._all.clear()
            self.active = 0
        for conn in conns:
            _shutdown_conn(conn)


def _resolve(host: str, port: int):
    from .loopback import resolve_loopback_address
    return resolve_loopback_address(host, port)


class BurpTransport:
    def __init__(self, endpoint: str = "http://127.0.0.1:8892", token: str = "", limits: Limits | None = None):
        parsed = urlparse(endpoint if endpoint.endswith("/send") or endpoint.endswith("/replay") else endpoint)
        # endpoint may be base or legacy /send URL
        if endpoint.rstrip("/").endswith("/send"):
            base = endpoint[: -len("/send")]
        elif endpoint.rstrip("/").endswith("/replay"):
            base = endpoint[: -len("/replay")]
        else:
            base = endpoint.rstrip("/")
        self.base = base or "http://127.0.0.1:8892"
        self.token = token
        self.limits = limits or Limits()
        self._idle: list[http.client.HTTPConnection] = []
        self._all: list[http.client.HTTPConnection] = []
        self._lock = threading.Lock()
        self._bridge_host = urlparse(self.base).hostname or "127.0.0.1"
        self._bridge_port = urlparse(self.base).port or 8892
        self.active = 0
        self.max_active = 0

    def _new_bridge(self) -> http.client.HTTPConnection:
        from .loopback import resolve_loopback_address
        ip, port, _ = resolve_loopback_address(self._bridge_host, self._bridge_port)
        return http.client.HTTPConnection(ip, port, timeout=30)

    def _checkout(self) -> http.client.HTTPConnection:
        with self._lock:
            conn = self._idle.pop() if self._idle else None
            self.active += 1
            self.max_active = max(self.max_active, self.active)
        if conn is None:
            try:
                conn = self._new_bridge()
            except Exception:
                with self._lock:
                    self.active = max(0, self.active - 1)
                raise
            with self._lock:
                self._all.append(conn)
        return conn

    def _checkin(self, conn: http.client.HTTPConnection, *, reuse: bool) -> None:
        discard = False
        with self._lock:
            self.active = max(0, self.active - 1)
            if reuse:
                self._idle.append(conn)
            else:
                if conn in self._all:
                    self._all.remove(conn)
                discard = True
        if discard:
            _shutdown_conn(conn)

    def _post(self, path: str, payload: dict[str, Any]) -> dict[str, Any]:
        body = json.dumps(payload).encode("utf-8")
        if len(body) > self.limits.max_request_body_bytes:
            raise PolicyViolation("request body exceeds size limit")
        headers = {"Content-Type": "application/json", "Authorization": f"Bearer {self.token}"}
        conn = self._checkout()
        reuse = False
        try:
            conn.request("POST", path, body=body, headers=headers)
            result = conn.getresponse()
            raw, truncated, original, digest = _read_bounded(result, self.limits)
            if truncated:
                raise TransportFailed("transport failed")
            data = json.loads(raw.decode("utf-8"))
            if result.status >= 400:
                raise TransportFailed("transport failed")
            reuse = True
            return data
        except (http.client.HTTPException, OSError, TimeoutError, json.JSONDecodeError) as exc:
            raise TransportFailed("transport failed") from exc
        finally:
            self._checkin(conn, reuse=reuse)

    def send(self, request: RequestSpec, session: dict[str, Any]) -> Response:
        handle = session.get("capture_handle")
        if handle:
            return self._replay(request, session, str(handle))
        return self._send_constructed(request, session)

    def _replay(self, request: RequestSpec, session: dict[str, Any], handle: str) -> Response:
        headers = _merge_headers(request, session)
        validate_headers(headers, self.limits, overlay=True)
        parsed = urlparse(request.url)
        overlay = {
            "method": request.method,
            "path": (parsed.path or "/") + (("?" + parsed.query) if parsed.query else ""),
            "headers": headers,
            "body": json.dumps(request.body) if isinstance(request.body, (dict, list)) else (request.body or ""),
        }
        data = self._post("/replay", {"handle": handle, "overlay": overlay, "host": parsed.hostname})
        return self._decode_bridge(data)

    def _send_constructed(self, request: RequestSpec, session: dict[str, Any]) -> Response:
        parsed = urlparse(request.url)
        headers = _merge_headers(request, session)
        path = parsed.path or "/"
        if parsed.query:
            path += "?" + parsed.query
        body = json.dumps(request.body) if isinstance(request.body, (dict, list)) else (request.body or "")
        if isinstance(request.body, (dict, list)):
            headers.setdefault("Content-Type", "application/json")
        if isinstance(body, str):
            headers["Content-Length"] = str(len(body.encode("utf-8")))
        raw = f"{request.method} {path} HTTP/1.1\r\nHost: {parsed.netloc}\r\n"
        raw += "".join(f"{k}: {v}\r\n" for k, v in headers.items()) + "\r\n" + (body if isinstance(body, str) else "")
        encoded = base64.b64encode(raw.encode()).decode()
        if len(encoded) > self.limits.max_capture_bytes:
            raise PolicyViolation("request body exceeds size limit")
        data = self._post("/send", {
            "host": parsed.hostname,
            "port": parsed.port or (443 if parsed.scheme == "https" else 80),
            "secure": parsed.scheme == "https",
            "request_b64": encoded,
        })
        return self._decode_bridge(data)

    def _decode_bridge(self, data: dict[str, Any]) -> Response:
        status = int(data["status"])
        # Montoya reports a dropped connection as a response with status 0.
        if status < 100:
            raise TransportFailed("transport failed")
        raw_response = base64.b64decode(data["response_b64"])
        java_truncated = bool(data.get("truncated"))
        java_original = int(data["original_length"]) if data.get("original_length") is not None else len(raw_response)
        text = raw_response.decode("utf-8", "replace")
        head, _, response_body = text.partition("\r\n\r\n")
        response_headers = {}
        for line in head.split("\r\n")[1:]:
            if ":" in line:
                key, value = line.split(":", 1)
                response_headers[key.strip()] = value.strip()
        body_bytes = response_body.encode("utf-8")
        retained, py_truncated, py_original, digest = _bound_body(body_bytes, self.limits)
        truncated = java_truncated or py_truncated
        original = java_original if java_truncated else py_original
        return Response(status, response_headers, retained.decode("utf-8", "replace"), truncated, original, digest, "burp")

    def invalidate(self) -> None:
        """Drop idle bridge connections only. A checked-out connection stays with its caller."""
        with self._lock:
            idle = list(self._idle)
            self._idle.clear()
            for conn in idle:
                if conn in self._all:
                    self._all.remove(conn)
        for conn in idle:
            _shutdown_conn(conn)

    def close(self) -> None:
        with self._lock:
            conns = list(self._all)
            self._idle.clear()
            self._all.clear()
            self.active = 0
        for conn in conns:
            _shutdown_conn(conn)


class CDPTransport:
    """Playwright sync API is thread-affine. All browser calls run on one owner thread."""

    def __init__(self, limits: Limits | None = None):
        self.limits = limits or Limits()
        self._pw = None
        self._browsers: dict[str, Any] = {}
        self._lock = threading.Lock()
        self._calls: queue.Queue = queue.Queue()
        self._owner: threading.Thread | None = None

    def send(self, request: RequestSpec, session: dict[str, Any]) -> Response:
        return self._on_owner(lambda: self._send_locked(request, session))

    def _on_owner(self, fn):
        self._start_owner()
        if threading.current_thread() is self._owner:
            return fn()
        done = threading.Event()
        slot: list[tuple[bool, Any]] = []

        def run() -> None:
            try:
                slot.append((True, fn()))
            except BaseException as exc:
                slot.append((False, exc))
            finally:
                done.set()

        self._calls.put(run)
        done.wait()
        ok, value = slot[0]
        if not ok:
            raise value
        return value

    def _start_owner(self) -> None:
        with self._lock:
            if self._owner is not None and self._owner.is_alive():
                return
            self._owner = threading.Thread(target=self._serve, name="authzloom-cdp", daemon=True)
            self._owner.start()

    def _serve(self) -> None:
        while True:
            job = self._calls.get()
            if job is None:
                self._shutdown_playwright()
                return
            job()

    def _send_locked(self, request: RequestSpec, session: dict[str, Any]) -> Response:
        page = self._ensure_page(session)
        headers = _merge_headers(request, session)
        data = page.evaluate(
            """async ({url, options}) => { const r = await fetch(url, options);
                return {status:r.status, headers:Object.fromEntries(r.headers.entries()), body:await r.text()}; }""",
            {"url": request.url, "options": {
                "method": request.method,
                "headers": headers,
                "body": None if request.body is None else json.dumps(request.body) if isinstance(request.body, (dict, list)) else request.body,
            }},
        )
        body = str(data["body"]).encode("utf-8")
        retained, truncated, original, digest = _bound_body(body, self.limits)
        return Response(int(data["status"]), data["headers"], retained.decode("utf-8", "replace"), truncated, original, digest, "cdp")

    def _ensure_page(self, session: dict[str, Any]):
        try:
            from playwright.sync_api import sync_playwright
        except ImportError as exc:
            raise RuntimeError("install AuthzLoom with the 'cdp' extra") from exc
        endpoint = session["endpoint"]
        if self._pw is None:
            self._pw = sync_playwright().start()
        browser = self._browsers.get(endpoint)
        if browser is None:
            browser = self._pw.chromium.connect_over_cdp(endpoint)
            self._browsers[endpoint] = browser
        pages = [page for context in browser.contexts for page in context.pages]
        return next((p for p in pages if session.get("page_host", "") in p.url), pages[0])

    def invalidate(self) -> None:
        self.close()

    def close(self) -> None:
        with self._lock:
            owner = self._owner
            self._owner = None
        if owner is None or not owner.is_alive():
            self._shutdown_playwright()
            return
        if threading.current_thread() is owner:
            self._shutdown_playwright()
            return
        self._calls.put(None)
        owner.join(timeout=10)

    def _shutdown_playwright(self) -> None:
        browsers = list(self._browsers.items())
        self._browsers.clear()
        pw = self._pw
        self._pw = None
        for _, browser in browsers:
            try:
                browser.close()
            except Exception:
                pass
        if pw is not None:
            try:
                pw.stop()
            except Exception:
                pass


class ScriptedTransport:
    """Deterministic transport for tests and benchmarks. Never opens a socket."""

    def __init__(self, handler=None, delay: float = 0.0, clock=None):
        self.handler = handler
        self.delay = delay
        self.clock = clock
        self.sends: list[RequestSpec] = []

    def send(self, request: RequestSpec, session: dict[str, Any]) -> Response:
        self.sends.append(request)
        if self.delay and self.clock is not None:
            self.clock.sleep(self.delay)
        elif self.delay:
            import time
            time.sleep(self.delay)
        if self.handler:
            return self.handler(request, session)
        return Response(200, {"Content-Type": "application/json"}, "{}", transport="scripted")

    def invalidate(self) -> None:
        pass

    def close(self) -> None:
        pass


class TransportRegistry:
    def __init__(self, burp_token: str = "", limits: Limits | None = None, overrides: dict[str, Transport] | None = None):
        self.limits = limits or Limits()
        self.burp_token = burp_token
        self._overrides = overrides or {}
        self._direct: DirectTransport | None = None
        self._burp: BurpTransport | None = None
        self._cdp: CDPTransport | None = None
        self._lock = threading.Lock()
        self.created = {"direct": 0, "burp": 0, "cdp": 0}

    def get(self, name: str, session: dict[str, Any] | None = None) -> Transport:
        if name in self._overrides:
            return self._overrides[name]
        with self._lock:
            if name == "direct":
                if self._direct is None:
                    self._direct = DirectTransport(self.limits)
                    self.created["direct"] += 1
                return self._direct
            if name == "burp":
                if self._burp is None:
                    self._burp = BurpTransport(token=self.burp_token, limits=self.limits)
                    self.created["burp"] += 1
                return self._burp
            if name == "cdp":
                if self._cdp is None:
                    self._cdp = CDPTransport(self.limits)
                    self.created["cdp"] += 1
                return self._cdp
        raise ValueError(f"unknown transport: {name}")

    def close(self) -> None:
        for transport in (self._direct, self._burp, self._cdp, *self._overrides.values()):
            if transport is not None:
                try:
                    transport.close()
                except Exception:
                    pass

    def invalidate(self, name: str) -> None:
        """Discard idle connections on the live transport. Do not close one a caller has checked out."""
        with self._lock:
            current = self._overrides.get(name) or {"direct": self._direct, "burp": self._burp, "cdp": self._cdp}.get(name)
        if current is not None:
            current.invalidate()


def transport_for(name: str, *, burp_token: str = "", limits: Limits | None = None) -> Transport:
    return TransportRegistry(burp_token, limits).get(name)
