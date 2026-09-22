"""Dependency-free MCP stdio adapter for AuthzLoom."""
from __future__ import annotations

import json
import os
import queue
import sys
import threading
from pathlib import Path

from . import __version__
from .captures import CaptureRegistry
from .errors import AuthzLoomError, LimitExceeded, MessageDecodeError, public_error
from .executor import run
from .limits import Limits
from .models import Scenario
from .planner import plan
from .redact import redact
from .store import Store

TOOLS = [
    {"name": "authzloom_ingest", "description": "Register capture metadata or redact a header snapshot. Raw request bytes are rejected.", "inputSchema": {"type": "object", "properties": {"capture": {"type": "object"}}, "required": ["capture"]}, "annotations": {"readOnlyHint": False, "destructiveHint": False, "idempotentHint": False}},
    {"name": "authzloom_plan", "description": "Validate a scenario and return its bounded authorization matrix", "inputSchema": {"type": "object", "properties": {"scenario": {"type": "object"}}, "required": ["scenario"]}, "annotations": {"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True}},
    {"name": "authzloom_run", "description": "Execute an approved scenario and save a redacted evidence capsule", "inputSchema": {"type": "object", "properties": {"scenario": {"type": "object"}}, "required": ["scenario"]}, "annotations": {"readOnlyHint": False, "destructiveHint": True, "idempotentHint": False}},
    {"name": "authzloom_status", "description": "List AuthzLoom runs", "inputSchema": {"type": "object", "properties": {"limit": {"type": "integer"}, "offset": {"type": "integer"}}}, "annotations": {"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True}},
    {"name": "authzloom_export", "description": "Return a redacted evidence capsule", "inputSchema": {"type": "object", "properties": {"run_id": {"type": "string"}}, "required": ["run_id"]}, "annotations": {"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True}},
]

SUPPORTED_PROTOCOL_VERSIONS = {"2024-11-05", "2025-03-26", "2025-06-18"}
CANCEL_METHODS = {"notifications/cancelled", "$/cancelRequest"}
PARSE_ERROR = {"code": -32700, "message": "parse error"}


def initialize_result(message):
    """Negotiate the stdio protocol instead of forcing one client version."""
    requested = message.get("params", {}).get("protocolVersion", "2025-06-18")
    protocol = requested if requested in SUPPORTED_PROTOCOL_VERSIONS else "2025-06-18"
    return {
        "protocolVersion": protocol,
        "capabilities": {"tools": {}, "experimental": {"progress": True}},
        "serverInfo": {"name": "authzloom", "version": __version__},
    }


def bridge_token(store):
    configured = os.environ.get("AUTHZLOOM_TOKEN", "")
    token_file = store.root / "runtime-token"
    return configured or (token_file.read_text(encoding="ascii").strip() if token_file.exists() else "")


class Runtime:
    def __init__(self, store: Store, limits: Limits, cancel: threading.Event | None = None):
        self.store = store
        self.limits = limits
        self.captures = CaptureRegistry(limits)
        self.cancel = cancel or threading.Event()


def dispatch(name, args, store, runtime: Runtime | None = None):
    runtime = runtime or Runtime(store, Limits.from_env())
    if name == "authzloom_ingest":
        capture = args["capture"]
        if any(key in capture for key in ("request_b64", "response_b64", "raw", "raw_capture")):
            raise LimitExceeded("captures must remain in the Burp bridge; send a handle")
        if capture.get("handle") and capture.get("host"):
            return runtime.captures.ingest_document(capture)
        return redact(capture)
    if name == "authzloom_plan":
        return [{"name": x.name, "session": x.session, "object_owner": x.object_owner} for x in plan(Scenario.from_dict(args["scenario"]))]
    if name == "authzloom_run":
        runtime.cancel.clear()
        result = run(Scenario.from_dict(args["scenario"]), burp_token=bridge_token(store), cancel=runtime.cancel)
        return {"run_id": store.save(result), "result": redact(result)}
    if name == "authzloom_status":
        return store.list(limit=int(args.get("limit", 50)), offset=int(args.get("offset", 0)))
    if name == "authzloom_export":
        return redact(store.get(args["run_id"]))
    raise ValueError("unknown tool")


EMPTY_LISTS = {"resources/list": {"resources": []}, "resources/templates/list": {"resourceTemplates": []}, "prompts/list": {"prompts": []}}


def handle(message, store, runtime: Runtime | None = None):
    """Return a JSON-RPC result, or None when the message needs no response."""
    method = message.get("method")
    if method == "initialize":
        return initialize_result(message)
    if method == "ping":
        return {}
    if method in CANCEL_METHODS:
        if runtime:
            runtime.cancel.set()
        return None
    if method == "tools/list":
        return {"tools": TOOLS}
    if method in EMPTY_LISTS:
        return EMPTY_LISTS[method]
    if method == "tools/call":
        value = dispatch(message["params"]["name"], message["params"].get("arguments", {}), store, runtime)
        return {"content": [{"type": "text", "text": json.dumps(value)}]}
    raise LookupError(method)


def _drain_to_newline(source) -> None:
    while True:
        chunk = source.readline(8192)
        if not chunk:
            return
        if isinstance(chunk, str):
            if chunk.endswith("\n"):
                return
        elif chunk.endswith(b"\n"):
            return


def read_bounded_line(fp, limit: int) -> str | None:
    """Read one line without retaining more than `limit` bytes. Drains the rest on overflow."""
    source = getattr(fp, "buffer", fp)
    buf = bytearray()
    while True:
        take = limit - len(buf) + 1
        if take <= 0:
            _drain_to_newline(source)
            raise LimitExceeded("input or output exceeds configured limits")
        chunk = source.readline(take)
        if not chunk:
            if not buf:
                return None
            break
        if isinstance(chunk, str):
            chunk = chunk.encode("utf-8")
        buf.extend(chunk)
        if buf.endswith(b"\n"):
            del buf[-1]
            if buf.endswith(b"\r"):
                del buf[-1]
            break
        if len(buf) > limit:
            _drain_to_newline(source)
            raise LimitExceeded("input or output exceeds configured limits")
    if len(buf) > limit:
        raise LimitExceeded("input or output exceeds configured limits")
    try:
        return buf.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise MessageDecodeError("parse error") from exc


def write_message(fp, obj) -> None:
    raw = (json.dumps(obj) + "\n").encode("utf-8")
    stream = getattr(fp, "buffer", fp)
    stream.write(raw)
    stream.flush()


def serve_stdio(stdin=None, stdout=None) -> None:
    """Read JSON-RPC from stdin on a pump thread so cancellation arrives during tools/call."""
    stdin = sys.stdin if stdin is None else stdin
    stdout = sys.stdout if stdout is None else stdout
    limits = Limits.from_env()
    shared_cancel = threading.Event()
    incoming: queue.Queue = queue.Queue()
    stop = threading.Event()
    store = None
    runtime = None

    def pump() -> None:
        while not stop.is_set():
            try:
                line = read_bounded_line(stdin, limits.max_mcp_message_bytes)
            except LimitExceeded as exc:
                incoming.put(("limit", exc))
                continue
            except MessageDecodeError as exc:
                incoming.put(("decode", exc))
                continue
            except Exception:
                incoming.put(("eof", None))
                return
            if line is None:
                incoming.put(("eof", None))
                return
            if not line.strip():
                continue
            try:
                message = json.loads(line)
            except json.JSONDecodeError:
                incoming.put(("parse", None))
                continue
            if isinstance(message, dict) and message.get("method") in CANCEL_METHODS:
                shared_cancel.set()
                if "id" not in message:
                    continue
            incoming.put(("rpc", message))

    reader = threading.Thread(target=pump, name="authzloom-mcp-stdin", daemon=True)
    reader.start()
    try:
        while True:
            kind, payload = incoming.get()
            if kind == "eof":
                break
            if kind == "limit":
                write_message(stdout, {"jsonrpc": "2.0", "id": None, "error": payload.to_dict()})
                continue
            if kind in {"decode", "parse"}:
                write_message(stdout, {"jsonrpc": "2.0", "id": None, "error": PARSE_ERROR})
                continue
            message = payload
            if store is None:
                store = Store(Path(os.environ.get("AUTHZLOOM_DATA_DIR", ".authzloom")), limits)
                runtime = Runtime(store, limits, cancel=shared_cancel)
            try:
                result = handle(message, store, runtime)
                if "id" not in message:
                    continue
                if result is None:
                    continue
                response = {"jsonrpc": "2.0", "id": message["id"], "result": result}
            except LookupError as exc:
                if "id" not in message:
                    continue
                response = {"jsonrpc": "2.0", "id": message["id"], "error": {"code": -32601, "message": f"method not found: {exc}"}}
            except AuthzLoomError as exc:
                if "id" not in message:
                    continue
                response = {"jsonrpc": "2.0", "id": message["id"], "error": {"code": -32000, "message": exc.public_message, "data": exc.to_dict()}}
            except Exception:
                if "id" not in message:
                    continue
                response = {"jsonrpc": "2.0", "id": message["id"], "error": {"code": -32000, "message": public_error(Exception())["message"]}}
            write_message(stdout, response)
    finally:
        stop.set()
        if store is not None:
            store.close()


def main():
    serve_stdio()


if __name__ == "__main__":
    main()
