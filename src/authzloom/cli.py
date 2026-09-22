from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import secrets
from pathlib import Path

from . import __version__
from .api import serve
from .captures import CaptureRegistry
from .errors import AuthzLoomError, public_error
from .executor import run
from .io import load_document
from .limits import Limits
from .models import Scenario
from .planner import explain, plan
from .redact import redact
from .schema import SCENARIO_V1
from .store import Store

SKELETON = {
    "policy": {
        "action_id": "A-AUTHZ-001",
        "program": "local-lab",
        "asset": "http://127.0.0.1:8877",
        "allowed_hosts": ["127.0.0.1"],
        "aggression": 0,
        "max_requests": 12,
        "rate_per_second": 20,
        "allowed_methods": ["GET", "PATCH"],
    },
    "sessions": {
        "A": {"headers": {"X-User": "A"}},
        "B": {"headers": {"X-User": "B"}},
        "none": {"headers": {}},
    },
    "objects": {"A": {"id": "a-note"}, "B": {"id": "b-note"}},
    "operation": {
        "request": {"method": "PATCH", "url": "http://127.0.0.1:8877/notes/{{object.id}}", "body": {"text": "authzloom-probe"}},
        "readback": {"method": "GET", "url": "http://127.0.0.1:8877/notes/{{object.id}}"},
        "readback_assertion": {"path": "text", "equals": "authzloom-probe"},
    },
}


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="authzloom")
    p.add_argument("--data-dir", default=".authzloom")
    p.add_argument("--diagnostics", action="store_true")
    sub = p.add_subparsers(dest="command")
    s = sub.add_parser("serve")
    s.add_argument("--host", default="127.0.0.1")
    s.add_argument("--port", type=int, default=8891)
    s.add_argument("--token")
    sub.add_parser("mcp")
    plan_p = sub.add_parser("plan")
    plan_p.add_argument("scenario")
    plan_p.add_argument("--explain", action="store_true")
    sub.add_parser("run").add_argument("scenario")
    sub.add_parser("ingest").add_argument("scenario")
    sub.add_parser("validate").add_argument("scenario")
    init_p = sub.add_parser("init")
    init_p.add_argument("path", nargs="?", default="scenario.json")
    sub.add_parser("status")
    e = sub.add_parser("export")
    e.add_argument("run_id")
    e.add_argument("--output")
    sub.add_parser("schema")
    return p


def _diagnostics() -> dict:
    schema_hash = hashlib.sha256(json.dumps(SCENARIO_V1, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    return {
        "name": "authzloom",
        "version": __version__,
        "python": platform.python_version(),
        "platform": platform.platform(),
        "schema_sha256": schema_hash,
        "tools": ["authzloom_ingest", "authzloom_plan", "authzloom_run", "authzloom_status", "authzloom_export"],
    }


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    if args.diagnostics or args.command is None:
        if args.diagnostics or args.command is None and argv and "--diagnostics" in (argv or []):
            print(json.dumps(_diagnostics(), indent=2))
            return 0
        if args.command is None:
            parser().error("the following arguments are required: command")
    root = Path(args.data_dir)
    try:
        if args.command == "mcp":
            from .mcp_server import serve_stdio

            serve_stdio()
            return 0
        if args.command == "serve":
            token = args.token or os.environ.get("AUTHZLOOM_TOKEN") or secrets.token_urlsafe(32)
            if not (args.token or os.environ.get("AUTHZLOOM_TOKEN")):
                print(f"Ephemeral token: {token}")
            serve(args.host, args.port, root, token)
            return 0
        if args.command == "schema":
            print(json.dumps(SCENARIO_V1, indent=2))
            return 0
        if args.command == "init":
            path = Path(args.path)
            if path.exists():
                print(json.dumps({"error": "SCENARIO_INVALID", "message": "path already exists"}))
                return 1
            path.write_text(json.dumps(SKELETON, indent=2) + "\n", encoding="utf-8")
            print(json.dumps({"path": str(path), "schema": "scenario.v1"}))
            return 0
        if args.command == "status":
            with Store(root) as store:
                print(json.dumps(store.list(), indent=2))
            return 0
        if args.command == "export":
            with Store(root) as store:
                value = store.get(args.run_id)
            output = json.dumps(redact(value), indent=2)
            if args.output:
                Path(args.output).write_text(output + "\n", encoding="utf-8")
            else:
                print(output)
            return 0
        document = load_document(args.scenario)
        if args.command == "ingest":
            registry = CaptureRegistry(Limits.from_env())
            if any(key in document for key in ("request_b64", "response_b64", "raw", "raw_capture")):
                print(json.dumps({"error": "LIMIT_EXCEEDED", "message": "captures must remain in the Burp bridge; send a handle"}))
                return 1
            if document.get("handle") and document.get("host"):
                print(json.dumps(registry.ingest_document(document), indent=2))
                return 0
            print(json.dumps(redact(document), indent=2))
            return 0
        scenario = Scenario.from_dict(document)
        if args.command == "validate":
            print(json.dumps({"ok": True, "action_id": scenario.policy.action_id}))
            return 0
        if args.command == "plan":
            if args.explain:
                print(json.dumps(explain(scenario), indent=2))
                return 0 if explain(scenario)["ok"] else 1
            print(json.dumps([{"name": x.name, "session": x.session, "object_owner": x.object_owner} for x in plan(scenario)], indent=2))
            return 0
        result = run(scenario, burp_token=os.environ.get("AUTHZLOOM_TOKEN", ""))
        with Store(root) as store:
            run_id = store.save(result)
        print(json.dumps({"run_id": run_id, "result": redact(result)}, indent=2))
        return 0
    except AuthzLoomError as exc:
        print(json.dumps(exc.to_dict()))
        return 1
    except Exception:
        print(json.dumps(public_error(Exception())))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
