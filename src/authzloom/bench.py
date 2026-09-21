"""Microbenchmarks and loopback benches. Fake clock by default; live loopback opt-in."""
from __future__ import annotations

import json
import statistics
import tempfile
import time
from pathlib import Path

from .executor import run
from .models import Scenario
from .pacer import FakeClock, RateLimiter
from .planner import plan
from .redact import redact
from .store import Store
from .transports import Response, ScriptedTransport, TransportRegistry


def _scenario() -> dict:
    return {
        "policy": {
            "action_id": "BENCH", "program": "lab", "asset": "http://127.0.0.1:9",
            "allowed_hosts": ["127.0.0.1"], "aggression": 0, "max_requests": 20,
            "rate_per_second": 1000, "allowed_methods": ["GET", "PATCH"],
        },
        "sessions": {"A": {"headers": {"X-User": "A"}}, "B": {"headers": {"X-User": "B"}}},
        "objects": {"A": {"id": "a-note"}, "B": {"id": "b-note"}},
        "cases": [
            {"name": "A-on-A", "session": "A", "object_owner": "A"},
            {"name": "B-on-B", "session": "B", "object_owner": "B"},
        ],
        "operation": {
            "request": {"method": "PATCH", "url": "http://127.0.0.1:9/notes/{{object.id}}", "body": {"text": "probe"}},
            "readback": {"method": "GET", "url": "http://127.0.0.1:9/notes/{{object.id}}"},
            "readback_assertion": {"path": "text", "equals": "probe"},
        },
    }


def timed(fn, n: int = 200) -> float:
    fn()
    started = time.perf_counter()
    for _ in range(n):
        fn()
    return (time.perf_counter() - started) / n


def nested(size: int) -> dict:
    payload = "x" * size
    return {"nested": {"csrf_token": "secret", "body": json.dumps({"access_token": "live", "blob": payload})}}


def run_micro() -> dict[str, float]:
    raw = _scenario()
    scenario = Scenario.from_dict(raw)
    parse = timed(lambda: Scenario.from_dict(raw), 200)
    planner = timed(lambda: plan(scenario), 500)
    from .executor import materialize
    from .planner import Case
    case = Case("A-on-A", "A", "A")
    material = timed(lambda: materialize(scenario.operation.request, case, scenario), 500)
    blob = nested(1_000_000)
    redaction = timed(lambda: redact(blob), 5)
    return {"parse_us": parse * 1e6, "plan_us": planner * 1e6, "materialize_us": material * 1e6, "redact_1mib_ms": redaction * 1e3}


def run_store() -> dict[str, float]:
    payload = {
        "action_id": "A",
        "request_count": 0,
        "cases": [{"case": {"name": "x"}, "steps": [{"kind": "request", "assertion_passed": None, "response": {"status": 200, "body": "x" * 3_000_000, "headers": {}}}]}],
    }
    times = []
    with tempfile.TemporaryDirectory() as directory:
        store = Store(Path(directory))
        try:
            store.save(payload)
            for _ in range(4):
                started = time.perf_counter()
                store.save(payload)
                times.append(time.perf_counter() - started)
            dirs = [path for path in Path(directory).iterdir() if path.is_dir()]
            last = max(dirs, key=lambda path: path.stat().st_mtime)
            disk = sum(path.stat().st_size for path in last.rglob("*") if path.is_file())
        finally:
            store.close()
    return {"save_ms": statistics.median(times) * 1e3, "disk_bytes": disk}


def run_scripted_rate(rate: float, n: int = 10) -> dict[str, float]:
    clock = FakeClock()
    limiter = RateLimiter(rate, clock)
    for _ in range(n):
        event = limiter.acquire()
        clock.advance(0.001)
        limiter.complete(event)
    return {"elapsed_ms": clock.monotonic() * 1e3, "starts": len(limiter.events), "interval": limiter.interval}


def run_scripted_execute() -> dict[str, float]:
    def handler(request, session):
        return Response(200, {"Content-Type": "application/json"}, '{"text":"probe","id":"a-note"}', transport="scripted")
    scenario = Scenario.from_dict(_scenario())
    registry = TransportRegistry(overrides={"direct": ScriptedTransport(handler)})
    started = time.perf_counter()
    result = run(scenario, registry=registry)
    return {"elapsed_ms": (time.perf_counter() - started) * 1e3, "requests": result["request_count"]}


def main() -> None:
    print(json.dumps({"micro": run_micro(), "store": run_store(), "rate20": run_scripted_rate(20), "rate1000": run_scripted_rate(1000), "execute": run_scripted_execute()}, indent=2))


if __name__ == "__main__":
    main()
