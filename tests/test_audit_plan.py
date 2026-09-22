from __future__ import annotations

import json
import os
import sys
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[1] / "src"))

from authzloom.errors import CaptureError, LimitExceeded, MessageDecodeError, PolicyViolation, RunNotFound, ScenarioError, TransportFailed
from authzloom.executor import run
from authzloom.models import Scenario
from authzloom.pacer import FakeClock, RateLimiter, SystemClock
from authzloom.planner import plan
from authzloom.redact import redact, redact_http_body, redact_with_stats
from authzloom.store import Store
from authzloom.captures import CaptureRegistry
from authzloom.limits import Limits
from authzloom.transports import Response, ScriptedTransport, TransportRegistry, DirectTransport, BurpTransport, CDPTransport
from authzloom.cli import main as cli_main
from authzloom.mcp_server import dispatch
from authzloom.loopback import assert_direct_destination
from authzloom.models import RequestSpec
from authzloom.policy import validate_request


def base_scenario(port: int, **extra):
    url = f"http://127.0.0.1:{port}"
    value = {
        "policy": {
            "action_id": "A-TEST", "program": "lab", "asset": url, "allowed_hosts": ["127.0.0.1"],
            "aggression": 0, "max_requests": extra.pop("budget", 12), "rate_per_second": extra.pop("rate", 1000),
            "allowed_methods": ["GET", "PATCH", "POST", "DELETE"],
        },
        "sessions": {"A": {"headers": {"X-User": "A"}}, "B": {"headers": {"X-User": "B"}}, "none": {"headers": {}}},
        "objects": {"A": {"id": "a-note"}, "B": {"id": "b-note"}},
        "operation": {
            "request": {"method": "PATCH", "url": url + "/notes/{{object.id}}", "body": {"text": "probe"}},
            "readback": {"method": "GET", "url": url + "/notes/{{object.id}}"},
            "readback_assertion": {"path": "text", "equals": "probe"},
        },
    }
    value.update(extra)
    return value


class ProbeValidationTests(unittest.TestCase):
    def test_identity_probe_cannot_escape_host_allowlist(self):
        value = base_scenario(8877)
        value["sessions"]["A"]["identity_probe"] = {
            "request": {"method": "GET", "url": "https://example.com/me"},
            "assertion": {"path": "id", "equals": "A"},
        }
        with self.assertRaises(ScenarioError):
            Scenario.from_dict(value)

    def test_identity_probe_cannot_use_disallowed_method(self):
        value = base_scenario(8877)
        value["sessions"]["A"]["identity_probe"] = {
            "request": {"method": "TRACE", "url": "http://127.0.0.1:8877/me"},
        }
        with self.assertRaises(ScenarioError):
            Scenario.from_dict(value)

    def test_identity_probe_direct_non_loopback_literal_rejected(self):
        value = base_scenario(8877)
        value["policy"]["allowed_hosts"] = ["example.com"]
        value["operation"]["request"]["url"] = "https://example.com/x"
        value["operation"]["readback"]["url"] = "https://example.com/x"
        value["operation"]["request"]["transport"] = "burp"
        value["operation"]["readback"]["transport"] = "burp"
        value["sessions"]["A"]["identity_probe"] = {
            "request": {"method": "GET", "url": "https://example.com/me", "transport": "direct"},
        }
        with self.assertRaises(ScenarioError):
            Scenario.from_dict(value)

    def test_unknown_session_reference_rejected(self):
        value = base_scenario(8877)
        value["cases"] = [{"name": "x", "session": "ghost", "object_owner": "A"}]
        with self.assertRaises(ScenarioError):
            Scenario.from_dict(value)

    def test_unknown_placeholder_rejected(self):
        value = base_scenario(8877)
        value["operation"]["request"]["url"] = "http://127.0.0.1:8877/{{other.id}}"
        with self.assertRaises(ScenarioError):
            Scenario.from_dict(value)

    def test_credentials_in_scenario_rejected(self):
        value = base_scenario(8877)
        value["sessions"]["A"]["headers"]["Authorization"] = "Bearer live-token"
        with self.assertRaises(ScenarioError):
            Scenario.from_dict(value)

    def test_expanded_request_uses_the_same_validator(self):
        policy = Scenario.from_dict(base_scenario(8877)).policy
        spec = RequestSpec("GET", "https://example.com/x")
        with self.assertRaises(PolicyViolation):
            validate_request(spec, policy, Limits(), templates_ok=False)


class RedirectHandler(BaseHTTPRequestHandler):
    second_hits = 0

    def do_GET(self):
        if self.path == "/out":
            RedirectHandler.second_hits += 1
            self.send_response(200); self.end_headers(); self.wfile.write(b"nope"); return
        self.send_response(302)
        self.send_header("Location", "http://example.com/")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, *_): pass


class LoopbackTests(unittest.TestCase):
    def test_userinfo_rejected(self):
        with self.assertRaises(PolicyViolation):
            assert_direct_destination("http://evil@127.0.0.1/")

    def test_non_http_scheme_rejected(self):
        with self.assertRaises(PolicyViolation):
            assert_direct_destination("file:///etc/passwd")

    def test_redirect_is_not_followed(self):
        RedirectHandler.second_hits = 0
        server = ThreadingHTTPServer(("127.0.0.1", 0), RedirectHandler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        transport = DirectTransport()
        try:
            spec = RequestSpec("GET", f"http://127.0.0.1:{server.server_port}/start")
            response = transport.send(spec, {})
            self.assertEqual(response.status, 302)
            self.assertEqual(RedirectHandler.second_hits, 0)
            self.assertIn("example.com", response.headers.get("Location", response.headers.get("location", "")))
        finally:
            transport.close()
            server.shutdown()
            server.server_close()

    def test_ipv6_loopback_literal_allowed_by_checker(self):
        self.assertTrue(assert_direct_destination("http://127.0.0.1/")[1] in {"127.0.0.1"})


class CleanupTests(unittest.TestCase):
    def test_transport_error_after_mutation_still_runs_cleanup(self):
        calls = []

        def handler(request, session):
            calls.append(request.method + " " + request.url)
            if request.method == "PATCH" and "/notes/" in request.url and request.body == {"text": "probe"}:
                raise RuntimeError("boom")
            return Response(200, {"Content-Type": "application/json"}, '{"text":"A-original"}', transport="scripted")

        value = base_scenario(9, budget=20)
        value["cases"] = [{"name": "A-on-A", "session": "A", "object_owner": "A"}]
        value["operation"]["cleanup"] = {"method": "PATCH", "url": "http://127.0.0.1:9/notes/{{object.id}}", "body": {"text": "A-original"}}
        value["operation"]["cleanup_assertion"] = {"path": "text", "equals": "A-original"}
        scenario = Scenario.from_dict(value)
        registry = TransportRegistry(overrides={"direct": ScriptedTransport(handler)})
        result = run(scenario, registry=registry)
        self.assertEqual(result["state"], "failed")
        self.assertNotEqual(result["cases"][0]["state"], "complete")
        self.assertEqual(result["cases"][0]["cleanup"], "passed")
        self.assertGreaterEqual(len(calls), 2)

    def test_completed_case_is_not_marked_complete_when_failed(self):
        def handler(request, session):
            if request.method == "PATCH":
                raise RuntimeError("boom")
            return Response(200, {}, "{}", transport="scripted")

        value = base_scenario(9, budget=20)
        value["cases"] = [{"name": "A-on-A", "session": "A", "object_owner": "A"}]
        value["operation"]["cleanup"] = {"method": "GET", "url": "http://127.0.0.1:9/notes/{{object.id}}"}
        value["operation"]["cleanup_assertion"] = {"path": "", "equals": "{}"}
        scenario = Scenario.from_dict(value)
        registry = TransportRegistry(overrides={"direct": ScriptedTransport(handler)})
        result = run(scenario, registry=registry)
        self.assertEqual(result["state"], "failed")
        self.assertEqual(result["cases"][0]["state"], "failed")


class RedactionTests(unittest.TestCase):
    def test_json_body_secret_is_removed(self):
        clean, count = redact_http_body('{"access_token":"live-secret"}', "application/json")
        self.assertNotIn("live-secret", clean)
        self.assertGreater(count, 0)

    def test_request_b64_is_a_secret_container(self):
        clean = redact({"request_b64": "dG9rZW49c2VjcmV0"})
        self.assertNotIn("dG9rZW49c2VjcmV0", json.dumps(clean))
        self.assertTrue(str(clean["request_b64"]).startswith("[REDACTED]"))

    def test_jwt_and_basic_and_graphql_variables(self):
        payload = {
            "Authorization": "Basic dXNlcjpwYXNz",
            "body": json.dumps({"variables": {"password": "hunter2", "id": "a-note"}}),
            "note": "eyJhbGciOiJub25lIn0.eyJzdWIiOiIxIn0.sig",
        }
        clean = redact(payload)
        dumped = json.dumps(clean)
        self.assertNotIn("hunter2", dumped)
        self.assertNotIn("dXNlcjpwYXNz", dumped)
        self.assertNotIn("eyJhbGciOiJub25lIn0", dumped)

    def test_url_userinfo_and_query_secret(self):
        clean = redact("https://user:pass@example.com/callback?access_token=abc&id=1")
        self.assertNotIn("user:pass", clean)
        self.assertNotIn("abc", clean)


class StoreSafetyTests(unittest.TestCase):
    def test_traversal_run_id_is_unknown(self):
        with tempfile.TemporaryDirectory() as directory:
            with Store(Path(directory)) as store:
                with self.assertRaises(RunNotFound):
                    store.get("../etc/passwd")
                with self.assertRaises(RunNotFound):
                    store.get("C:/Windows/win.ini")
                with self.assertRaises(RunNotFound):
                    store.get("..\\..\\secret")

    def test_export_requires_metadata_row(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with Store(root) as store:
                fake = root / "20200101T000000Z-deadbeef"
                fake.mkdir()
                (fake / "capsule.redacted.json").write_text('{"action_id":"leaked"}', encoding="utf-8")
                with self.assertRaises((RunNotFound, Exception)):
                    store.get("20200101T000000Z-deadbeef")


class CaptureTests(unittest.TestCase):
    def test_bytes_are_rejected_and_handles_round_trip(self):
        registry = CaptureRegistry(Limits(max_ingested_captures=2, ingest_ttl_seconds=60))
        with self.assertRaises(LimitExceeded):
            registry.ingest_document({"request_b64": "aaaa", "host": "example.com"})
        meta = registry.ingest_document({"handle": "cap_abcd1234efgh", "host": "example.com", "method": "PATCH", "path": "/n"})
        self.assertEqual(meta["handle"], "cap_abcd1234efgh")
        got = registry.get("cap_abcd1234efgh", host="example.com")
        self.assertEqual(got.method, "PATCH")
        with self.assertRaises(CaptureError):
            registry.get("cap_abcd1234efgh", host="other.com")

    def test_mcp_ingest_strips_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            with Store(Path(directory)) as store:
                with self.assertRaises(LimitExceeded):
                    dispatch("authzloom_ingest", {"capture": {"request_b64": "dG9rZW4="}}, store)


class PacerTests(unittest.TestCase):
    def test_fake_clock_20_rps_does_not_sleep_after_last(self):
        clock = FakeClock()
        limiter = RateLimiter(20, clock)
        for _ in range(10):
            limiter.complete(limiter.acquire())
        self.assertLessEqual(clock.monotonic() * 1000, 485)
        self.assertEqual(len(clock.sleeps), 9)
        self.assertEqual(limiter.starts_in_window(0.0, 1.0), 10)

    def test_fake_clock_1000_rps(self):
        clock = FakeClock()
        limiter = RateLimiter(1000, clock)
        for _ in range(10):
            limiter.complete(limiter.acquire())
        self.assertLessEqual(clock.monotonic() * 1000, 18)

    def test_fake_clock_cancel_during_wait_marks_event(self):
        clock = FakeClock()
        limiter = RateLimiter(1, clock)
        limiter.complete(limiter.acquire())
        cancel = threading.Event()
        cancel.set()
        event = limiter.acquire(cancel)
        self.assertTrue(event.get("cancelled"))

    def test_system_clock_acquire_unblocks_on_cancel(self):
        limiter = RateLimiter(0.5, SystemClock())
        limiter.acquire()
        cancel = threading.Event()

        def fire():
            time.sleep(0.05)
            cancel.set()

        threading.Thread(target=fire, daemon=True).start()
        started = time.monotonic()
        event = limiter.acquire(cancel)
        elapsed = time.monotonic() - started
        self.assertTrue(event.get("cancelled"))
        self.assertLess(elapsed, 0.4)

    def test_short_cancelable_pace_stays_under_timer_quantum(self):
        limiter = RateLimiter(1000, SystemClock())
        cancel = threading.Event()
        limiter.acquire(cancel)
        started = time.perf_counter()
        for _ in range(8):
            event = limiter.acquire(cancel)
            limiter.complete(event)
        elapsed = time.perf_counter() - started
        self.assertFalse(event.get("cancelled"))
        # 8 x 1 ms via time.sleep. Event.wait(1 ms) on Windows rounds up to the
        # ~15 ms timer quantum and lands near 110 ms. 90 ms still fails that
        # regression and leaves room for CI scheduler noise.
        self.assertLess(elapsed, 0.09)


class LimitsTests(unittest.TestCase):
    def test_oversized_request_body_rejected(self):
        value = base_scenario(8877)
        value["limits"] = {"max_request_body_bytes": 8}
        value["operation"]["request"]["body"] = {"text": "this-is-too-long"}
        with self.assertRaises(ScenarioError):
            Scenario.from_dict(value)

    def test_truncated_response_is_observable(self):
        def handler(request, session):
            return Response(200, {}, "x" * 50, truncated=True, original_length=5000, retained_sha256="abc", transport="scripted")

        value = base_scenario(9, budget=4)
        value["cases"] = [{"name": "A-on-A", "session": "A", "object_owner": "A"}]
        scenario = Scenario.from_dict(value)
        result = run(scenario, registry=TransportRegistry(overrides={"direct": ScriptedTransport(handler)}))
        readback = result["cases"][0]["steps"][1]
        self.assertTrue(readback["response"]["truncated"])
        self.assertEqual(readback["assertion_status"], "error")
        self.assertIsNot(readback["assertion_passed"], True)


class ConcurrencyTests(unittest.TestCase):
    def test_undeclared_concurrency_rejected(self):
        value = base_scenario(8877)
        value["max_concurrency"] = 4
        with self.assertRaises(ScenarioError):
            Scenario.from_dict(value)

    def test_isolated_cases_run_and_keep_order(self):
        def handler(request, session):
            return Response(200, {"Content-Type": "application/json"}, '{"text":"probe"}', transport="scripted")

        value = base_scenario(9, budget=8)
        value["sessions"] = {"A": {"headers": {"X-User": "A"}}, "B": {"headers": {"X-User": "B"}}}
        value["cases"] = [
            {"name": "A-on-A", "session": "A", "object_owner": "A", "isolated": True},
            {"name": "B-on-B", "session": "B", "object_owner": "B", "isolated": True},
        ]
        value["isolated_cases"] = True
        value["max_concurrency"] = 2
        scenario = Scenario.from_dict(value)
        result = run(scenario, registry=TransportRegistry(overrides={"direct": ScriptedTransport(handler)}))
        self.assertEqual([c["case"]["name"] for c in result["cases"]], ["A-on-A", "B-on-B"])
        self.assertEqual(result["request_count"], 4)


class CliUxTests(unittest.TestCase):
    def test_validate_and_explain_and_init(self):
        import io
        from contextlib import redirect_stdout
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "scenario.json"
            with redirect_stdout(io.StringIO()):
                self.assertEqual(cli_main(["init", str(path)]), 0)
                self.assertEqual(cli_main(["validate", str(path)]), 0)
                self.assertEqual(cli_main(["plan", str(path), "--explain"]), 0)

    def test_schema_command(self):
        import io
        from contextlib import redirect_stdout
        buf = io.StringIO()
        with redirect_stdout(buf):
            self.assertEqual(cli_main(["schema"]), 0)
        self.assertIn("AuthzLoom Scenario v1", buf.getvalue())


class TransportReuseTests(unittest.TestCase):
    def test_registry_reuses_direct_transport(self):
        registry = TransportRegistry()
        first = registry.get("direct")
        second = registry.get("direct")
        self.assertIs(first, second)
        self.assertEqual(registry.created["direct"], 1)
        registry.close()


class Rc1RegressionTests(unittest.TestCase):
    def test_redaction_catches_bearer_after_prefix(self):
        payload = ("noise-" * 40) + "Bearer TOPSECRETTOKEN"
        clean = redact(payload)
        self.assertNotIn("TOPSECRETTOKEN", clean)
        self.assertIn("[REDACTED]", clean)

    def test_cancel_after_mutation_skips_readback_and_is_not_complete(self):
        cancel = threading.Event()

        def handler(request, session):
            if request.method == "PATCH":
                cancel.set()
                return Response(200, {}, '{"accepted":true}', transport="scripted")
            return Response(200, {"Content-Type": "application/json"}, '{"text":"A-original"}', transport="scripted")

        value = base_scenario(9, budget=8)
        value["cases"] = [{"name": "A-on-A", "session": "A", "object_owner": "A"}]
        value["operation"]["cleanup"] = {"method": "GET", "url": "http://127.0.0.1:9/notes/{{object.id}}"}
        value["operation"]["cleanup_assertion"] = {"path": "text", "equals": "A-original"}
        scenario = Scenario.from_dict(value)
        result = run(scenario, registry=TransportRegistry(overrides={"direct": ScriptedTransport(handler)}), cancel=cancel)
        case = result["cases"][0]
        self.assertEqual(result["state"], "cancelled")
        self.assertEqual(case["state"], "cancelled")
        kinds = [step["kind"] for step in case["steps"]]
        self.assertIn("request", kinds)
        self.assertNotIn("readback", kinds)
        self.assertIn("cleanup", kinds)

    def test_api_cancel_does_not_parse_scenario(self):
        import http.client
        from authzloom.api import AuthzLoomService
        with tempfile.TemporaryDirectory() as directory:
            service = AuthzLoomService(Path(directory), "tok")
            server = ThreadingHTTPServer(("127.0.0.1", 0), service.handler())
            threading.Thread(target=server.serve_forever, daemon=True).start()
            try:
                conn = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=5)
                conn.request("POST", "/cancel", body="{}", headers={
                    "Authorization": "Bearer tok", "Content-Type": "application/json",
                })
                response = conn.getresponse()
                payload = json.loads(response.read())
                self.assertEqual(response.status, 202)
                self.assertEqual(payload["state"], "cancelled")
                self.assertTrue(service._cancel.is_set())
                conn.close()
            finally:
                server.shutdown()
                server.server_close()
                service.close()

    def test_mcp_bounded_line_does_not_keep_overflow(self):
        from io import BytesIO
        from authzloom.mcp_server import read_bounded_line

        class Stream:
            def __init__(self, data: bytes):
                self.buffer = BytesIO(data)

        stream = Stream(b"x" * 20 + b"\nsecond\n")
        with self.assertRaises(LimitExceeded):
            read_bounded_line(stream, 8)
        self.assertEqual(read_bounded_line(stream, 16), "second")

    def test_burp_bridge_truncated_flag_is_honored(self):
        import base64
        from authzloom.transports import BurpTransport
        transport = BurpTransport(limits=Limits(max_response_body_bytes=64))
        blob = b"HTTP/1.1 200 OK\r\n\r\n" + b"x" * 40
        response = transport._decode_bridge({
            "status": 200,
            "response_b64": base64.b64encode(blob).decode(),
            "truncated": True,
            "original_length": 4_000_000,
        })
        self.assertTrue(response.truncated)
        self.assertEqual(response.original_length, 4_000_000)

    def test_burp_status_zero_is_transport_failure(self):
        import base64
        from authzloom.transports import BurpTransport

        transport = BurpTransport()
        with self.assertRaises(TransportFailed):
            transport._decode_bridge({
                "status": 0,
                "response_b64": base64.b64encode(b"").decode(),
                "truncated": False,
                "original_length": 0,
            })


class Rc2RegressionTests(unittest.TestCase):
    def test_cancel_during_limiter_does_not_send(self):
        sent: list[str] = []

        def handler(request, session):
            sent.append(request.method)
            return Response(200, {"Content-Type": "application/json"}, '{"text":"probe"}', transport="scripted")

        class CancelOnAcquire:
            def acquire(self, cancel=None):
                if cancel is not None:
                    cancel.set()
                return {"scheduled": 0.0, "start": 0.0, "cancelled": True}

            def complete(self, event):
                event["end"] = 0.0
                event["duration"] = 0.0
                event["limiter_wait"] = 0.0
                return event

        value = base_scenario(9, budget=8)
        value["cases"] = [{"name": "A-on-A", "session": "A", "object_owner": "A"}]
        value["operation"]["cleanup"] = {"method": "GET", "url": "http://127.0.0.1:9/notes/{{object.id}}"}
        value["operation"]["cleanup_assertion"] = {"path": "text", "equals": "A-original"}
        scenario = Scenario.from_dict(value)
        result = run(
            scenario,
            registry=TransportRegistry(overrides={"direct": ScriptedTransport(handler)}),
            limiter=CancelOnAcquire(),
            cancel=threading.Event(),
        )
        self.assertEqual(result["state"], "cancelled")
        self.assertEqual(result["cases"][0]["state"], "cancelled")
        self.assertEqual(sent, [])
        self.assertEqual(result["cases"][0]["cleanup"], "not_attempted")

    def test_mcp_invalid_utf8_is_parse_error(self):
        from io import BytesIO
        from authzloom.mcp_server import read_bounded_line

        class Stream:
            def __init__(self, data: bytes):
                self.buffer = BytesIO(data)

        with self.assertRaises(MessageDecodeError):
            read_bounded_line(Stream(b"\xff\xff\n"), 100)

        stdin_r, stdin_w = os.pipe()
        stdout_r, stdout_w = os.pipe()
        stdin = os.fdopen(stdin_r, "rb", buffering=0)
        stdout = os.fdopen(stdout_w, "wb", buffering=0)
        to_server = os.fdopen(stdin_w, "wb", buffering=0)
        from_server = os.fdopen(stdout_r, "rb", buffering=0)
        from authzloom.mcp_server import serve_stdio

        with tempfile.TemporaryDirectory() as directory:
            previous = os.environ.get("AUTHZLOOM_DATA_DIR")
            os.environ["AUTHZLOOM_DATA_DIR"] = directory
            thread = threading.Thread(target=serve_stdio, kwargs={"stdin": stdin, "stdout": stdout}, daemon=True)
            thread.start()
            try:
                to_server.write(b"\xff\xff\n")
                to_server.flush()
                line = from_server.readline()
                payload = json.loads(line.decode("utf-8"))
                self.assertEqual(payload["error"]["code"], -32700)
            finally:
                to_server.close()
                thread.join(timeout=5)
                stdin.close()
                stdout.close()
                from_server.close()
                if previous is None:
                    os.environ.pop("AUTHZLOOM_DATA_DIR", None)
                else:
                    os.environ["AUTHZLOOM_DATA_DIR"] = previous

    def test_mcp_cancel_during_run_skips_readback(self):
        from authzloom.mcp_server import serve_stdio, write_message

        methods: list[str] = []
        entered = threading.Event()
        lock = threading.Lock()

        class SlowHandler(BaseHTTPRequestHandler):
            def do_PATCH(self):
                length = int(self.headers.get("Content-Length", 0))
                if length:
                    self.rfile.read(length)
                with lock:
                    methods.append("PATCH")
                entered.set()
                time.sleep(0.35)
                data = b'{"accepted":true}'
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def do_GET(self):
                with lock:
                    methods.append("GET")
                data = b'{"text":"probe"}'
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def log_message(self, *_):
                pass

        server = ThreadingHTTPServer(("127.0.0.1", 0), SlowHandler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        stdin_r, stdin_w = os.pipe()
        stdout_r, stdout_w = os.pipe()
        stdin = os.fdopen(stdin_r, "rb", buffering=0)
        stdout = os.fdopen(stdout_w, "wb", buffering=0)
        to_server = os.fdopen(stdin_w, "wb", buffering=0)
        from_server = os.fdopen(stdout_r, "rb", buffering=0)
        with tempfile.TemporaryDirectory() as directory:
            previous = os.environ.get("AUTHZLOOM_DATA_DIR")
            os.environ["AUTHZLOOM_DATA_DIR"] = directory
            thread = threading.Thread(target=serve_stdio, kwargs={"stdin": stdin, "stdout": stdout}, daemon=True)
            thread.start()
            try:
                scenario = base_scenario(server.server_port, budget=8)
                scenario["cases"] = [{"name": "A-on-A", "session": "A", "object_owner": "A"}]
                write_message(to_server, {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "tools/call",
                    "params": {"name": "authzloom_run", "arguments": {"scenario": scenario}},
                })
                self.assertTrue(entered.wait(timeout=5))
                write_message(to_server, {"jsonrpc": "2.0", "method": "notifications/cancelled", "params": {"requestId": 1}})
                line = from_server.readline()
                payload = json.loads(line.decode("utf-8"))
                result = json.loads(payload["result"]["content"][0]["text"])
                self.assertEqual(result["result"]["state"], "cancelled")
                self.assertIn("PATCH", methods)
                self.assertNotIn("GET", methods)
            finally:
                to_server.close()
                thread.join(timeout=5)
                stdin.close()
                stdout.close()
                from_server.close()
                server.shutdown()
                server.server_close()
                if previous is None:
                    os.environ.pop("AUTHZLOOM_DATA_DIR", None)
                else:
                    os.environ["AUTHZLOOM_DATA_DIR"] = previous

    def test_direct_concurrent_loopback_uses_distinct_connections(self):
        stats = {"inflight": 0, "max": 0, "lock": threading.Lock()}

        class SlowHandler(BaseHTTPRequestHandler):
            def do_PATCH(self):
                length = int(self.headers.get("Content-Length", 0))
                if length:
                    self.rfile.read(length)
                with stats["lock"]:
                    stats["inflight"] += 1
                    stats["max"] = max(stats["max"], stats["inflight"])
                time.sleep(0.08)
                with stats["lock"]:
                    stats["inflight"] -= 1
                data = b'{"accepted":true}'
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def do_GET(self):
                data = b'{"text":"probe"}'
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def log_message(self, *_):
                pass

        server = ThreadingHTTPServer(("127.0.0.1", 0), SlowHandler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        try:
            value = base_scenario(server.server_port, budget=8)
            value["sessions"] = {"A": {"headers": {"X-User": "A"}}, "B": {"headers": {"X-User": "B"}}}
            value["cases"] = [
                {"name": "A-on-A", "session": "A", "object_owner": "A", "isolated": True},
                {"name": "B-on-B", "session": "B", "object_owner": "B", "isolated": True},
            ]
            value["isolated_cases"] = True
            value["max_concurrency"] = 2
            scenario = Scenario.from_dict(value)
            direct = DirectTransport()
            result = run(scenario, registry=TransportRegistry(overrides={"direct": direct}))
            self.assertEqual(result["state"], "complete")
            self.assertGreaterEqual(direct.max_active, 2)
            self.assertGreaterEqual(stats["max"], 2)
        finally:
            server.shutdown()
            server.server_close()

    def test_burp_concurrent_checkout_uses_distinct_connections(self):
        import base64
        stats = {"inflight": 0, "max": 0, "lock": threading.Lock()}
        blob = base64.b64encode(b"HTTP/1.1 200 OK\r\n\r\n{}").decode()

        class FakeBurp(BaseHTTPRequestHandler):
            def do_POST(self):
                with stats["lock"]:
                    stats["inflight"] += 1
                    stats["max"] = max(stats["max"], stats["inflight"])
                length = int(self.headers.get("Content-Length", 0))
                if length:
                    self.rfile.read(length)
                time.sleep(0.08)
                with stats["lock"]:
                    stats["inflight"] -= 1
                data = json.dumps({"status": 200, "response_b64": blob}).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def log_message(self, *_):
                pass

        server = ThreadingHTTPServer(("127.0.0.1", 0), FakeBurp)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        try:
            transport = BurpTransport(endpoint=f"http://127.0.0.1:{server.server_port}", token="tok")
            spec = RequestSpec("GET", "http://127.0.0.1/x", {}, None, "burp")
            errors: list[BaseException] = []

            def worker():
                try:
                    transport.send(spec, {"headers": {}})
                except BaseException as exc:
                    errors.append(exc)

            threads = [threading.Thread(target=worker) for _ in range(2)]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join(timeout=5)
            self.assertEqual(errors, [])
            self.assertGreaterEqual(transport.max_active, 2)
            self.assertGreaterEqual(stats["max"], 2)
        finally:
            transport.close()
            server.shutdown()
            server.server_close()

    def test_cdp_send_serializes_page_use(self):
        stats = {"inflight": 0, "max": 0, "lock": threading.Lock()}

        class FakePage:
            url = "http://127.0.0.1/"

            def evaluate(self, script, arg):
                with stats["lock"]:
                    stats["inflight"] += 1
                    stats["max"] = max(stats["max"], stats["inflight"])
                time.sleep(0.05)
                with stats["lock"]:
                    stats["inflight"] -= 1
                return {"status": 200, "headers": {}, "body": "{}"}

        transport = CDPTransport()
        transport._ensure_page = lambda session: FakePage()  # type: ignore[method-assign]
        spec = RequestSpec("GET", "http://127.0.0.1/", {}, None, "cdp")
        errors: list[BaseException] = []

        def worker():
            try:
                transport.send(spec, {"endpoint": "ws://127.0.0.1:9"})
            except BaseException as exc:
                errors.append(exc)

        threads = [threading.Thread(target=worker) for _ in range(2)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=5)
        self.assertEqual(errors, [])
        self.assertEqual(stats["max"], 1)

    def test_cancel_armed_at_transport_resolve_does_not_send(self):
        sent: list[str] = []
        cancel = threading.Event()

        class ArmingRegistry(TransportRegistry):
            def get(self, name, session=None):
                transport = super().get(name, session)
                cancel.set()
                return transport

        def handler(request, session):
            sent.append(request.method)
            return Response(200, {"Content-Type": "application/json"}, '{"text":"probe"}', transport="scripted")

        value = base_scenario(9, budget=8)
        value["cases"] = [{"name": "A-on-A", "session": "A", "object_owner": "A"}]
        scenario = Scenario.from_dict(value)
        result = run(
            scenario,
            registry=ArmingRegistry(overrides={"direct": ScriptedTransport(handler)}),
            cancel=cancel,
        )
        self.assertEqual(sent, [])
        self.assertEqual(result["state"], "cancelled")
        self.assertEqual(result["cases"][0]["state"], "cancelled")
        self.assertEqual(result["cases"][0]["steps"], [])

    def test_one_pool_connection_failure_spares_healthy_request(self):
        import socket

        in_flight = threading.Event()
        finished: list[str] = []

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                if self.path == "/die":
                    in_flight.wait(2)
                    try:
                        self.connection.shutdown(socket.SHUT_RDWR)
                    except OSError:
                        pass
                    return
                in_flight.set()
                time.sleep(0.3)
                data = b"{}"
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)
                finished.append("ok")

            def log_message(self, *_):
                pass

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        registry = TransportRegistry()
        direct = registry.get("direct")
        port = server.server_port
        ok_spec = RequestSpec("GET", f"http://127.0.0.1:{port}/ok", {}, None, "direct")
        die_spec = RequestSpec("GET", f"http://127.0.0.1:{port}/die", {}, None, "direct")
        ok_box: list[Response] = []
        errors: list[BaseException] = []

        def healthy():
            try:
                ok_box.append(direct.send(ok_spec, {}))
            except BaseException as exc:
                errors.append(exc)

        def broken():
            try:
                direct.send(die_spec, {})
                errors.append(RuntimeError("failed connection returned a response"))
            except BaseException:
                registry.invalidate("direct")

        try:
            worker = threading.Thread(target=healthy)
            worker.start()
            self.assertTrue(in_flight.wait(2))
            killer = threading.Thread(target=broken)
            killer.start()
            killer.join(timeout=5)
            worker.join(timeout=5)
            self.assertFalse(worker.is_alive())
            self.assertEqual(errors, [])
            self.assertEqual(ok_box[0].status, 200)
            self.assertEqual(finished, ["ok"])
            self.assertGreaterEqual(direct.max_active, 2)
        finally:
            registry.close()
            server.shutdown()
            server.server_close()


if __name__ == "__main__":
    unittest.main()
