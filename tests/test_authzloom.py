from __future__ import annotations

import json
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[1] / "src"))

from authzloom.executor import run
from authzloom.models import Scenario, ScenarioError
from authzloom.planner import plan
from authzloom.redact import redact
from authzloom.store import Store
from authzloom.mcp_server import bridge_token, dispatch, handle, initialize_result


class LabHandler(BaseHTTPRequestHandler):
    objects = {"a-note": {"owner": "A", "text": "A-original"}, "b-note": {"owner": "B", "text": "B-original"}}
    secure = False

    def reply(self, status, value):
        data = json.dumps(value).encode(); self.send_response(status); self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data))); self.end_headers(); self.wfile.write(data)

    def do_GET(self):
        user = self.headers.get("X-User")
        if self.path == "/me": return self.reply(200, {"id": user})
        if self.path.startswith("/notes/"):
            obj = self.objects[self.path.rsplit("/", 1)[-1]]
            if self.secure and user != obj["owner"]: return self.reply(403, {"error": "forbidden"})
            return self.reply(200, obj)
        self.reply(404, {})

    def do_PATCH(self):
        user = self.headers.get("X-User"); obj = self.objects[self.path.rsplit("/", 1)[-1]]
        body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))))
        if self.secure and user != obj["owner"]: return self.reply(403, {"error": "forbidden"})
        obj["text"] = body["text"]; self.reply(200, {"accepted": True})

    def do_POST(self):
        if self.path != "/graphql": return self.reply(404, {})
        body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))))
        obj = self.objects[body["variables"]["id"]]; user = self.headers.get("X-User")
        if self.secure and user != obj["owner"]: return self.reply(200, {"errors": [{"message": "forbidden"}]})
        obj["text"] = body["variables"]["text"]; self.reply(200, {"data": {"updateNote": {"ok": True}}})

    def log_message(self, *_): pass


def scenario(port: int, *, graphql=False, budget=12):
    url = f"http://127.0.0.1:{port}"
    request = ({"method": "POST", "url": url + "/graphql", "body": {"query": "mutation($id:ID!,$text:String!){updateNote(id:$id,text:$text){ok}}", "variables": {"id": "{{object.id}}", "text": "probe"}}}
               if graphql else {"method": "PATCH", "url": url + "/notes/{{object.id}}", "body": {"text": "probe"}})
    return {"policy": {"action_id": "A-TEST", "program": "lab", "asset": url, "allowed_hosts": ["127.0.0.1"],
            "aggression": 0, "max_requests": budget, "rate_per_second": 1000, "allowed_methods": ["GET", "PATCH", "POST"]},
            "sessions": {"A": {"headers": {"X-User": "A"}}, "B": {"headers": {"X-User": "B"}}, "none": {}},
            "objects": {"A": {"id": "a-note"}, "B": {"id": "b-note"}},
            "operation": {"request": request, "readback": {"method": "GET", "url": url + "/notes/{{object.id}}"},
                          "readback_assertion": {"path": "text", "equals": "probe"}}}


class AuthzLoomTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), LabHandler); cls.port = cls.server.server_port
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def setUp(self):
        LabHandler.secure = False
        LabHandler.objects = {"a-note": {"owner": "A", "text": "A-original"}, "b-note": {"owner": "B", "text": "B-original"}}

    def test_matrix_and_vulnerable_readback(self):
        result = run(Scenario.from_dict(scenario(self.port)))
        self.assertEqual([x["case"]["name"] for x in result["cases"]], ["A-on-A", "B-on-B", "B-on-A", "A-on-B", "none-on-A"])
        b_on_a = next(x for x in result["cases"] if x["case"]["name"] == "B-on-A")
        self.assertTrue(b_on_a["steps"][1]["assertion_passed"])

    def test_secure_control_blocks_cross_account(self):
        LabHandler.secure = True
        result = run(Scenario.from_dict(scenario(self.port)))
        b_on_a = next(x for x in result["cases"] if x["case"]["name"] == "B-on-A")
        self.assertEqual(b_on_a["steps"][0]["response"]["status"], 403)
        self.assertFalse(b_on_a["steps"][1]["assertion_passed"])

    def test_graphql_variables_are_swapped(self):
        result = run(Scenario.from_dict(scenario(self.port, graphql=True)))
        self.assertEqual(result["request_count"], 10)
        self.assertTrue(next(x for x in result["cases"] if x["case"]["name"] == "B-on-A")["steps"][1]["assertion_passed"])

    def test_budget_and_host_guards(self):
        with self.assertRaises(ScenarioError): plan(Scenario.from_dict(scenario(self.port, budget=3)))
        value = scenario(self.port); value["operation"]["request"]["url"] = "https://example.com/x"
        with self.assertRaises(ScenarioError): Scenario.from_dict(value)

    def test_mutation_requires_readback(self):
        value = scenario(self.port); del value["operation"]["readback"]
        with self.assertRaises(ScenarioError): Scenario.from_dict(value)

    def test_identity_mismatch_aborts_before_matrix(self):
        value = scenario(self.port, budget=13)
        value["sessions"]["A"]["identity_probe"] = {
            "request": {"method": "GET", "url": f"http://127.0.0.1:{self.port}/me"},
            "assertion": {"path": "id", "equals": "someone-else"}}
        with self.assertRaisesRegex(RuntimeError, "identity mismatch"):
            run(Scenario.from_dict(value))

    def test_redaction_and_store(self):
        clean = redact({"Authorization": "Bearer abc", "nested": {"csrf_token": "xyz"}})
        self.assertEqual(clean["Authorization"], "[REDACTED]")
        with tempfile.TemporaryDirectory() as directory:
            with Store(Path(directory)) as store:
                run_id = store.save({"action_id": "A", "request_count": 0, "cases": []})
                self.assertEqual(store.get(run_id)["action_id"], "A")

    def test_two_mcp_clients_can_open_the_same_store(self):
        with tempfile.TemporaryDirectory() as directory:
            with Store(Path(directory)) as first:
                with Store(Path(directory)) as second:
                    self.assertEqual(first.list(), [])
                    self.assertEqual(second.list(), [])

    def test_mcp_ingest_and_runtime_bridge_token(self):
        with tempfile.TemporaryDirectory() as directory:
            with Store(Path(directory)) as store:
                (store.root / "runtime-token").write_text("burp-runtime-token", encoding="ascii")
                self.assertEqual(bridge_token(store), "burp-runtime-token")
                clean = dispatch("authzloom_ingest", {"capture": {"Authorization": "Bearer live"}}, store)
                self.assertEqual(clean["Authorization"], "[REDACTED]")

    def test_mcp_export_never_returns_raw_secrets(self):
        with tempfile.TemporaryDirectory() as directory:
            with Store(Path(directory)) as store:
                run_id = store.save({
                    "action_id": "A", "request_count": 0, "cases": [],
                    "Authorization": "Bearer live",
                })
                clean = dispatch("authzloom_export", {"run_id": run_id}, store)
                self.assertEqual(clean["Authorization"], "[REDACTED]")

    def test_status_does_not_disclose_local_paths(self):
        with tempfile.TemporaryDirectory() as directory:
            with Store(Path(directory)) as store:
                store.save({"action_id": "A", "request_count": 0, "cases": []})
                self.assertNotIn("path", store.list()[0])

    def test_mcp_answers_the_capability_probes_cursor_sends(self):
        for method, key in (("resources/list", "resources"), ("prompts/list", "prompts")):
            self.assertEqual(handle({"method": method}, None), {key: []})

    def test_mcp_unknown_method_is_method_not_found(self):
        with self.assertRaises(LookupError):
            handle({"method": "sampling/createMessage"}, None)

    def test_mcp_initialize_negotiates_cursor_protocol(self):
        result = initialize_result({
            "params": {"protocolVersion": "2024-11-05"},
        })
        self.assertEqual(result["protocolVersion"], "2024-11-05")


if __name__ == "__main__": unittest.main()
