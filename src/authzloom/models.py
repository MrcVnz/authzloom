from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any

from .errors import PolicyViolation, ScenarioError
from .limits import Limits

SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}
ALLOWED_TRANSPORTS = ("direct", "burp", "cdp")
ALLOWED_METHODS = ("GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE")
PLACEHOLDER = re.compile(r"\{\{([A-Za-z_][A-Za-z0-9_]*)\.([A-Za-z_][A-Za-z0-9_]*)\}\}")
HEADER_NAME = re.compile(r"^[A-Za-z0-9!#$%&'*+.^_`|~-]+$")
CREDENTIAL_HEADER = re.compile(r"^(authorization|proxy-authorization|cookie|set-cookie|x-api-key|api-key)$", re.I)
CREDENTIAL_KEY = re.compile(r"(access_token|refresh_token|id_token|password|secret|authorization|cookie|api[_-]?key)", re.I)
BEARER_OR_JWT = re.compile(r"(?i)(bearer\s+[A-Za-z0-9._~+/=-]+|eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)")
CAPTURE_HANDLE = re.compile(r"^cap_[A-Za-z0-9_-]{8,64}$")
KNOWN_ROOT = {"policy", "sessions", "objects", "operation", "cases", "irreversible", "max_concurrency", "isolated_cases", "limits"}
KNOWN_POLICY = {
    "action_id", "program", "asset", "allowed_hosts", "aggression", "max_requests",
    "rate_per_second", "allowed_methods", "allow_irreversible", "allowed_ports",
    "allowed_transports", "max_concurrency", "isolated_cases",
}
KNOWN_REQUEST = {"method", "url", "headers", "body", "transport"}
KNOWN_ASSERTION = {"path", "equals", "segments"}
KNOWN_OPERATION = {"request", "readback", "readback_assertion", "cleanup", "cleanup_assertion"}
KNOWN_SESSION = {"headers", "identity_probe", "capture_handle", "endpoint", "page_host"}
KNOWN_PROBE = {"request", "assertion"}
KNOWN_CASE = {"name", "session", "object_owner", "isolated"}
FORBIDDEN_REQUEST_HEADERS = {"host", "content-length"}


def _reject_unknown(value: dict[str, Any], allowed: set[str], where: str) -> None:
    unknown = set(value) - allowed
    if unknown:
        raise ScenarioError(f"unknown field in {where}: {sorted(unknown)[0]}")


def _as_str_dict(value: Any, where: str) -> dict[str, str]:
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise ScenarioError(f"{where} must be an object")
    return {str(k): str(v) for k, v in value.items()}


@dataclass(slots=True)
class RequestSpec:
    method: str
    url: str
    headers: dict[str, str] = field(default_factory=dict)
    body: Any = None
    transport: str = "direct"

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "RequestSpec":
        if not isinstance(value, dict):
            raise ScenarioError("request must be an object")
        _reject_unknown(value, KNOWN_REQUEST, "request")
        if "url" not in value:
            raise ScenarioError("request url is required")
        return cls(
            method=str(value.get("method", "GET")).upper(),
            url=str(value["url"]),
            headers=_as_str_dict(value.get("headers"), "headers"),
            body=value.get("body"),
            transport=str(value.get("transport", "direct")).lower(),
        )

    def encoded_body_size(self) -> int:
        if self.body is None:
            return 0
        if isinstance(self.body, bytes):
            return len(self.body)
        if isinstance(self.body, (dict, list)):
            return len(json.dumps(self.body).encode("utf-8"))
        return len(str(self.body).encode("utf-8"))


@dataclass(slots=True)
class Assertion:
    path: str = ""
    equals: Any = None
    segments: list[Any] = field(default_factory=list)

    @classmethod
    def from_dict(cls, value: dict[str, Any] | None) -> "Assertion | None":
        if value is None:
            return None
        if not isinstance(value, dict):
            raise ScenarioError("assertion must be an object")
        _reject_unknown(value, KNOWN_ASSERTION, "assertion")
        segments = list(value["segments"]) if value.get("segments") else []
        return cls(str(value.get("path", "")), value.get("equals"), segments)


@dataclass(slots=True)
class IdentityProbe:
    request: RequestSpec
    assertion: Assertion | None = None

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "IdentityProbe":
        if not isinstance(value, dict):
            raise ScenarioError("identity_probe must be an object")
        _reject_unknown(value, KNOWN_PROBE, "identity_probe")
        if "request" not in value:
            raise ScenarioError("identity_probe.request is required")
        return cls(RequestSpec.from_dict(value["request"]), Assertion.from_dict(value.get("assertion")))


@dataclass(slots=True)
class Session:
    headers: dict[str, str] = field(default_factory=dict)
    identity_probe: IdentityProbe | None = None
    capture_handle: str | None = None
    endpoint: str | None = None
    page_host: str | None = None

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "Session":
        if not isinstance(value, dict):
            raise ScenarioError("session must be an object")
        _reject_unknown(value, KNOWN_SESSION, "session")
        handle = value.get("capture_handle")
        if handle is not None:
            handle = str(handle)
            if not CAPTURE_HANDLE.fullmatch(handle):
                raise ScenarioError("capture_handle is invalid")
        probe = IdentityProbe.from_dict(value["identity_probe"]) if value.get("identity_probe") else None
        return cls(
            headers=_as_str_dict(value.get("headers"), "session.headers"),
            identity_probe=probe,
            capture_handle=handle,
            endpoint=str(value["endpoint"]) if value.get("endpoint") else None,
            page_host=str(value["page_host"]) if value.get("page_host") else None,
        )

    def as_runtime(self) -> dict[str, Any]:
        data: dict[str, Any] = {"headers": dict(self.headers)}
        if self.capture_handle:
            data["capture_handle"] = self.capture_handle
        if self.endpoint:
            data["endpoint"] = self.endpoint
        if self.page_host:
            data["page_host"] = self.page_host
        return data

    def template_dict(self) -> dict[str, Any]:
        return {"headers": dict(self.headers)}


@dataclass(slots=True)
class Operation:
    request: RequestSpec
    readback: RequestSpec | None = None
    readback_assertion: Assertion | None = None
    cleanup: RequestSpec | None = None
    cleanup_assertion: Assertion | None = None

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "Operation":
        if not isinstance(value, dict):
            raise ScenarioError("operation must be an object")
        _reject_unknown(value, KNOWN_OPERATION, "operation")
        if "request" not in value:
            raise ScenarioError("operation.request is required")
        return cls(
            request=RequestSpec.from_dict(value["request"]),
            readback=RequestSpec.from_dict(value["readback"]) if value.get("readback") else None,
            readback_assertion=Assertion.from_dict(value.get("readback_assertion")),
            cleanup=RequestSpec.from_dict(value["cleanup"]) if value.get("cleanup") else None,
            cleanup_assertion=Assertion.from_dict(value.get("cleanup_assertion")),
        )


@dataclass(slots=True)
class Policy:
    action_id: str
    program: str
    asset: str
    allowed_hosts: list[str]
    aggression: int = 0
    max_requests: int = 20
    rate_per_second: float = 2.0
    allowed_methods: list[str] = field(default_factory=lambda: ["GET", "POST", "PUT", "PATCH", "DELETE"])
    allow_irreversible: bool = False
    allowed_ports: list[int] | None = None
    allowed_transports: list[str] = field(default_factory=lambda: list(ALLOWED_TRANSPORTS))
    max_concurrency: int = 1
    isolated_cases: bool = False

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "Policy":
        if not isinstance(value, dict):
            raise ScenarioError("policy must be an object")
        _reject_unknown(value, KNOWN_POLICY, "policy")
        for key in ("action_id", "program", "asset", "allowed_hosts"):
            if key not in value:
                raise ScenarioError(f"policy.{key} is required")
        hosts = [str(x).lower() for x in value["allowed_hosts"]]
        if not hosts:
            raise ScenarioError("allowed_hosts must not be empty")
        methods = [str(x).upper() for x in value.get("allowed_methods", ["GET", "POST", "PUT", "PATCH", "DELETE"])]
        if not methods:
            raise ScenarioError("allowed_methods must not be empty")
        for method in methods:
            if method not in ALLOWED_METHODS:
                raise ScenarioError(f"unsupported method: {method}")
        transports = [str(x).lower() for x in value.get("allowed_transports", list(ALLOWED_TRANSPORTS))]
        if not transports:
            raise ScenarioError("allowed_transports must not be empty")
        for transport in transports:
            if transport not in ALLOWED_TRANSPORTS:
                raise ScenarioError(f"unknown transport: {transport}")
        ports = [int(x) for x in value["allowed_ports"]] if value.get("allowed_ports") is not None else None
        if ports is not None:
            if not ports:
                raise ScenarioError("allowed_ports must not be empty when set")
            for port in ports:
                if not 1 <= port <= 65535:
                    raise ScenarioError("allowed_ports contains an invalid port")
        policy = cls(
            action_id=str(value["action_id"]),
            program=str(value["program"]),
            asset=str(value["asset"]),
            allowed_hosts=hosts,
            aggression=int(value.get("aggression", 0)),
            max_requests=int(value.get("max_requests", 20)),
            rate_per_second=float(value.get("rate_per_second", 2.0)),
            allowed_methods=methods,
            allow_irreversible=bool(value.get("allow_irreversible", False)),
            allowed_ports=ports,
            allowed_transports=transports,
            max_concurrency=int(value.get("max_concurrency", 1)),
            isolated_cases=bool(value.get("isolated_cases", False)),
        )
        if not 0 <= policy.aggression <= 3:
            raise ScenarioError("aggression must be between 0 and 3")
        if policy.max_requests < 1 or policy.rate_per_second <= 0:
            raise ScenarioError("request budget and rate must be positive")
        if policy.max_concurrency < 1:
            raise ScenarioError("max_concurrency must be at least 1")
        return policy


@dataclass(slots=True)
class CaseSpec:
    name: str
    session: str
    object_owner: str
    isolated: bool = False

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "CaseSpec":
        if not isinstance(value, dict):
            raise ScenarioError("case must be an object")
        _reject_unknown(value, KNOWN_CASE, "case")
        for key in ("name", "session", "object_owner"):
            if key not in value:
                raise ScenarioError(f"case.{key} is required")
        return cls(str(value["name"]), str(value["session"]), str(value["object_owner"]), bool(value.get("isolated", False)))


@dataclass(slots=True)
class Scenario:
    policy: Policy
    sessions: dict[str, Session]
    objects: dict[str, dict[str, Any]]
    operation: Operation
    cases: list[CaseSpec] = field(default_factory=list)
    irreversible: bool = False
    limits: Limits = field(default_factory=Limits)

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "Scenario":
        if not isinstance(value, dict):
            raise ScenarioError("scenario must be an object")
        _reject_unknown(value, KNOWN_ROOT, "scenario")
        for key in ("policy", "sessions", "objects", "operation"):
            if key not in value:
                raise ScenarioError(f"{key} is required")
        if not isinstance(value["sessions"], dict) or not isinstance(value["objects"], dict):
            raise ScenarioError("sessions and objects must be objects")
        sessions = {str(name): Session.from_dict(body) for name, body in value["sessions"].items()}
        objects = {str(name): dict(body) for name, body in value["objects"].items()}
        raw_cases = value.get("cases") or []
        cases = [CaseSpec.from_dict(item) for item in raw_cases]
        max_concurrency = int(value["max_concurrency"]) if "max_concurrency" in value else None
        isolated_cases = bool(value["isolated_cases"]) if "isolated_cases" in value else None
        obj = cls(
            Policy.from_dict(value["policy"]),
            sessions,
            objects,
            Operation.from_dict(value["operation"]),
            cases,
            bool(value.get("irreversible", False)),
            Limits.from_dict(value.get("limits")),
        )
        if max_concurrency is not None:
            obj.policy.max_concurrency = max_concurrency
            if obj.policy.max_concurrency < 1:
                raise ScenarioError("max_concurrency must be at least 1")
        if isolated_cases is not None:
            obj.policy.isolated_cases = isolated_cases
        obj.validate()
        return obj

    def iter_request_specs(self) -> list[tuple[str, RequestSpec]]:
        specs: list[tuple[str, RequestSpec]] = [("operation", self.operation.request)]
        if self.operation.readback:
            specs.append(("readback", self.operation.readback))
        if self.operation.cleanup:
            specs.append(("cleanup", self.operation.cleanup))
        for name, session in self.sessions.items():
            if session.identity_probe:
                specs.append((f"identity_probe:{name}", session.identity_probe.request))
        return specs

    def validate(self) -> None:
        from .policy import collect_placeholders, validate_request

        if self.irreversible and not self.policy.allow_irreversible:
            raise ScenarioError("irreversible operation is not explicitly authorized")
        if len(self.sessions) > self.limits.max_sessions:
            raise ScenarioError("too many sessions")
        if len(self.objects) > self.limits.max_objects:
            raise ScenarioError("too many objects")
        if len(self.cases) > self.limits.max_cases:
            raise ScenarioError("too many cases")
        if not self.sessions or not self.objects:
            raise ScenarioError("sessions and objects must not be empty")
        names = [case.name for case in self.cases]
        if len(names) != len(set(names)):
            raise ScenarioError("duplicate case name")
        for case in self.cases:
            if case.session not in self.sessions:
                raise ScenarioError(f"unknown session reference: {case.session}")
            if case.object_owner not in self.objects:
                raise ScenarioError(f"unknown object reference: {case.object_owner}")
        if self.policy.max_concurrency > 1 and not self.policy.isolated_cases:
            raise ScenarioError("max_concurrency > 1 requires isolated_cases")
        if self.policy.isolated_cases:
            owners = [case.object_owner for case in self.cases] if self.cases else list(self.objects)
            if len(owners) != len(set(owners)) and self.cases:
                raise ScenarioError("isolated cases may not share object_owner")
        if self.operation.request.method not in SAFE_METHODS and not self.operation.readback:
            raise ScenarioError("state-changing operations require readback")
        if self.operation.cleanup and not self.operation.cleanup_assertion:
            raise ScenarioError("cleanup requires a confirmation assertion")
        if self.operation.cleanup_assertion and not self.operation.cleanup:
            raise ScenarioError("cleanup_assertion requires cleanup")
        blobs: list[str] = []
        for where, spec in self.iter_request_specs():
            validate_request(spec, self.policy, self.limits, templates_ok=True, where=where)
            blobs.append(spec.url)
            blobs.extend(spec.headers.values())
            if isinstance(spec.body, str):
                blobs.append(spec.body)
            elif spec.body is not None:
                blobs.append(json.dumps(spec.body))
        placeholders = collect_placeholders("\n".join(blobs))
        for root, key in placeholders:
            if root == "object":
                for name, obj in self.objects.items():
                    if key not in obj:
                        raise ScenarioError(f"unresolved object placeholder {key} on {name}")
            elif root == "session":
                if key != "headers":
                    raise ScenarioError(f"unknown session placeholder: {key}")
            else:
                raise ScenarioError(f"unknown template root: {root}")
        for session in self.sessions.values():
            _reject_credentials(session.headers, "session.headers")
            if session.capture_handle and session.identity_probe:
                # both allowed: probe still has to be a validated request
                pass
        _reject_embedded_secrets(self)


def _reject_credentials(headers: dict[str, str], where: str) -> None:
    for name, value in headers.items():
        if CREDENTIAL_HEADER.match(name):
            raise ScenarioError(f"credentials must not be stored in {where}")
        if BEARER_OR_JWT.search(value):
            raise ScenarioError(f"credentials must not be stored in {where}")


def _walk_for_secrets(value: Any, key: str = "") -> None:
    if CREDENTIAL_KEY.search(key) and value not in (None, "", "[REDACTED]"):
        raise ScenarioError("credentials must not be stored in the scenario")
    if isinstance(value, dict):
        for child_key, child in value.items():
            _walk_for_secrets(child, str(child_key))
        return
    if isinstance(value, list):
        for child in value:
            _walk_for_secrets(child)
        return
    if isinstance(value, str) and BEARER_OR_JWT.search(value):
        raise ScenarioError("credentials must not be stored in the scenario")


def _reject_embedded_secrets(scenario: Scenario) -> None:
    for _, spec in scenario.iter_request_specs():
        _reject_credentials(spec.headers, "request.headers")
        _walk_for_secrets(spec.body)
        if "@" in spec.url.split("://", 1)[-1].split("/", 1)[0]:
            raise ScenarioError("credentials must not be stored in the scenario")
    for obj in scenario.objects.values():
        _walk_for_secrets(obj)
