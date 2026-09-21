"""Single validation path for every network-capable request, including identity probes."""
from __future__ import annotations

from urllib.parse import urlparse

from .errors import PolicyViolation, ScenarioError
from .limits import Limits
from .loopback import ALLOWED_SCHEMES, LOOPBACK_HOST_ALIASES, is_loopback_host_literal, parse_url
from .models import ALLOWED_TRANSPORTS, HEADER_NAME, PLACEHOLDER, FORBIDDEN_REQUEST_HEADERS, Policy, RequestSpec

OVERLAY_FORBIDDEN = {"authorization", "proxy-authorization", "cookie", "set-cookie", "host"}


def collect_placeholders(text: str) -> set[tuple[str, str]]:
    return {(match.group(1), match.group(2)) for match in PLACEHOLDER.finditer(text)}


def host_is_templated(url: str) -> bool:
    try:
        host = urlparse(url).hostname or ""
    except ValueError:
        host = ""
    if "{{" in host:
        return True
    # urlparse may keep the template in netloc
    return "{{" in url.split("://", 1)[-1].split("/", 1)[0]


def validate_headers(headers: dict[str, str], limits: Limits, *, overlay: bool = False) -> None:
    if len(headers) > limits.max_headers:
        raise ScenarioError("too many headers")
    for name, value in headers.items():
        if not HEADER_NAME.fullmatch(name) or any(ch in name for ch in "\r\n\x00"):
            raise ScenarioError("invalid header name")
        if any(ch in value for ch in "\r\n\x00") or len(value.encode("utf-8")) > limits.max_header_value_bytes:
            raise ScenarioError("invalid header value")
        lowered = name.lower()
        if lowered in FORBIDDEN_REQUEST_HEADERS:
            raise ScenarioError(f"{name} header is not allowed; it is derived from the URL")
        if overlay and lowered in OVERLAY_FORBIDDEN:
            raise PolicyViolation("overlay may not set credential or Host headers")


def validate_request(
    spec: RequestSpec,
    policy: Policy,
    limits: Limits,
    *,
    templates_ok: bool = False,
    where: str = "request",
) -> None:
    if spec.transport not in ALLOWED_TRANSPORTS:
        raise ScenarioError(f"unknown transport: {spec.transport}")
    if spec.transport not in policy.allowed_transports:
        raise PolicyViolation(f"transport outside scenario allowlist: {spec.transport}")
    if spec.method not in policy.allowed_methods:
        raise PolicyViolation(f"method outside scenario allowlist: {spec.method}")
    if len(spec.url.encode("utf-8")) > limits.max_url_bytes:
        raise ScenarioError("url exceeds size limit")
    validate_headers(spec.headers, limits)
    if spec.encoded_body_size() > limits.max_request_body_bytes:
        raise ScenarioError("request body exceeds size limit")
    templated = "{{" in spec.url
    if templated and not templates_ok:
        raise PolicyViolation("unresolved template placeholder")
    if templated and templates_ok:
        leftovers = spec.url
        for match in PLACEHOLDER.finditer(spec.url):
            leftovers = leftovers.replace(match.group(0), "x")
        if "{{" in leftovers or "}}" in leftovers:
            raise ScenarioError("malformed template placeholder")
        if host_is_templated(spec.url):
            scheme = spec.url.split(":", 1)[0].lower()
            if scheme not in ALLOWED_SCHEMES:
                raise PolicyViolation("only http and https schemes are allowed")
            return
    parsed, host, port = parse_url(spec.url)
    if host not in {item.lower() for item in policy.allowed_hosts}:
        raise PolicyViolation(f"host outside scenario allowlist: {host}")
    if policy.allowed_ports is not None and port not in policy.allowed_ports:
        raise PolicyViolation("port outside scenario allowlist")
    if spec.transport == "direct":
        if host not in LOOPBACK_HOST_ALIASES and not is_loopback_host_literal(host):
            raise PolicyViolation("direct transport is restricted to local labs; use Burp or CDP for live assets")
    _ = parsed
