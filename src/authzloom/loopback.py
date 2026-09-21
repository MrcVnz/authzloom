"""Direct-transport containment: loopback addresses only, http(s) only, no userinfo, no redirect follow."""
from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlparse

from .errors import PolicyViolation, ScenarioError

ALLOWED_SCHEMES = {"http", "https"}
LOOPBACK_HOST_ALIASES = {"localhost", "127.0.0.1", "::1", "0:0:0:0:0:0:0:1"}


def parse_url(url: str):
    if not isinstance(url, str) or not url:
        raise ScenarioError("url is required")
    if any(ch in url for ch in ("\\", " ", "\t", "\r", "\n", "\x00")):
        raise PolicyViolation("url contains ambiguous characters")
    parsed = urlparse(url)
    if parsed.scheme.lower() not in ALLOWED_SCHEMES:
        raise PolicyViolation("only http and https schemes are allowed")
    if parsed.username is not None or parsed.password is not None:
        raise PolicyViolation("urls must not contain userinfo")
    if "@" in (parsed.netloc or ""):
        raise PolicyViolation("urls must not contain userinfo")
    host = (parsed.hostname or "").lower()
    if not host:
        raise PolicyViolation("url host is missing")
    port = parsed.port
    if port is None:
        port = 443 if parsed.scheme.lower() == "https" else 80
    if not 1 <= port <= 65535:
        raise PolicyViolation("url port is invalid")
    return parsed, host, port


def is_loopback_host_literal(host: str) -> bool:
    lowered = host.lower().strip("[]")
    if lowered in LOOPBACK_HOST_ALIASES:
        return True
    try:
        return ipaddress.ip_address(lowered).is_loopback
    except ValueError:
        return False


def resolve_loopback_address(host: str, port: int) -> tuple[str, int, int]:
    """Return (ip, port, address_family) after proving every resolved address is loopback."""
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise PolicyViolation("direct host could not be resolved as loopback") from exc
    if not infos:
        raise PolicyViolation("direct host could not be resolved as loopback")
    chosen = None
    for family, _, _, _, sockaddr in infos:
        ip_text = sockaddr[0]
        try:
            ip = ipaddress.ip_address(ip_text)
        except ValueError as exc:
            raise PolicyViolation("direct host resolved to an invalid address") from exc
        if ip.version == 6 and getattr(ip, "ipv4_mapped", None) is not None and ip.ipv4_mapped is not None:
            ip = ip.ipv4_mapped
            ip_text = str(ip)
        if not ip.is_loopback:
            raise PolicyViolation("direct transport is restricted to loopback laboratories")
        if chosen is None:
            chosen = (ip_text, sockaddr[1] if len(sockaddr) > 1 else port, family)
    assert chosen is not None
    return chosen


def assert_direct_destination(url: str) -> tuple[str, str, int, str]:
    """Validate a fully expanded URL for direct transport. Returns scheme, host, port, path+query."""
    parsed, host, port = parse_url(url)
    if not is_loopback_host_literal(host):
        # Still allow names that resolve exclusively to loopback, but never a non-loopback literal.
        try:
            ipaddress.ip_address(host.strip("[]"))
            raise PolicyViolation("direct transport is restricted to loopback laboratories")
        except ValueError:
            pass
    resolve_loopback_address(host, port)
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query
    return parsed.scheme.lower(), host, port, path
