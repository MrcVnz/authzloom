from __future__ import annotations

import os
from dataclasses import dataclass


def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None or raw == "":
        return default
    value = int(raw)
    if value < 1:
        raise ValueError(f"{name} must be positive")
    return value


@dataclass(slots=True)
class Limits:
    max_request_body_bytes: int = 1_048_576
    max_response_body_bytes: int = 2_097_152
    max_capture_bytes: int = 1_048_576
    max_mcp_message_bytes: int = 1_048_576
    max_api_body_bytes: int = 1_048_576
    max_cases: int = 64
    max_objects: int = 32
    max_sessions: int = 16
    max_headers: int = 64
    max_header_value_bytes: int = 8_192
    max_run_bytes: int = 32 * 1024 * 1024
    max_ingested_captures: int = 32
    ingest_ttl_seconds: int = 3600
    max_url_bytes: int = 4_096
    max_placeholder_bytes: int = 256

    @classmethod
    def from_dict(cls, value: dict | None) -> "Limits":
        base = cls.from_env()
        if not value:
            return base
        allowed = {f.name for f in cls.__dataclass_fields__.values()}  # type: ignore[attr-defined]
        unknown = set(value) - allowed
        if unknown:
            raise ValueError(f"unknown limits field: {sorted(unknown)[0]}")
        data = {name: getattr(base, name) for name in allowed}
        for key, raw in value.items():
            data[key] = int(raw)
            if data[key] < 1:
                raise ValueError(f"limits.{key} must be positive")
        return cls(**data)

    @classmethod
    def from_env(cls) -> "Limits":
        return cls(
            max_request_body_bytes=_env_int("AUTHZLOOM_MAX_REQUEST_BODY", 1_048_576),
            max_response_body_bytes=_env_int("AUTHZLOOM_MAX_RESPONSE_BODY", 2_097_152),
            max_capture_bytes=_env_int("AUTHZLOOM_MAX_CAPTURE", 1_048_576),
            max_mcp_message_bytes=_env_int("AUTHZLOOM_MAX_MCP_MESSAGE", 1_048_576),
            max_api_body_bytes=_env_int("AUTHZLOOM_MAX_API_BODY", 1_048_576),
            max_cases=_env_int("AUTHZLOOM_MAX_CASES", 64),
            max_objects=_env_int("AUTHZLOOM_MAX_OBJECTS", 32),
            max_sessions=_env_int("AUTHZLOOM_MAX_SESSIONS", 16),
            max_headers=_env_int("AUTHZLOOM_MAX_HEADERS", 64),
            max_header_value_bytes=_env_int("AUTHZLOOM_MAX_HEADER_VALUE", 8_192),
            max_run_bytes=_env_int("AUTHZLOOM_MAX_RUN_BYTES", 32 * 1024 * 1024),
            max_ingested_captures=_env_int("AUTHZLOOM_MAX_INGESTED", 32),
            ingest_ttl_seconds=_env_int("AUTHZLOOM_INGEST_TTL", 3600),
            max_url_bytes=_env_int("AUTHZLOOM_MAX_URL", 4_096),
            max_placeholder_bytes=_env_int("AUTHZLOOM_MAX_PLACEHOLDER", 256),
        )
