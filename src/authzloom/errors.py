"""Typed errors shared by CLI, API, and MCP. Messages never include local paths, tokens, or traces."""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(slots=True)
class ErrorInfo:
    code: str
    message: str
    http_status: int = 400

    def to_dict(self) -> dict[str, str]:
        return {"error": self.code, "message": self.message}


class AuthzLoomError(Exception):
    code = "INTERNAL"
    http_status = 400
    public_message = "request failed"

    def __init__(self, message: str | None = None, *, code: str | None = None):
        self.public_message = message or self.public_message
        if code:
            self.code = code
        super().__init__(self.public_message)

    def to_dict(self) -> dict[str, str]:
        return {"error": self.code, "message": self.public_message}


class ScenarioError(AuthzLoomError, ValueError):
    """Invalid scenario. Kept as ValueError so existing callers keep working."""

    code = "SCENARIO_INVALID"
    public_message = "scenario is invalid"


class ScenarioInvalid(ScenarioError):
    pass


class PolicyViolation(ScenarioError):
    code = "POLICY_VIOLATION"
    public_message = "request violates the declared policy"


class IdentityMismatch(AuthzLoomError, RuntimeError):
    code = "IDENTITY_MISMATCH"
    public_message = "identity mismatch for session; run aborted"
    http_status = 409


class BudgetExhausted(AuthzLoomError, RuntimeError):
    code = "BUDGET_EXHAUSTED"
    public_message = "request budget exhausted"
    http_status = 429


class CaptureError(AuthzLoomError):
    code = "CAPTURE_STALE"
    public_message = "capture handle is stale, unknown, or identity-mismatched"
    http_status = 409


class LimitExceeded(AuthzLoomError):
    code = "LIMIT_EXCEEDED"
    public_message = "input or output exceeds configured limits"
    http_status = 413


class RunNotFound(AuthzLoomError):
    code = "RUN_NOT_FOUND"
    public_message = "unknown run"
    http_status = 404


class RunIncomplete(AuthzLoomError):
    code = "RUN_INCOMPLETE"
    public_message = "run is incomplete"
    http_status = 409


class Cancelled(AuthzLoomError):
    code = "CANCELLED"
    public_message = "run cancelled"
    http_status = 499


class MessageDecodeError(AuthzLoomError):
    code = "MESSAGE_DECODE"
    public_message = "parse error"
    http_status = 400


class RunInProgress(AuthzLoomError):
    code = "RUN_IN_PROGRESS"
    public_message = "another run is already active"
    http_status = 409


class TransportFailed(AuthzLoomError):
    code = "TRANSPORT_ERROR"
    public_message = "transport failed"
    http_status = 502


def public_error(exc: BaseException) -> dict[str, str]:
    if isinstance(exc, AuthzLoomError):
        return exc.to_dict()
    if isinstance(exc, RuntimeError) and "identity mismatch" in str(exc).lower():
        return IdentityMismatch().to_dict()
    if isinstance(exc, RuntimeError) and "budget" in str(exc).lower():
        return BudgetExhausted().to_dict()
    return {"error": "INTERNAL", "message": "request failed"}
