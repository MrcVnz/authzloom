from __future__ import annotations

import json
import re
from typing import Any

from .models import Assertion

STATUS_NOT_RUN = "not_run"
STATUS_PASSED = "passed"
STATUS_FAILED = "failed"
STATUS_ERROR = "error"

_INDEX = re.compile(r"^(0|[1-9][0-9]*)$")


def _walk(value: Any, segments: list[Any]) -> Any:
    for part in segments:
        if isinstance(value, list):
            if not isinstance(part, int):
                if not (isinstance(part, str) and _INDEX.fullmatch(part)):
                    raise KeyError(part)
                part = int(part)
            value = value[part]
        elif isinstance(value, dict):
            if part in value:
                value = value[part]
            elif str(part) in value:
                value = value[str(part)]
            else:
                raise KeyError(part)
        else:
            raise TypeError(part)
    return value


def path_segments(assertion: Assertion) -> list[Any]:
    if assertion.segments:
        return list(assertion.segments)
    if not assertion.path:
        return []
    parts: list[Any] = []
    for part in assertion.path.strip(".").split("."):
        if _INDEX.fullmatch(part):
            parts.append(int(part))
        else:
            parts.append(part)
    return parts


def evaluate(response_body: str, assertion: Assertion | None, *, truncated: bool = False) -> tuple[bool | None, str]:
    if assertion is None:
        return None, STATUS_NOT_RUN
    if truncated:
        return False, STATUS_ERROR
    try:
        value: Any = json.loads(response_body)
        parse_error = False
    except json.JSONDecodeError:
        value = response_body
        parse_error = True
    segments = path_segments(assertion)
    if segments:
        if parse_error:
            return False, STATUS_ERROR
        try:
            value = _walk(value, segments)
        except (KeyError, IndexError, TypeError, ValueError):
            return False, STATUS_FAILED
    passed = value == assertion.equals
    return passed, STATUS_PASSED if passed else STATUS_FAILED
