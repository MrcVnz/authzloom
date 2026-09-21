from __future__ import annotations

import json
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any

from .assertions import STATUS_ERROR, STATUS_NOT_RUN, evaluate
from .budget import Budget
from .errors import BudgetExhausted, Cancelled, IdentityMismatch
from .models import Assertion, RequestSpec, Scenario
from .pacer import RateLimiter
from .planner import Case, plan
from .policy import validate_request
from .transports import Response, TransportRegistry

CLEANUP_PASSED = "passed"
CLEANUP_FAILED = "failed"
CLEANUP_NOT_ATTEMPTED = "not_attempted"
STATE_RUNNING = "running"
STATE_CLEANUP_PENDING = "cleanup_pending"
STATE_COMPLETE = "complete"
STATE_FAILED = "failed"
STATE_CANCELLED = "cancelled"
STATE_INCOMPLETE = "incomplete"


def _expand(value: Any, context: dict[str, Any]) -> Any:
    if isinstance(value, dict):
        return {k: _expand(v, context) for k, v in value.items()}
    if isinstance(value, list):
        return [_expand(v, context) for v in value]
    if not isinstance(value, str):
        return value
    for root_name, root in context.items():
        if isinstance(root, dict):
            for key, replacement in root.items():
                value = value.replace("{{" + root_name + "." + key + "}}", str(replacement))
    return value


def materialize(spec: RequestSpec, case: Case, scenario: Scenario) -> RequestSpec:
    session = scenario.sessions[case.session]
    context = {"object": dict(scenario.objects[case.object_owner]), "session": session.template_dict()}
    url = _expand(spec.url, context)
    headers = _expand(spec.headers, context)
    body = _expand(spec.body, context)
    text_blobs = [url if isinstance(url, str) else ""]
    if isinstance(headers, dict):
        text_blobs.extend(str(v) for v in headers.values())
    if isinstance(body, str):
        text_blobs.append(body)
    if any("{{" in blob for blob in text_blobs):
        _unresolved()
    return RequestSpec(spec.method, url, headers, body, spec.transport)


def _unresolved():
    from .errors import PolicyViolation
    raise PolicyViolation("unresolved template placeholder")


def _graphql_meta(response: Response) -> dict[str, Any] | None:
    try:
        payload = json.loads(response.body)
    except json.JSONDecodeError:
        return None
    if not isinstance(payload, dict):
        return None
    if "data" not in payload and "errors" not in payload:
        return None
    return {"http_status": response.status, "errors": payload.get("errors")}


def _step(
    kind: str,
    spec: RequestSpec,
    response: Response,
    assertion: Assertion | None,
    timings: dict[str, float],
) -> dict[str, Any]:
    passed, status = evaluate(response.body, assertion, truncated=response.truncated)
    if assertion is not None and response.truncated:
        passed, status = False, STATUS_ERROR
    item: dict[str, Any] = {
        "kind": kind,
        "request": {"method": spec.method, "url": spec.url, "headers": spec.headers, "body": spec.body, "transport": spec.transport},
        "response": {
            "status": response.status,
            "headers": response.headers,
            "body": response.body,
            "truncated": response.truncated,
            "original_length": response.original_length,
            "retained_sha256": response.retained_sha256,
        },
        "assertion_passed": passed,
        "assertion_status": status if assertion is not None else STATUS_NOT_RUN,
        "timings": timings,
        "transport": response.transport or spec.transport,
    }
    gql = _graphql_meta(response)
    if gql is not None:
        item["graphql"] = gql
    return item


def _prepare(spec: RequestSpec, case: Case, scenario: Scenario, budget: Budget) -> RequestSpec:
    materialized = materialize(spec, case, scenario)
    validate_request(materialized, scenario.policy, scenario.limits, templates_ok=False)
    budget.consume()
    return materialized


def _cancelled(cancel: threading.Event | None, event: dict[str, float] | None) -> bool:
    if cancel is None:
        return False
    if event is not None and event.get("cancelled"):
        return True
    return cancel.is_set()


def _dispatch(
    materialized: RequestSpec,
    case: Case,
    scenario: Scenario,
    registry: TransportRegistry,
    limiter: RateLimiter,
    cancel: threading.Event | None = None,
    *,
    ignore_cancel: bool = False,
) -> tuple[Response, dict[str, float]]:
    event = limiter.acquire(None if ignore_cancel else cancel)
    try:
        if not ignore_cancel and _cancelled(cancel, event):
            cancel.set()
            raise Cancelled("run cancelled")
        session = scenario.sessions[case.session]
        transport = registry.get(materialized.transport, session.as_runtime())
        if not ignore_cancel and _cancelled(cancel, None):
            cancel.set()
            raise Cancelled("run cancelled")
        response = transport.send(materialized, session.as_runtime())
        return response, limiter.complete(event)
    except Cancelled:
        limiter.complete(event)
        raise
    except Exception:
        limiter.complete(event)
        registry.invalidate(materialized.transport)
        raise


def _send(
    spec: RequestSpec,
    case: Case,
    scenario: Scenario,
    registry: TransportRegistry,
    limiter: RateLimiter,
    budget: Budget,
    cancel: threading.Event | None = None,
    *,
    ignore_cancel: bool = False,
) -> tuple[RequestSpec, Response, dict[str, float]]:
    materialized = _prepare(spec, case, scenario, budget)
    response, timings = _dispatch(
        materialized, case, scenario, registry, limiter, cancel, ignore_cancel=ignore_cancel,
    )
    return materialized, response, timings


def _run_case(
    case: Case,
    scenario: Scenario,
    registry: TransportRegistry,
    limiter: RateLimiter,
    budget: Budget,
    cancel: threading.Event,
) -> dict[str, Any]:
    item: dict[str, Any] = {
        "case": {"name": case.name, "session": case.session, "object_owner": case.object_owner},
        "steps": [],
        "state": STATE_RUNNING,
        "cleanup": CLEANUP_NOT_ATTEMPTED,
    }
    mutation_sent = False
    interrupted = False
    primary: BaseException | None = None
    try:
        if cancel.is_set():
            item["state"] = STATE_CANCELLED
            return item
        materialized = _prepare(scenario.operation.request, case, scenario, budget)
        try:
            response, timings = _dispatch(materialized, case, scenario, registry, limiter, cancel)
        except Cancelled:
            interrupted = True
            item["state"] = STATE_CANCELLED
            return item
        except Exception:
            mutation_sent = True
            raise
        mutation_sent = True
        item["steps"].append(_step("request", materialized, response, None, timings))
        if scenario.operation.readback:
            if cancel.is_set():
                interrupted = True
            else:
                try:
                    rb_spec, rb_response, rb_timings = _send(
                        scenario.operation.readback, case, scenario, registry, limiter, budget, cancel,
                    )
                    item["steps"].append(_step("readback", rb_spec, rb_response, scenario.operation.readback_assertion, rb_timings))
                    if cancel.is_set():
                        interrupted = True
                except Cancelled:
                    interrupted = True
        if interrupted:
            item["state"] = STATE_CLEANUP_PENDING if scenario.operation.cleanup else STATE_CANCELLED
        else:
            item["state"] = STATE_CLEANUP_PENDING if scenario.operation.cleanup else STATE_COMPLETE
    except Exception as exc:
        if isinstance(exc, Cancelled):
            interrupted = True
            item["state"] = STATE_CANCELLED
        else:
            primary = exc
            item["state"] = STATE_FAILED
            from .errors import public_error
            item["error"] = public_error(exc)
    finally:
        if mutation_sent and scenario.operation.cleanup:
            try:
                cl_spec, cl_response, cl_timings = _send(
                    scenario.operation.cleanup, case, scenario, registry, limiter, budget, cancel,
                    ignore_cancel=True,
                )
                step = _step("cleanup", cl_spec, cl_response, scenario.operation.cleanup_assertion, cl_timings)
                item["steps"].append(step)
                if step["assertion_passed"] is True:
                    item["cleanup"] = CLEANUP_PASSED
                else:
                    item["cleanup"] = CLEANUP_FAILED
                    item["cleanup_failed"] = True
            except Exception as cl_exc:
                item["cleanup"] = CLEANUP_FAILED
                item["cleanup_failed"] = True
                from .errors import public_error
                item["cleanup_error"] = public_error(cl_exc)
        if primary is not None:
            item["state"] = STATE_FAILED
        elif interrupted or (cancel.is_set() and mutation_sent):
            item["state"] = STATE_FAILED if item["cleanup"] == CLEANUP_FAILED else STATE_CANCELLED
        elif item["state"] == STATE_CLEANUP_PENDING:
            item["state"] = STATE_COMPLETE if item["cleanup"] != CLEANUP_FAILED else STATE_FAILED
        elif cancel.is_set() and item["state"] == STATE_RUNNING:
            item["state"] = STATE_CANCELLED
    if primary is not None and isinstance(primary, (BudgetExhausted, IdentityMismatch)):
        item["_raise"] = primary
    return item


def _identity_probes(
    cases: list[Case],
    scenario: Scenario,
    registry: TransportRegistry,
    limiter: RateLimiter,
    budget: Budget,
    cancel: threading.Event,
) -> int:
    checked: set[str] = set()
    count = 0
    for case in cases:
        if cancel.is_set():
            raise Cancelled("run cancelled")
        session = scenario.sessions[case.session]
        probe = session.identity_probe
        if not probe or case.session in checked:
            continue
        materialized, response, _timings = _send(probe.request, case, scenario, registry, limiter, budget, cancel)
        count += 1
        passed, _status = evaluate(response.body, probe.assertion, truncated=response.truncated)
        if passed is not True:
            raise IdentityMismatch(f"identity mismatch for session {case.session}; run aborted")
        checked.add(case.session)
        _ = materialized
    return count


def run(
    scenario: Scenario,
    *,
    burp_token: str = "",
    registry: TransportRegistry | None = None,
    limiter: RateLimiter | None = None,
    cancel: threading.Event | None = None,
) -> dict[str, Any]:
    cases = plan(scenario)
    cancel = cancel or threading.Event()
    limiter = limiter or RateLimiter(scenario.policy.rate_per_second)
    budget = Budget(scenario.policy.max_requests)
    owned = registry is None
    registry = registry or TransportRegistry(burp_token, scenario.limits)
    state = STATE_RUNNING
    results: list[dict[str, Any]] = []
    try:
        _identity_probes(cases, scenario, registry, limiter, budget, cancel)
        max_workers = scenario.policy.max_concurrency
        if max_workers <= 1 or len(cases) <= 1:
            for case in cases:
                if cancel.is_set():
                    results.append({
                        "case": {"name": case.name, "session": case.session, "object_owner": case.object_owner},
                        "steps": [],
                        "state": STATE_CANCELLED,
                        "cleanup": CLEANUP_NOT_ATTEMPTED,
                    })
                    continue
                item = _run_case(case, scenario, registry, limiter, budget, cancel)
                raised = item.pop("_raise", None)
                results.append(item)
                if raised is not None:
                    state = STATE_FAILED
                    raise raised
                if item["state"] == STATE_FAILED:
                    state = STATE_FAILED
                    cancel.set()
        else:
            order = {case.name: index for index, case in enumerate(cases)}
            collected: dict[int, dict[str, Any]] = {}
            with ThreadPoolExecutor(max_workers=max_workers) as pool:
                futures = {
                    pool.submit(_run_case, case, scenario, registry, limiter, budget, cancel): case
                    for case in cases
                }
                first_error: BaseException | None = None
                for future in as_completed(futures):
                    item = future.result()
                    raised = item.pop("_raise", None)
                    collected[order[item["case"]["name"]]] = item
                    if raised is not None and first_error is None:
                        first_error = raised
                        cancel.set()
                    elif item["state"] == STATE_FAILED:
                        cancel.set()
                results = []
                for index, case in enumerate(cases):
                    results.append(collected.get(index, {
                        "case": {"name": case.name, "session": case.session, "object_owner": case.object_owner},
                        "steps": [],
                        "state": STATE_CANCELLED,
                        "cleanup": CLEANUP_NOT_ATTEMPTED,
                    }))
                if first_error is not None:
                    state = STATE_FAILED
                    raise first_error
        if cancel.is_set() and state != STATE_FAILED:
            state = STATE_CANCELLED
        elif state != STATE_FAILED:
            state = STATE_COMPLETE
        if any(item["state"] not in {STATE_COMPLETE, STATE_CANCELLED} for item in results):
            if any(item["state"] == STATE_FAILED for item in results):
                state = STATE_FAILED
        return {
            "action_id": scenario.policy.action_id,
            "request_count": budget.used,
            "cases": results,
            "state": state,
        }
    except Cancelled:
        return {
            "action_id": scenario.policy.action_id,
            "request_count": budget.used,
            "cases": results,
            "state": STATE_CANCELLED,
        }
    except BudgetExhausted:
        raise
    finally:
        if owned:
            registry.close()
