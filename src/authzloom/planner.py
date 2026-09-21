from __future__ import annotations

from dataclasses import dataclass

from .errors import ScenarioError
from .models import SAFE_METHODS, Scenario


@dataclass(slots=True)
class Case:
    name: str
    session: str
    object_owner: str
    isolated: bool = False


def build_cases(scenario: Scenario) -> list[Case]:
    if scenario.cases:
        return [Case(c.name, c.session, c.object_owner, c.isolated) for c in scenario.cases]
    labels = [x for x in ("A", "B") if x in scenario.sessions and x in scenario.objects]
    cases: list[Case] = []
    for label in labels:
        cases.append(Case(f"{label}-on-{label}", label, label, isolated=True))
    if "A" in labels and "B" in labels:
        cases.extend([Case("B-on-A", "B", "A"), Case("A-on-B", "A", "B")])
    if "none" in scenario.sessions and "A" in scenario.objects:
        cases.append(Case("none-on-A", "none", "A"))
    return cases


def requests_required(scenario: Scenario, cases: list[Case]) -> tuple[int, int]:
    per_case = 1 + int(scenario.operation.readback is not None) + int(scenario.operation.cleanup is not None)
    identity_probes = len({case.session for case in cases if scenario.sessions[case.session].identity_probe})
    return len(cases) * per_case + identity_probes, identity_probes


def explain(scenario: Scenario) -> dict:
    cases = build_cases(scenario)
    required, probes = requests_required(scenario, cases)
    rejected = []
    ok = True
    error = None
    if not cases:
        ok = False
        error = "scenario produced no cases"
        rejected.append(error)
    if required > scenario.policy.max_requests:
        ok = False
        error = f"plan needs {required} requests, budget is {scenario.policy.max_requests}"
        rejected.append(error)
    if scenario.policy.max_concurrency > 1:
        if not scenario.policy.isolated_cases:
            ok = False
            rejected.append("max_concurrency > 1 requires isolated_cases")
        owners = [case.object_owner for case in cases]
        if len(owners) != len(set(owners)):
            ok = False
            rejected.append("isolated cases may not share object_owner")
    return {
        "ok": ok,
        "error": error,
        "cases": [{"name": c.name, "session": c.session, "object_owner": c.object_owner, "isolated": c.isolated} for c in cases],
        "requests_required": required,
        "identity_probes": probes,
        "budget": scenario.policy.max_requests,
        "per_case": 1 + int(scenario.operation.readback is not None) + int(scenario.operation.cleanup is not None),
        "rate_per_second": scenario.policy.rate_per_second,
        "max_concurrency": scenario.policy.max_concurrency,
        "rejected": rejected,
    }


def plan(scenario: Scenario) -> list[Case]:
    cases = build_cases(scenario)
    if not cases:
        raise ScenarioError("scenario produced no cases")
    required, _ = requests_required(scenario, cases)
    if required > scenario.policy.max_requests:
        raise ScenarioError(f"plan needs {required} requests, budget is {scenario.policy.max_requests}")
    if scenario.policy.max_concurrency > 1:
        if not scenario.policy.isolated_cases:
            raise ScenarioError("max_concurrency > 1 requires isolated_cases")
        owners = [case.object_owner for case in cases]
        if len(owners) != len(set(owners)):
            raise ScenarioError("isolated cases may not share object_owner")
        if scenario.operation.request.method not in SAFE_METHODS:
            # isolation is about objects, not about skipping readback/cleanup
            pass
    return cases
