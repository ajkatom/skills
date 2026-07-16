"""Pre-build gate logic (M7). Stdlib only, pure/unit-testable.

Mutation validation: a scenario's `then` is "discriminating" iff it
rejects a deliberately-wrong (adversarial) observation. This catches
inert/tautological checks (e.g. {"stdout_contains": ""}) that would
pass regardless of the actual output — a green run against such a
scenario would not mean anything.

Coverage: `behaviors.json` (control-plane, human-declared) lists the
spec's behavior IDs. `check_coverage` traces each declared behavior to
its dev/final scenarios, reporting gaps (uncovered_dev) and scenarios
whose behavior_id was never declared (orphan_scenarios).
"""
import json
import os
import re

import run_scenarios

_BEHAVIOR_ID_RE = re.compile(r"^BHV-[A-Za-z0-9-]{1,32}$")


class GateError(ValueError):
    pass


_HTTP_THEN_KEYS = {"http_status", "body_contains", "json_equals", "json_contains", "json_path"}


def _is_http_then(then: dict) -> bool:
    return bool(set(then) & _HTTP_THEN_KEYS)


def is_discriminating(then: dict) -> bool:
    """True iff `then` rejects a constructed adversarial mutant observation.

    M20 Task 1: an http `then` (detected by its key set -- `http_status`/
    `body_contains`/`json_equals`/`json_contains`/`json_path`) is checked
    against an adversarial HTTP mutant via `evaluate_http`, exactly like a
    CLI `then` is checked via `evaluate_then` below -- same principle
    (reject inert/tautological checks that would pass regardless of the
    actual response), different oracle.
    """
    if _is_http_then(then):
        mutant = {
            "http_status": (then.get("http_status", 0) + 1) or 599,
            "body": "\x00MUTANT",
            "json": {"__mutant__": True},
        }
        return run_scenarios.evaluate_http(then, mutant) is not None
    mutant = {
        "exit_code": (then["exit_code"] + 1) if "exit_code" in then else 999999,
        "stdout": "\x00DF-MUTANT-\x00",
        "stderr": "\x00DF-MUTANT-\x00",
        # M12: the mutant carries NO twin evidence -- any twin_observed/
        # stdout_echoes_twin assertion must reject an observation with no
        # recorded evidence, so it's discriminating by construction.
        "twin_observations": {},
        "twin_tokens": {},
    }
    return run_scenarios.evaluate_then(then, mutant) is not None


def validate_oracle(scenarios: list) -> list[str]:
    """Return the sorted list of scenario ids whose `then` is NOT discriminating."""
    inert = [sc["id"] for sc in scenarios if not is_discriminating(sc["then"])]
    return sorted(inert)


def load_behaviors(control_root: str) -> list[dict] | None:
    """Load + validate `<control_root>/behaviors.json` if present.

    Returns the `behaviors` list, or None if the file is absent (coverage
    is optional). Raises GateError on any malformed content.
    """
    path = os.path.join(control_root, "behaviors.json")
    if not os.path.exists(path):
        return None

    with open(path, encoding="utf-8") as f:
        try:
            data = json.load(f)
        except json.JSONDecodeError as e:
            raise GateError(f"behaviors.json is not valid JSON: {e}") from e

    if not isinstance(data, dict):
        raise GateError("behaviors.json must be a JSON object")
    behaviors = data.get("behaviors")
    if not isinstance(behaviors, list):
        raise GateError('behaviors.json must have a "behaviors" list')

    seen_ids = set()
    for entry in behaviors:
        if not isinstance(entry, dict):
            raise GateError(f"behaviors.json entry is not an object: {entry!r}")
        bid = entry.get("id")
        if not isinstance(bid, str) or not _BEHAVIOR_ID_RE.match(bid):
            raise GateError(f"behaviors.json entry has invalid id: {bid!r}")
        if bid in seen_ids:
            raise GateError(f"behaviors.json has duplicate id: {bid}")
        seen_ids.add(bid)
        description = entry.get("description")
        if description is not None and not isinstance(description, str):
            raise GateError(
                f"behaviors.json entry {bid} has non-string description"
            )

    return behaviors


def check_coverage(behaviors: list[dict], scenarios: list[dict]) -> dict:
    """Trace declared behaviors to dev/final scenarios.

    A behavior is dev-covered iff >=1 scenario with that behavior_id has
    cohort "dev". The gate PASSES iff uncovered_dev == [] and
    orphan_scenarios == [] (enforced by the caller, not here).
    """
    declared_ids = {b["id"] for b in behaviors}

    dev_covered = set()
    final_covered = set()
    orphan_scenarios = []
    for sc in scenarios:
        bid = sc.get("behavior_id")
        if bid not in declared_ids:
            orphan_scenarios.append(sc["id"])
            continue
        if sc.get("cohort") == "dev":
            dev_covered.add(bid)
        elif sc.get("cohort") == "final":
            final_covered.add(bid)

    uncovered_dev = declared_ids - dev_covered

    return {
        "checked": True,
        "behaviors": sorted(declared_ids),
        "uncovered_dev": sorted(uncovered_dev),
        "orphan_scenarios": sorted(set(orphan_scenarios)),
        "final_covered": sorted(final_covered),
    }
