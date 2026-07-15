"""Pre-build gate logic (M7). Stdlib only, pure/unit-testable.

Mutation validation: a scenario's `then` is "discriminating" iff it
rejects a deliberately-wrong (adversarial) observation. This catches
inert/tautological checks (e.g. {"stdout_contains": ""}) that would
pass regardless of the actual output — a green run against such a
scenario would not mean anything.
"""
import run_scenarios


class GateError(ValueError):
    pass


def is_discriminating(then: dict) -> bool:
    """True iff `then` rejects a constructed adversarial mutant observation."""
    mutant = {
        "exit_code": (then["exit_code"] + 1) if "exit_code" in then else 999999,
        "stdout": "\x00DF-MUTANT-\x00",
        "stderr": "\x00DF-MUTANT-\x00",
    }
    return run_scenarios.evaluate_then(then, mutant) is not None


def validate_oracle(scenarios: list) -> list[str]:
    """Return the sorted list of scenario ids whose `then` is NOT discriminating."""
    inert = [sc["id"] for sc in scenarios if not is_discriminating(sc["then"])]
    return sorted(inert)
