"""Oracle IR v0.2 runner (the verifier's executable check contract). Stdlib only.

IR v0.2: one JSON file per scenario:
  {
    "ir_version": "0.1",
    "id": "BHV-001-S1",              # scenario id
    "behavior_id": "BHV-001",         # ^BHV-[A-Za-z0-9-]{1,32}$
    "title": "...", "given": "...",   # human view; NEVER crosses the barrier
    "when": {"run": ["cmd", ...], "timeout_s": 10},
    "then": {"exit_code": 0,
             "stdout_equals"|"stdout_contains"|
             "stderr_equals"|"stderr_contains": "...",
             "twin_observed": {"twin": "<name>", "contains": "<nonempty str>"},
             "stdout_echoes_twin": {"twin": "<name>"}}   # >= 1 assertion
  }
`twin_observed` passes iff the per-scenario observation DELTA for that twin
(the ndjson lines a twin appended to its observer file WHILE this scenario's
command ran, and only then) contains `contains` as a raw-line substring.
`stdout_echoes_twin` passes iff at least one `token` recorded in that delta
appears verbatim in this scenario's stdout; zero tokens recorded is a fail
(no evidence of a live, echoing call). Both produce taxonomy
"no_twin_evidence" on failure -- this is evidence FROM THE TWIN's own
observer state, not from anything the candidate's own output claims, so a
builder cannot forge it by pattern-matching stdout.

Taxonomy priority on failure: timeout > crash > wrong_exit_code >
wrong_output > no_twin_evidence. Equality assertions strip one trailing
newline from both sides.
"""
import glob
import json
import os
import re
import subprocess

IR_VERSION = "0.1"
BEHAVIOR_RE = re.compile(r"^BHV-[A-Za-z0-9-]{1,32}$")
ASSERT_KEYS = {
    "exit_code",
    "stdout_equals",
    "stdout_contains",
    "stderr_equals",
    "stderr_contains",
    "twin_observed",
    "stdout_echoes_twin",
}


class OracleError(ValueError):
    pass


def _validate_twin_then(then: dict, fname: str) -> None:
    """Load-time shape validation for the twin-evidence assertion keys.

    Deliberately does NOT check the `twin` name against any known-twins set
    -- that requires runtime context (which twins this runner was given,
    `run_all`'s `observer_files`) that isn't available here. That check
    happens in `run_all`, before any scenario in the call runs.
    """
    if "twin_observed" in then:
        spec = then["twin_observed"]
        if not isinstance(spec, dict) or set(spec) != {"twin", "contains"}:
            raise OracleError(
                f"{fname}: twin_observed must be {{'twin': str, 'contains': str}}")
        if not isinstance(spec["twin"], str) or not spec["twin"]:
            raise OracleError(f"{fname}: twin_observed.twin must be a non-empty string")
        if not isinstance(spec["contains"], str) or not spec["contains"]:
            raise OracleError(f"{fname}: twin_observed.contains must be a non-empty string")
    if "stdout_echoes_twin" in then:
        spec = then["stdout_echoes_twin"]
        if not isinstance(spec, dict) or set(spec) != {"twin"}:
            raise OracleError(f"{fname}: stdout_echoes_twin must be {{'twin': str}}")
        if not isinstance(spec["twin"], str) or not spec["twin"]:
            raise OracleError(f"{fname}: stdout_echoes_twin.twin must be a non-empty string")


def _validate(sc: dict, fname: str) -> None:
    if sc.get("ir_version") != IR_VERSION:
        raise OracleError(f"{fname}: ir_version must be {IR_VERSION!r}")
    for key in ("id", "behavior_id", "title", "given", "when", "then"):
        if key not in sc:
            raise OracleError(f"{fname}: missing {key!r}")
    if not BEHAVIOR_RE.fullmatch(sc["behavior_id"]):
        raise OracleError(f"{fname}: invalid behavior_id {sc['behavior_id']!r}")
    if "cohort" in sc and sc["cohort"] not in ("dev", "final"):
        raise OracleError(f"{fname}: cohort must be 'dev' or 'final', got {sc['cohort']!r}")
    run = sc["when"].get("run")
    if not isinstance(run, list) or not run or not all(isinstance(x, str) for x in run):
        raise OracleError(f"{fname}: when.run must be a non-empty list of strings")
    then = sc["then"]
    if not isinstance(then, dict) or not (set(then) & ASSERT_KEYS) or set(then) - ASSERT_KEYS:
        raise OracleError(f"{fname}: then needs >=1 known assertion key {sorted(ASSERT_KEYS)}")
    _validate_twin_then(then, fname)


def load_scenarios(scenarios_dir: str) -> list:
    scs = []
    for path in sorted(glob.glob(os.path.join(scenarios_dir, "*.json"))):
        with open(path, encoding="utf-8") as f:
            sc = json.load(f)
        _validate(sc, os.path.basename(path))
        sc.setdefault("cohort", "dev")
        scs.append(sc)
    if not scs:
        raise OracleError(f"no scenarios found in {scenarios_dir}")
    return scs


def _norm(s: str) -> str:
    return s[:-1] if s.endswith("\n") else s


def evaluate_then(then: dict, observed: dict) -> str | None:
    """Pure assertion evaluator: returns the failure taxonomy or None (pass).

    `observed` has keys exit_code (int|None), stdout (str), stderr (str),
    and (M12) twin_observations ({name: [str lines]}) and twin_tokens
    ({name: [str]}) -- both ABSENT keys behave as empty dicts, so twin
    assertions fail closed (no evidence recorded => fail) while every
    scenario that doesn't ask for twin evidence is completely unaffected.
    Priority: exit_code, then output, then twin evidence -- checked in that
    order and the first mismatch wins (a scenario with wrong output never
    reports "no_twin_evidence" even if its twin assertion would also fail).
    Equality assertions strip one trailing newline from both sides (see
    _norm).
    """
    if "exit_code" in then and observed["exit_code"] != then["exit_code"]:
        return "wrong_exit_code"
    if (
        ("stdout_equals" in then and _norm(observed["stdout"]) != _norm(then["stdout_equals"]))
        or ("stdout_contains" in then and then["stdout_contains"] not in observed["stdout"])
        or ("stderr_equals" in then and _norm(observed["stderr"]) != _norm(then["stderr_equals"]))
        or ("stderr_contains" in then and then["stderr_contains"] not in observed["stderr"])
    ):
        return "wrong_output"
    if "twin_observed" in then:
        spec = then["twin_observed"]
        lines = observed.get("twin_observations", {}).get(spec["twin"], [])
        if not any(spec["contains"] in line for line in lines):
            return "no_twin_evidence"
    if "stdout_echoes_twin" in then:
        spec = then["stdout_echoes_twin"]
        tokens = observed.get("twin_tokens", {}).get(spec["twin"], [])
        if not tokens or not any(tok in observed["stdout"] for tok in tokens):
            return "no_twin_evidence"
    return None


def _observer_offsets(observer_files: dict | None) -> dict:
    offsets = {}
    for name, path in (observer_files or {}).items():
        offsets[name] = os.path.getsize(path) if os.path.exists(path) else 0
    return offsets


def _read_twin_deltas(observer_files: dict | None, offsets: dict) -> tuple[dict, dict]:
    """Read each observer file from its pre-run offset to EOF (the delta this
    scenario's command produced) and split it into (twin_observations,
    twin_tokens). Lines are parsed tolerantly: an unparseable line is kept
    as a raw string in twin_observations (so `contains` can still match raw
    text) but contributes no token."""
    observations, tokens = {}, {}
    for name, path in (observer_files or {}).items():
        content = ""
        if os.path.exists(path):
            with open(path, encoding="utf-8") as f:
                f.seek(offsets.get(name, 0))
                content = f.read()
        obs_lines, tok_list = [], []
        for line in content.splitlines():
            if not line.strip():
                continue
            obs_lines.append(line)
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(obj, dict) and isinstance(obj.get("token"), str):
                tok_list.append(obj["token"])
        observations[name] = obs_lines
        tokens[name] = tok_list
    return observations, tokens


def run_scenario(sc: dict, workspace: str, exec_wrapper: list | None = None, env_extra: dict | None = None,
                 observer_files: dict | None = None) -> dict:
    timeout = sc["when"].get("timeout_s", 30)
    observed = {"exit_code": None, "stdout": "", "stderr": ""}
    taxonomy = None
    command = (list(exec_wrapper) if exec_wrapper else []) + sc["when"]["run"]
    env = None
    if env_extra:
        env = dict(os.environ, **env_extra)
    # M12: snapshot each observer file's size BEFORE the candidate runs, so
    # only lines appended DURING this scenario's command are attributed to
    # it -- a scenario that makes zero twin calls gets an empty delta, never
    # a previous scenario's leftover lines.
    offsets = _observer_offsets(observer_files)
    try:
        proc = subprocess.run(
            command,
            cwd=workspace,
            capture_output=True,
            text=True,
            timeout=timeout,
            env=env,
        )
        observed = {
            "exit_code": proc.returncode,
            "stdout": proc.stdout,
            "stderr": proc.stderr,
        }
    except subprocess.TimeoutExpired:
        taxonomy = "timeout"
    except (FileNotFoundError, PermissionError, OSError):
        taxonomy = "crash"

    twin_observations, twin_tokens = _read_twin_deltas(observer_files, offsets)
    observed["twin_observations"] = twin_observations
    observed["twin_tokens"] = twin_tokens

    if taxonomy is None:
        taxonomy = evaluate_then(sc["then"], observed)

    return {
        "id": sc["id"],
        "behavior_id": sc["behavior_id"],
        "pass": taxonomy is None,
        "taxonomy": taxonomy,
        "observed": observed,
    }


def run_all(
    scenarios_dir: str,
    workspace: str,
    exec_wrapper: list | None = None,
    env_extra: dict | None = None,
    cohort: str | None = None,
    observer_files: dict | None = None,
) -> dict:
    scs = load_scenarios(scenarios_dir)
    # Load-time validation (M12): a twin assertion naming a twin this runner
    # doesn't know about is an oracle defect, caught BEFORE any scenario in
    # this call runs. This is checked over the FULL, UNFILTERED scenario set
    # (all cohorts) on EVERY run_all call -- like the shape validation in
    # _validate_twin_then -- so a typo'd twin name in a cohort="final"
    # scenario surfaces on the very first dev-cohort run, not only once the
    # sealed final exam eventually runs (which may be never, or only after
    # burning the whole iteration/budget cap). observer_files=None means zero
    # known twins, so ANY twin assertion errors here (correct: none configured).
    known_twins = set(observer_files) if observer_files else set()
    for sc in scs:
        then = sc["then"]
        for key in ("twin_observed", "stdout_echoes_twin"):
            if key in then and then[key]["twin"] not in known_twins:
                raise OracleError(
                    f"{sc['id']}: {key} references unknown twin {then[key]['twin']!r}")
    if cohort is not None:
        scs = [sc for sc in scs if sc["cohort"] == cohort]
    results = [run_scenario(sc, workspace, exec_wrapper, env_extra, observer_files=observer_files)
               for sc in scs]
    return {
        "report_version": "0.1",
        "cohort": cohort if cohort is not None else "all",
        "results": results,
        "all_pass": all(r["pass"] for r in results) if results else True,
        "count": len(results),
    }
