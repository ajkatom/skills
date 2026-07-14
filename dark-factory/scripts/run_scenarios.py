"""Oracle IR v0 runner (the verifier's executable check contract). Stdlib only.

IR v0: one JSON file per scenario:
  {
    "ir_version": "0.1",
    "id": "BHV-001-S1",              # scenario id
    "behavior_id": "BHV-001",         # ^BHV-[A-Za-z0-9-]{1,32}$
    "title": "...", "given": "...",   # human view; NEVER crosses the barrier
    "when": {"run": ["cmd", ...], "timeout_s": 10},
    "then": {"exit_code": 0,
             "stdout_equals"|"stdout_contains"|
             "stderr_equals"|"stderr_contains": "..."}   # >= 1 assertion
  }
Taxonomy priority on failure: timeout > crash > wrong_exit_code > wrong_output.
Equality assertions strip one trailing newline from both sides.
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
}


class OracleError(ValueError):
    pass


def _validate(sc: dict, fname: str) -> None:
    if sc.get("ir_version") != IR_VERSION:
        raise OracleError(f"{fname}: ir_version must be {IR_VERSION!r}")
    for key in ("id", "behavior_id", "title", "given", "when", "then"):
        if key not in sc:
            raise OracleError(f"{fname}: missing {key!r}")
    if not BEHAVIOR_RE.fullmatch(sc["behavior_id"]):
        raise OracleError(f"{fname}: invalid behavior_id {sc['behavior_id']!r}")
    run = sc["when"].get("run")
    if not isinstance(run, list) or not run or not all(isinstance(x, str) for x in run):
        raise OracleError(f"{fname}: when.run must be a non-empty list of strings")
    then = sc["then"]
    if not isinstance(then, dict) or not (set(then) & ASSERT_KEYS) or set(then) - ASSERT_KEYS:
        raise OracleError(f"{fname}: then needs >=1 known assertion key {sorted(ASSERT_KEYS)}")


def load_scenarios(scenarios_dir: str) -> list:
    scs = []
    for path in sorted(glob.glob(os.path.join(scenarios_dir, "*.json"))):
        with open(path, encoding="utf-8") as f:
            sc = json.load(f)
        _validate(sc, os.path.basename(path))
        scs.append(sc)
    if not scs:
        raise OracleError(f"no scenarios found in {scenarios_dir}")
    return scs


def _norm(s: str) -> str:
    return s[:-1] if s.endswith("\n") else s


def run_scenario(sc: dict, workspace: str, exec_wrapper: list | None = None, env_extra: dict | None = None) -> dict:
    timeout = sc["when"].get("timeout_s", 30)
    observed = {"exit_code": None, "stdout": "", "stderr": ""}
    taxonomy = None
    command = (list(exec_wrapper) if exec_wrapper else []) + sc["when"]["run"]
    env = None
    if env_extra:
        env = dict(os.environ, **env_extra)
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

    if taxonomy is None:
        then = sc["then"]
        if "exit_code" in then and observed["exit_code"] != then["exit_code"]:
            taxonomy = "wrong_exit_code"
        elif (
            ("stdout_equals" in then and _norm(observed["stdout"]) != _norm(then["stdout_equals"]))
            or ("stdout_contains" in then and then["stdout_contains"] not in observed["stdout"])
            or ("stderr_equals" in then and _norm(observed["stderr"]) != _norm(then["stderr_equals"]))
            or ("stderr_contains" in then and then["stderr_contains"] not in observed["stderr"])
        ):
            taxonomy = "wrong_output"

    return {
        "id": sc["id"],
        "behavior_id": sc["behavior_id"],
        "pass": taxonomy is None,
        "taxonomy": taxonomy,
        "observed": observed,
    }


def run_all(scenarios_dir: str, workspace: str, exec_wrapper: list | None = None, env_extra: dict | None = None) -> dict:
    results = [
        run_scenario(sc, workspace, exec_wrapper, env_extra) for sc in load_scenarios(scenarios_dir)
    ]
    return {
        "report_version": "0.1",
        "results": results,
        "all_pass": all(r["pass"] for r in results),
    }
