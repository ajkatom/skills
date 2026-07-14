"""dark-factory supervisor: the sole state-changing entry point (spec 7.7).

M1 walking skeleton, cooperative tier only. FSM:
  INIT -> SNAPSHOT -> [BUILD -> VERIFY -> (FEEDBACK ->)]* ->
  CONVERGED -> COMPLETE_UNQUALIFIED | CAP_REACHED | ABORTED_BUILD_ERROR
"""
import argparse
import datetime
import json
import os
import subprocess
import sys
import uuid

from df_common import atomic_write, canonical_json, sha256_file, sha256_str
from df_config import ConfigError, load_config
from id_feedback import project_feedback
from run_scenarios import OracleError, run_all
from snapshot_source import SnapshotError, snapshot

BUILDER_RULES = """## Builder rules
- You are the BUILDER in a dark-factory run. Implement the specification below
  in the current working directory.
- Work ONLY inside this directory.
- Hidden acceptance scenarios exist; they are NOT visible to you. Do not try to
  find or read them. Verification feedback arrives only as behavior IDs plus a
  coarse failure taxonomy.
"""


class LockError(RuntimeError):
    pass


def _now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def acquire_lock(control_root: str) -> str:
    path = os.path.join(control_root, ".lock")
    try:
        fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
    except FileExistsError:
        try:
            pid = int(open(path, encoding="utf-8").read().strip())
            os.kill(pid, 0)  # raises if dead
        except (ValueError, ProcessLookupError):
            sys.stderr.write(f"dark-factory: removing stale lock {path}\n")
            os.unlink(path)
            return acquire_lock(control_root)
        except PermissionError:
            raise LockError(f"another invocation holds {path} (pid {pid}, live)")
        raise LockError(f"another invocation holds {path} (pid {pid})")
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(str(os.getpid()))
    return path


def release_lock(lock_path: str) -> None:
    if os.path.exists(lock_path):
        os.unlink(lock_path)


class Journal:
    def __init__(self, path: str):
        self.path = path
        os.makedirs(os.path.dirname(path), exist_ok=True)

    def write(self, state: str, **data) -> None:
        line = canonical_json({"ts": _now(), "state": state, "data": data})
        with open(self.path, "a", encoding="utf-8") as f:
            f.write(line + "\n")
            f.flush()
            os.fsync(f.fileno())


def finalize_manifest(run_dir: str, extra: dict) -> str:
    """Write manifest.json + manifest.sha256 sidecar.

    HONESTY (spec 7.5, cooperative/standard tier): a local process that can
    rewrite both files can defeat this. It detects accidental edits and
    casual tampering only; a signed chain / off-box anchor is hardened+.
    """
    journal_path = os.path.join(run_dir, "journal.jsonl")
    manifest = dict(extra)
    manifest["manifest_version"] = "0.1"
    manifest["journal_sha256"] = sha256_file(journal_path)
    manifest["finished_ts"] = _now()
    text = canonical_json(manifest)
    atomic_write(os.path.join(run_dir, "manifest.json"), text)
    digest = sha256_str(text)
    atomic_write(os.path.join(run_dir, "manifest.sha256"), digest + "\n")
    return digest


def verify_manifest(run_dir: str) -> bool:
    mp = os.path.join(run_dir, "manifest.json")
    sp = os.path.join(run_dir, "manifest.sha256")
    jp = os.path.join(run_dir, "journal.jsonl")
    if not (os.path.exists(mp) and os.path.exists(sp) and os.path.exists(jp)):
        print("TAMPERED (missing manifest, sidecar, or journal)")
        return False
    text = open(mp, encoding="utf-8").read()
    if sha256_str(text) != open(sp, encoding="utf-8").read().strip():
        print("TAMPERED (manifest.json does not match manifest.sha256)")
        return False
    manifest = json.loads(text)
    if sha256_file(jp) != manifest.get("journal_sha256"):
        print("TAMPERED (journal.jsonl does not match manifest)")
        return False
    print("OK")
    return True


def compose_prompt(spec_text: str, feedback) -> str:
    fb_block = (
        json.dumps(feedback, indent=2, sort_keys=True)
        if feedback is not None
        else "none — first iteration"
    )
    return (
        f"{BUILDER_RULES}\n## Specification\n{spec_text}\n"
        f"\n## Verification feedback (previous round; behavior IDs + taxonomy only)\n"
        f"{fb_block}\n"
    )


def invoke_adapter(adapter: str, role: str, workdir: str, prompt_file: str, timeout_s: int):
    req = {
        "adapter_protocol": "0.1",
        "role": role,
        "workdir": workdir,
        "prompt_file": prompt_file,
        "timeout_s": timeout_s,
    }
    try:
        proc = subprocess.run(
            [adapter], input=json.dumps(req), capture_output=True, text=True,
            timeout=timeout_s + 60,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError, PermissionError, OSError) as e:
        return None, f"adapter spawn failed: {e}"
    if proc.returncode != 0:
        return None, f"adapter exited {proc.returncode}: {proc.stderr[-500:]}"
    try:
        resp = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return None, f"adapter wrote unparseable stdout: {proc.stdout[-500:]}"
    if resp.get("adapter_protocol") != "0.1":
        return None, "adapter protocol mismatch"
    return resp, None


def _scenario_set_hash(scenarios_dir: str) -> str:
    files = {
        name: sha256_file(os.path.join(scenarios_dir, name))
        for name in sorted(os.listdir(scenarios_dir))
        if name.endswith(".json")
    }
    return sha256_str(canonical_json(files))


def run(control_root: str, project_src) -> int:
    control_root = os.path.abspath(control_root)
    try:
        cfg = load_config(control_root)
    except ConfigError as e:
        sys.stderr.write(f"dark-factory: config error: {e}\n")
        return 2

    try:
        lock = acquire_lock(control_root)
    except LockError as e:
        sys.stderr.write(f"dark-factory: {e}\n")
        return 2
    try:
        return _run_locked(control_root, project_src, cfg)
    finally:
        release_lock(lock)


def _run_locked(control_root: str, project_src, cfg) -> int:
    invocation = _now().replace(":", "").replace("-", "") + "-" + uuid.uuid4().hex[:8]
    run_dir = os.path.join(control_root, "runs", invocation)
    os.makedirs(run_dir, exist_ok=True)
    journal = Journal(os.path.join(run_dir, "journal.jsonl"))

    if not cfg["_qualified"]:
        sys.stderr.write(
            "dark-factory: COOPERATIVE MODE — unqualified: no probe-proven "
            "isolation; outcome can never be a qualified ship-candidate.\n"
        )

    spec_path = os.path.join(control_root, "spec.md")
    if not os.path.exists(spec_path):
        sys.stderr.write(f"dark-factory: missing spec: {spec_path}\n")
        return 2
    spec_text = open(spec_path, encoding="utf-8").read()
    scenarios_dir = os.path.join(control_root, "scenarios")
    if not os.path.isdir(scenarios_dir) or not any(
        n.endswith(".json") for n in os.listdir(scenarios_dir)
    ):
        sys.stderr.write(f"dark-factory: no scenarios in {scenarios_dir}\n")
        return 2
    adapter = cfg["roles"]["builder"]["adapter"]
    timeout_s = cfg["roles"]["builder"].get("timeout_s", 600)

    journal.write(
        "INIT",
        invocation=invocation,
        tier=cfg["assurance"],
        qualified=cfg["_qualified"],
        config_sha256=cfg["_config_sha256"],
        spec_sha256=sha256_str(spec_text),
        scenario_set_sha256=_scenario_set_hash(scenarios_dir),
        adapter=adapter,
        adapter_sha256=sha256_file(adapter) if os.path.exists(adapter) else None,
    )

    manifest_base = {
        "invocation": invocation,
        "tier": cfg["assurance"],
        "qualified": cfg["_qualified"],
        "config_sha256": cfg["_config_sha256"],
        "spec_sha256": sha256_str(spec_text),
        "scenario_set_sha256": _scenario_set_hash(scenarios_dir),
        "adapter_sha256": sha256_file(adapter) if os.path.exists(adapter) else None,
    }

    workspace = os.path.join(cfg["workspace_root"], invocation)
    if project_src:
        try:
            manifest, snap_hash = snapshot(project_src, workspace)
        except SnapshotError as e:
            journal.write("ABORTED_BUILD_ERROR", iteration=0, detail=f"snapshot failed: {e}")
            finalize_manifest(
                run_dir,
                dict(manifest_base, outcome="ABORTED_BUILD_ERROR", iterations=0,
                     snapshot_sha256=None),
            )
            sys.stderr.write(f"dark-factory: {e}\n")
            return 2
    else:
        os.makedirs(workspace, exist_ok=True)
        manifest, snap_hash = {"manifest_version": "0.1", "files": []}, sha256_str(
            canonical_json({"manifest_version": "0.1", "files": []})
        )
    atomic_write(os.path.join(workspace, "spec.md"), spec_text)
    journal.write("SNAPSHOT", workspace=workspace, snapshot_sha256=snap_hash,
                  file_count=len(manifest["files"]))
    manifest_base["snapshot_sha256"] = snap_hash

    feedback = None
    converged = False
    last_report = None
    for i in range(1, cfg["max_iterations"] + 1):
        prompt = compose_prompt(spec_text, feedback)
        prompt_file = os.path.join(run_dir, f"prompt_iter_{i}.md")
        atomic_write(prompt_file, prompt)
        resp, err = invoke_adapter(adapter, "builder", workspace, prompt_file, timeout_s)
        if err or resp.get("status") != "ok":
            journal.write("ABORTED_BUILD_ERROR", iteration=i,
                          detail=err or resp.get("detail", ""))
            sys.stderr.write(f"dark-factory: build error at iteration {i}\n")
            finalize_manifest(
                run_dir, dict(manifest_base, outcome="ABORTED_BUILD_ERROR", iterations=i)
            )
            return 2
        journal.write("BUILD", iteration=i)

        try:
            report = run_all(scenarios_dir, workspace)
        except OracleError as e:
            journal.write("ABORTED_BUILD_ERROR", iteration=i, detail=f"invalid scenarios: {e}")
            finalize_manifest(
                run_dir, dict(manifest_base, outcome="ABORTED_BUILD_ERROR", iterations=i)
            )
            sys.stderr.write(f"dark-factory: {e}\n")
            return 2
        last_report = report
        atomic_write(
            os.path.join(run_dir, f"verifier_report_iter_{i}.json"),
            canonical_json(report),
        )
        passing = sum(1 for r in report["results"] if r["pass"])
        journal.write("VERIFY", iteration=i, passing=passing,
                      total=len(report["results"]))

        if report["all_pass"]:
            journal.write("CONVERGED", iteration=i)
            converged = True
            break

        feedback = project_feedback(report)
        atomic_write(
            os.path.join(run_dir, f"feedback_iter_{i}.json"), canonical_json(feedback)
        )
        atomic_write(os.path.join(workspace, "feedback.json"), canonical_json(feedback))
        journal.write("FEEDBACK", iteration=i,
                      failing=[f["behavior_id"] for f in feedback["failures"]])

    if converged:
        journal.write(
            "COMPLETE_UNQUALIFIED",
            note="cooperative tier cannot produce a qualified ship-candidate",
            workspace=workspace,
        )
        print(f"dark-factory: CONVERGED (unqualified, cooperative tier). "
              f"Workspace: {workspace}  Run: {run_dir}")
        finalize_manifest(
            run_dir, dict(manifest_base, outcome="COMPLETE_UNQUALIFIED", iterations=i)
        )
        return 0

    failing = sorted(
        {r["behavior_id"] for r in last_report["results"] if not r["pass"]}
    )
    journal.write("CAP_REACHED", failing_behaviors=failing,
                  note="likely spec ambiguity — human decision needed")
    print(f"dark-factory: CAP REACHED after {cfg['max_iterations']} iterations. "
          f"Still failing: {', '.join(failing)}. Likely spec ambiguity — "
          f"human decision needed. Run: {run_dir}")
    finalize_manifest(
        run_dir,
        dict(manifest_base, outcome="CAP_REACHED", iterations=cfg["max_iterations"]),
    )
    return 3


def main():
    ap = argparse.ArgumentParser(prog="dark-factory supervisor")
    sub = ap.add_subparsers(dest="cmd", required=True)
    p_run = sub.add_parser("run", help="execute the build/verify loop")
    p_run.add_argument("--control-root", required=True)
    p_run.add_argument("--project-src", default=None)
    p_ver = sub.add_parser("verify-manifest", help="check a run's audit manifest")
    p_ver.add_argument("--run-dir", required=True)
    args = ap.parse_args()
    if args.cmd == "run":
        sys.exit(run(args.control_root, args.project_src))
    elif args.cmd == "verify-manifest":
        sys.exit(0 if verify_manifest(args.run_dir) else 4)


if __name__ == "__main__":
    main()
