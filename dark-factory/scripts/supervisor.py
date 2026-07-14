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

import df_audit
import df_kb
import df_sandbox
import df_twins
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


PAUSED = 10


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


def save_state(run_dir, next_iter, feedback, workspace):
    atomic_write(
        os.path.join(run_dir, "state.json"),
        canonical_json({
            "state_version": "0.1",
            "next_iter": next_iter,
            "feedback": feedback,
            "workspace": workspace,
            "run_dir": run_dir,
        }),
    )


def load_state(run_dir):
    with open(os.path.join(run_dir, "state.json"), encoding="utf-8") as f:
        return json.load(f)


def _snapshot_sha256_from_journal(run_dir):
    path = os.path.join(run_dir, "journal.jsonl")
    with open(path, encoding="utf-8") as f:
        for line in f:
            e = json.loads(line)
            if e.get("state") == "SNAPSHOT":
                return e.get("data", {}).get("snapshot_sha256")
    return None


def latest_paused_run(control_root):
    runs_dir = os.path.join(control_root, "runs")
    if not os.path.isdir(runs_dir):
        return None
    paused = [
        os.path.join(runs_dir, name)
        for name in sorted(os.listdir(runs_dir), reverse=True)
        if os.path.exists(os.path.join(runs_dir, name, "state.json"))
    ]
    return paused[0] if paused else None


def write_checkpoint_report(run_dir, iteration, report):
    passing = sum(1 for r in report["results"] if r["pass"])
    total = len(report["results"])
    lines = [
        f"# Checkpoint — iteration {iteration}",
        "",
        f"Passing: **{passing}/{total}**  (twin-observed, cooperative tier — unqualified)",
        "",
        "| behavior | scenario | pass | taxonomy | exit |",
        "|---|---|:--:|---|--:|",
    ]
    for r in report["results"]:
        mark = "✅" if r["pass"] else "❌"
        tax = r["taxonomy"] or ""
        code = r["observed"].get("exit_code")
        lines.append(f"| {r['behavior_id']} | {r['id']} | {mark} | {tax} | {code} |")
    lines += [
        "",
        "Decide: `resume --decision continue` (build again) · edit `spec.md` then "
        "`resume --decision continue` (adjust) · `resume --decision accept` (stop, "
        "waived/unverified) · `resume --decision abort`.",
        "",
    ]
    path = os.path.join(run_dir, f"checkpoint_iter_{iteration}.md")
    atomic_write(path, "\n".join(lines))
    return path


def _load_audit_key(cfg, journal):
    """Load the run's audit signing key once, if cfg["_audit"]["signing"].

    Returns (key_or_None, error_exit_code_or_None). On AuditKeyError this is a
    precondition failure — journal AUDIT_KEY_ERROR and return an exit code
    instead of silently proceeding unsigned.
    """
    audit_cfg = cfg.get("_audit", {"signing": False, "key_path": ""})
    if not audit_cfg.get("signing"):
        return None, None
    try:
        return df_audit.load_or_create_key(audit_cfg["key_path"]), None
    except df_audit.AuditKeyError as e:
        journal.write("AUDIT_KEY_ERROR", detail=str(e))
        sys.stderr.write(f"dark-factory: audit key error: {e}\n")
        return None, 2


def finalize_manifest(run_dir: str, extra: dict, audit_key: bytes = None) -> str:
    """Write manifest.json + manifest.sha256 sidecar.

    HONESTY (spec 7.5, cooperative/standard tier): a local process that can
    rewrite both files can defeat this. It detects accidental edits and
    casual tampering only; a signed chain / off-box anchor is hardened+.

    If `audit_key` is given, also write manifest.hmac (HMAC-SHA256 over the
    exact canonical manifest text, spec 7.5). The key itself is NEVER
    written to any run artifact.
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
    if audit_key is not None:
        sig = df_audit.sign(audit_key, text.encode("utf-8"))
        atomic_write(os.path.join(run_dir, "manifest.hmac"), sig + "\n")
    return digest


def _kb_writeback(cfg, journal, manifest_dict, failing):
    """Opt-in KB write-back after a terminal manifest is finalized.

    Side-effect only: never raises, never affects control flow or exit codes.
    """
    kb = cfg.get("_kb", {"kind": "none"})
    if kb.get("kind") != "wiki" or not kb.get("write_back"):
        return
    try:
        path = df_kb.write_run_summary(kb, manifest_dict, failing)
        if path:
            journal.write("KB_WRITEBACK", path=path)
    except Exception as e:
        journal.write("KB_WRITEBACK_ERROR", detail=str(e))


def verify_manifest(run_dir: str, key: bytes = None) -> bool:
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
    hp = os.path.join(run_dir, "manifest.hmac")
    if os.path.exists(hp):
        if key is None:
            print("UNVERIFIED (signed manifest; supply --key-path)")
            return False
        sig = open(hp, encoding="utf-8").read().strip()
        if not df_audit.verify(key, text.encode("utf-8"), sig):
            print("TAMPERED (bad signature)")
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


def invoke_adapter(adapter: str, role: str, workdir: str, prompt_file: str, timeout_s: int,
                   exec_prefix=None, env_extra=None):
    req = {
        "adapter_protocol": "0.1",
        "role": role,
        "workdir": workdir,
        "prompt_file": prompt_file,
        "timeout_s": timeout_s,
    }
    argv = (list(exec_prefix) if exec_prefix else []) + [adapter]
    env = dict(os.environ, **env_extra) if env_extra else None
    try:
        proc = subprocess.run(
            argv, input=json.dumps(req), capture_output=True, text=True,
            timeout=timeout_s + 60, env=env,
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


def resolve_isolation(cfg, control_root, workspace, journal, allow_downgrade):
    if cfg["assurance"] != "standard":
        return "cooperative", [], None, None
    backend = df_sandbox.current_backend()
    name = backend.name if backend is not None else None
    ok = backend is not None and backend.available() and df_sandbox.probe_denial(
        backend, control_root, workspace)
    if ok:
        return "standard", backend.wrap_prefix(control_root, workspace), name, True
    if allow_downgrade:
        journal.write("DOWNGRADE", requested="standard", effective="cooperative",
                      reason="sandbox unavailable or denial probe failed")
        sys.stderr.write("dark-factory: standard tier UNavailable/probe failed — "
                         "DOWNGRADED to cooperative (unqualified) by --allow-downgrade.\n")
        return "cooperative", [], name, False
    journal.write("PROBE_FAILED", requested="standard",
                  reason="sandbox unavailable or denial probe failed")
    raise df_sandbox.SandboxError(
        "standard tier requires a working OS sandbox + passing denial probe; "
        "none available. Fix the sandbox or set assurance=cooperative "
        "(or pass --allow-downgrade).")


def run(control_root: str, project_src, allow_downgrade: bool = False) -> int:
    control_root = os.path.abspath(control_root)
    try:
        cfg = load_config(control_root)
    except ConfigError as e:
        sys.stderr.write(f"dark-factory: config error: {e}\n")
        return 2
    cfg["_control_root"] = control_root

    try:
        lock = acquire_lock(control_root)
    except LockError as e:
        sys.stderr.write(f"dark-factory: {e}\n")
        return 2
    try:
        return _run_locked(control_root, project_src, cfg, allow_downgrade)
    finally:
        release_lock(lock)


def _run_locked(control_root: str, project_src, cfg, allow_downgrade: bool = False) -> int:
    invocation = _now().replace(":", "").replace("-", "") + "-" + uuid.uuid4().hex[:8]
    run_dir = os.path.join(control_root, "runs", invocation)
    os.makedirs(run_dir, exist_ok=True)
    journal = Journal(os.path.join(run_dir, "journal.jsonl"))

    audit_key, audit_err = _load_audit_key(cfg, journal)
    if audit_err is not None:
        return audit_err

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
            mf = dict(manifest_base, outcome="ABORTED_BUILD_ERROR", iterations=0,
                      snapshot_sha256=None, qualified=False,
                      sandbox_backend=None, denial_probe_passed=False)
            finalize_manifest(run_dir, mf, audit_key=audit_key)
            _kb_writeback(cfg, journal, mf, [])
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

    try:
        eff_tier, exec_prefix, backend_name, probe_passed = resolve_isolation(
            cfg, control_root, workspace, journal, allow_downgrade)
    except df_sandbox.SandboxError as e:
        sys.stderr.write(f"dark-factory: {e}\n")
        return 2
    manifest_base["qualified"] = (eff_tier == "standard")
    manifest_base["sandbox_backend"] = backend_name
    manifest_base["denial_probe_passed"] = probe_passed
    manifest_base["_effective_tier"] = eff_tier   # internal; stripped before finalize
    # cooperative banner only when the EFFECTIVE tier is cooperative:
    if eff_tier != "standard":
        sys.stderr.write("dark-factory: COOPERATIVE MODE — unqualified: no probe-proven "
                         "isolation; outcome can never be a qualified ship-candidate.\n")
    return _run_loop(cfg, journal, run_dir, manifest_base, spec_text, scenarios_dir,
                     adapter, timeout_s, workspace, start_iter=1, feedback=None,
                     exec_prefix=exec_prefix, audit_key=audit_key)


def _run_loop(cfg, journal, run_dir, manifest_base, spec_text, scenarios_dir,
              adapter, timeout_s, workspace, start_iter, feedback, exec_prefix=None,
              audit_key=None):
    exec_prefix = exec_prefix or []
    mb_clean = {k: v for k, v in manifest_base.items() if k != "_effective_tier"}

    def _clear_state():
        p = os.path.join(run_dir, "state.json")
        if os.path.exists(p):
            os.unlink(p)

    def _twin_error_abort(iteration, e):
        journal.write("TWIN_ERROR", iteration=iteration, detail=str(e))
        mf = dict(mb_clean, outcome="ABORTED_BUILD_ERROR", iterations=iteration, qualified=False)
        finalize_manifest(run_dir, mf, audit_key=audit_key)
        _clear_state()
        _kb_writeback(cfg, journal, mf, [])
        sys.stderr.write(f"dark-factory: twin precondition failed at iteration {iteration}: {e}\n")
        return 2

    twins_enabled = cfg["_twins"]["enabled"]
    ts = df_twins.TwinSet() if twins_enabled else None
    # Twins are SHARED/dev (not holdout): reaping them is non-negotiable — this
    # try/finally must wrap the WHOLE loop so every terminal (return) and any
    # exception still stops the twin processes. No orphans, ever.
    try:
        twin_defs = None
        twin_timeout = None
        twins_started = False
        if twins_enabled:
            control_root = cfg["_control_root"]
            twin_timeout = cfg["_twins"]["startup_timeout_s"]
            try:
                twin_defs = df_twins.load_defs(os.path.join(control_root, "twins"))
            except df_twins.TwinError as e:
                return _twin_error_abort(start_iter, e)

        last_report = None
        for i in range(start_iter, cfg["max_iterations"] + 1):
            build_env_extra = None
            if twins_enabled:
                if not twins_started:
                    try:
                        build_env_extra = ts.start(twin_defs, run_dir, twin_timeout)
                        twins_started = True
                    except df_twins.TwinError as e:
                        return _twin_error_abort(i, e)
                else:
                    build_env_extra = ts.env

            prompt = compose_prompt(spec_text, feedback)
            # Audit copy on the control plane (barrier tests assert MARKER-absence here).
            audit_prompt_file = os.path.join(run_dir, f"prompt_iter_{i}.md")
            atomic_write(audit_prompt_file, prompt)
            # Working copy the adapter actually reads: under standard tier, control_root
            # is OS-denied to the wrapped builder, so prompt_file must live in the
            # workspace instead (readable) or every standard build aborts with
            # PermissionError. This is barrier-safe: prompt content is compose_prompt's
            # output (spec + ID/taxonomy feedback only, no scenario content), and the
            # spec is already present in the workspace as spec.md — no holdout leak.
            prompt_file = os.path.join(workspace, "DARK_FACTORY_PROMPT.md")
            atomic_write(prompt_file, prompt)
            resp, err = invoke_adapter(adapter, "builder", workspace, prompt_file, timeout_s,
                                       exec_prefix=exec_prefix, env_extra=build_env_extra)
            if err or resp.get("status") != "ok":
                journal.write("ABORTED_BUILD_ERROR", iteration=i, detail=err or resp.get("detail", ""))
                mf = dict(mb_clean, outcome="ABORTED_BUILD_ERROR", iterations=i, qualified=False)
                finalize_manifest(run_dir, mf, audit_key=audit_key)
                _clear_state()
                _kb_writeback(cfg, journal, mf, [])
                sys.stderr.write(f"dark-factory: build error at iteration {i}\n")
                return 2
            journal.write("BUILD", iteration=i)

            verify_env_extra = None
            if twins_enabled:
                try:
                    verify_env_extra = ts.reset(twin_defs, run_dir, twin_timeout)
                except df_twins.TwinError as e:
                    return _twin_error_abort(i, e)

            try:
                report = run_all(scenarios_dir, workspace, exec_wrapper=exec_prefix,
                                  env_extra=verify_env_extra)
            except OracleError as e:
                journal.write("ABORTED_BUILD_ERROR", iteration=i, detail=f"invalid scenarios: {e}")
                mf = dict(mb_clean, outcome="ABORTED_BUILD_ERROR", iterations=i, qualified=False)
                finalize_manifest(run_dir, mf, audit_key=audit_key)
                _clear_state()
                _kb_writeback(cfg, journal, mf, [])
                sys.stderr.write(f"dark-factory: {e}\n")
                return 2
            last_report = report
            atomic_write(os.path.join(run_dir, f"verifier_report_iter_{i}.json"), canonical_json(report))
            passing = sum(1 for r in report["results"] if r["pass"])
            journal.write("VERIFY", iteration=i, passing=passing, total=len(report["results"]))

            if report["all_pass"]:
                journal.write("CONVERGED", iteration=i)
                eff = manifest_base.get("_effective_tier", "cooperative")
                outcome = "COMPLETE_QUALIFIED" if eff == "standard" else "COMPLETE_UNQUALIFIED"
                mf = dict(mb_clean, outcome=outcome, iterations=i)
                finalize_manifest(run_dir, mf, audit_key=audit_key)
                _clear_state()
                _kb_writeback(cfg, journal, mf, [])
                print(f"dark-factory: CONVERGED "
                      f"({'qualified, standard' if eff == 'standard' else 'unqualified, cooperative'} tier). "
                      f"Workspace: {workspace}  Run: {run_dir}")
                return 0

            feedback = project_feedback(report)
            atomic_write(os.path.join(run_dir, f"feedback_iter_{i}.json"), canonical_json(feedback))
            atomic_write(os.path.join(workspace, "feedback.json"), canonical_json(feedback))
            journal.write("FEEDBACK", iteration=i, failing=[f["behavior_id"] for f in feedback["failures"]])

            if cfg["_checkpoint"] == "pause" and i < cfg["max_iterations"]:
                write_checkpoint_report(run_dir, i, report)
                save_state(run_dir, next_iter=i + 1, feedback=feedback, workspace=workspace)
                journal.write("CHECKPOINT", iteration=i,
                              failing=[f["behavior_id"] for f in feedback["failures"]])
                print(f"dark-factory: PAUSED at checkpoint (iteration {i}). "
                      f"Review {run_dir}/checkpoint_iter_{i}.md, then "
                      f"`supervisor.py resume --control-root {cfg.get('_control_root', '<CR>')}`.")
                return PAUSED

        failing = sorted({r["behavior_id"] for r in last_report["results"] if not r["pass"]})
        journal.write("CAP_REACHED", failing_behaviors=failing,
                      note="likely spec ambiguity — human decision needed")
        mf = dict(mb_clean, outcome="CAP_REACHED", iterations=cfg["max_iterations"], qualified=False)
        finalize_manifest(run_dir, mf, audit_key=audit_key)
        _clear_state()
        _kb_writeback(cfg, journal, mf, failing)
        print(f"dark-factory: CAP REACHED after {cfg['max_iterations']} iterations. "
              f"Still failing: {', '.join(failing)}. Run: {run_dir}")
        return 3
    finally:
        if ts is not None:
            ts.stop()


def resume(control_root, decision="continue", allow_downgrade: bool = False):
    control_root = os.path.abspath(control_root)
    try:
        cfg = load_config(control_root)
    except ConfigError as e:
        sys.stderr.write(f"dark-factory: config error: {e}\n")
        return 2
    cfg["_control_root"] = control_root

    run_dir = latest_paused_run(control_root)
    if run_dir is None:
        sys.stderr.write("dark-factory: no paused run to resume\n")
        return 2

    try:
        lock = acquire_lock(control_root)
    except LockError as e:
        sys.stderr.write(f"dark-factory: {e}\n")
        return 2
    try:
        state = load_state(run_dir)
        journal = Journal(os.path.join(run_dir, "journal.jsonl"))

        audit_key, audit_err = _load_audit_key(cfg, journal)
        if audit_err is not None:
            return audit_err

        spec_text = open(os.path.join(control_root, "spec.md"), encoding="utf-8").read()
        scenarios_dir = os.path.join(control_root, "scenarios")
        adapter = cfg["roles"]["builder"]["adapter"]
        timeout_s = cfg["roles"]["builder"].get("timeout_s", 600)
        manifest_base = {
            "invocation": os.path.basename(run_dir),
            "tier": cfg["assurance"],
            "qualified": cfg["_qualified"],
            "config_sha256": cfg["_config_sha256"],
            "spec_sha256": sha256_str(spec_text),
            "scenario_set_sha256": _scenario_set_hash(scenarios_dir),
            "adapter_sha256": sha256_file(adapter) if os.path.exists(adapter) else None,
            "snapshot_sha256": _snapshot_sha256_from_journal(run_dir),
        }

        if decision == "abort":
            journal.write("ABORTED_BY_HUMAN")
            mf = dict(manifest_base, outcome="ABORTED_BY_HUMAN",
                      iterations=state["next_iter"] - 1,
                      qualified=False,
                      sandbox_backend=None, denial_probe_passed=False)
            finalize_manifest(run_dir, mf, audit_key=audit_key)
            os.unlink(os.path.join(run_dir, "state.json"))
            _kb_writeback(cfg, journal, mf, [])
            print("dark-factory: ABORTED by human.")
            return 2
        if decision == "accept":
            journal.write("ACCEPTED_BY_HUMAN",
                          note="human accepted a non-passing build — waived/unverified")
            mf = dict(manifest_base, outcome="ACCEPTED_WAIVED",
                      qualified=False,
                      sandbox_backend=None, denial_probe_passed=False,
                      iterations=state["next_iter"] - 1)
            finalize_manifest(run_dir, mf, audit_key=audit_key)
            os.unlink(os.path.join(run_dir, "state.json"))
            _kb_writeback(cfg, journal, mf, [])
            print("dark-factory: ACCEPTED (waived/unverified — not a qualified ship-candidate).")
            return 0
        # decision == "continue" — isolation cannot be trusted across a pause;
        # re-probe (and re-wrap) before re-entering the loop.
        try:
            eff_tier, exec_prefix, backend_name, probe_passed = resolve_isolation(
                cfg, control_root, state["workspace"], journal, allow_downgrade)
        except df_sandbox.SandboxError as e:
            sys.stderr.write(f"dark-factory: {e}\n")
            return 2
        manifest_base["qualified"] = (eff_tier == "standard")
        manifest_base["sandbox_backend"] = backend_name
        manifest_base["denial_probe_passed"] = probe_passed
        manifest_base["_effective_tier"] = eff_tier
        if eff_tier != "standard":
            sys.stderr.write("dark-factory: COOPERATIVE MODE — unqualified: no probe-proven "
                             "isolation; outcome can never be a qualified ship-candidate.\n")
        return _run_loop(
            cfg, journal, run_dir, manifest_base, spec_text, scenarios_dir,
            adapter, timeout_s, state["workspace"],
            start_iter=state["next_iter"], feedback=state["feedback"],
            exec_prefix=exec_prefix, audit_key=audit_key,
        )
    finally:
        release_lock(lock)


def main():
    ap = argparse.ArgumentParser(prog="dark-factory supervisor")
    sub = ap.add_subparsers(dest="cmd", required=True)
    p_run = sub.add_parser("run", help="execute the build/verify loop")
    p_run.add_argument("--control-root", required=True)
    p_run.add_argument("--project-src", default=None)
    p_run.add_argument("--allow-downgrade", action="store_true",
                       help="if standard tier is unavailable/probe fails, downgrade to "
                            "cooperative (unqualified) instead of failing closed")
    p_ver = sub.add_parser("verify-manifest", help="check a run's audit manifest")
    p_ver.add_argument("--run-dir", required=True)
    p_ver.add_argument("--key-path", default=None,
                       help="path to the audit signing key; required to verify a "
                            "signed (manifest.hmac) run")
    p_res = sub.add_parser("resume", help="resume a paused run")
    p_res.add_argument("--control-root", required=True)
    p_res.add_argument("--decision", choices=["continue", "accept", "abort"], default="continue")
    p_res.add_argument("--allow-downgrade", action="store_true",
                       help="if standard tier is unavailable/probe fails on re-probe, "
                            "downgrade to cooperative (unqualified) instead of failing closed")
    args = ap.parse_args()
    if args.cmd == "run":
        sys.exit(run(args.control_root, args.project_src, allow_downgrade=args.allow_downgrade))
    elif args.cmd == "verify-manifest":
        vkey = None
        if args.key_path:
            try:
                vkey = df_audit.load_or_create_key(args.key_path)
            except df_audit.AuditKeyError as e:
                sys.stderr.write(f"dark-factory: audit key error: {e}\n")
                sys.exit(2)
        sys.exit(0 if verify_manifest(args.run_dir, key=vkey) else 4)
    elif args.cmd == "resume":
        sys.exit(resume(args.control_root, args.decision, allow_downgrade=args.allow_downgrade))


if __name__ == "__main__":
    main()
