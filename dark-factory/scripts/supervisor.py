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
import df_gates
import df_kb
import df_sandbox
import df_security
import df_twins
from df_common import atomic_write, canonical_json, sha256_file, sha256_str
from df_config import ConfigError, load_config
from id_feedback import project_feedback
from run_scenarios import OracleError, load_scenarios, run_all
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


def save_state(run_dir, next_iter, feedback, workspace, dev_status=None, regressions=None,
              builder_calls=0, estimated_usd=0.0, budget_alerted=False, reason="checkpoint"):
    atomic_write(
        os.path.join(run_dir, "state.json"),
        canonical_json({
            "state_version": "0.1",
            "next_iter": next_iter,
            "feedback": feedback,
            "workspace": workspace,
            "run_dir": run_dir,
            "dev_status": dev_status or {},
            "regressions": sorted(regressions) if regressions else [],
            "builder_calls": builder_calls,
            "estimated_usd": estimated_usd,
            "budget_alerted": budget_alerted,
            "reason": reason,
        }),
    )


def load_state(run_dir):
    with open(os.path.join(run_dir, "state.json"), encoding="utf-8") as f:
        state = json.load(f)
    # Additive fields (M8): default them when absent so a pre-M8 state.json
    # (or an old checkpoint-pause save) resumes cleanly with a fresh budget.
    state.setdefault("builder_calls", 0)
    state.setdefault("estimated_usd", 0.0)
    state.setdefault("budget_alerted", False)
    state.setdefault("reason", "checkpoint")
    return state


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


def _budget_enforced(b):
    """Which caps are actively enforced (can trigger a BUDGET_PAUSE).

    Returns (dollar_enforced, calls_enforced). A $ cap requires billing=="api"
    AND max_usd AND per_call_usd (no per_call_usd => no estimate to reserve
    against => downgraded to alert-only, spec M8). max_calls is exact and
    enforced under any billing.
    """
    dollar_enforced = (b["billing"] == "api" and b["max_usd"] is not None
                       and b["per_call_usd"] is not None)
    calls_enforced = b["max_calls"] is not None
    return dollar_enforced, calls_enforced


def _budget_manifest_field(b, builder_calls, estimated_usd):
    dollar_enforced, calls_enforced = _budget_enforced(b)
    return {
        "billing": b["billing"],
        "builder_calls": builder_calls,
        "estimated_usd": estimated_usd,
        "cap_usd": b["max_usd"],
        "max_calls": b["max_calls"],
        "enforced": bool(dollar_enforced or calls_enforced),
        "estimate_caveat": "estimated from per_call_usd; not metered usage",
    }


def _run_security_gates(cfg, journal, run_dir, workspace):
    """Run mandatory security gates (M9) on the converged artifact, if enabled.

    Shared by BOTH the primary run() path and resume()'s continue path,
    since both funnel through _run_loop's CONVERGED branch — there is only
    one call site, so "gates run on resume exactly like the primary path"
    falls out for free rather than needing a second wiring.

    Disabled (default, back-compatible): returns {"checked": False} with no
    journal entry and no security_report.json written. Enabled: runs
    df_security.run_gates over the workspace, writes security_report.json
    into run_dir (control plane — the report is about the artifact, not
    holdout content), and journals SECURITY_GATES(checked=True, failed=...).
    """
    sec_cfg = cfg["_security"]
    if not sec_cfg.get("enabled"):
        return {"checked": False}
    sec_report = df_security.run_gates(workspace, sec_cfg)
    atomic_write(os.path.join(run_dir, "security_report.json"), canonical_json(sec_report))
    journal.write("SECURITY_GATES", checked=True, failed=sec_report["failed"])
    return sec_report


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
    if audit_key is not None:
        manifest["audit_signing"] = True
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
    expect_sig = (key is not None) or bool(manifest.get("audit_signing"))
    if os.path.exists(hp):
        if key is None:
            print("UNVERIFIED (signed manifest; supply --key-path)")
            return False
        sig = open(hp, encoding="utf-8").read().strip()
        if not df_audit.verify(key, text.encode("utf-8"), sig):
            print("TAMPERED (bad signature)")
            return False
    elif expect_sig:
        print("UNVERIFIED (expected a signed manifest; manifest.hmac is missing)")
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

    # --- Pre-build gate (M7): mutation validation + coverage traceability,
    # entirely control-plane, BEFORE any builder invocation — a gate failure
    # journals + finalizes a GATE_FAILED manifest and returns 2 with no build
    # ever run. Fresh run ONLY: a resumed run already passed this gate once;
    # resume() recomputes the same deterministic coverage/oracle fields for
    # its manifests instead of re-running (and re-failing) the gate.
    try:
        scenarios = load_scenarios(scenarios_dir)
    except OracleError as e:
        journal.write("ABORTED_BUILD_ERROR", iteration=0, detail=f"invalid scenarios: {e}")
        mf = dict(manifest_base, outcome="ABORTED_BUILD_ERROR", iterations=0, qualified=False,
                  sandbox_backend=None, denial_probe_passed=False, snapshot_sha256=None,
                  final_exam={"ran": False, "passed": None, "count": 0}, regressions=[],
                  security={"checked": False},
                  budget=_budget_manifest_field(cfg["_budget"], 0, 0.0))
        finalize_manifest(run_dir, mf, audit_key=audit_key)
        _kb_writeback(cfg, journal, mf, [])
        sys.stderr.write(f"dark-factory: {e}\n")
        return 2

    # Mutation validation first (order matters: an inert oracle is a more
    # fundamental defect than a coverage gap, and coverage hasn't been
    # computed yet, so its manifest field is honestly {"checked": False}).
    inert = df_gates.validate_oracle(scenarios)
    if inert:
        journal.write("ORACLE_GATE_FAILED", inert=inert)
        mf = dict(manifest_base, outcome="GATE_FAILED", iterations=0, qualified=False,
                  sandbox_backend=None, denial_probe_passed=False, snapshot_sha256=None,
                  final_exam={"ran": False, "passed": None, "count": 0}, regressions=[],
                  oracle={"mutation_validated": False, "inert": inert},
                  coverage={"checked": False},
                  security={"checked": False},
                  budget=_budget_manifest_field(cfg["_budget"], 0, 0.0))
        finalize_manifest(run_dir, mf, audit_key=audit_key)
        _kb_writeback(cfg, journal, mf, [])
        sys.stderr.write(
            f"dark-factory: pre-build gate FAILED — {len(inert)} inert (non-discriminating) "
            f"scenario oracle(s), no build was run: {', '.join(inert)}\n"
        )
        return 2

    try:
        behaviors = df_gates.load_behaviors(control_root)
    except df_gates.GateError as e:
        journal.write("GATE_ERROR", detail=str(e))
        sys.stderr.write(f"dark-factory: behaviors.json error: {e}\n")
        return 2

    if behaviors is not None:
        cov = df_gates.check_coverage(behaviors, scenarios)
        if cov["uncovered_dev"] or cov["orphan_scenarios"]:
            journal.write("COVERAGE_GATE_FAILED", uncovered=cov["uncovered_dev"],
                          orphans=cov["orphan_scenarios"])
            mf = dict(manifest_base, outcome="GATE_FAILED", iterations=0, qualified=False,
                      sandbox_backend=None, denial_probe_passed=False, snapshot_sha256=None,
                      final_exam={"ran": False, "passed": None, "count": 0}, regressions=[],
                      oracle={"mutation_validated": True, "inert": []}, coverage=cov,
                      security={"checked": False},
                      budget=_budget_manifest_field(cfg["_budget"], 0, 0.0))
            finalize_manifest(run_dir, mf, audit_key=audit_key)
            _kb_writeback(cfg, journal, mf, [])
            sys.stderr.write(
                f"dark-factory: pre-build gate FAILED — coverage gap, no build was run: "
                f"uncovered_dev={cov['uncovered_dev']} orphan_scenarios={cov['orphan_scenarios']}\n"
            )
            return 2
    else:
        cov = {"checked": False}

    journal.write("GATE_PASSED", coverage_checked=cov["checked"], scenarios=len(scenarios))
    manifest_base["coverage"] = cov
    manifest_base["oracle"] = {"mutation_validated": True, "inert": []}
    # M9 default: {"checked": False} threads into every terminal manifest via
    # mb_clean unless the CONVERGED path overrides it with the real gate
    # report (gates only run after dev converges + final exam passes).
    manifest_base["security"] = {"checked": False}

    workspace = os.path.join(cfg["workspace_root"], invocation)
    if project_src:
        try:
            manifest, snap_hash = snapshot(project_src, workspace)
        except SnapshotError as e:
            journal.write("ABORTED_BUILD_ERROR", iteration=0, detail=f"snapshot failed: {e}")
            mf = dict(manifest_base, outcome="ABORTED_BUILD_ERROR", iterations=0,
                      snapshot_sha256=None, qualified=False,
                      sandbox_backend=None, denial_probe_passed=False,
                      final_exam={"ran": False, "passed": None, "count": 0},
                      regressions=[],
                      budget=_budget_manifest_field(cfg["_budget"], 0, 0.0))
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
              audit_key=None, prev_dev_status=None, regressions=None,
              builder_calls=0, estimated_usd=0.0, budget_alerted=False):
    exec_prefix = exec_prefix or []
    mb_clean = {k: v for k, v in manifest_base.items() if k != "_effective_tier"}
    # Regression tracking (green->red on dev, spec §6/§15.3): prev_dev_status maps
    # behavior_id -> did every dev scenario of that behavior pass LAST iteration.
    # regressed accumulates behavior-IDs that ever flip True->False across the run.
    # Barrier-safe: only ever behavior-IDs, never scenario content.
    prev_dev_status = dict(prev_dev_status or {})
    regressed = set(regressions or [])
    # Budget accounting (M8): builder_calls/estimated_usd/budget_alerted thread
    # through resume via state.json — reassigned as plain locals below (no
    # mutable-container aliasing concern, unlike prev_dev_status/regressed).
    budget_downgrade_noted = False

    def _clear_state():
        p = os.path.join(run_dir, "state.json")
        if os.path.exists(p):
            os.unlink(p)

    def _twin_error_abort(iteration, e):
        journal.write("TWIN_ERROR", iteration=iteration, detail=str(e))
        mf = dict(mb_clean, outcome="ABORTED_BUILD_ERROR", iterations=iteration, qualified=False,
                  final_exam={"ran": False, "passed": None, "count": 0},
                  regressions=sorted(regressed),
                  budget=_budget_manifest_field(cfg["_budget"], builder_calls, estimated_usd))
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

            # --- Budget admission control (M8): reserve BEFORE the builder call,
            # regardless of checkpoint mode (even auto/L5) — a cost overrun pauses
            # here rather than proceeding unattended. billing=="subscription" can't
            # meter dollars (alert-only, milestone-only); max_calls is exact and
            # enforced under any billing. api+max_usd without per_call_usd has no
            # estimate to reserve against, so the $ cap downgrades to alert-only
            # (still counted, never pauses on $).
            b = cfg["_budget"]
            calls_after = builder_calls + 1
            est_after = estimated_usd + (b["per_call_usd"] or 0.0)
            dollar_enforced, calls_enforced = _budget_enforced(b)

            if (b["billing"] == "api" and b["max_usd"] is not None
                    and b["per_call_usd"] is None and not budget_downgrade_noted):
                journal.write(
                    "BUDGET_DOWNGRADE",
                    reason="max_usd set without per_call_usd; no estimate to reserve "
                           "against — $ cap downgraded to alert-only",
                )
                budget_downgrade_noted = True

            if not budget_alerted:
                hit_dollar = dollar_enforced and estimated_usd >= b["alert_at"] * b["max_usd"]
                hit_calls = calls_enforced and builder_calls >= b["alert_at"] * b["max_calls"]
                if hit_dollar or hit_calls:
                    journal.write("BUDGET_ALERT", estimated_usd=estimated_usd,
                                  builder_calls=builder_calls, cap_usd=b["max_usd"],
                                  max_calls=b["max_calls"])
                    sys.stderr.write(
                        f"dark-factory: BUDGET ALERT — {b['alert_at']:.0%} of budget cap "
                        f"reached (estimated_usd={estimated_usd}, builder_calls={builder_calls}).\n")
                    budget_alerted = True

            if (b["billing"] == "subscription" and not dollar_enforced and not calls_enforced
                    and calls_after % 5 == 0):
                journal.write("BUDGET_ALERT", milestone=True, builder_calls=calls_after,
                              estimated_usd=est_after)
                sys.stderr.write(
                    f"dark-factory: budget milestone — {calls_after} builder calls "
                    f"(subscription billing; informational only).\n")

            budget_pause = ((calls_enforced and calls_after > b["max_calls"]) or
                            (dollar_enforced and est_after > b["max_usd"]))
            if budget_pause:
                journal.write("BUDGET_PAUSE", estimated_usd=estimated_usd,
                              builder_calls=builder_calls, cap_usd=b["max_usd"],
                              max_calls=b["max_calls"])
                save_state(run_dir, next_iter=i, feedback=feedback, workspace=workspace,
                          dev_status=prev_dev_status, regressions=regressed,
                          builder_calls=builder_calls, estimated_usd=estimated_usd,
                          budget_alerted=budget_alerted, reason="budget")
                print(f"dark-factory: PAUSED — budget cap reached (estimated_usd={estimated_usd}, "
                      f"builder_calls={builder_calls}). Raise budget.max_usd (or max_calls) in "
                      f"config.json and run: supervisor.py resume --control-root "
                      f"{cfg.get('_control_root', '<cr>')} --decision continue")
                return PAUSED

            resp, err = invoke_adapter(adapter, "builder", workspace, prompt_file, timeout_s,
                                       exec_prefix=exec_prefix, env_extra=build_env_extra)
            if err or resp.get("status") != "ok":
                journal.write("ABORTED_BUILD_ERROR", iteration=i, detail=err or resp.get("detail", ""))
                mf = dict(mb_clean, outcome="ABORTED_BUILD_ERROR", iterations=i, qualified=False,
                          final_exam={"ran": False, "passed": None, "count": 0},
                          regressions=sorted(regressed),
                          budget=_budget_manifest_field(cfg["_budget"], builder_calls, estimated_usd))
                finalize_manifest(run_dir, mf, audit_key=audit_key)
                _clear_state()
                _kb_writeback(cfg, journal, mf, [])
                sys.stderr.write(f"dark-factory: build error at iteration {i}\n")
                return 2
            journal.write("BUILD", iteration=i)
            builder_calls = calls_after
            estimated_usd = est_after

            verify_env_extra = None
            if twins_enabled:
                try:
                    verify_env_extra = ts.reset(twin_defs, run_dir, twin_timeout)
                except df_twins.TwinError as e:
                    return _twin_error_abort(i, e)

            try:
                report = run_all(scenarios_dir, workspace, exec_wrapper=exec_prefix,
                                  env_extra=verify_env_extra, cohort="dev")
            except OracleError as e:
                journal.write("ABORTED_BUILD_ERROR", iteration=i, detail=f"invalid scenarios: {e}")
                mf = dict(mb_clean, outcome="ABORTED_BUILD_ERROR", iterations=i, qualified=False,
                          final_exam={"ran": False, "passed": None, "count": 0},
                          regressions=sorted(regressed),
                          budget=_budget_manifest_field(cfg["_budget"], builder_calls, estimated_usd))
                finalize_manifest(run_dir, mf, audit_key=audit_key)
                _clear_state()
                _kb_writeback(cfg, journal, mf, [])
                sys.stderr.write(f"dark-factory: {e}\n")
                return 2
            last_report = report
            atomic_write(os.path.join(run_dir, f"verifier_report_iter_{i}.json"), canonical_json(report))
            passing = sum(1 for r in report["results"] if r["pass"])
            journal.write("VERIFY", iteration=i, passing=passing, total=len(report["results"]))

            # Regression tracking (green->red on dev): a behavior passes this
            # iteration iff EVERY one of its dev scenarios passed. Any behavior
            # that was True last iteration and is False now regressed — journal
            # the behavior-ID only (barrier-safe), then roll prev_dev_status
            # forward. Informational + auditable; does not change control flow
            # (a regressed behavior is failing, so the loop already won't
            # converge on it).
            cur_dev_status = {}
            for r in report["results"]:
                bid = r["behavior_id"]
                cur_dev_status[bid] = cur_dev_status.get(bid, True) and bool(r["pass"])
            for bid, ok in cur_dev_status.items():
                if prev_dev_status.get(bid) is True and not ok:
                    journal.write("REGRESSION", iteration=i, behavior_id=bid)
                    regressed.add(bid)
            prev_dev_status = cur_dev_status

            if report["all_pass"]:
                # DEV converged. The sealed FINAL exam runs exactly ONCE, here, and its
                # results are NEVER fed back: project_feedback is never called on it,
                # nothing from it is written to `workspace`, and only final
                # behavior-IDs (never title/given/when/then/observed) reach the
                # journal/manifest. Same reset twin env as dev's verify (same phase).
                final = run_all(scenarios_dir, workspace, exec_wrapper=exec_prefix,
                                 env_extra=verify_env_extra, cohort="final")
                atomic_write(os.path.join(run_dir, "final_exam_report.json"), canonical_json(final))
                final_ran = final["count"] > 0
                journal.write("FINAL_EXAM", ran=final_ran,
                              passing=sum(1 for r in final["results"] if r["pass"]),
                              total=final["count"])
                fe = {"ran": final_ran, "passed": bool(final["all_pass"]) if final_ran else None,
                      "count": final["count"]}

                if final_ran and not final["all_pass"]:
                    journal.write("FINAL_EXAM_FAILED",
                                  failing=sorted({r["behavior_id"] for r in final["results"]
                                                  if not r["pass"]}))
                    mf = dict(mb_clean, outcome="FINAL_EXAM_FAILED", iterations=i,
                              qualified=False, final_exam=fe, regressions=sorted(regressed),
                              budget=_budget_manifest_field(cfg["_budget"], builder_calls, estimated_usd))
                    finalize_manifest(run_dir, mf, audit_key=audit_key)
                    _clear_state()
                    _kb_writeback(cfg, journal, mf, [])
                    print(f"dark-factory: FINAL-EXAM FAILED (artifact rejected; held-out "
                          f"scenarios not disclosed). Run: {run_dir}")
                    return 3

                # dev converged AND (final passed OR no final cohort): mandatory
                # security gates (M9) run HERE, on the converged artifact,
                # independent of scenario pass — a clean scenario run with a
                # planted secret still must not ship. AFTER the final exam,
                # BEFORE CONVERGED is declared.
                sec_report = _run_security_gates(cfg, journal, run_dir, workspace)
                if sec_report.get("failed"):
                    journal.write("SECURITY_GATE_FAILED", failed=sec_report["failed"])
                    mf = dict(mb_clean, outcome="SECURITY_GATE_FAILED", iterations=i,
                              qualified=False, final_exam=fe, regressions=sorted(regressed),
                              security=sec_report,
                              budget=_budget_manifest_field(cfg["_budget"], builder_calls, estimated_usd))
                    finalize_manifest(run_dir, mf, audit_key=audit_key)
                    _clear_state()
                    _kb_writeback(cfg, journal, mf, [])
                    print(f"dark-factory: security gate failed (artifact rejected): "
                          f"{', '.join(sec_report['failed'])}. Run: {run_dir}")
                    return 3

                journal.write("CONVERGED", iteration=i)
                eff = manifest_base.get("_effective_tier", "cooperative")
                outcome = "COMPLETE_QUALIFIED" if eff == "standard" else "COMPLETE_UNQUALIFIED"
                mf = dict(mb_clean, outcome=outcome, iterations=i, final_exam=fe,
                          regressions=sorted(regressed), security=sec_report,
                          budget=_budget_manifest_field(cfg["_budget"], builder_calls, estimated_usd))
                finalize_manifest(run_dir, mf, audit_key=audit_key)
                _clear_state()
                _kb_writeback(cfg, journal, mf, [])
                note = "" if final_ran else " [no sealed final exam administered]"
                print(f"dark-factory: CONVERGED "
                      f"({'qualified, standard' if eff == 'standard' else 'unqualified, cooperative'} tier). "
                      f"Workspace: {workspace}  Run: {run_dir}{note}")
                return 0

            feedback = project_feedback(report)
            atomic_write(os.path.join(run_dir, f"feedback_iter_{i}.json"), canonical_json(feedback))
            atomic_write(os.path.join(workspace, "feedback.json"), canonical_json(feedback))
            journal.write("FEEDBACK", iteration=i, failing=[f["behavior_id"] for f in feedback["failures"]])

            if cfg["_checkpoint"] == "pause" and i < cfg["max_iterations"]:
                write_checkpoint_report(run_dir, i, report)
                save_state(run_dir, next_iter=i + 1, feedback=feedback, workspace=workspace,
                          dev_status=prev_dev_status, regressions=regressed,
                          builder_calls=builder_calls, estimated_usd=estimated_usd,
                          budget_alerted=budget_alerted, reason="checkpoint")
                journal.write("CHECKPOINT", iteration=i,
                              failing=[f["behavior_id"] for f in feedback["failures"]])
                print(f"dark-factory: PAUSED at checkpoint (iteration {i}). "
                      f"Review {run_dir}/checkpoint_iter_{i}.md, then "
                      f"`supervisor.py resume --control-root {cfg.get('_control_root', '<CR>')}`.")
                return PAUSED

        failing = sorted({r["behavior_id"] for r in last_report["results"] if not r["pass"]})
        journal.write("CAP_REACHED", failing_behaviors=failing,
                      note="likely spec ambiguity — human decision needed")
        mf = dict(mb_clean, outcome="CAP_REACHED", iterations=cfg["max_iterations"], qualified=False,
                  final_exam={"ran": False, "passed": None, "count": 0},
                  regressions=sorted(regressed),
                  budget=_budget_manifest_field(cfg["_budget"], builder_calls, estimated_usd))
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

        # M7: coverage/oracle are deterministic from the control root +
        # scenarios, so resume() recomputes them (cheaply) instead of
        # re-running the fail-closed gate — a resumed run already passed the
        # gate once, on the initial `run`; re-gating here could spuriously
        # fail an already-approved run. If scenarios no longer load cleanly
        # (control root edited mid-run — not the gate's contract to police
        # here), fall back to honest "unknown" fields; a genuine oracle
        # problem still surfaces normally when `continue` re-enters the loop
        # and run_all() re-loads the scenarios itself.
        try:
            gate_scenarios = load_scenarios(scenarios_dir)
            gate_inert = df_gates.validate_oracle(gate_scenarios)
            oracle = {"mutation_validated": not gate_inert, "inert": gate_inert}
            try:
                gate_behaviors = df_gates.load_behaviors(control_root)
                cov = (df_gates.check_coverage(gate_behaviors, gate_scenarios)
                       if gate_behaviors is not None else {"checked": False})
            except df_gates.GateError:
                cov = {"checked": False}
        except OracleError:
            cov, oracle = {"checked": False}, {"mutation_validated": False, "inert": []}
        manifest_base["coverage"] = cov
        manifest_base["oracle"] = oracle
        # M9 default (same reasoning as _run_locked): overridden on a
        # resumed-converge by _run_loop's CONVERGED branch, which is the
        # SAME code both run() and resume() funnel through.
        manifest_base["security"] = {"checked": False}

        if decision == "abort":
            journal.write("ABORTED_BY_HUMAN")
            mf = dict(manifest_base, outcome="ABORTED_BY_HUMAN",
                      iterations=state["next_iter"] - 1,
                      qualified=False,
                      sandbox_backend=None, denial_probe_passed=False,
                      final_exam={"ran": False, "passed": None, "count": 0},
                      regressions=sorted(state.get("regressions", [])),
                      budget=_budget_manifest_field(
                          cfg["_budget"], state.get("builder_calls", 0),
                          state.get("estimated_usd", 0.0)))
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
                      iterations=state["next_iter"] - 1,
                      final_exam={"ran": False, "passed": None, "count": 0},
                      regressions=sorted(state.get("regressions", [])),
                      budget=_budget_manifest_field(
                          cfg["_budget"], state.get("builder_calls", 0),
                          state.get("estimated_usd", 0.0)))
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
            prev_dev_status=state.get("dev_status", {}),
            regressions=state.get("regressions", []),
            builder_calls=state.get("builder_calls", 0),
            estimated_usd=state.get("estimated_usd", 0.0),
            budget_alerted=state.get("budget_alerted", False),
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
                vkey = df_audit.load_key(args.key_path)
            except df_audit.AuditKeyError as e:
                sys.stderr.write(f"dark-factory: audit key error: {e}\n")
                sys.exit(2)
        sys.exit(0 if verify_manifest(args.run_dir, key=vkey) else 4)
    elif args.cmd == "resume":
        sys.exit(resume(args.control_root, args.decision, allow_downgrade=args.allow_downgrade))


if __name__ == "__main__":
    main()
