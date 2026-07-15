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
import df_container
import df_creds
import df_gates
import df_kb
import df_sandbox
import df_security
import df_twins
from df_common import atomic_write, canonical_json, sha256_file, sha256_str
from df_config import ConfigError, _disjoint, load_config
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
    def __init__(self, path: str, redactor=None):
        self.path = path
        self.redactor = redactor
        os.makedirs(os.path.dirname(path), exist_ok=True)

    def write(self, state: str, **data) -> None:
        if self.redactor is not None:
            data = self.redactor.redact_obj(data)
        line = canonical_json({"ts": _now(), "state": state, "data": data})
        with open(self.path, "a", encoding="utf-8") as f:
            f.write(line + "\n")
            f.flush()
            os.fsync(f.fileno())


def _redacted_write(path: str, payload, redactor) -> str:
    """The single choke point every persisted run artifact goes through.

    `payload` is either a str (already-serialized text, e.g. the checkpoint
    markdown) or a JSON-able dict/list (canonical_json'd here). `redactor`'s
    redact/redact_obj runs immediately before the bytes hit disk via
    atomic_write. redactor=None (no credentials configured) is a strict
    no-op: the exact bytes that would have been written pre-M11. Returns the
    text actually written (callers that need to hash/sign it use this, never
    a pre-redaction copy).
    """
    if isinstance(payload, str):
        text = redactor.redact(payload) if redactor is not None else payload
    else:
        obj = redactor.redact_obj(payload) if redactor is not None else payload
        text = canonical_json(obj)
    atomic_write(path, text)
    return text


def save_state(run_dir, next_iter, feedback, workspace, dev_status=None, regressions=None,
              builder_calls=0, estimated_usd=0.0, budget_alerted=False, reason="checkpoint",
              redactor=None):
    # state.json must NEVER carry a credential value: it holds only control-
    # plane bookkeeping (iteration counters, ID/taxonomy feedback, paths), but
    # it goes through the same redaction choke point as every other artifact
    # for defense in depth (redactor=None is a strict no-op).
    _redacted_write(
        os.path.join(run_dir, "state.json"),
        {
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
        },
        redactor,
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


def write_checkpoint_report(run_dir, iteration, report, redactor=None):
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
    _redacted_write(path, "\n".join(lines), redactor)
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


def _run_security_gates(cfg, journal, run_dir, workspace, redactor=None):
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
    _redacted_write(os.path.join(run_dir, "security_report.json"), sec_report, redactor)
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


def finalize_manifest(run_dir: str, extra: dict, audit_key: bytes = None, redactor=None) -> str:
    """Write manifest.json + manifest.sha256 sidecar.

    HONESTY (spec 7.5, cooperative/standard tier): a local process that can
    rewrite both files can defeat this. It detects accidental edits and
    casual tampering only; a signed chain / off-box anchor is hardened+.

    If `audit_key` is given, also write manifest.hmac (HMAC-SHA256 over the
    exact canonical manifest text, spec 7.5). The key itself is NEVER
    written to any run artifact.

    `redactor` (M11), if given, redacts credential VALUES out of the manifest
    before it is ever serialized — the digest and (if signed) the HMAC are
    computed over the redacted text, so verify-manifest's integrity checks
    stay consistent with the bytes actually on disk. `credentials` fields on
    the manifest are names/allowlist only and are never themselves subject to
    redaction (they contain no values).
    """
    journal_path = os.path.join(run_dir, "journal.jsonl")
    manifest = dict(extra)
    manifest["manifest_version"] = "0.1"
    manifest["journal_sha256"] = sha256_file(journal_path)
    manifest["finished_ts"] = _now()
    if audit_key is not None:
        manifest["audit_signing"] = True
    text = _redacted_write(os.path.join(run_dir, "manifest.json"), manifest, redactor)
    digest = sha256_str(text)
    atomic_write(os.path.join(run_dir, "manifest.sha256"), digest + "\n")
    if audit_key is not None:
        sig = df_audit.sign(audit_key, text.encode("utf-8"))
        atomic_write(os.path.join(run_dir, "manifest.hmac"), sig + "\n")
    return digest


def _kb_writeback(cfg, journal, manifest_dict, failing):
    """Opt-in KB write-back after a terminal manifest is finalized.

    Side-effect only: never raises, never affects control flow or exit codes.

    REDACTION COUPLING (M11): call sites pass the PRE-redaction manifest
    object. That is safe today ONLY because df_kb.build_summary hard-
    allowlists {finished_ts, invocation, outcome, tier, qualified,
    iterations} and never touches e.g. manifest["security"] (whose
    external-gate `detail` can embed a matched secret from tools like
    trufflehog). Any widening of build_summary's field allowlist MUST route
    the manifest through the run's Redactor (redact_obj) first.
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
                   exec_prefix=None, env_extra=None, env_full=None):
    """`env_full`, if given, is used INSTEAD of the inherit+merge below — it is
    the exact env dict the subprocess gets (e.g. df_creds.launcher_scoped_env's
    output, which STRIPS vars from os.environ; env_extra's dict(os.environ,
    **env_extra) merge can only add, never remove, so it cannot express a
    strip). `env_extra` behavior is unchanged when `env_full` is None (the
    verifier/twins path never sets env_full)."""
    req = {
        "adapter_protocol": "0.1",
        "role": role,
        "workdir": workdir,
        "prompt_file": prompt_file,
        "timeout_s": timeout_s,
    }
    argv = (list(exec_prefix) if exec_prefix else []) + [adapter]
    if env_full is not None:
        env = dict(env_full)
    else:
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
    if cfg["assurance"] == "hardened":
        os_backend = df_sandbox.current_backend()
        os_name = os_backend.name if os_backend is not None else None
        os_ok = os_backend is not None and os_backend.available() and df_sandbox.probe_denial(
            os_backend, control_root, workspace)
        c = cfg["_container"]
        dk_ok = df_container.docker_available() and df_container.probe_container(
            c["image"], control_root, workspace)
        if os_ok and dk_ok:
            return ("hardened", os_backend.wrap_prefix(control_root, workspace),
                    df_container.BACKEND_NAME, True)
        failed = []
        if not dk_ok:
            failed.append("docker")
        if not os_ok:
            failed.append("os_sandbox")
        reason = f"hardened probe failed: {', '.join(failed)}"
        if allow_downgrade:
            if os_ok:
                journal.write("DOWNGRADE", requested="hardened", effective="standard",
                              reason=reason)
                sys.stderr.write("dark-factory: hardened tier UNavailable — DOWNGRADED to "
                                 "standard (qualified) by --allow-downgrade.\n")
                return ("standard", os_backend.wrap_prefix(control_root, workspace), os_name, True)
            journal.write("DOWNGRADE", requested="hardened", effective="cooperative",
                          reason=reason)
            sys.stderr.write("dark-factory: hardened tier UNavailable — DOWNGRADED to "
                             "cooperative (unqualified) by --allow-downgrade.\n")
            # Intentionally (os_name, False), NOT (None, None) like a
            # configured-cooperative run: here the backend was probed and
            # FAILED, vs never probed at all — manifests keep that distinction.
            return ("cooperative", [], os_name, False)
        journal.write("PROBE_FAILED", requested="hardened", reason=reason)
        raise df_sandbox.SandboxError(
            "hardened tier requires a running Docker daemon + passing container probe "
            "(and a working OS sandbox for the verifier); none available "
            f"({reason}). Fix the sandbox/docker or set assurance=standard/cooperative "
            "(or pass --allow-downgrade).")
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


def _resolve_credentials(cfg):
    """Resolve cfg["_credentials"] (if configured) into (creds, redactor).

    Fail-closed at run start (spec: "ConfigError-style refusal at run start,
    exit 2, never a silent empty value"): a CredsError here writes only to
    stderr — no run_dir, no journal entry, nothing on disk — and the caller
    must return 2 before touching anything else. Absent block -> (None, None):
    exactly today's behavior, no builder env change, no writer touched.
    """
    if not cfg["_credentials"]:
        return None, None, None
    try:
        creds = df_creds.load_credentials(cfg["_credentials"])
    except df_creds.CredsError as e:
        return None, None, e
    return creds, df_creds.Redactor(creds.values()), None


def _twin_manifest_field(cfg, scenarios):
    """Compute the additive `twin_evidence` manifest field (M12), or None if
    twins aren't enabled. Loads twin defs FRESH (cheap, pure, read-only) so
    `variants` reflects whatever is on disk right now; raises
    df_twins.TwinError if twins are enabled but the defs don't load -- the
    caller decides how to abort (mirrors the existing twin-precondition
    failure handling, `_twin_error_abort`).

    `observed_assertions` counts scenarios (either cohort) whose `then`
    carries a twin-evidence assertion key -- purely a property of the
    already-validated scenario set, independent of any twin ever starting.
    """
    if not cfg["_twins"]["enabled"]:
        return None
    defs = df_twins.load_defs(os.path.join(cfg["_control_root"], "twins"))
    observed_assertions = sum(
        1 for sc in scenarios
        if "twin_observed" in sc["then"] or "stdout_echoes_twin" in sc["then"]
    )
    return {
        "variants": any(d.get("supports_variants") for d in defs),
        "observed_assertions": observed_assertions,
    }


def _variant_seed_extra(twin_defs):
    """A fresh per-pass DF_TWIN_VARIANT_SEED extra_env dict, ONLY when at
    least one twin def declares supports_variants -- else None, which makes
    the caller's ts.reset(..., extra_env=None) byte-identical to the
    pre-M12 reset call. Build-phase ts.start is NEVER passed this (the
    builder must never see a seed); only the verifier's reset calls are."""
    if any(d.get("supports_variants") for d in (twin_defs or [])):
        return {"DF_TWIN_VARIANT_SEED": uuid.uuid4().hex}
    return None


def _run_locked(control_root: str, project_src, cfg, allow_downgrade: bool = False) -> int:
    creds, redactor, creds_err = _resolve_credentials(cfg)
    if creds_err is not None:
        sys.stderr.write(f"dark-factory: credentials: {creds_err}\n")
        return 2

    invocation = _now().replace(":", "").replace("-", "") + "-" + uuid.uuid4().hex[:8]
    run_dir = os.path.join(control_root, "runs", invocation)
    os.makedirs(run_dir, exist_ok=True)
    journal = Journal(os.path.join(run_dir, "journal.jsonl"), redactor=redactor)

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
        # Additive (M11), names/allowlist only — NEVER values — on every
        # terminal manifest since manifest_base feeds every `dict(manifest_base,
        # outcome=...)` branch below, including the pre-build gate aborts.
        "credentials": ({"source": cfg["_credentials"]["source"],
                        "allowlist": list(cfg["_credentials"]["allowlist"])}
                       if cfg["_credentials"] else None),
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
                  security={"checked": False}, container=None,
                  budget=_budget_manifest_field(cfg["_budget"], 0, 0.0))
        finalize_manifest(run_dir, mf, audit_key=audit_key, redactor=redactor)
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
                  security={"checked": False}, container=None,
                  budget=_budget_manifest_field(cfg["_budget"], 0, 0.0))
        finalize_manifest(run_dir, mf, audit_key=audit_key, redactor=redactor)
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
                      security={"checked": False}, container=None,
                      budget=_budget_manifest_field(cfg["_budget"], 0, 0.0))
            finalize_manifest(run_dir, mf, audit_key=audit_key, redactor=redactor)
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

    # M12: twin_evidence manifest field, computed here (scenarios validated,
    # nothing built yet) so it's on every terminal manifest from this point
    # on -- the same "additive, present as soon as it's knowable" pattern as
    # `credentials` (M11). A load failure here is a twin precondition
    # failure exactly like the one _twin_error_abort handles inside the
    # build/verify loop, just caught before any build is attempted.
    try:
        manifest_base["twin_evidence"] = _twin_manifest_field(cfg, scenarios)
    except df_twins.TwinError as e:
        journal.write("TWIN_ERROR", iteration=0, detail=str(e))
        mf = dict(manifest_base, outcome="ABORTED_BUILD_ERROR", iterations=0, qualified=False,
                  sandbox_backend=None, denial_probe_passed=False, snapshot_sha256=None,
                  final_exam={"ran": False, "passed": None, "count": 0}, regressions=[],
                  container=None, twin_evidence=None,
                  budget=_budget_manifest_field(cfg["_budget"], 0, 0.0))
        finalize_manifest(run_dir, mf, audit_key=audit_key, redactor=redactor)
        _kb_writeback(cfg, journal, mf, [])
        sys.stderr.write(f"dark-factory: twin precondition failed: {e}\n")
        return 2

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
                      regressions=[], container=None,
                      budget=_budget_manifest_field(cfg["_budget"], 0, 0.0))
            finalize_manifest(run_dir, mf, audit_key=audit_key, redactor=redactor)
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
    manifest_base["qualified"] = eff_tier in ("standard", "hardened")
    manifest_base["sandbox_backend"] = backend_name
    manifest_base["denial_probe_passed"] = probe_passed
    manifest_base["container"] = dict(cfg["_container"]) if eff_tier == "hardened" else None
    manifest_base["_effective_tier"] = eff_tier   # internal; stripped before finalize
    # cooperative banner only when the EFFECTIVE tier is cooperative:
    if eff_tier not in ("standard", "hardened"):
        sys.stderr.write("dark-factory: COOPERATIVE MODE — unqualified: no probe-proven "
                         "isolation; outcome can never be a qualified ship-candidate.\n")
    try:
        return _run_loop(cfg, journal, run_dir, manifest_base, spec_text, scenarios_dir,
                         adapter, timeout_s, workspace, start_iter=1, feedback=None,
                         exec_prefix=exec_prefix, audit_key=audit_key,
                         creds=creds, redactor=redactor)
    except df_sandbox.SandboxError as e:
        # In-loop fail-closed guards (e.g. the hardened adapter-mount re-check)
        # must exit 2 like every other refusal, not escape as a traceback.
        sys.stderr.write(f"dark-factory: {e}\n")
        return 2


def _run_loop(cfg, journal, run_dir, manifest_base, spec_text, scenarios_dir,
              adapter, timeout_s, workspace, start_iter, feedback, exec_prefix=None,
              audit_key=None, prev_dev_status=None, regressions=None,
              builder_calls=0, estimated_usd=0.0, budget_alerted=False,
              creds=None, redactor=None):
    exec_prefix = exec_prefix or []
    effective = manifest_base.get("_effective_tier", "cooperative")
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
        finalize_manifest(run_dir, mf, audit_key=audit_key, redactor=redactor)
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
                          budget_alerted=budget_alerted, reason="budget", redactor=redactor)
                print(f"dark-factory: PAUSED — budget cap reached (estimated_usd={estimated_usd}, "
                      f"builder_calls={builder_calls}). Raise budget.max_usd (or max_calls) in "
                      f"config.json and run: supervisor.py resume --control-root "
                      f"{cfg.get('_control_root', '<cr>')} --decision continue")
                return PAUSED

            # Builder isolation: at effective "hardened" the builder runs inside a
            # Docker container (control root never mounted — barrier by
            # construction), built fresh per call; the OS-sandbox exec_prefix
            # returned by resolve_isolation is reserved for the VERIFIER only
            # (run_all below), unchanged. Builder-side twin env cannot cross the
            # container boundary in M10 (journaled, not silently dropped) — the
            # container always gets a clean env regardless of twins, PLUS
            # (M11) the configured credential allowlist via `-e` container env.
            builder_env_full = None
            if effective == "hardened":
                c = cfg["_container"]
                adapter_ro_dir = os.path.dirname(os.path.realpath(adapter))
                # Belt-and-suspenders (defense in depth against config drift /
                # TOCTOU): df_config already rejects a hardened adapter whose
                # directory overlaps the control root, but this dir is about to
                # be bind-mounted into the builder container — re-verify at the
                # moment of use rather than trusting the load-time check.
                if not _disjoint(adapter_ro_dir, cfg["_control_root"]):
                    raise df_sandbox.SandboxError(
                        "hardened: refusing to mount the adapter directory — it "
                        f"overlaps the control root ({adapter_ro_dir}); the "
                        "holdout barrier would be breached by construction")
                # (M11) Credential values enter the container ONLY as `-e` argv
                # baked into the docker invocation by build_argv — never via the
                # docker CLIENT process's own env. This is the sole channel any
                # env reaches the hardened builder; `-e K=V` is visible to local
                # `ps` (documented residual, see references/credentials.md).
                builder_prefix = df_container.build_argv(
                    c["image"], workspace,
                    ro_mounts=[adapter_ro_dir],
                    network=c["network"], memory=c["memory"], pids=c["pids"],
                    env=creds if creds else None)
                if build_env_extra:
                    journal.write("TWIN_ENV_SKIPPED", tier="hardened",
                                  reason="builder-side twin env not forwarded into "
                                         "container (M12)")
                builder_env = creds
            else:
                builder_prefix = exec_prefix
                if creds:
                    # Strip credential-shaped launcher vars that aren't
                    # allowlisted, then merge the resolved creds in — a full
                    # env REPLACEMENT (env_full), since env_extra's
                    # dict(os.environ, **env_extra) merge can only add, never
                    # strip. Twin env (build_env_extra: DF_TWIN_* endpoints)
                    # is NOT a credential and keeps flowing to non-hardened
                    # builders exactly as pre-M11 — merged over the scoped
                    # env so twins+credentials compose instead of silently
                    # dropping the twin endpoints.
                    builder_env = None
                    builder_env_full = df_creds.launcher_scoped_env(
                        os.environ, cfg["_credentials"]["allowlist"], creds)
                    builder_env_full.update(build_env_extra or {})
                else:
                    builder_env = build_env_extra

            # env_full is only ever passed when actually set (M11 credentials
            # configured at standard/cooperative): existing invoke_adapter
            # call sites/tests that predate env_full and don't accept it as a
            # kwarg keep working unchanged when no credentials are configured.
            _invoke_kwargs = {"exec_prefix": builder_prefix, "env_extra": builder_env}
            if builder_env_full is not None:
                _invoke_kwargs["env_full"] = builder_env_full
            resp, err = invoke_adapter(adapter, "builder", workspace, prompt_file, timeout_s,
                                       **_invoke_kwargs)
            if err or resp.get("status") != "ok":
                journal.write("ABORTED_BUILD_ERROR", iteration=i, detail=err or resp.get("detail", ""))
                mf = dict(mb_clean, outcome="ABORTED_BUILD_ERROR", iterations=i, qualified=False,
                          final_exam={"ran": False, "passed": None, "count": 0},
                          regressions=sorted(regressed),
                          budget=_budget_manifest_field(cfg["_budget"], builder_calls, estimated_usd))
                finalize_manifest(run_dir, mf, audit_key=audit_key, redactor=redactor)
                _clear_state()
                _kb_writeback(cfg, journal, mf, [])
                sys.stderr.write(f"dark-factory: build error at iteration {i}\n")
                return 2
            journal.write("BUILD", iteration=i)
            builder_calls = calls_after
            estimated_usd = est_after

            # M12: the dev-cohort verify pass gets a FRESH twin reset with a
            # fresh per-pass seed (only when a twin def supports_variants --
            # else extra_env=None, exactly today's reset). The seed lives
            # ONLY in this local var, fed to run_all (the scenario/candidate
            # env) below -- it never touches build_env_extra/builder_env, so
            # it cannot reach the builder (see the barrier note above
            # invoke_adapter's env_extra/env_full handling).
            verify_env_extra = None
            if twins_enabled:
                try:
                    verify_env_extra = ts.reset(twin_defs, run_dir, twin_timeout,
                                                 extra_env=_variant_seed_extra(twin_defs))
                except df_twins.TwinError as e:
                    return _twin_error_abort(i, e)

            try:
                report = run_all(scenarios_dir, workspace, exec_wrapper=exec_prefix,
                                  env_extra=verify_env_extra, cohort="dev",
                                  observer_files=ts.observer_files if ts else None)
            except OracleError as e:
                journal.write("ABORTED_BUILD_ERROR", iteration=i, detail=f"invalid scenarios: {e}")
                mf = dict(mb_clean, outcome="ABORTED_BUILD_ERROR", iterations=i, qualified=False,
                          final_exam={"ran": False, "passed": None, "count": 0},
                          regressions=sorted(regressed),
                          budget=_budget_manifest_field(cfg["_budget"], builder_calls, estimated_usd))
                finalize_manifest(run_dir, mf, audit_key=audit_key, redactor=redactor)
                _clear_state()
                _kb_writeback(cfg, journal, mf, [])
                sys.stderr.write(f"dark-factory: {e}\n")
                return 2
            last_report = report
            # verifier_report_iter_*.json carries raw builder-produced observed
            # stdout/stderr (spec: run_all's `observed` dict) — a real smuggle
            # channel, not merely defensive — so it goes through the redactor.
            _redacted_write(os.path.join(run_dir, f"verifier_report_iter_{i}.json"), report, redactor)
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
                # journal/manifest. M12: when a twin supports_variants, the
                # final exam gets its OWN fresh twin reset with a fresh seed
                # (distinct from dev-verify's) -- a builder that hardcoded
                # dev-verify's served token cannot rely on seeing it again at
                # final exam. When NO twin supports_variants, a reset would be
                # pure churn (kill+relaunch+readiness-wait) with no variant to
                # serve, so we reuse dev-verify's already-running twins --
                # byte-identical to the pre-M12 final-exam path (zero restart).
                final_env_extra = verify_env_extra
                if twins_enabled:
                    seed_extra = _variant_seed_extra(twin_defs)
                    if seed_extra is not None:
                        try:
                            final_env_extra = ts.reset(twin_defs, run_dir, twin_timeout,
                                                        extra_env=seed_extra)
                        except df_twins.TwinError as e:
                            return _twin_error_abort(i, e)
                final = run_all(scenarios_dir, workspace, exec_wrapper=exec_prefix,
                                 env_extra=final_env_extra, cohort="final",
                                 observer_files=ts.observer_files if ts else None)
                _redacted_write(os.path.join(run_dir, "final_exam_report.json"), final, redactor)
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
                    finalize_manifest(run_dir, mf, audit_key=audit_key, redactor=redactor)
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
                sec_report = _run_security_gates(cfg, journal, run_dir, workspace, redactor=redactor)
                if sec_report.get("failed"):
                    journal.write("SECURITY_GATE_FAILED", failed=sec_report["failed"])
                    mf = dict(mb_clean, outcome="SECURITY_GATE_FAILED", iterations=i,
                              qualified=False, final_exam=fe, regressions=sorted(regressed),
                              security=sec_report,
                              budget=_budget_manifest_field(cfg["_budget"], builder_calls, estimated_usd))
                    finalize_manifest(run_dir, mf, audit_key=audit_key, redactor=redactor)
                    _clear_state()
                    _kb_writeback(cfg, journal, mf, [])
                    print(f"dark-factory: security gate failed (artifact rejected): "
                          f"{', '.join(sec_report['failed'])}. Run: {run_dir}")
                    return 3

                journal.write("CONVERGED", iteration=i)
                eff = manifest_base.get("_effective_tier", "cooperative")
                outcome = "COMPLETE_QUALIFIED" if eff in ("standard", "hardened") else "COMPLETE_UNQUALIFIED"
                mf = dict(mb_clean, outcome=outcome, iterations=i, final_exam=fe,
                          regressions=sorted(regressed), security=sec_report,
                          budget=_budget_manifest_field(cfg["_budget"], builder_calls, estimated_usd))
                finalize_manifest(run_dir, mf, audit_key=audit_key, redactor=redactor)
                _clear_state()
                _kb_writeback(cfg, journal, mf, [])
                note = "" if final_ran else " [no sealed final exam administered]"
                print(f"dark-factory: CONVERGED "
                      f"({'qualified, ' + eff if eff in ('standard', 'hardened') else 'unqualified, cooperative'} tier). "
                      f"Workspace: {workspace}  Run: {run_dir}{note}")
                return 0

            feedback = project_feedback(report)
            # feedback_iter/*.json and workspace/feedback.json are structurally
            # guaranteed value-free (validate_feedback's ALLOWED_TOP/ALLOWED_FAILURE
            # keysets — behavior_id/taxonomy only), so redaction is a defensive
            # no-op here rather than a load-bearing choke point.
            _redacted_write(os.path.join(run_dir, f"feedback_iter_{i}.json"), feedback, redactor)
            atomic_write(os.path.join(workspace, "feedback.json"), canonical_json(feedback))
            journal.write("FEEDBACK", iteration=i, failing=[f["behavior_id"] for f in feedback["failures"]])

            if cfg["_checkpoint"] == "pause" and i < cfg["max_iterations"]:
                write_checkpoint_report(run_dir, i, report, redactor=redactor)
                save_state(run_dir, next_iter=i + 1, feedback=feedback, workspace=workspace,
                          dev_status=prev_dev_status, regressions=regressed,
                          builder_calls=builder_calls, estimated_usd=estimated_usd,
                          budget_alerted=budget_alerted, reason="checkpoint", redactor=redactor)
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
        finalize_manifest(run_dir, mf, audit_key=audit_key, redactor=redactor)
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

    # Isolation cannot be trusted across a pause, and neither can credentials:
    # re-resolve them every resume (env-file/keychain contents may have
    # changed, or the operator may be fixing a prior refusal) — fail-closed,
    # exit 2, BEFORE any builder call, exactly like the fresh-run path.
    creds, redactor, creds_err = _resolve_credentials(cfg)
    if creds_err is not None:
        sys.stderr.write(f"dark-factory: credentials: {creds_err}\n")
        return 2

    try:
        lock = acquire_lock(control_root)
    except LockError as e:
        sys.stderr.write(f"dark-factory: {e}\n")
        return 2
    try:
        state = load_state(run_dir)
        journal = Journal(os.path.join(run_dir, "journal.jsonl"), redactor=redactor)

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
            "credentials": ({"source": cfg["_credentials"]["source"],
                            "allowlist": list(cfg["_credentials"]["allowlist"])}
                           if cfg["_credentials"] else None),
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
        gate_scenarios = None
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

        # M12: twin_evidence, recomputed fresh on every resume (deterministic
        # from cfg + the control root's twins/*.json + scenarios) -- same
        # "fresh + resume" threading as `credentials`. gate_scenarios may be
        # None if scenarios failed to reload above; observed_assertions then
        # honestly falls back to 0 rather than raising here too.
        try:
            manifest_base["twin_evidence"] = _twin_manifest_field(cfg, gate_scenarios or [])
        except df_twins.TwinError as e:
            journal.write("TWIN_ERROR", detail=str(e))
            mf = dict(manifest_base, outcome="ABORTED_BUILD_ERROR",
                      iterations=state["next_iter"] - 1, qualified=False,
                      sandbox_backend=None, denial_probe_passed=False, container=None,
                      final_exam={"ran": False, "passed": None, "count": 0},
                      regressions=sorted(state.get("regressions", [])),
                      twin_evidence=None,
                      budget=_budget_manifest_field(
                          cfg["_budget"], state.get("builder_calls", 0),
                          state.get("estimated_usd", 0.0)))
            finalize_manifest(run_dir, mf, audit_key=audit_key, redactor=redactor)
            os.unlink(os.path.join(run_dir, "state.json"))
            _kb_writeback(cfg, journal, mf, [])
            sys.stderr.write(f"dark-factory: twin precondition failed: {e}\n")
            return 2

        if decision == "abort":
            journal.write("ABORTED_BY_HUMAN")
            mf = dict(manifest_base, outcome="ABORTED_BY_HUMAN",
                      iterations=state["next_iter"] - 1,
                      qualified=False,
                      sandbox_backend=None, denial_probe_passed=False, container=None,
                      final_exam={"ran": False, "passed": None, "count": 0},
                      regressions=sorted(state.get("regressions", [])),
                      budget=_budget_manifest_field(
                          cfg["_budget"], state.get("builder_calls", 0),
                          state.get("estimated_usd", 0.0)))
            finalize_manifest(run_dir, mf, audit_key=audit_key, redactor=redactor)
            os.unlink(os.path.join(run_dir, "state.json"))
            _kb_writeback(cfg, journal, mf, [])
            print("dark-factory: ABORTED by human.")
            return 2
        if decision == "accept":
            journal.write("ACCEPTED_BY_HUMAN",
                          note="human accepted a non-passing build — waived/unverified")
            mf = dict(manifest_base, outcome="ACCEPTED_WAIVED",
                      qualified=False,
                      sandbox_backend=None, denial_probe_passed=False, container=None,
                      iterations=state["next_iter"] - 1,
                      final_exam={"ran": False, "passed": None, "count": 0},
                      regressions=sorted(state.get("regressions", [])),
                      budget=_budget_manifest_field(
                          cfg["_budget"], state.get("builder_calls", 0),
                          state.get("estimated_usd", 0.0)))
            finalize_manifest(run_dir, mf, audit_key=audit_key, redactor=redactor)
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
        manifest_base["qualified"] = eff_tier in ("standard", "hardened")
        manifest_base["sandbox_backend"] = backend_name
        manifest_base["denial_probe_passed"] = probe_passed
        manifest_base["container"] = dict(cfg["_container"]) if eff_tier == "hardened" else None
        manifest_base["_effective_tier"] = eff_tier
        if eff_tier not in ("standard", "hardened"):
            sys.stderr.write("dark-factory: COOPERATIVE MODE — unqualified: no probe-proven "
                             "isolation; outcome can never be a qualified ship-candidate.\n")
        try:
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
                creds=creds, redactor=redactor,
            )
        except df_sandbox.SandboxError as e:
            # In-loop fail-closed guards exit 2, not an unhandled traceback.
            sys.stderr.write(f"dark-factory: {e}\n")
            return 2
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
