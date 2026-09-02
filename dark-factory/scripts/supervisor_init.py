"""The `init` scaffold command and the agent-authored `author-scenarios` flow.

Extracted verbatim from supervisor.py (see supervisor.py for the CLI entry point and
the run/resume core). Every top-level name here is re-exported by supervisor.py, so
`supervisor.<name>` keeps working for tests and df_evidence_bundle.
"""
import json
import os
import shutil
import sys
import tempfile

import df_author
import df_critic
import df_gates
import df_init
from df_common import atomic_write, sha256_file
from df_config import (
    ConfigError,
)
from run_scenarios import (
    load_scenarios,
)
from supervisor_core import (
    Journal,
    _enforce_adapter_digests,
    _sup,
)


def _init_report_lines(report: dict) -> list:
    """Human-readable failure lines for a not-ok df_init.validate_scaffold
    report -- covers every branch that report shape can take (config,
    scenario-load, behaviors-load, inert, coverage, spec_leak)."""
    lines = []
    if not report.get("config_ok"):
        lines.append(f"  config.json: FAILED ({report.get('config_error', 'did not load')})")
        return lines
    if "scenarios_error" in report:
        lines.append(f"  scenarios/: FAILED to load ({report['scenarios_error']})")
        return lines
    if "behaviors_error" in report:
        lines.append(f"  behaviors.json: FAILED to load ({report['behaviors_error']})")
        return lines
    if report.get("inert"):
        lines.append(f"  inert (non-discriminating) scenarios: {report['inert']}")
    coverage = report.get("coverage", {})
    if coverage.get("uncovered_dev"):
        lines.append(f"  behaviors with no dev-cohort scenario: {coverage['uncovered_dev']}")
    if coverage.get("orphan_scenarios"):
        lines.append(f"  scenarios referencing an undeclared behavior_id: {coverage['orphan_scenarios']}")
    if report.get("spec_leak"):
        ids = sorted({leak["scenario_id"] for leak in report["spec_leak"]})
        lines.append(
            f"  spec_leak: scenario(s) {ids} have a `then` value appearing verbatim in "
            "spec.md (the builder-visible spec would leak the holdout answer)"
        )
    if report.get("network_incompatible"):
        lines.append(
            f"  candidate_network 'deny' vs http scenario(s) {report['network_incompatible']}: "
            "an http/property-http scenario polls the candidate over 127.0.0.1, which "
            "'deny' blocks — use candidate_network 'loopback' or drop the http steps "
            "(run's pre-build gate enforces the SAME rule)"
        )
    if report.get("adequacy_under_covered"):
        lines.append(
            f"  scenario-class adequacy: {report['adequacy_under_covered']} — behavior(s) "
            "missing a required scenario class under this root's scenario_adequacy "
            "policy (run's pre-build gate enforces the SAME rule)"
        )
    if not lines:
        lines.append("  (validate_scaffold reported not-ok with no specific failure recorded)")
    return lines


def _init_prerequisite_lines(cfg: dict) -> list:
    """Run-time prerequisites for the scaffolded control root's assurance
    tier -- printed, never checked here (init never runs a build; `run`
    fails closed on its own if these aren't actually met)."""
    adapter = cfg.get("roles", {}).get("builder", {}).get("adapter", "<unset>")
    lines = [f"  - the builder CLI/adapter must be installed and executable: {adapter}"]
    assurance = cfg.get("assurance")
    if assurance in ("hardened", "enterprise"):
        lines.append(f"  - a running Docker daemon (assurance: {assurance})")
        lines.append("  - a working OS sandbox backend for the verifier (macOS sandbox-exec / Linux bwrap)")
    elif assurance == "standard":
        lines.append("  - a working OS sandbox backend (macOS sandbox-exec / Linux bwrap) + a passing denial probe")
    if assurance == "enterprise":
        lines.append(
            "  - approver PRIVATE keys distributed to the operators named by "
            "custody.approvers (generated off-host, e.g. `supervisor.py "
            "df-custody keygen`; init never generates or sees a private key) "
            "-- a run stays CUSTODY_PENDING until >=threshold approvers sign "
            "via `df-custody sign` + `attach` (see references/enterprise.md)"
        )
        lines.append(
            "  - the configured audit sink must be REACHABLE and its WORM/"
            "retention (Object Lock) config ACTIVE -- init only checked the "
            "sink config's SHAPE, never reached it; verify this by hand "
            "(see references/enterprise.md, 'Manual WORM-readback preflight')"
        )
    if cfg.get("enterprise_downgrade_note"):
        lines.append(f"  - NOTE: {cfg['enterprise_downgrade_note']}")
    return lines


def init_cmd(control_root: str, answers_path: str, force: bool = False, force_keep: bool = False) -> int:
    """CLI body for `init`: df_init.scaffold(control_root, answers) then
    df_init.validate_scaffold(control_root) -- init BLESSES a control root
    only when the real validators (df_config.load_config, oracle
    discrimination, coverage, the spec_leak barrier check) all pass, exactly
    what `run` would independently accept. Never runs a build.

    ok -> prints the scaffolded tree summary + the exact `run` command + the
    tier's run-time prerequisites, returns 0.
    not ok -> prints the report's specific failures, removes the scaffolded
    tree (unless `force_keep`), returns 2.
    An InitError raised by scaffold() itself (a pure-answers violation, or a
    non-empty control_root refused without `force`) means NOTHING was ever
    written -- printed to stderr, returns 2, no cleanup needed.
    """
    control_root = os.path.abspath(control_root)
    try:
        if answers_path == "-":
            answers_text = sys.stdin.read()
        else:
            with open(answers_path, encoding="utf-8") as f:
                answers_text = f.read()
    except OSError as e:
        sys.stderr.write(f"dark-factory: init: cannot read answers ({e})\n")
        return 2

    try:
        answers = json.loads(answers_text)
    except json.JSONDecodeError as e:
        sys.stderr.write(f"dark-factory: init: answers is not valid JSON ({e})\n")
        return 2
    if not isinstance(answers, dict):
        sys.stderr.write("dark-factory: init: answers must be a JSON object\n")
        return 2

    # --control-root is the single source of truth for WHERE the scaffold is
    # written; overwrite whatever (likely placeholder) control_root the
    # answers carry so df_init's disjointness check (build_config) runs
    # against the ACTUAL write target, never a stale path from the file.
    answers = dict(answers)
    answers["control_root"] = control_root
    if force:
        answers["force"] = True

    try:
        df_init.scaffold(control_root, answers)
    except df_init.InitError as e:
        sys.stderr.write(f"dark-factory: init: {e}\n")
        return 2

    ok, report = df_init.validate_scaffold(control_root)
    if not ok:
        sys.stderr.write(f"dark-factory: init: scaffolded control root FAILED validation ({control_root}):\n")
        for line in _init_report_lines(report):
            sys.stderr.write(line + "\n")
        if force_keep:
            sys.stderr.write(
                f"dark-factory: init: --force-keep set -- leaving the invalid tree at {control_root}\n")
        else:
            shutil.rmtree(control_root, ignore_errors=True)
            sys.stderr.write(f"dark-factory: init: removed the invalid control root {control_root}\n")
        return 2

    cfg = _sup().load_config(control_root)
    behaviors = df_gates.load_behaviors(control_root) or []
    # M40: a scenarios-pending-author scaffold validated as structurally OK
    # (validate_scaffold set scenarios_pending) but has NO scenario files yet.
    # Print the pending summary + the author-scenarios next step instead of
    # loading a scenario set that doesn't exist.
    pending = report.get("scenarios_pending")
    if not pending:
        scenarios = load_scenarios(os.path.join(control_root, "scenarios"))
        dev_n = sum(1 for s in scenarios if s.get("cohort", "dev") == "dev")
        final_n = sum(1 for s in scenarios if s.get("cohort") == "final")

    print(f"dark-factory: init OK -- control root {control_root}")
    print(f"  config.json     assurance={cfg['assurance']}  autonomy={cfg['autonomy']}")
    if cfg.get("enterprise_downgrade_note"):
        print(f"  ** NOT enterprise-qualified ** {cfg['enterprise_downgrade_note']}")
    print("  spec.md         (builder-visible; no scenario content)")
    print(f"  behaviors.json  {len(behaviors)} behavior(s): {', '.join(b['id'] for b in behaviors)}")
    if pending:
        author_adapter = cfg.get("roles", {}).get("author", {}).get("adapter", "<unset>")
        print("  scenarios/      PENDING -- an agent author will write them "
              "(scenarios_pending_author marker present)")
        print("Next: have the author agent write the hidden scenarios:")
        print(f"  python3 {os.path.abspath(_sup().__file__)} author-scenarios --control-root {control_root}")
        print(f"  (author adapter, a DIFFERENT model than the builder: {author_adapter})")
        print("Then, after reviewing scenarios/*.json:")
        print(f"  python3 {os.path.abspath(_sup().__file__)} run --control-root {control_root}")
    else:
        print(f"  scenarios/      {len(scenarios)} scenario(s) ({dev_n} dev, {final_n} final/sealed)")
        print("Run:")
        print(f"  python3 {os.path.abspath(_sup().__file__)} run --control-root {control_root}")
    print("Prerequisites:")
    for line in _init_prerequisite_lines(cfg):
        print(line)
    return 0


def _author_review_confirm(normalized: list) -> bool:
    """--review gate: print every generated scenario (id/behavior/cohort/title
    + the literal run/then, control-plane only -- these never reach the
    builder) and require an interactive 'yes' before install. Honors the
    documented "human review is RECOMMENDED" limitation without forcing it
    (off by default). A non-tty stdin or anything but an explicit yes is a
    fail-closed decline -- authoring never installs an unreviewed set under
    --review."""
    print("dark-factory: author-scenarios --review -- generated scenarios "
          "(NOT yet installed):")
    for sc in normalized:
        print(f"  [{sc['id']}] behavior={sc['behavior_id']} cohort={sc['cohort']} "
              f"title={sc.get('title', '')!r}")
        print(f"      run:  {sc['when']['run']}")
        print(f"      then: {json.dumps(sc['then'], sort_keys=True)}")
    try:
        answer = input("Install these scenarios? [y/N] ").strip().lower()
    except EOFError:
        answer = ""
    return answer in ("y", "yes")


def _author_once(adapter, spec_text, behaviors, policy, timeout_s, *,
                 attempt_feedback, critic_feedback):
    """One author invocation in a FRESH scratch workdir (torn down here -- a
    pre-run artifact that must never persist or reach the builder). Returns
    (status, payload):
      ("adapter_error", detail)          -- transport/env failure (deterministic)
      ("parse_error", report)            -- unusable scenarios.json (retryable)
      ("invalid", report)                -- failed a gate (retryable)
      ("ok", (report, normalized))       -- a validated, installable set
    `policy` (M42) is threaded into BOTH the prompt (so the author knows the
    required classes) and validate_authored (so the adequacy gate uses it).
    `critic_feedback`, when set, carries a prior critic's BLOCKING findings for
    the author to address in this revision (barrier-safe: verifier-side text)."""
    workdir = tempfile.mkdtemp(prefix="df-author-")
    try:
        prompt = df_author.compose_author_prompt(
            spec_text, behaviors, policy=policy,
            attempt_feedback=attempt_feedback, critic_feedback=critic_feedback)
        prompt_file = os.path.join(workdir, "AUTHOR_PROMPT.md")
        atomic_write(prompt_file, prompt)
        resp, err = _sup().invoke_adapter(adapter, "author", workdir, prompt_file, timeout_s)
        if err or resp.get("status") != "ok":
            return "adapter_error", (err or resp.get("detail", ""))
        try:
            scenarios_raw = df_author.parse_author_output(workdir)
        except df_author.AuthorError as e:
            report = _empty_author_report()
            report["schema_errors"] = [str(e)]
            return "parse_error", report
        ok, report, normalized = df_author.validate_authored(
            scenarios_raw, spec_text, behaviors, policy)
        if not ok:
            return "invalid", report
        return "ok", (report, normalized)
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


def _critic_once(critic_adapter, spec_text, behaviors, normalized, policy,
                 timeout_s, declared_ids):
    """One critic invocation in a FRESH scratch workdir (torn down here -- its
    output is control-plane and MUST NEVER reach the builder workspace).
    Returns (status, payload):
      ("adapter_error", detail)              -- transport/env failure
      ("parse_error", detail)                -- unparseable/wrong-shape verdict
      ("ok", (blocking, advisories))         -- normalized findings
    The critic sees the AUTHORED scenarios (verifier side); its verdict never
    crosses the barrier."""
    workdir = tempfile.mkdtemp(prefix="df-critic-")
    try:
        prompt = df_critic.compose_critic_prompt(spec_text, behaviors, normalized, policy=policy)
        prompt_file = os.path.join(workdir, "CRITIC_PROMPT.md")
        atomic_write(prompt_file, prompt)
        resp, err = _sup().invoke_adapter(critic_adapter, "critic", workdir, prompt_file, timeout_s)
        if err or resp.get("status") != "ok":
            return "adapter_error", (err or resp.get("detail", ""))
        try:
            verdict = df_critic.parse_critic_output(workdir)
            blocking, advisories = df_critic.validate_critic_verdict(verdict, declared_ids)
        except df_critic.CriticError as e:
            return "parse_error", str(e)
        return "ok", (blocking, advisories)
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


def author_scenarios_cmd(control_root: str, attempts: int = 3, review: bool = False) -> int:
    """CLI body for `author-scenarios` (M40): an AGENT author (a different
    model than the builder, enforced at config load) writes the hidden
    scenarios into a scaffolded, scenarios-pending control root.

    Flow: load config (must have roles.author) -> load spec.md + behaviors.json
    -> invoke the author adapter in a FRESH scratch workdir (role="author") ->
    parse its scenarios.json -> validate through the IDENTICAL init gates
    (discrimination/coverage/spec-leak/shape). On a validation failure, re-invoke
    with impoverished, barrier-safe feedback up to `attempts` times. On success,
    ATOMICALLY install one file per scenario into <control_root>/scenarios/ (the
    same layout df_init.scaffold produces), clear the pending marker LAST (the
    commit point -- a crash before it leaves `run` still fail-closed), and journal
    an AUTHORED_SCENARIOS control-plane event (adapter/attempts/counts -- NEVER
    scenario content). Exhausted attempts => exit 2, control root left with NO
    scenarios (never a bad partial set). The barrier is byte-for-byte unchanged:
    scenarios seal via the existing path and `run` is untouched.
    """
    control_root = os.path.abspath(control_root)
    try:
        cfg = _sup().load_config(control_root)
    except ConfigError as e:
        sys.stderr.write(f"dark-factory: author-scenarios: config error: {e}\n")
        return 2

    author = cfg.get("_author")
    if author is None:
        sys.stderr.write(
            "dark-factory: author-scenarios: no roles.author configured in "
            f"{control_root}/config.json -- add a roles.author block (a DIFFERENT "
            "adapter than roles.builder) and re-run\n")
        return 2

    scenarios_dir = os.path.join(control_root, "scenarios")
    existing = (
        [n for n in os.listdir(scenarios_dir) if n.endswith(".json")]
        if os.path.isdir(scenarios_dir) else []
    )
    if existing:
        # Never clobber an already-populated scenarios/ -- whether human- or a
        # prior author-written. Re-authoring is an explicit, destructive act the
        # operator must do by clearing scenarios/ (and restoring the pending
        # marker) themselves; this command only FILLS an empty set.
        sys.stderr.write(
            "dark-factory: author-scenarios: control root already has "
            f"{len(existing)} scenario file(s) -- refusing to overwrite. Clear "
            "scenarios/ (and re-scaffold pending) to re-author.\n")
        return 2

    spec_path = os.path.join(control_root, "spec.md")
    if not os.path.exists(spec_path):
        sys.stderr.write(f"dark-factory: author-scenarios: missing spec: {spec_path}\n")
        return 2
    spec_text = open(spec_path, encoding="utf-8").read()

    try:
        behaviors = df_gates.load_behaviors(control_root)
    except df_gates.GateError as e:
        sys.stderr.write(f"dark-factory: author-scenarios: behaviors.json error: {e}\n")
        return 2
    if not behaviors:
        sys.stderr.write(
            "dark-factory: author-scenarios: behaviors.json declares no behaviors "
            "-- there is nothing for an author to write scenarios for\n")
        return 2

    adapter = author["adapter"]
    timeout_s = author["timeout_s"]
    attempts = max(attempts, 1)

    # M42: the adequacy policy (required classes + min_per_class) the authored
    # set must satisfy, and the decorrelated critic loop toggle. cfg["_adequacy"]
    # is resolved by df_config (agent-authored -> happy+boundary+failure, critic
    # on iff roles.critic set, unless overridden).
    policy = cfg["_adequacy"]
    critic = cfg.get("_critic")
    critic_enabled = policy["critic"]["enabled"] and critic is not None
    max_rounds = policy["critic"]["max_rounds"]
    declared_ids = {b["id"] for b in behaviors}

    journal = Journal(os.path.join(control_root, "authored.jsonl"))

    # M47 condition #7 (review fix): enforce any pinned adapter digest BEFORE the
    # author/critic adapters are ever invoked. The builder-run path enforces this
    # at run start, but author-scenarios is a SEPARATE command that executes the
    # author (and critic) adapters here — an operator who pins
    # roles.author.adapter_sha256 to bind "only these exact bytes may author my
    # hidden scenarios" must be protected AT authoring time, not only at a later
    # `run` (a swap-then-swap-back would otherwise author the barrier scenarios
    # with a substituted model undetected). Fail-closed, exit 2.
    _digest_err = _enforce_adapter_digests(cfg, journal)
    if _digest_err is not None:
        sys.stderr.write(f"dark-factory: author-scenarios: {_digest_err}\n")
        return 2

    critic_round = 0            # completed author<->critic revision cycles
    critic_feedback = None      # blocking findings the author must address
    total_blocking_raised = 0   # cumulative blocking findings across rounds
    last_advisories = []        # advisories from the FINAL critic pass
    validated = None            # (report, normalized) once a set passes the gates

    # Outer loop: one iteration == "obtain a validated set, then (if enabled)
    # critique it". Bounded: the inner author loop is capped at `attempts`
    # invocations; the critic revision count is capped at max_rounds. Every
    # exit is fail-closed (install-and-return, or return 2 with NOTHING
    # installed and the pending marker retained).
    while True:
        # Inner: reach a validated set within `attempts` author invocations.
        # Validation feedback resets each critic round (the previous set was
        # valid -- this round the author is addressing critic blocking, not a
        # validation defect); critic_feedback persists across the inner tries.
        validated = None
        attempt_feedback = None
        for attempt in range(1, attempts + 1):
            status, payload = _author_once(
                adapter, spec_text, behaviors, policy, timeout_s,
                attempt_feedback=attempt_feedback, critic_feedback=critic_feedback)
            if status == "adapter_error":
                # Deterministic transport/env failure -- retrying re-hits the
                # same wall. Fail closed immediately.
                journal.write("AUTHORED_SCENARIOS_ABORTED", adapter=adapter,
                              attempt=attempt, reason="adapter_error",
                              detail=str(payload)[:500])
                sys.stderr.write(
                    f"dark-factory: author-scenarios: author adapter failed on attempt "
                    f"{attempt}: {payload}\n")
                return 2
            if status == "parse_error":
                attempt_feedback = payload
                journal.write("AUTHORED_SCENARIOS_ATTEMPT", adapter=adapter,
                              attempt=attempt, ok=False, reason="parse_error")
                sys.stderr.write(
                    f"dark-factory: author-scenarios: attempt {attempt} produced "
                    f"unusable output\n")
                continue
            if status == "invalid":
                attempt_feedback = payload
                journal.write("AUTHORED_SCENARIOS_ATTEMPT", adapter=adapter,
                              attempt=attempt, ok=False, counts=payload["counts"])
                sys.stderr.write(
                    f"dark-factory: author-scenarios: attempt {attempt} FAILED validation:\n")
                for line in df_author._feedback_lines(payload):
                    sys.stderr.write(f"  - {line}\n")
                continue
            # status == "ok"
            report, normalized = payload
            journal.write("AUTHORED_SCENARIOS_ATTEMPT", adapter=adapter,
                          attempt=attempt, ok=True, counts=report["counts"])
            validated = (report, normalized)
            break

        if validated is None:
            sys.stderr.write(
                f"dark-factory: author-scenarios: exhausted {attempts} attempt(s) without "
                "a valid scenario set -- fail-closed, NO scenarios installed (control root "
                "still pending)\n")
            return 2
        report, normalized = validated

        if not critic_enabled:
            break  # no decorrelated review -> straight to install

        # Decorrelated critic pass on the validated set.
        cstatus, cpayload = _critic_once(
            critic["adapter"], spec_text, behaviors, normalized, policy,
            critic["timeout_s"], declared_ids)
        if cstatus in ("adapter_error", "parse_error"):
            # A critic that can't run or can't emit a valid verdict is a
            # transport/config problem, not something the author can fix. Fail
            # closed (NOTHING installed) rather than silently skipping the
            # decorrelated review the operator asked for.
            journal.write("CRITIC_ABORTED", adapter=critic["adapter"],
                          round=critic_round, reason=cstatus, detail=str(cpayload)[:500])
            sys.stderr.write(
                f"dark-factory: author-scenarios: critic {cstatus} "
                f"({cpayload}) -- fail-closed, NO scenarios installed\n")
            return 2
        blocking, last_advisories = cpayload
        journal.write("CRITIC_ATTEMPT", adapter=critic["adapter"], round=critic_round,
                      blocking=len(blocking), advisories=len(last_advisories))

        if not blocking:
            break  # converged: the second mind found no blocking gap -> install

        total_blocking_raised += len(blocking)
        if critic_round >= max_rounds:
            # The author and critic did not converge within the bound. Fail
            # closed -- a persistently-contested set is NOT sealed.
            journal.write("CRITIC_UNRESOLVED", adapter=critic["adapter"],
                          rounds=critic_round, blocking=len(blocking))
            sys.stderr.write(
                f"dark-factory: author-scenarios: critic still reports {len(blocking)} "
                f"blocking gap(s) after {max_rounds} revision round(s) -- fail-closed, "
                "NO scenarios installed (control root still pending)\n")
            return 2
        critic_round += 1
        critic_feedback = blocking  # next author cycle must address these
        # loop back: re-author addressing the blocking findings.

    # ---- install path (validated, and critic-clean if enabled) ----
    if review and not _author_review_confirm(normalized):
        journal.write("AUTHORED_SCENARIOS_DECLINED", adapter=adapter,
                      counts=report["counts"])
        sys.stderr.write(
            "dark-factory: author-scenarios: review declined -- NO scenarios "
            "installed (control root still pending)\n")
        return 2

    _install_authored_scenarios(control_root, scenarios_dir, normalized)

    if critic_enabled:
        # scenario_review.md is CONTROL-PLANE ONLY (never installed into the
        # builder workspace). It records the blocking loop summary + the
        # advisories -- likely-missing REQUIREMENTS surfaced to the operator,
        # NEVER auto-applied. The journal events are content-free (counts only).
        review_md = df_critic.render_scenario_review(
            last_advisories, rounds=critic_round, blocking_resolved=total_blocking_raised)
        atomic_write(os.path.join(control_root, "scenario_review.md"), review_md)
        journal.write("CRITIC_REVIEW", adapter=critic["adapter"],
                      adapter_sha256=(sha256_file(critic["adapter"])
                                      if os.path.exists(critic["adapter"]) else None),
                      same_model_ack=critic["same_model_ack"],
                      rounds=critic_round, blocking_resolved=total_blocking_raised,
                      advisories=len(last_advisories))
        if last_advisories:
            journal.write("CRITIC_ADVISORY", count=len(last_advisories))

    journal.write("AUTHORED_SCENARIOS", adapter=adapter,
                  adapter_sha256=(sha256_file(adapter)
                                  if os.path.exists(adapter) else None),
                  same_model_ack=author["same_model_ack"],
                  counts=report["counts"])
    print(f"dark-factory: author-scenarios OK -- {report['counts']['scenarios']} "
          f"scenario(s) ({report['counts']['dev']} dev, "
          f"{report['counts']['final']} final) installed into {scenarios_dir}")
    print(f"  authored by (independent model): {adapter}"
          + ("  [same-model ack]" if author["same_model_ack"] else ""))
    if critic_enabled:
        print(f"  reviewed by (decorrelated critic): {critic['adapter']} "
              f"-- {critic_round} revision round(s), {len(last_advisories)} advisory(ies) "
              f"in scenario_review.md")
    print("Review the generated scenarios/*.json, then run:")
    print(f"  python3 {os.path.abspath(_sup().__file__)} run --control-root {control_root}")
    return 0


def _empty_author_report() -> dict:
    """A zero-valued validate_authored-shaped report, for the parse-error retry
    path (which has no normalized scenarios to report counts over)."""
    return {
        "schema_errors": [],
        "non_discriminating_titles": [],
        "non_sharp_survivors": {},
        "uncovered_behaviors": [],
        "under_covered_classes": [],
        "orphan_titles": [],
        "spec_leak_values": [],
        "counts": {"scenarios": 0, "dev": 0, "final": 0},
    }


def _install_authored_scenarios(control_root: str, scenarios_dir: str, normalized: list) -> None:
    """Atomically install a VALIDATED author scenario set into `scenarios_dir`
    (same one-file-per-scenario layout df_init.scaffold produces), then clear
    the pending marker LAST. Staging + per-file os.replace + marker-removal-last
    means a crash mid-install never yields a bad PARTIAL set that `run` would
    accept: the pending marker stays until every file has landed, so `run`
    keeps fail-closing until the install fully commits."""
    os.makedirs(scenarios_dir, exist_ok=True)
    staging = tempfile.mkdtemp(prefix=".df-author-stage-", dir=control_root)
    try:
        for sc in normalized:
            staged = os.path.join(staging, f"{sc['id']}.json")
            with open(staged, "w", encoding="utf-8") as f:
                json.dump(sc, f, indent=2)
                f.write("\n")
        for sc in normalized:
            os.replace(os.path.join(staging, f"{sc['id']}.json"),
                       os.path.join(scenarios_dir, f"{sc['id']}.json"))
    finally:
        shutil.rmtree(staging, ignore_errors=True)
    # Commit point: with every scenario file now in place, drop the marker so a
    # subsequent `run` proceeds. Removed last, on purpose (see docstring).
    marker = os.path.join(control_root, df_init.PENDING_MARKER)
    if os.path.exists(marker):
        os.remove(marker)
