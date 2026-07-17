"""df_init: authoring scaffold for dark-factory control roots. Stdlib only.

`dark-factory init` (Task 2's CLI) turns a small `answers` dict into a
ready-to-run control root: a validated `config.json`, a builder-visible
`spec.md` (NO scenario content), `behaviors.json`, and `scenarios/<id>.json`
oracle IR files. The pure builders here (`build_config`, `build_behaviors`,
`build_scenarios`) never write anything and raise `InitError` on any
violation; `scaffold` writes the tree; `validate_scaffold` re-checks the
written tree using the REAL validators (`df_config.load_config`,
`run_scenarios.load_scenarios`, `df_gates.validate_oracle`,
`df_gates.check_coverage`, `df_gates.load_behaviors`) so a control root
`init` blesses is exactly one `run` would accept -- never a reimplementation
of those checks.

The `answers` contract (single source of truth for `init`):
    {
      "app_name": str, "spec_text": str, "assurance": str,
      "workspace_root": str, "control_root": str,   # for disjointness only
      "builder_adapter": str,
      "max_iterations": int?, "autonomy": int?, "checkpoint": str?,
      "behaviors": [
        {"id": "BHV-...", "description": str?,
         "scenarios": [{"cohort": "dev"|"final", "run": [argv...],
                         "then": {...}, "title": str?, "given": str?,
                         "timeout_s": int?}, ...]}, ...
      ],
      "options": {"security_gates": {...}?, "twins": {...}?,
                  "budget": {...}?, "knowledge_base": {...}?},
      "force": bool?,
    }
"""
import json
import os
import re

import df_config
import df_custody
import df_gates
import run_scenarios


class InitError(RuntimeError):
    pass


# --- assurance: "enterprise" scaffolding (DF-04) ----------------------------
#
# df_config.load_config REQUIRES, for assurance: "enterprise": a `custody`
# block (approvers + threshold), `credential_proxy.enabled: true` (+ a valid
# token_env), `audit.sink.required: true` (a real http-append or
# s3-objectlock sink), `builder_confinement.required: true`, and
# `audit.signing: true`. None of these can be invented by `init` -- the
# approver PUBLIC keys, the credential proxy's allowlist/token_env name, and
# the audit sink's endpoint are all operator-only inputs (and the matching
# approver PRIVATE keys must be generated OFF-HOST -- init never generates,
# sees, or stores one). So `build_config` has exactly two outcomes at
# assurance: "enterprise", never a silent middle:
#
#   1. `answers` supplies every operator input (`approver_pubkeys`,
#      `custody_threshold`, `credential_proxy`, `audit_sink`) -> the full
#      mandatory enterprise config is generated AND preflight-validated
#      (malformed pubkeys, malformed sink URL/bucket, inline secrets) before
#      a single byte is returned, so `scaffold` (which calls `build_config`
#      before writing anything) never writes an enterprise-shaped-but-invalid
#      tree. A resulting `init --answers <enterprise-answers>` control root
#      passes `df_config.load_config` on the first try.
#   2. Any of those inputs is missing -> InitError naming exactly which keys
#      are missing (fail closed), UNLESS `answers.allow_dev_downgrade` is
#      truthy, in which case `assurance` is silently downgraded to
#      "hardened" (an explicitly NON-enterprise config -- `cooperative`/
#      `standard`/`hardened` init is unaffected by any of this) with a
#      `enterprise_downgrade_note` recorded in the returned config for the
#      caller (`supervisor.py init`) to print/journal. There is no
#      "enterprise but missing a guarantee" output -- ever.
_ENTERPRISE_ANSWER_HELP = (
    "generate approver keypairs OFF-HOST (see references/enterprise.md, "
    "'supervisor.py df-custody keygen') and supply ONLY their PUBLIC keys as "
    "answers.approver_pubkeys -- the private keys must never touch this "
    "host. Also provide answers.custody_threshold (int), "
    "answers.credential_proxy (object: token_env + a non-empty allowlist), "
    "and answers.audit_sink (object: kind 'http-append' + url, or "
    "'s3-objectlock' + endpoint/bucket/region). To scaffold a non-enterprise "
    "fallback instead, set answers.allow_dev_downgrade: true (assurance is "
    "downgraded to 'hardened' and the control root is marked NOT "
    "enterprise-qualified)."
)


def _missing_enterprise_inputs(answers: dict) -> list:
    """Which operator-only enterprise inputs are absent/wrong-shaped in
    `answers` -- a shape-only gate that decides whether build_config may
    proceed to generate+preflight the enterprise config at all, or must fail
    closed (or downgrade). Deep validation (malformed pubkey, malformed sink
    URL) happens only once this returns []."""
    missing = []

    pubkeys = answers.get("approver_pubkeys")
    if not isinstance(pubkeys, list) or not pubkeys:
        missing.append("approver_pubkeys (non-empty list of 64-hex ed25519 PUBLIC keys)")

    threshold = answers.get("custody_threshold")
    if not isinstance(threshold, int) or isinstance(threshold, bool):
        missing.append("custody_threshold (int)")

    proxy = answers.get("credential_proxy")
    if (
        not isinstance(proxy, dict)
        or not proxy.get("token_env")
        or not isinstance(proxy.get("allowlist"), list)
        or not proxy.get("allowlist")
    ):
        missing.append("credential_proxy (object with token_env + a non-empty allowlist)")

    sink = answers.get("audit_sink")
    if not isinstance(sink, dict) or sink.get("kind") not in ("http-append", "s3-objectlock"):
        missing.append(
            "audit_sink (object with kind: 'http-append' (+ url) or "
            "'s3-objectlock' (+ endpoint/bucket/region))"
        )
    elif sink["kind"] == "http-append" and not sink.get("url"):
        missing.append("audit_sink.url (required for kind 'http-append')")
    elif sink["kind"] == "s3-objectlock":
        for field in ("endpoint", "bucket", "region"):
            if not sink.get(field):
                missing.append(f"audit_sink.{field} (required for kind 's3-objectlock')")

    return missing


def _build_enterprise_addendum(answers: dict) -> dict:
    """Preflight-validate + generate the mandatory enterprise config blocks
    (custody, credential_proxy, audit.sink+signing, builder_confinement)
    from operator-supplied `answers`. Only called once
    `_missing_enterprise_inputs` has already returned [] -- every input here
    is present and shape-checked at that gate; this function does the DEEP
    validation (an actual ed25519 public key, a well-formed sink URL/bucket,
    no inline secrets) and raises InitError on the first violation, before
    returning anything -- this IS the "operational preflight": it runs
    before `scaffold` ever touches disk, not after, so a preflight failure
    never leaves a half-written control root behind.

    The DEEP preflight this does NOT do -- actually reaching the configured
    sink and reading back an anchored object with active retention/Object
    Lock -- requires real provisioned infra and is intentionally never run
    here; see `verify_worm_readback_MANUAL` below and
    references/enterprise.md.
    """
    pubkeys = answers["approver_pubkeys"]
    canonical_pubkeys = []
    seen = set()
    for i, pk in enumerate(pubkeys):
        if not isinstance(pk, str) or not df_config._HEX64_RE.match(pk):
            raise InitError(
                f"answers.approver_pubkeys[{i}] must be a 64-hex-char ed25519 "
                f"public key, got {pk!r}"
            )
        try:
            df_custody.validate_public_key(pk)
        except df_custody.CustodyError as e:
            raise InitError(f"answers.approver_pubkeys[{i}]: {e}") from e
        canonical = pk.lower()
        if canonical in seen:
            raise InitError(f"answers.approver_pubkeys has a duplicate entry: {pk!r}")
        seen.add(canonical)
        canonical_pubkeys.append(canonical)

    threshold = answers["custody_threshold"]
    if not (1 <= threshold <= len(canonical_pubkeys)):
        raise InitError(
            f"answers.custody_threshold must be an int in 1..{len(canonical_pubkeys)} "
            "(the number of approver_pubkeys)"
        )

    proxy = answers["credential_proxy"]
    if "token" in proxy:
        raise InitError(
            "answers.credential_proxy.token is a raw secret value and is not "
            "allowed -- use credential_proxy.token_env to name an "
            "environment variable instead (init never accepts inline secrets)"
        )
    token_env = proxy.get("token_env")
    if not isinstance(token_env, str) or not df_config._CRED_NAME_RE.match(token_env):
        raise InitError(
            "answers.credential_proxy.token_env must be an environment "
            f"variable NAME matching {df_config._CRED_NAME_RE.pattern!r}, "
            f"got {token_env!r}"
        )
    allowlist = proxy["allowlist"]
    for entry in allowlist:
        if not isinstance(entry, str) or not entry:
            raise InitError(
                f"answers.credential_proxy.allowlist entries must be "
                f"non-empty hostname strings, got {entry!r}"
            )
    header = proxy.get("header", "authorization")
    if header not in ("authorization", "x-api-key"):
        raise InitError(
            "answers.credential_proxy.header must be 'authorization' or 'x-api-key'"
        )

    sink = answers["audit_sink"]
    for forbidden in ("secret_key", "access_key"):
        if forbidden in sink:
            raise InitError(
                f"answers.audit_sink.{forbidden} is a raw secret value and is "
                f"not allowed -- use audit_sink.{forbidden}_env to name an "
                "environment variable instead (init never accepts inline secrets)"
            )

    sink_kind = sink["kind"]
    sink_cfg = {"kind": sink_kind, "required": True}
    if sink_kind == "http-append":
        url = sink.get("url")
        if not isinstance(url, str) or not re.match(r"^https?://\S+$", url):
            raise InitError("answers.audit_sink.url must be a http(s):// URL")
        sink_cfg["url"] = url
    else:  # s3-objectlock
        for field in ("endpoint", "bucket", "region"):
            val = sink.get(field)
            if not isinstance(val, str) or not val:
                raise InitError(
                    f"answers.audit_sink.{field} is required for kind 's3-objectlock'"
                )
            sink_cfg[field] = val
        prefix = sink.get("prefix", "")
        if not isinstance(prefix, str):
            raise InitError("answers.audit_sink.prefix must be a str")
        sink_cfg["prefix"] = prefix
        for env_field, default in (
            ("access_key_env", "DF_AUDIT_S3_ACCESS_KEY"),
            ("secret_key_env", "DF_AUDIT_S3_SECRET_KEY"),
        ):
            env_name = sink.get(env_field, default)
            if not isinstance(env_name, str) or not df_config._CRED_NAME_RE.match(env_name):
                raise InitError(
                    f"answers.audit_sink.{env_field} must be an environment "
                    f"variable NAME matching {df_config._CRED_NAME_RE.pattern!r} "
                    "(never a raw secret)"
                )
            sink_cfg[env_field] = env_name

    addendum = {
        "custody": {"approvers": canonical_pubkeys, "threshold": threshold},
        "credential_proxy": {
            "enabled": True,
            "token_env": token_env,
            "allowlist": list(allowlist),
            "header": header,
        },
        "audit": {"signing": True, "sink": sink_cfg},
        "builder_confinement": {"enabled": True, "required": True},
    }

    seccomp_profile = answers.get("seccomp_profile")
    if seccomp_profile:
        addendum["enterprise"] = {"seccomp_profile": seccomp_profile}

    return addendum


def verify_worm_readback_MANUAL(sink_cfg: dict) -> None:
    """STUB -- deliberately never called by build_config/scaffold/init or any
    unit test. The offline preflight in `_build_enterprise_addendum` proves
    only that the sink config is well-formed (a real http(s) URL, or a
    bucket/endpoint/region triple, with *_env NAMES rather than inline
    secrets) -- it never touches the network. It CANNOT prove the sink is
    actually WORM: that an object pushed through it reads back byte-
    identical, and that the bucket/object carries an ACTIVE retention /
    Object Lock configuration that would refuse deletion before the
    retention period elapses. Proving that requires REAL provisioned infra
    (a live http-append receiver or an S3-compatible bucket with Object Lock
    actually enabled) -- exactly the kind of external dependency this test
    suite never stands up for a WORM guarantee (df_audit_sink.py's own
    module docstring: "WORM here is NOT enforced ... that is the operator's
    object-lock retention configuration").

    Treat this as a checklist, not working code: run it (or an equivalent
    manual check) by hand, or in a CI job with real infra, after
    provisioning the sink and before relying on it for enterprise custody
    attestations. See references/enterprise.md, "Manual WORM-readback
    preflight (operator step)".
    """
    raise NotImplementedError(
        "verify_worm_readback_MANUAL is a documented manual/CI-with-infra "
        "step, not an automated check -- see its docstring and "
        "references/enterprise.md"
    )


def build_config(answers: dict) -> dict:
    """Build a config.json dict from `answers`. Pure -- raises InitError on
    any violation, BEFORE anything is ever written to disk."""
    control_root = answers.get("control_root")
    workspace_root = answers.get("workspace_root")
    if not control_root:
        raise InitError("answers.control_root is required (for the disjointness check)")
    if not workspace_root:
        raise InitError("answers.workspace_root is required")
    if not df_config._disjoint(workspace_root, control_root):
        raise InitError(
            "answers.workspace_root must be disjoint from answers.control_root "
            "(a run's workspace can never live inside the control root it's barred from seeing)"
        )

    tiers = df_config.load_supported_tiers()["tiers"]
    assurance = answers.get("assurance")
    if assurance not in tiers:
        raise InitError(
            f"assurance {assurance!r} has no conforming backend in this build; "
            f"supported: {sorted(tiers)}"
        )

    autonomy = answers.get("autonomy", 4)
    if autonomy not in (4, 5):
        raise InitError("autonomy must be 4 or 5")
    if autonomy == 5 and assurance not in ("hardened", "enterprise"):
        raise InitError(
            "autonomy 5 (lights-off) requires assurance: hardened or enterprise"
        )

    checkpoint = answers.get("checkpoint", "auto")
    if checkpoint not in ("pause", "auto"):
        raise InitError("checkpoint must be 'pause' or 'auto'")

    max_iterations = answers.get("max_iterations", 8)
    if (
        not isinstance(max_iterations, int)
        or isinstance(max_iterations, bool)
        or not (1 <= max_iterations <= 20)
    ):
        raise InitError("max_iterations must be an int in 1..20")

    builder_adapter = answers.get("builder_adapter")
    if not builder_adapter:
        raise InitError("answers.builder_adapter is required")

    cfg = {
        "config_version": "0.1",
        "feedback": "ids",
        "autonomy": autonomy,
        "checkpoint": checkpoint,
        "assurance": assurance,
        "max_iterations": max_iterations,
        "workspace_root": workspace_root,
        "roles": {"builder": {"adapter": builder_adapter}},
        "budget": {"billing": "subscription"},
    }

    options = answers.get("options") or {}
    if not isinstance(options, dict):
        raise InitError("answers.options must be an object")
    if "budget" in options:
        cfg["budget"] = {"billing": "subscription", **options["budget"]}
    for key in ("security_gates", "twins", "knowledge_base"):
        if key in options:
            cfg[key] = options[key]

    if assurance == "enterprise":
        missing = _missing_enterprise_inputs(answers)
        if missing:
            if answers.get("allow_dev_downgrade"):
                cfg["assurance"] = "hardened"
                cfg["enterprise_downgrade_note"] = (
                    "assurance downgraded from 'enterprise' to 'hardened' at "
                    "init time (answers.allow_dev_downgrade was set) -- the "
                    "following required enterprise operator inputs were not "
                    f"supplied in answers: {'; '.join(missing)}. This control "
                    "root is NOT enterprise-qualified."
                )
            else:
                raise InitError(
                    "assurance: enterprise requires operator-supplied inputs "
                    f"missing from answers: {'; '.join(missing)}. {_ENTERPRISE_ANSWER_HELP}"
                )
        else:
            cfg.update(_build_enterprise_addendum(answers))

    return cfg


def build_behaviors(answers: dict) -> dict:
    """Build behaviors.json's dict from answers.behaviors[].{id,description}."""
    behaviors = []
    for b in answers.get("behaviors", []):
        bid = b.get("id")
        if not bid:
            raise InitError("every behavior needs an 'id'")
        entry = {"id": bid}
        if b.get("description"):
            entry["description"] = b["description"]
        behaviors.append(entry)
    return {"behaviors": behaviors}


def build_scenarios(answers: dict) -> list:
    """Build one oracle-IR scenario dict per answers.behaviors[].scenarios[]
    entry. Every behavior needs >=1 dev-cohort scenario; every `then` must be
    discriminating (df_gates.is_discriminating) -- else InitError naming the
    offending behavior."""
    scenarios = []
    for b in answers.get("behaviors", []):
        bid = b.get("id")
        if not bid:
            raise InitError("every behavior needs an 'id'")
        counters = {"dev": 0, "final": 0}
        for sc_ans in b.get("scenarios", []):
            cohort = sc_ans.get("cohort", "dev")
            if cohort not in ("dev", "final"):
                raise InitError(
                    f"behavior {bid}: scenario cohort must be 'dev' or 'final', got {cohort!r}"
                )
            run = sc_ans.get("run")
            if not isinstance(run, list) or not run or not all(isinstance(x, str) for x in run):
                raise InitError(f"behavior {bid}: a scenario's 'run' must be a non-empty list of str")
            then = sc_ans.get("then")
            if not isinstance(then, dict) or not then:
                raise InitError(f"behavior {bid}: a scenario's 'then' must be a non-empty object")
            if not df_gates.is_discriminating(then):
                raise InitError(
                    f"behavior {bid}: scenario 'then' ({then!r}) is not discriminating "
                    "-- it would pass regardless of the actual observed output"
                )

            counters[cohort] += 1
            suffix = "S" if cohort == "dev" else "F"
            sc_id = f"{bid}-{suffix}{counters[cohort]}"

            scenarios.append({
                "ir_version": "0.1",
                "id": sc_id,
                "behavior_id": bid,
                "cohort": cohort,
                "title": sc_ans.get("title", ""),
                "given": sc_ans.get("given", ""),
                "when": {"run": list(run), "timeout_s": sc_ans.get("timeout_s", 10)},
                "then": then,
            })

        if counters["dev"] < 1:
            raise InitError(f"behavior {bid}: needs >=1 dev-cohort scenario")

    return scenarios


def scaffold(control_root: str, answers: dict) -> None:
    """Write config.json, spec.md, behaviors.json, scenarios/<id>.json under
    `control_root`. Refuses (InitError) to overwrite a non-empty control_root
    unless answers.get("force") is truthy. Builds (and validates the pure
    builder contracts) BEFORE writing a single file."""
    control_root = os.path.abspath(control_root)
    if os.path.isdir(control_root) and os.listdir(control_root) and not answers.get("force"):
        raise InitError(
            f"control root {control_root!r} is not empty; pass answers['force']=True to overwrite"
        )

    cfg = build_config(answers)
    behaviors = build_behaviors(answers)
    scenarios = build_scenarios(answers)
    spec_text = answers.get("spec_text", "")

    os.makedirs(control_root, exist_ok=True)

    with open(os.path.join(control_root, "config.json"), "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2)
        f.write("\n")

    with open(os.path.join(control_root, "spec.md"), "w", encoding="utf-8") as f:
        f.write(spec_text)

    with open(os.path.join(control_root, "behaviors.json"), "w", encoding="utf-8") as f:
        json.dump(behaviors, f, indent=2)
        f.write("\n")

    scenarios_dir = os.path.join(control_root, "scenarios")
    os.makedirs(scenarios_dir, exist_ok=True)
    for sc in scenarios:
        with open(os.path.join(scenarios_dir, f"{sc['id']}.json"), "w", encoding="utf-8") as f:
            json.dump(sc, f, indent=2)
            f.write("\n")


def _iter_then_strings(then: dict):
    """Yield every non-empty string leaf under a `then` dict (recursing into
    nested assertion objects like twin_observed/stdout_echoes_twin)."""
    def walk(obj):
        if isinstance(obj, str):
            if obj:
                yield obj
        elif isinstance(obj, dict):
            for v in obj.values():
                yield from walk(v)
        elif isinstance(obj, list):
            for v in obj:
                yield from walk(v)

    yield from walk(then)


def _find_spec_leaks(spec_text: str, scenarios: list) -> list:
    """Barrier scaffold-check: any scenario `then` string literal that
    appears verbatim in the builder-visible spec.md is a scaffold bug -- it
    would leak the holdout answer straight to the builder.

    A `then` value (e.g. a `stdout_equals` assertion) commonly carries one
    trailing newline (the candidate's own `print(...)` terminator) that has
    nothing to do with whether the literal answer is embedded in spec.md --
    comparing the raw value would let a leak evade this check merely because
    the leaked copy in spec.md happens to lack that trailing "\n" (or vice
    versa). Normalize exactly one trailing newline off the value before the
    substring check, mirroring run_scenarios._norm's equality handling.
    """
    leaks = []
    for sc in scenarios:
        for value in _iter_then_strings(sc.get("then", {})):
            normalized = value[:-1] if value.endswith("\n") else value
            if normalized and normalized in spec_text:
                leaks.append({"scenario_id": sc["id"], "value": value})
    return leaks


def validate_scaffold(control_root: str) -> tuple:
    """Re-validate a scaffolded control root using the REAL validators
    (df_config.load_config, run_scenarios.load_scenarios,
    df_gates.validate_oracle, df_gates.check_coverage, df_gates.load_behaviors)
    plus the spec_leak barrier check. Returns (ok, report); never raises --
    any validator failure is captured into the report and ok=False."""
    control_root = os.path.abspath(control_root)
    report = {"config_ok": False, "inert": [], "coverage": {}, "spec_leak": []}

    try:
        df_config.load_config(control_root)
        report["config_ok"] = True
    except df_config.ConfigError as e:
        report["config_error"] = str(e)
        return False, report

    try:
        scenarios = run_scenarios.load_scenarios(os.path.join(control_root, "scenarios"))
    except run_scenarios.OracleError as e:
        report["scenarios_error"] = str(e)
        return False, report

    report["inert"] = df_gates.validate_oracle(scenarios)

    try:
        behaviors = df_gates.load_behaviors(control_root) or []
    except df_gates.GateError as e:
        report["behaviors_error"] = str(e)
        return False, report

    report["coverage"] = df_gates.check_coverage(behaviors, scenarios)

    spec_path = os.path.join(control_root, "spec.md")
    spec_text = ""
    if os.path.exists(spec_path):
        with open(spec_path, encoding="utf-8") as f:
            spec_text = f.read()
    report["spec_leak"] = _find_spec_leaks(spec_text, scenarios)

    coverage = report["coverage"]
    ok = (
        report["config_ok"]
        and not report["inert"]
        and not coverage.get("uncovered_dev")
        and not coverage.get("orphan_scenarios")
        and not report["spec_leak"]
    )
    return ok, report
