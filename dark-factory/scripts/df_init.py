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

import df_config
import df_gates
import run_scenarios


class InitError(RuntimeError):
    pass


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
