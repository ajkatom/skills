"""df_author: agent-authored holdout scenarios (M40, the `author` role).

WHY this module exists: dark-factory's information barrier says the builder
must implement `spec.md` WITHOUT ever seeing the hidden acceptance scenarios.
M40 lets an *agent* (a DIFFERENT model than the builder) write those hidden
scenarios in place of a human, with the SAME barrier preserved. The human
still owns the ground truth (`spec.md` + `behaviors.json` — WHAT the app must
do); the agent writes only `scenarios/*.json` (HOW to test each behavior). An
agent that invented the spec, the behaviors, AND the tests would just grade
itself — so this stays scenarios-only, on purpose.

WHY validation is load-bearing here (not advisory): with no human writing the
tests, the machine gates that were a *floor* for a human become the *primary*
guard for the agent's output. `validate_authored` runs the agent's scenarios
through the IDENTICAL validators `df_init` applies to hand-authored ones —
oracle discrimination (`df_gates.is_discriminating`), behavior coverage
(`df_gates.check_coverage`), the spec-leak barrier check
(`df_init._find_spec_leaks`), and full oracle-IR shape validity (mirroring
`df_init.build_scenarios`). Output failing ANY gate is rejected fail-closed
and NEVER installed — the agent's scenarios earn no more trust than a human's,
and arguably get the stricter treatment (bounded auto-retry on impoverished
feedback, then refuse).

WHY the feedback is impoverished + barrier-safe: on a failed attempt the
author is re-invoked with a report that carries ONLY uncovered behavior-ids,
the *titles* of non-discriminating/orphan scenarios (author-generated text,
never holdout answers — there is no holdout yet at authoring time), and any
spec-leak values (which are spec.md content the author already sees). Nothing
that would teach a future builder crosses back, because the report never
reaches the builder at all — authoring is a clean PRE-RUN step whose scratch
workdir is discarded after extraction.

Honest limitation (documented, not hidden): these gates prove the scenarios
are schema-valid, discriminating, cover every behavior, and don't leak — they
CANNOT prove they capture the human's *intent*. Reviewing the generated
scenarios stays RECOMMENDED (the supervisor's `--review` gate offers it).

Stdlib only. Runtime guards `raise` (never bare `assert` — the suite runs
under `python -O`).
"""
import json
import os

import df_gates
import df_init
import run_scenarios


class AuthorError(RuntimeError):
    """Any fail-closed violation in the authoring pipeline (missing/garbage
    author output, wrong shape). Mirrors df_init.InitError / df_config's
    ConfigError — a single typed refusal the supervisor turns into exit 2."""


# The output file the author agent must write into its scratch workdir. One
# fixed name (the CLI adapters write files natively; the api adapters honor a
# {"files": {"scenarios.json": "..."}} return) so parse_author_output knows
# exactly which file to read back — no adapter code changes for M40.
OUTPUT_FILENAME = "scenarios.json"


_AUTHOR_RULES = """## Author role — write the hidden acceptance scenarios

You are the AUTHOR in a dark-factory run. You are NOT the builder. Your one
job is to write the hidden acceptance scenarios that a SEPARATE, isolated
builder model will be graded against — WITHOUT that builder ever seeing what
you write. You are given the builder-visible specification and the declared
list of behavior IDs. You write one or more test scenarios per behavior.

### Output contract (STRICT — a machine reads this, no human will)
Write EXACTLY ONE file named `scenarios.json` in your working directory,
containing a single JSON object of this exact shape and nothing else:

    {"scenarios": [
      {"behavior_id": "BHV-...", "cohort": "dev", "class": "happy",
       "run": ["python3", "app.py", "..."],
       "then": {"exit_code": 0, "stdout_equals": "..."},
       "title": "short human label", "given": "optional context"},
      ...
    ]}

Field rules (a scenario that breaks any of these is REJECTED, not repaired):
- `behavior_id` (required): one of the declared behavior IDs below. Every
  scenario tests exactly ONE behavior.
- `cohort` (optional, default "dev"): "dev" or "final". "dev" scenarios drive
  the iterative feedback; "final" scenarios are the sealed exam, run once
  after dev converges and never fed back. EVERY declared behavior needs at
  least one "dev" scenario. Reserve "final" for the behaviors you most want
  protected from teaching-to-the-test.
- `class` (optional, default "happy"): "happy", "boundary", or "failure" --
  ORTHOGONAL to cohort. It says WHAT KIND of case this scenario exercises:
  * "happy"    -- a normal, valid input on the intended path.
  * "boundary" -- an edge: empty input, the maximum/minimum, a duplicate, a
                  missing field, a wrong-type value, an off-by-one limit.
  * "failure"  -- the ERROR contract: what the spec promises on invalid use
                  (a non-zero exit / error status / error message the spec
                  actually mandates -- do NOT invent wording it doesn't state).
  The adequacy policy below lists the classes REQUIRED per behavior; cover
  every one of them.
- `run` (required): a non-empty list of strings — the literal argv the
  verifier executes with cwd = the builder's workspace (e.g. run the built
  program, or a `python3 -c "..."` harness that imports it).
- `then` (required): a non-empty object of assertions checked against the
  run's exit code / stdout / stderr. Use one or more of: `exit_code` (int),
  `stdout_equals`, `stdout_contains`, `stderr_equals`, `stderr_contains`
  (strings). Equality strips one trailing newline.
- `title` (optional but encouraged): a short human label.
- `given` (optional): human-only context.

### Rules for writing GOOD scenarios (enforced mechanically; obey them)
- ONE behavior per scenario. Don't fold two behaviors into one run/then.
- Make every `then` SHARP: it must FAIL against a wrong or stub implementation,
  not just pass against the right one. Every assertion you write is tested
  against a BATTERY of near-miss mutant outputs -- an empty output, a
  one-character change, a truncation, a wrong exit/status, a changed/removed
  JSON field. A `then` that any near-miss SURVIVES (e.g. an inert
  `{"stdout_contains": ""}`, or asserting only `exit_code` while ignoring the
  output the behavior is really about) is rejected as not sharp. Assert the
  SPECIFIC value this scenario's own input should produce, on every dimension
  that matters -- exit code AND the exact output, status AND the body/JSON.
- COVER THE REQUIRED CLASSES: for each behavior, write a scenario for every
  class the adequacy policy lists (happy + boundary + failure unless stated
  otherwise). A boundary/failure scenario must feed a boundary/invalid INPUT
  and assert the boundary/error RESULT -- not just re-test the happy path.
- WATCH THE BARRIER: never assert a string that appears VERBATIM in the
  specification — that would leak the answer straight to the builder and is
  rejected. Prefer asserting on something specific to your scenario's own test
  data (the exact key/value your input used), not a bare token the spec must
  already state (like a status code). This is both a stronger check and avoids
  the leak.
- Don't OVER-ASSERT unspecified details. If the spec doesn't mandate an exact
  error message, don't assert its literal wording — a correct alternative
  implementation would then fail a scenario it should pass. Assert only what
  the spec actually promises.
- Cover EVERY declared behavior with at least one dev scenario.

Output ONLY the `scenarios.json` file. Do not write any other file, and do not
attempt to implement the specification — that is the builder's job, not yours.
"""


def compose_author_prompt(spec_text, behaviors, *, policy=None, attempt_feedback=None,
                          critic_feedback=None):
    """Build the author prompt: the authoring rules + the builder-visible
    spec + the declared behavior IDs (the ONLY public inputs; there is no
    holdout yet, so nothing is withheld). `attempt_feedback`, when a prior
    attempt failed validation, is the impoverished, barrier-safe report from
    `validate_authored` — appended so the author can fix the SAME classes of
    defect (uncovered behaviors/classes, non-sharp/orphan titles, spec leaks)
    without ever learning anything a builder could exploit. `critic_feedback`
    (M42 Task 4), when a decorrelated critic returned BLOCKING findings, is a
    barrier-safe list of {behavior_id, kind, detail} lines the author must
    address in the next revision.

    `policy` (M42 Task 1), when given, is the adequacy policy
    ({required_classes, min_per_class}) so the prompt can state exactly which
    classes each behavior must be covered by.

    `behaviors` is the parsed behaviors.json `behaviors` list ([{id, description?}]).
    """
    lines = [_AUTHOR_RULES]
    if policy is not None:
        req = ", ".join(policy.get("required_classes", ["happy"]))
        n = policy.get("min_per_class", 1)
        lines.append(
            f"\n## Adequacy policy (ENFORCED)\nEach declared behavior must be covered "
            f"by at least {n} scenario(s) of EACH of these classes: {req}."
        )
    lines.append("\n## Declared behaviors (write scenarios for EACH)")
    for b in behaviors:
        bid = b.get("id", "")
        desc = b.get("description")
        lines.append(f"- {bid}" + (f": {desc}" if desc else ""))
    lines.append("\n## Specification (builder-visible — do NOT quote verbatim in a `then`)\n")
    lines.append(spec_text)

    if critic_feedback:
        # A SECOND, independent (different-model) critic flagged these as
        # blocking. This is verifier-side text that never reaches the builder,
        # so it is safe to hand the author in full -- addressing it is required
        # before the set can install.
        lines.append(
            "\n## A decorrelated critic flagged BLOCKING gaps — address each and re-emit\n")
        for f in critic_feedback:
            bid = f.get("behavior_id", "")
            kind = f.get("kind", "")
            detail = f.get("detail", "")
            lines.append(f"- [{bid}] ({kind}) {detail}")

    if attempt_feedback is not None:
        # Impoverished feedback: only the shapes of what failed, never a
        # corrected answer. This is safe to hand back because the author
        # already sees the spec + behaviors, there is no holdout yet, and this
        # text never reaches the builder (authoring is a discarded pre-run
        # step). Rendered deterministically for a stable, diff-able prompt.
        lines.append(
            "\n## Your previous attempt FAILED validation — fix these and re-emit "
            "the FULL scenarios.json\n"
        )
        for msg in _feedback_lines(attempt_feedback):
            lines.append(f"- {msg}")

    return "\n".join(lines) + "\n"


def _feedback_lines(report):
    """Render a validate_authored report into barrier-safe, actionable bullet
    lines for the author's retry prompt. Only behavior-ids, author-authored
    titles, and spec-leak values (spec content the author already has) ever
    appear — never a corrected `then` or any content a builder could exploit."""
    out = []
    for msg in report.get("schema_errors", []):
        out.append(f"schema error: {msg}")
    for bid in report.get("uncovered_behaviors", []):
        out.append(
            f"behavior {bid} has NO dev-cohort scenario — add at least one "
            f"discriminating dev scenario for it"
        )
    for title in report.get("orphan_titles", []):
        out.append(
            f"scenario titled {title!r} names a behavior_id that is NOT in the "
            f"declared behaviors list — fix its behavior_id or remove it"
        )
    # M42: a non-sharp `then` -- the survivor mutant KINDS are barrier-safe
    # category labels ("stdout_equals:empty", "json_contains:value_changed"),
    # never a holdout value, so they can be fed back verbatim to sharpen the
    # assertion. We name the shape that survived, NOT a corrected assertion.
    non_sharp = report.get("non_sharp_survivors", {})
    for title in report.get("non_discriminating_titles", []):
        kinds = non_sharp.get(title)
        detail = (f" — near-miss mutant(s) it accepted: {', '.join(kinds)}"
                  if kinds else "")
        out.append(
            f"scenario titled {title!r} has a non-sharp `then` (a near-miss wrong "
            f"output would still pass it){detail} — assert the specific value your "
            f"input should produce, on every dimension that matters"
        )
    # M42: a behavior missing a required CLASS. Barrier-safe: behavior-id +
    # class name only (never a suggested assertion).
    for entry in report.get("under_covered_classes", []):
        bid = entry.get("behavior")
        missing = ", ".join(entry.get("missing", []))
        out.append(
            f"behavior {bid} is missing required scenario class(es): {missing} — "
            f"add a scenario of each missing class (feed that KIND of input and "
            f"assert its result)"
        )
    for value in report.get("spec_leak_values", []):
        out.append(
            f"a `then` asserts {value!r}, which appears VERBATIM in the spec — "
            f"this leaks the answer to the builder; assert on your scenario's own "
            f"test data instead"
        )
    return out


def parse_author_output(workdir):
    """Read `<workdir>/scenarios.json` written by the author adapter and
    return the raw list of scenario dicts. Fail-closed (AuthorError) on a
    missing / unparseable / wrong-shaped file — there is NEVER a partial or
    empty install: a malformed author response is a clean refusal, not a
    best-effort salvage (mirrors the CLI/api adapters' own "no partial
    success" posture)."""
    path = os.path.join(workdir, OUTPUT_FILENAME)
    if not os.path.isfile(path):
        raise AuthorError(
            f"author did not write {OUTPUT_FILENAME} into its workdir "
            f"(expected {path})"
        )
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError) as e:
        raise AuthorError(f"author's {OUTPUT_FILENAME} could not be read/parsed: {e}") from e

    if not isinstance(data, dict):
        raise AuthorError(f"author's {OUTPUT_FILENAME} must be a JSON object, got {type(data).__name__}")
    scenarios = data.get("scenarios")
    if not isinstance(scenarios, list):
        raise AuthorError(f"author's {OUTPUT_FILENAME} must have a 'scenarios' list")
    if not scenarios:
        raise AuthorError(f"author's {OUTPUT_FILENAME} 'scenarios' list is empty")
    for i, sc in enumerate(scenarios):
        if not isinstance(sc, dict):
            raise AuthorError(f"author's scenarios[{i}] is not an object: {sc!r}")
    return scenarios


def _normalize(scenarios_raw, declared_ids):
    """Turn the author's raw scenario dicts into full oracle-IR scenarios,
    assigning ids with the SAME `{bid}-S{n}`/`{bid}-F{n}` scheme
    df_init.build_scenarios uses — so the installed files are byte-shaped
    exactly like human-authored ones and pass run_scenarios.load_scenarios.

    Unlike build_scenarios (which RAISES on the first shape violation, right
    for an interactive human), this COLLECTS every shape error into
    `schema_errors` so a single retry can fix them all at once. Returns
    (normalized_scenarios, schema_errors); a scenario with a fatal shape
    problem (missing/blank behavior_id, bad run/then, bad cohort) is recorded
    and skipped rather than normalized, so downstream discrimination/coverage
    checks run only over well-formed scenarios."""
    normalized = []
    schema_errors = []
    # Per-behavior S/F counters, seeded for EVERY declared behavior so id
    # assignment is deterministic regardless of the order the author emits.
    counters = {}
    for i, sc in enumerate(scenarios_raw):
        title = sc.get("title", "")
        label = f"scenarios[{i}]" + (f" ({title!r})" if title else "")

        bid = sc.get("behavior_id")
        if not isinstance(bid, str) or not bid:
            schema_errors.append(f"{label}: missing/blank 'behavior_id'")
            continue

        cohort = sc.get("cohort", "dev")
        if cohort not in ("dev", "final"):
            schema_errors.append(f"{label}: cohort must be 'dev' or 'final', got {cohort!r}")
            continue

        # M42: the optional class axis (default happy). Validated here so a
        # typo is a collected schema error (one retry fixes all), matching how
        # cohort is handled -- rather than surfacing later as an OracleError.
        cls = sc.get("class", run_scenarios.DEFAULT_SCENARIO_CLASS)
        if cls not in run_scenarios.SCENARIO_CLASSES:
            schema_errors.append(
                f"{label}: class must be one of {list(run_scenarios.SCENARIO_CLASSES)}, "
                f"got {cls!r}")
            continue

        run = sc.get("run")
        if not isinstance(run, list) or not run or not all(isinstance(x, str) for x in run):
            schema_errors.append(f"{label}: 'run' must be a non-empty list of strings")
            continue

        then = sc.get("then")
        if not isinstance(then, dict) or not then:
            schema_errors.append(f"{label}: 'then' must be a non-empty object")
            continue

        timeout_s = sc.get("timeout_s", 10)
        if not isinstance(timeout_s, int) or isinstance(timeout_s, bool) or timeout_s < 1:
            schema_errors.append(f"{label}: 'timeout_s' must be a positive int")
            continue

        cd = counters.setdefault(bid, {"dev": 0, "final": 0})
        cd[cohort] += 1
        suffix = "S" if cohort == "dev" else "F"
        sc_id = f"{bid}-{suffix}{cd[cohort]}"

        normalized.append({
            "ir_version": "0.1",
            "id": sc_id,
            "behavior_id": bid,
            "cohort": cohort,
            "class": cls,
            "title": title,
            "given": sc.get("given", ""),
            "when": {"run": list(run), "timeout_s": timeout_s},
            "then": then,
        })

    return normalized, schema_errors


def validate_authored(scenarios_raw, spec_text, behaviors, policy=None):
    """Run the author's raw scenarios through the IDENTICAL gates df_init
    applies to human-authored scenarios, returning (ok, report, normalized).

    `policy` (M42 Task 1), when given, is the adequacy policy
    ({required_classes, min_per_class}) the authored set must satisfy per
    behavior. Absent -> the back-compat happy-only default (which any covering
    set already meets), so pre-M42 callers are byte-identical.

    The report is impoverished + barrier-safe (see module docstring):
      - schema_errors: list[str] shape violations (behavior-id refs only)
      - non_discriminating_titles: titles of scenarios whose `then` is NOT
        sharp (a near-miss survived)
      - non_sharp_survivors: {title: [mutant-kind, ...]} -- the barrier-safe
        category labels of the near-miss(es) each non-sharp `then` accepted
      - uncovered_behaviors: declared behavior ids with no dev scenario
      - under_covered_classes: [{behavior, missing:[class,...]}] per the policy
      - orphan_titles: titles of scenarios naming an undeclared behavior id
      - spec_leak_values: `then` string values that appear verbatim in spec.md
      - counts: {scenarios, dev, final}

    ok is True iff NOTHING failed — same fail-closed conjunction
    df_init.validate_scaffold enforces, PLUS (M42) sharpness on every `then`
    and class adequacy per the policy. `normalized` is the installable
    oracle-IR scenario list (only meaningful when ok)."""
    if policy is None:
        policy = df_gates.default_adequacy_policy()
    declared_ids = {b["id"] for b in behaviors}
    normalized, schema_errors = _normalize(scenarios_raw, declared_ids)

    # Strict oracle-IR validation -- the SAME run_scenarios._validate the
    # INSTALLED set passes at run time (via load_scenarios). df_gates
    # discrimination alone is NOT enough: a `then` like
    # {"exit_code": 0, "output_is": "..."} passes is_discriminating (it sees
    # exit_code) but carries an UNKNOWN assertion key that _validate rejects
    # (then_keys - ASSERT_KEYS). Without this check such a set would validate,
    # INSTALL, clear the pending marker, then deadlock `run` with an OracleError
    # -- and author-scenarios would then refuse ("already has scenarios"). So we
    # run every normalized scenario through _validate here, fold any failure
    # into schema_errors (drives a retry, pre-install), and DROP the offending
    # scenario from the coverage/discrimination checks (an unrunnable scenario
    # provides no coverage and must not be installed).
    runnable = []
    for sc in normalized:
        try:
            run_scenarios._validate(sc, f"{sc['id']}.json")
        except run_scenarios.OracleError as e:
            schema_errors.append(str(e))
        else:
            runnable.append(sc)
    normalized = runnable

    report = {
        "schema_errors": schema_errors,
        "non_discriminating_titles": [],
        "non_sharp_survivors": {},
        "uncovered_behaviors": [],
        "under_covered_classes": [],
        "orphan_titles": [],
        "spec_leak_values": [],
        "counts": {
            "scenarios": len(normalized),
            "dev": sum(1 for s in normalized if s["cohort"] == "dev"),
            "final": sum(1 for s in normalized if s["cohort"] == "final"),
        },
    }

    # id -> title, so sharpness/coverage findings can be reported by the
    # author-facing TITLE (barrier-safe author text) rather than the internal id.
    id_to_title = {s["id"]: (s["title"] or s["id"]) for s in normalized}

    # Sharpness (M42): the SAME df_gates battery run/df_init use. Report the
    # per-scenario survivor mutant-KINDS (barrier-safe labels) keyed by title,
    # so the retry feedback can name exactly which near-miss slipped through.
    survivors_by_id = df_gates.sharpness_survivors(normalized)
    report["non_discriminating_titles"] = sorted(id_to_title[i] for i in survivors_by_id)
    report["non_sharp_survivors"] = {
        id_to_title[i]: kinds for i, kinds in survivors_by_id.items()
    }

    # Coverage: the SAME df_gates.check_coverage. uncovered_dev = declared
    # behaviors with no dev scenario; orphan_scenarios = scenarios naming an
    # undeclared behavior id (reported by title for the author).
    cov = df_gates.check_coverage(behaviors, normalized)
    report["uncovered_behaviors"] = list(cov["uncovered_dev"])
    report["orphan_titles"] = sorted(id_to_title[i] for i in cov["orphan_scenarios"])

    # Adequacy (M42): per-behavior class coverage against the policy. Reported
    # barrier-safe (behavior-id + class names only).
    adq = df_gates.check_adequacy(behaviors, normalized, policy)
    report["under_covered_classes"] = adq["under_covered"]
    report["adequacy"] = adq

    # Barrier: the SAME df_init._find_spec_leaks — any `then` string literal
    # that appears verbatim in the builder-visible spec.md is a leak.
    leaks = df_init._find_spec_leaks(spec_text, normalized)
    report["spec_leak_values"] = sorted({leak["value"] for leak in leaks})

    ok = (
        not report["schema_errors"]
        and not report["non_discriminating_titles"]
        and not report["uncovered_behaviors"]
        and not report["under_covered_classes"]
        and not report["orphan_titles"]
        and not report["spec_leak_values"]
    )
    return ok, report, normalized
