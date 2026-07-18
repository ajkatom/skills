"""df_critic: the decorrelated critic role (M42 Task 4).

WHY this module exists: M40 lets an AGENT (a different model than the builder)
author the hidden acceptance scenarios. But one author model has blind spots,
and two correlated minds (author + builder from the same lineage) tend to miss
the SAME unknown-unknowns. M42 adds a SECOND, independent (different-model)
agent -- the CRITIC -- that adversarially reviews the authored scenario set for
gaps BEFORE it is sealed. The critic sits on the VERIFIER side of the barrier,
exactly like the author: it may see spec.md + behaviors + the authored
scenarios (run/then/class) + the oracle format, and it emits a strict JSON
verdict. Its `blocking` findings drive a bounded author<->critic revision loop
(the author re-emits addressing them, and the set is re-validated + re-critiqued
up to a cap). Its `advisories` (likely-MISSING REQUIREMENTS -- "a production X
usually also needs auth / idempotency / pagination; your behaviors declare none
-- confirm intended") are NEVER auto-applied: inventing requirements would be
the machine overriding human intent. They are surfaced to the operator
(scenario_review.md + a content-free journal event) so a SILENT spec gap
becomes a VISIBLE one -- the most a machine can honestly do about the
human-input residual.

BARRIER (enforced + tested like M40's author discipline): the critic's output
-- the verdict, the blocking findings, scenario_review.md -- is control-plane
and MUST NEVER enter the builder workspace. The revision loop runs at AUTHOR
time (a discarded pre-run step whose scratch workdir is torn down after
extraction), so nothing the critic writes can reach a future builder.

MODEL DISTINCTNESS (df_config, fail-closed): realpath(critic) != builder
(COLLUSION -- a critic must not bless scenarios its own model will build
against) AND realpath(critic) != author (DECORRELATION -- the whole point is a
second, independent mind). An `allow_same_model_ack` escape hatch, sealed into
the manifest, records the weaker guarantee when the operator explicitly accepts
it (mirrors M40's authored_by.same_model_ack).

Stdlib only. Runtime guards `raise` (never bare `assert` -- the suite runs
under `python -O`)."""
import json
import os


class CriticError(RuntimeError):
    """Any fail-closed violation in the critic pipeline (missing/garbage critic
    output, wrong shape). Mirrors df_author.AuthorError -- a single typed
    refusal the supervisor turns into exit 2."""


# The output file the critic agent must write into its scratch workdir (one
# fixed name, like df_author.OUTPUT_FILENAME) so parse_critic_output knows
# exactly which file to read back.
OUTPUT_FILENAME = "critic.json"

# The blocking-finding kinds the critic may emit. A finding with any other kind
# is dropped (fail-safe: an unknown kind can't gate an author revision toward a
# target the loop doesn't understand) -- see validate_critic_verdict.
BLOCKING_KINDS = ("missing_class", "weak_assertion", "missing_case")


_CRITIC_RULES = """## Critic role — adversarially review the hidden scenarios

You are the CRITIC in a dark-factory run. You are NOT the builder and NOT the
author. A separate AUTHOR model has written the hidden acceptance scenarios that
an isolated builder model will be graded against. Your one job is to find GAPS
in that scenario set — cases a correct-looking build could pass while still
being wrong, or requirements the spec/behaviors likely need but don't state.

You are given the builder-visible specification, the declared behaviors, and the
AUTHORED scenarios (their inputs and assertions). You do NOT write scenarios and
you do NOT implement anything.

### Output contract (STRICT — a machine reads this, no human will)
Write EXACTLY ONE file named `critic.json` in your working directory, containing
a single JSON object of this exact shape and nothing else:

    {"blocking": [
       {"behavior_id": "BHV-...", "kind": "missing_class|weak_assertion|missing_case",
        "detail": "one concrete sentence naming the gap"}],
     "advisories": [
       {"topic": "short label", "detail": "a likely-missing REQUIREMENT to confirm"}]}

- `blocking` — DEFECTS in the scenario set the author must fix before it seals:
  * "missing_class"   — a behavior is missing a happy/boundary/failure case.
  * "weak_assertion"  — a `then` that a wrong build could still pass (asserts
                        too little; e.g. checks only an exit code, not output).
  * "missing_case"    — an important input the behavior implies is untested
                        (an empty/duplicate/oversized/malformed input, an error
                        path the spec promises).
  Every blocking finding MUST name a declared `behavior_id`. Be specific and
  concrete; do NOT restate the whole spec. Do NOT propose the exact assertion
  string (the author must write it) — name the GAP, not the answer.
- `advisories` — likely-MISSING REQUIREMENTS at the spec/behaviors level (auth,
  idempotency, pagination, rate limiting, input validation, concurrency, …)
  that a production version of this system usually needs but the behaviors do
  not declare. These are for a HUMAN to confirm — they will NOT be auto-added.
  Raise them when the spec reads thinner than the domain implies.

If the scenario set is already thorough, return {"blocking": [], "advisories": []}.
Output ONLY the `critic.json` file. Do not write any other file.
"""


def compose_critic_prompt(spec_text, behaviors, scenarios, *, policy=None):
    """Build the critic prompt: the critic rules + the builder-visible spec +
    the declared behaviors + the AUTHORED scenarios (behavior/class/run/then,
    all verifier-side) + (optionally) the adequacy policy so the critic knows
    which classes are required. `scenarios` is the normalized oracle-IR list."""
    lines = [_CRITIC_RULES]
    if policy is not None:
        req = ", ".join(policy.get("required_classes", ["happy"]))
        lines.append(
            f"\n## Adequacy policy in force\nEach behavior must be covered by "
            f"class(es): {req}. Flag any behavior missing one as blocking "
            f"(kind missing_class)."
        )
    lines.append("\n## Declared behaviors")
    for b in behaviors:
        bid = b.get("id", "")
        desc = b.get("description")
        lines.append(f"- {bid}" + (f": {desc}" if desc else ""))
    lines.append("\n## Authored scenarios (review these for gaps)")
    for sc in scenarios:
        title = sc.get("title", "")
        lines.append(
            f"- id={sc['id']} behavior={sc['behavior_id']} "
            f"class={sc.get('class', 'happy')} cohort={sc.get('cohort', 'dev')}"
            + (f" title={title!r}" if title else "")
        )
        when = sc.get("when", {})
        if "run" in when:
            lines.append(f"    run:  {json.dumps(when['run'])}")
        elif "http" in when:
            lines.append(f"    http: {json.dumps(when['http'])}")
        lines.append(f"    then: {json.dumps(sc['then'], sort_keys=True)}")
    lines.append("\n## Specification (builder-visible)\n")
    lines.append(spec_text)
    return "\n".join(lines) + "\n"


def parse_critic_output(workdir):
    """Read `<workdir>/critic.json` written by the critic adapter and return the
    raw verdict dict. Fail-closed (CriticError) on a missing / unparseable /
    wrong-shaped file — there is NEVER a partial or best-effort salvage
    (mirrors df_author.parse_author_output)."""
    path = os.path.join(workdir, OUTPUT_FILENAME)
    if not os.path.isfile(path):
        raise CriticError(
            f"critic did not write {OUTPUT_FILENAME} into its workdir (expected {path})")
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError) as e:
        raise CriticError(f"critic's {OUTPUT_FILENAME} could not be read/parsed: {e}") from e
    if not isinstance(data, dict):
        raise CriticError(
            f"critic's {OUTPUT_FILENAME} must be a JSON object, got {type(data).__name__}")
    return data


def validate_critic_verdict(verdict, declared_ids):
    """Normalize a raw critic verdict into (blocking, advisories), dropping
    malformed entries fail-SAFE.

    A blocking finding is kept only if it is an object with a KNOWN kind and a
    DECLARED behavior_id — an unknown kind or an undeclared behavior can't
    steer an author revision toward a target the loop understands, so it is
    dropped rather than allowed to deadlock the loop (fail-safe: dropping a
    malformed blocker can only make the loop converge sooner, never install a
    worse set, since the FULL adequacy/sharpness gates still run afterward).
    Advisories are free-form {topic, detail}; malformed ones are dropped.
    Returns (blocking, advisories) as lists of dicts."""
    raw_blocking = verdict.get("blocking")
    raw_advisories = verdict.get("advisories")
    if raw_blocking is not None and not isinstance(raw_blocking, list):
        raise CriticError("critic verdict 'blocking' must be a list")
    if raw_advisories is not None and not isinstance(raw_advisories, list):
        raise CriticError("critic verdict 'advisories' must be a list")

    blocking = []
    for f in (raw_blocking or []):
        if not isinstance(f, dict):
            continue
        bid = f.get("behavior_id")
        kind = f.get("kind")
        if kind not in BLOCKING_KINDS or bid not in declared_ids:
            continue
        blocking.append({
            "behavior_id": bid,
            "kind": kind,
            "detail": str(f.get("detail", ""))[:500],
        })

    advisories = []
    for a in (raw_advisories or []):
        if not isinstance(a, dict):
            continue
        advisories.append({
            "topic": str(a.get("topic", ""))[:120],
            "detail": str(a.get("detail", ""))[:500],
        })

    return blocking, advisories


def render_scenario_review(advisories, *, rounds, blocking_resolved):
    """Render the operator-facing `scenario_review.md` (control-plane only,
    NEVER installed into the builder workspace). It records the critic's
    advisory findings — likely-missing REQUIREMENTS for a human to confirm —
    plus a one-line summary of the blocking loop. Advisories are NEVER
    auto-applied; this file exists precisely to make a silent spec gap
    visible."""
    out = [
        "# Scenario review (decorrelated critic)",
        "",
        "A second, independent (different-model) critic reviewed the "
        "agent-authored hidden scenarios.",
        "",
        f"- author<->critic revision rounds: {rounds}",
        f"- blocking findings resolved: {blocking_resolved}",
        f"- advisories (below): {len(advisories)}",
        "",
        "## Advisories — likely-missing REQUIREMENTS (NOT auto-applied)",
        "",
        "These concern human INTENT, so the machine surfaces them and applies "
        "NOTHING. Review each; if it matters, update spec.md + behaviors.json "
        "and re-author.",
        "",
    ]
    if not advisories:
        out.append("_None._")
    else:
        for a in advisories:
            topic = a.get("topic") or "(untitled)"
            out.append(f"- **{topic}** — {a.get('detail', '')}")
    return "\n".join(out) + "\n"
