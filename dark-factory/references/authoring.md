# Authoring a run — the `init` interview script

`dark-factory init` turns a small `answers` JSON document into a
ready-to-run control root: a validated `config.json`, a builder-visible
`spec.md`, `behaviors.json`, and `scenarios/*.json`. This is the interview
the orchestrator (you, or the Claude session driving the SKILL) follows to
produce that answers document — either by asking the human the questions
below directly, or by filling in the worked example at
`examples/kv-service/answers.json` and adapting it.

**Honest scope, up front:** `init` validates STRUCTURE — the config loads,
every scenario's `then` is a real (discriminating) assertion, every declared
behavior has dev-cohort coverage, and no scenario's exact expected output
leaks into the builder-visible spec. It does **not**, and cannot, judge
whether your scenarios actually capture what you meant by the spec — that
is still entirely your judgment call. `init` also never auto-generates
scenarios from spec text (that risks silently teaching to the test) and
never runs a build — it prints the exact `run` command instead. See the
Self-Review section at the end for how to sanity-check your own answers
document before trusting it.

## 1. What does the app do? (the spec)

Ask (or answer, if you're the human authoring solo):

- What is the app, in one sentence? What's its **interface** — a CLI, an
  HTTP API, a library function, a file format? Be concrete: if it's an HTTP
  API, what's the exact request/response shape; if it's a CLI, what are the
  exact argv and exit codes; if it's a library, what's the exact function
  signature the code is exercised through.
- List the **behaviors** the app must have, each as a short imperative
  sentence ("PUT /kv/<key> stores a value and returns 200"). Each becomes
  one `behaviors.json` entry (`answers.behaviors[].id`, `BHV-<NAME>`) plus a
  `description`.

This becomes `answers.spec_text` — the ONLY thing the builder ever reads.
Write it as if the builder has zero other context: no scenario content,
but everything a competent engineer would need to implement each behavior
correctly (including the parts that feel "obvious" — a real builder that
guesses wrong on an unstated edge case is a spec bug, not a scenario bug).

## 2. Which assurance tier?

| Tier | Guarantees | Prerequisites |
|---|---|---|
| `cooperative` | Honor-system isolation. Every run is explicitly **unqualified** — nothing stops a curious builder process from reading the control root; it just doesn't. Works everywhere. | None. |
| `standard` | OS read-denial sandbox (macOS `sandbox-exec` / Linux `bwrap`), probe-verified at run start — a converged run is **qualified**. | A supported OS sandbox backend + a passing startup denial probe. |
| `hardened` | Builder runs inside a Docker container that never has the control root mounted — denial **by construction**, not a deny-rule — still probe-verified. Unlocks `autonomy: 5` (fully unattended). | A running Docker daemon + a passing container probe + a working OS sandbox for the verifier. Mandatory signed audit. |
| `enterprise` | Everything `hardened` gives, plus kernel-locked egress to a host-side credential proxy, a restrictive seccomp profile, and **split-custody sign-off** (K-of-N ed25519 approvers must sign the sealed manifest before it's qualified — with threshold >= 2 no single operator can ship; K-of-N proves distinct keys/signatures, not distinct human owners). | Everything `hardened` needs, plus a running credential proxy, a required off-box audit sink, and approver keypairs. `init` **does** scaffold the `custody`/`credential_proxy`/`audit.sink` blocks for you — see "Enterprise answers" below — but only from operator-supplied inputs it can never invent (approver *public* keys, the proxy's allowlist, the sink's endpoint); missing any of them is a fail-closed `InitError`, never a broken scaffold. |

Set `answers.assurance` to one of the four. Default `answers.autonomy` is 4;
`autonomy: 5` requires `hardened`/`enterprise`. If in doubt, start at
`cooperative` to prove the spec and scenarios out, then raise the tier once
the app converges.

### Enterprise answers (DF-04)

`assurance: "enterprise"` requires `df_config.load_config` to see a
`custody` block, an enabled `credential_proxy`, a required off-box
`audit.sink`, required `builder_confinement`, and signed audit — none of
which `init` can invent, since the values are operator-only (a real
approver public key, a real proxy allowlist, a real sink endpoint). So
`answers.assurance: "enterprise"` also requires these top-level keys:

- `answers.approver_pubkeys` — a non-empty list of **64-hex-char ed25519
  PUBLIC keys**. Generate each keypair **off-host**, one per approver,
  with `supervisor.py df-custody keygen` — `init` never generates, sees,
  or stores a private key; only the public half goes into `answers`.
- `answers.custody_threshold` — the K in K-of-N (an int, `1..len(approver_pubkeys)`).
- `answers.credential_proxy` — `{"token_env": "<ENV_VAR_NAME>", "allowlist": ["host", ...]}`.
  `token_env` is the NAME of an environment variable the proxy reads
  host-side at request time — never the token value itself (`init`
  rejects a literal `"token"` key outright, same as `df_config`).
- `answers.audit_sink` — either `{"kind": "http-append", "url": "https://..."}`
  or `{"kind": "s3-objectlock", "endpoint": "...", "bucket": "...",
  "region": "...", "prefix": "..."?, "access_key_env": "..."?,
  "secret_key_env": "..."?}`. Like `credential_proxy`, the `*_env` fields
  are NAMES, never inline secret values (`init` rejects a literal
  `"secret_key"`/`"access_key"` key).
- `answers.seccomp_profile` (optional) — a path to a Docker seccomp JSON
  profile; absent uses the shipped default (see `references/enterprise.md`).

`init` preflight-validates all of this **before writing a single file**:
each pubkey is parsed as an ed25519 public key (`df_custody.validate_public_key`),
the sink URL/bucket-triple is checked for well-formedness, and any inline
secret is rejected — a malformed input is an `InitError` naming exactly
what's wrong, not a half-written control root. A successful `init
--answers <enterprise-answers>` therefore passes `df_config.load_config`
immediately.

**If you don't have the operator inputs yet:** `init` fails closed with an
`InitError` listing exactly which of the keys above are missing — it never
emits an enterprise-shaped-but-invalid config. To scaffold something
runnable anyway (e.g. to iterate on behaviors/scenarios before custody is
set up), set `answers.allow_dev_downgrade: true`: `init` scaffolds at
`assurance: "hardened"` instead, and prints/records a note that the
control root is **not** enterprise-qualified.

**What `init` still can't prove:** that the audit sink is actually
reachable and its WORM/retention (Object Lock) configuration is active —
that requires live infra `init` never provisions or touches. See
`references/enterprise.md`, "Manual WORM-readback preflight (operator
step)", before relying on a scaffolded sink for real custody attestations.

**Default intervention mode is H2 (supervised), matching `load_config`.**
When `answers` supplies NEITHER `intervention_mode` NOR any legacy
`autonomy`/`checkpoint` field, `init` scaffolds `intervention_mode: "H2"` —
the same default `df_config.load_config` uses and every doc names (pauses
after each non-converged verify and before ship). (Earlier `init` wrote
`checkpoint: "auto"`, which resolved to **H3** and silently gave the
canonical on-ramp fewer human gates than advertised — DF-R4-05, fixed.) A
scripted / unattended scaffold opts into fewer gates EXPLICITLY:
`answers.intervention_mode: "H3"` (guarded — runs through, pauses only at a
hard budget guard) or `"H4"` at `hardened`/`enterprise` (lights-out). The
worked `examples/kv-service/answers.json` sets `H3` for exactly this reason.
Legacy `answers.autonomy`/`answers.checkpoint`, when supplied explicitly, are
still honored verbatim.

**Intervention mode selectable at init (M47 condition #10).** You no longer
need a hand-edit to get H1: set `answers.intervention_mode` to `H1`/`directed`,
`H2`/`supervised`, `H3`/`guarded`, or `H4`/`lights_out` (case/hyphen-
insensitive) and `init` scaffolds it directly. It is mutually exclusive with
the legacy `answers.autonomy`/`answers.checkpoint` pair — setting both is an
`InitError` (pick one scheme; the legacy fields still work when
`intervention_mode` is absent). `H4` (lights-out) requires
`hardened`/`enterprise`. See `references/modes.md` for the pause-point table.

**Confine the built app's egress to QUALIFY at `standard`+ (M47 RA-08(a)).**
For a run you want sealed `COMPLETE_QUALIFIED`, set `candidate_network` to
`"deny"` (the built app needs no network) or `"loopback"` (it must reach
digital twins on `127.0.0.1`). Leaving it `"unrestricted"` (the default) at
`standard`+ now seals the distinct `CANDIDATE_EGRESS_OPEN` (qualified `false`):
the run still converges, but an app free to reach anywhere is not certified.
`"deny"` cannot be combined with `twins.enabled` or http scenarios (use
`"loopback"`); `"loopback"` is macOS-only. See `references/config-reference.md`
and `references/isolation.md`.

## 3. The must-pass behaviors and their holdout scenarios

For each behavior in `answers.behaviors[]`, write 1-3 `scenarios[]` — a
concrete input and the exact expected outcome. Each scenario is
`{"cohort": "dev"|"final", "run": [argv...], "then": {...}, "title": "...",
"given": "..."?}`. `run` is the literal argv the verifier executes (cwd =
the builder's workspace); `then` is checked against its exit code /
stdout / stderr (see `references/scenario-format.md` for the full oracle
IR). The builder **never** sees any of this — not the scenario files, not
their content, not even their existence beyond a bare behavior ID in
feedback.

**Guidance for writing GOOD scenarios (`init` enforces some of this
mechanically; the rest is on you):**

- **One behavior per scenario.** Don't fold two behaviors into a single
  `run`/`then` pair — if a scenario's assertion is really testing two
  different things, split it. Coverage and feedback are both keyed by
  `behavior_id`; a scenario that silently exercises a second, undeclared
  behavior gives you no signal when only that second thing breaks.
- **Make every `then` discriminating.** `init` mechanically rejects a
  tautological assertion (`{"stdout_contains": ""}` — matches anything,
  including a completely broken build) via `df_gates.is_discriminating`,
  but that's a floor, not a design review: prefer a real assertion over the
  *specific* thing you're checking, not just "something got printed". A
  scenario that would pass against a stub or an empty stdout is worthless.
- **Watch the barrier, not just discrimination.** A `then` value that
  appears **verbatim** in your `spec_text` leaks the holdout answer
  straight to the builder — `init` catches this (`spec_leak` in the
  validation report) and refuses the scaffold. Bare, generic tokens that
  your spec must legitimately document (an HTTP status code like `200`,
  `404`) are the usual trigger, since spec.md necessarily states them as
  part of the public contract. Prefer asserting on something **specific to
  the scenario's own test data** (the exact key/value your scenario used,
  not just the bare code) — it's both a stronger check and naturally avoids
  colliding with the spec's own prose. See
  `examples/kv-service/answers.json` for worked examples of this pattern
  (e.g. checking `"200\n{\"key\": \"color\", \"value\": \"blue\"}"` rather
  than the bare `"200"`).
- **Don't over-assert on unspecified details.** If your spec says an error
  response is `{"error": "<message>"}` without mandating the exact wording,
  don't assert the literal message text either — a correct alternative
  implementation with different wording would then fail a scenario it
  should pass. Assert only what the spec actually promises (e.g. the status
  code plus the presence of an `error` key).
- **Dev vs. sealed final cohort.** `"cohort": "dev"` scenarios (the
  default) are what the loop iterates against every round — their
  pass/fail drives ID+taxonomy feedback back to the builder. Every declared
  behavior needs **at least one** dev scenario (`init` rejects a behavior
  with zero — `build_scenarios` raises `InitError` naming it).
  `"cohort": "final"` scenarios are the **sealed exam**: held out of every
  iteration, run exactly once after dev converges, never fed back — only
  the behavior ID (never content) reaches the journal/manifest. Reserve
  `final` scenarios for the behaviors you most want protected from
  teaching-to-the-test; a control root with zero `final` scenarios is
  valid (it just administers no sealed exam, and the manifest says so
  honestly).
- **The builder NEVER sees any of this.** Author scenarios in a session
  separate from whatever will drive the builder, and never paste scenario
  content into a conversation that also talks to the builder — same rule
  as hand-authoring, `init` doesn't change it.

## 4. Options

Optional `answers.options` block, passed through into `config.json`:

- `security_gates` — mandatory secret/dangerous-pattern/SBOM/license scans
  on the converged artifact, independent of scenario pass-rate. Recommended
  whenever nothing else will review the code before it ships. See
  `references/security-gates.md`.
- `twins` — if the app talks to an external service, define a behavioral
  mock so the builder can develop against something real instead of a
  network call that may not even be reachable from its sandbox. See
  `references/digital-twins.md`.
- `budget` — a dollar and/or call cap on the builder loop. See
  `references/budget.md`.
- `knowledge_base` — a markdown wiki (or open-brain) to draw on / write a
  barrier-safe run summary to. See `references/knowledge-base.md`.
- `candidate_network` — restrict the network of the *built app* itself
  (the candidate), separately from the builder: `"deny"` (no network) or
  `"loopback"` (only localhost — twin-compatible, macOS only), default
  `"unrestricted"`. Requires `standard` or above. Offer this when the app
  shouldn't reach the network during verification. See
  `references/isolation.md`.

**Builder choice — offer the direct-API adapters too.** Besides the
`claude`/`codex`/`gemini` CLIs, `api_anthropic` and `api_openai` build over
the provider HTTP API with no CLI installed (the only builders that work
*inside* the hardened/enterprise container) and report real token cost. Set
`answers.builder_adapter` to their adapter path when the user wants OpenAI,
a real-model build in-container, or authoritative cost metering. See
`references/role-adapters.md`.

`init` scaffolds `custody`/`credential_proxy`/`audit.sink` automatically at
`assurance: "enterprise"` when `answers` supplies the operator inputs
listed in "Enterprise answers" above (otherwise it fails closed, or
downgrades under `allow_dev_downgrade` — never a broken scaffold). It does
**not** currently scaffold `hardened.*` (including `hardened.dep_cache_dir`
— the offline pinned-dependency cache for a network-restricted builder,
spec §7.3, see `references/hardened.md`), `credentials`, or `brownfield`
blocks at any tier — add those to the scaffolded `config.json` by hand per
`references/config-reference.md` if your tier or workflow needs them.

## Then: init → review → run

1. Assemble the answers above into a JSON file (or adapt
   `examples/kv-service/answers.json`).
2. `python3 <skill_dir>/scripts/supervisor.py init --control-root <cr> --answers <file.json>`
   (or `--answers -` to pipe JSON on stdin). On success it prints the
   scaffolded tree summary, the exact `run` command, and the tier's
   run-time prerequisites. On failure it prints the specific validation
   failures (inert scenarios, uncovered behaviors, orphan scenarios, or a
   spec leak) and removes the invalid tree (pass `--force-keep` to inspect
   it instead) — exit 2 either way, so a broken control root is never left
   around to fail confusingly later at `run`.
3. **Review the generated `scenarios/*.json` yourself.** `init` proved the
   scaffold is *structurally* sound; it did not, and cannot, prove your
   scenarios capture what you actually meant. Read them once before
   trusting them — this is the one step `init` cannot do for you.
4. `python3 <skill_dir>/scripts/supervisor.py run --control-root <cr> [--project-src <dir>]`.

## Self-Review before you trust an answers document

Three questions worth asking about your own answers file before running
`init` for real:

1. Does every behavior have a dev scenario whose `then` would genuinely
   FAIL against a plausible wrong implementation (not just an empty one)?
2. Does `spec_text` give the builder everything it needs, with nothing a
   scenario's `then` depends on stated only implicitly?
3. If you swapped every one of your `then` assertions for the OPPOSITE of
   what a correct implementation produces, would every scenario now fail?
   If any wouldn't, that scenario isn't discriminating in practice even if
   `init` didn't reject it.

## Agent-authored scenarios (the `author` role, M40)

You don't have to write the hidden scenarios yourself — an **agent** can write
them, with the SAME information barrier the builder runs under. You still own
the ground truth (`spec.md` + `behaviors.json` — WHAT the app must do); the
agent writes only `scenarios/*.json` (HOW to test each behavior). An agent that
invented the spec, the behaviors, AND the tests would just grade itself, so
this is deliberately **scenarios-only**.

**The distinct-adapter-identity requirement.** The author must resolve to a
**different adapter path than the builder**, enforced fail-closed at config
load: `realpath(roles.author.adapter) != realpath(roles.builder.adapter)` or the
run refuses (symlink/relative/absolute all resolved on both sides). This gate is
a distinct **resolved path**, NOT a proven different *model*. For the
**fixed-model CLI adapters** (`claude`/`codex`/`gemini`) a distinct path is (in
practice) a distinct model. For the **env-parameterized API adapters**
(`api_anthropic`/`api_openai`) the path check alone does NOT guarantee distinct
models: two different adapter files (or the same file used for both roles) can
be pointed at the *same* backing model via `DF_API_MODEL` / the base-URL env —
the realpath check cannot see that. The same adapter file for both roles is
refused outright unless you set `roles.author.allow_same_model_ack: true` (which
records the weaker guarantee in the manifest's `authored_by.same_model_ack`).
Rationale: an agent grading its own model's build is not an independent check.

To get a stronger guarantee than "distinct path":

- **Content-level (verified).** Pin `adapter_sha256` on **both** roles. Identical
  bytes = the same adapter = the same model, so two roles pinning the SAME
  digest is a `ConfigError` (M50, DF-R3-04) — unless that pair's
  `allow_same_model_ack`. This is the way to *prove* distinct adapter content
  even when two copies live at different paths.
- **Operator-asserted (not verified).** Set `roles.author.model_identity` /
  `roles.builder.model_identity` (free-form strings, e.g.
  `"anthropic/claude-opus-4"` vs `"openai/gpt-5-codex"`). Two must-differ roles
  asserting the SAME value → `ConfigError`. Sealed verbatim into
  `authored_by.model_identity` for an auditor. This is an **operator assertion**,
  never system-verified — dark-factory cannot prove which model a black-box API
  key actually reaches.

**The workflow — init → author-scenarios → review → run:**

1. Write an answers doc with `author_adapter` (a path to any protocol-0.1
   adapter, a DIFFERENT model than `builder_adapter`) and **zero** scenarios
   in `behaviors[]`. `init` scaffolds `spec.md` + `behaviors.json` + a config
   carrying `roles.author`, with an EMPTY `scenarios/` and a
   `scenarios_pending_author` marker. `run` refuses a scenarios-pending
   control root (`no scenarios; run author-scenarios first`).
2. `python3 <skill_dir>/scripts/supervisor.py author-scenarios --control-root
   <cr> [--attempts N] [--review]`. The author agent is invoked in a fresh
   scratch workdir (discarded after) and writes one `scenarios.json`; its
   output is validated through the **identical** gates a human's scenarios
   pass — oracle discrimination, behavior coverage, the spec-leak barrier
   check, and full oracle-IR shape. On a failure the author is re-invoked with
   **impoverished, barrier-safe** feedback (uncovered behavior-ids,
   non-discriminating/orphan scenario titles, spec-leak values — never a
   corrected answer) up to `--attempts` (default 3). On success the validated
   set is installed atomically into `scenarios/` and the marker cleared;
   exhausted attempts ⇒ exit 2 with **no** scenarios installed (never a bad
   partial set).
3. **Review the generated `scenarios/*.json` (RECOMMENDED).** `--review`
   prints each generated scenario and requires interactive confirmation before
   install. This matters because of the honest limit below.
4. `run` — the barrier is byte-for-byte unchanged: the agent's scenarios seal
   through the exact path a human's do, and the builder still never sees them.

**Honest limit (documented, not hidden).** The gates prove the agent's
scenarios are schema-valid, discriminating, cover every behavior, and don't
leak — they **cannot** prove the scenarios capture the human's *intent* (the
same limit a human faces, minus the human's presumed knowledge of their own
intent). So with an agent author and no human review, "discriminating + covers
behaviors + faithful to the spec's stated contract" is the ceiling. The human
still owns spec + behaviors, and reviewing the generated scenarios stays
RECOMMENDED. M42 (below) adds the decorrelated **critic** the M40 note
anticipated, plus class-typed adequacy and a sharpness battery — narrowing this
ceiling to human spec/behavior fidelity + non-functional properties the oracle
can't express.

## Class-typed adequacy + the decorrelated critic (M42)

Three additional strengtheners layer on top of the author flow; full detail in
`references/scenario-adequacy.md`.

- **Class-typed coverage.** Scenarios carry an optional `class ∈
  {happy,boundary,failure}` (absent ⇒ happy). The M7 adequacy gate requires each
  behavior to be covered by the policy's `required_classes`. An **agent author**
  defaults to `["happy","boundary","failure"]` (a human root stays `["happy"]`);
  override with `scenario_adequacy.required_classes`. A gap fails closed
  (`ADEQUACY_GATE_FAILED`) before any build. The author prompt states the
  required classes; a missing class is folded into the barrier-safe retry
  feedback (behavior-id + class name only).
- **Sharpness battery.** The oracle gate now requires each `then` to reject a
  BATTERY of near-miss observation-mutants (per asserted dimension), not one
  synthetic garbage output — catching an inert sub-assertion (e.g. a
  `stdout_contains: ""` riding alongside a real check) the old single-mutant
  check missed. Deterministic, no build; it mutates the OBSERVATION, not the
  built code.
- **Decorrelated critic (`roles.critic`).** A SECOND, independent
  (different-model) agent adversarially reviews the authored set at author time.
  Its `blocking` findings drive a bounded author↔critic revision loop
  (`scenario_adequacy.critic.max_rounds`, default 2; non-convergence fails
  closed). Its `advisories` — likely-missing REQUIREMENTS ("usually also needs
  auth / idempotency / pagination — confirm intended") — are written to
  `<control_root>/scenario_review.md` and surfaced to you, **NEVER auto-applied**
  (the human owns intent). Two fail-closed model-distinctness inequalities apply:
  critic ≠ builder (collusion) and critic ≠ author (decorrelation); one
  `roles.critic.allow_same_model_ack: true` waives both. The critic's output is
  control-plane and never reaches the builder.

Add `critic_adapter` (a path to a third, distinct protocol-0.1 adapter) to the
answers doc to enable it; the ideal is three distinct models (author=Codex,
critic=Gemini, builder=Claude). `scenario_review.md` is your operator artifact —
read the advisories, and if one matters, update `spec.md` + `behaviors.json` and
re-author.
