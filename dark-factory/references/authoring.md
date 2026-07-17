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
| `enterprise` | Everything `hardened` gives, plus kernel-locked egress to a host-side credential proxy, a restrictive seccomp profile, and **split-custody sign-off** (K-of-N ed25519 approvers must sign the sealed manifest before it's qualified — no single operator can ship). | Everything `hardened` needs, plus a running credential proxy, a required off-box audit sink, and approver keypairs. `init` does **not** scaffold the `custody`/`credential_proxy`/`hardened.*` config blocks for you — add them to `config.json` by hand after `init` (see `references/enterprise.md`). |

Set `answers.assurance` to one of the four. Default `answers.autonomy` is 4;
`autonomy: 5` requires `hardened`/`enterprise`. If in doubt, start at
`cooperative` to prove the spec and scenarios out, then raise the tier once
the app converges.

**Checkpoint default differs from a hand-written config.json.** `init`
always writes `checkpoint: "auto"` regardless of autonomy (matching this
on-ramp's scripting/example use case), whereas a hand-authored
`config.json` at `autonomy: 4` defaults to `"pause"` (a checkpoint after
every non-converging iteration, per `references/config-reference.md`). If
you want per-iteration human review at autonomy 4, set
`answers.checkpoint: "pause"` explicitly.

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

`init` does **not** currently scaffold `hardened.*` (including
`hardened.dep_cache_dir` — the offline pinned-dependency cache for a
network-restricted builder, spec §7.3, see `references/hardened.md`),
`custody`, `credential_proxy`, `audit.sink`, `credentials`, or `brownfield`
blocks — add those to the scaffolded `config.json` by hand per
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
