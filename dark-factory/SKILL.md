---
name: dark-factory
description: "Use when the user wants to build a task or feature dark-factory style — the human writes a spec, an isolated builder agent implements it WITHOUT ever seeing the hidden acceptance scenarios, a verifier runs those holdout scenarios, and only behavior-ID + failure-taxonomy feedback crosses back until convergence. Triggers on 'dark factory', 'dark-factory', 'hidden tests', 'holdout scenarios', 'build without seeing the tests', or stopping an AI builder teaching to the test. Four tiers — cooperative (honor-system, unqualified), standard (OS read-denial sandbox on macOS/Linux, probe-verified and qualified), hardened (builder in a Docker container with the control root never mounted, denial by construction, unlocks the unattended H4 lights-out mode), and enterprise (hardened + kernel-locked egress + seccomp + K-of-N split-custody sign-off, the strongest tier). The human-intervention axis is a single intervention_mode — H1 directed, H2 supervised (default), H3 guarded, H4 lights-out (hardened/enterprise only)."
---

# dark-factory

Runs a StrongDM-style dark-factory loop: **spec in → hidden holdout scenarios
→ isolated builder (spec-only) → verifier → deterministic ID feedback → loop →
outcome**. Design spec: `docs/superpowers/specs/2026-07-13-dark-factory-skill-design.md`
(Codex-approved). Four assurance tiers ship: **cooperative** (honor-system isolation — every run is explicitly UNQUALIFIED), **standard** (OS read-denial sandbox on macOS/Linux, verified by a fail-closed startup denial probe — a converged run is QUALIFIED), **hardened** (the builder runs inside a Docker container that never has the control root mounted — denial by *construction*, not a deny-rule — still probe-verified fail-closed; see `references/hardened.md`), and **enterprise** (hardened + kernel-locked egress to a host-side credential proxy + seccomp + **split-custody sign-off**: a run is qualified only via a separate K-of-N ed25519 approver attestation bound to the sealed manifest — with `threshold ≥ 2` no single operator can ship, and K-of-N proves distinct keys/signatures, not distinct human owners; see `references/enterprise.md`). `hardened` (and `enterprise`) unlock the fully-unattended **H4 `lights_out`** intervention mode (legacy `autonomy: 5` — spec §2.2).

**Two independent axes, not one.** Assurance tier
(cooperative/standard/hardened/enterprise) and intervention mode
(`intervention_mode`: H1 directed / H2 supervised / H3 guarded / H4
lights-out) are separate config choices. Every tier defaults to **H2**;
only `hardened`/`enterprise` may select **H4** (any human-needed condition
becomes a fail-closed TERMINAL, e.g. `BUDGET_HALTED`; at enterprise the
before-ship gate is the `CUSTODY_PENDING` terminal + K-of-N attestation).
`intervention_mode` and the legacy `autonomy`/`checkpoint` pair are mutually
exclusive (both = config error); convert old configs with
`supervisor.py df-migrate-config <control_root>` (idempotent, leaves a
`.bak`). Per-mode pause-point table + resume workflow: `references/modes.md`.

## Authoring a run (`init`) — the on-ramp for "provide context and specs"

When the user's ask is "here's my spec/context, build me a dark-factory
run" rather than a from-scratch interview, `dark-factory init` scaffolds a
**ready-to-run control root** — validated `config.json`, builder-visible
`spec.md`, `behaviors.json`, and holdout `scenarios/*.json` — from a small
`answers` JSON document, instead of hand-writing every control-plane file
across workflow steps 2-4 below. It reuses the exact same validators `run`
does (`df_config.load_config`, oracle discrimination, coverage, scenario-class
adequacy, the candidate-network/http compatibility rule, plus a
barrier check that no scenario's exact expected output leaked into
`spec.md`), so a control root `init` blesses passes every pre-build gate
`run` enforces (run-TIME prerequisites — docker, the OS sandbox, a live
adapter — are still checked by `run` itself) — and it refuses (removing the
invalid tree) rather than leaving a broken control root to fail confusingly
later.

- **The interview.** `references/authoring.md` is the script to follow:
  what the app does + its interface (the spec), which assurance tier and
  why, the must-pass behaviors with 1-3 holdout scenarios each (with
  guidance on writing scenarios that are actually discriminating and don't
  leak the answer into the spec), and the optional config blocks
  (`security_gates`/`twins`/`budget`/`knowledge_base`, plus `candidate_network`
  to restrict the built app's network and, at `hardened`/`enterprise`,
  `hardened.dep_cache_dir` for an offline pinned-dependency cache).
- **A worked example.** `examples/kv-service/answers.json` is a complete,
  copyable answers document for a small KV JSON HTTP API — 7 behaviors, 12
  dev+final scenarios, hand-verified against a real converged
  implementation. Copy it, edit `workspace_root`/`control_root`/
  `builder_adapter` to real absolute paths, and adapt the spec/behaviors to
  your app.
- **Run it:**
  `python3 <skill_dir>/scripts/supervisor.py init --control-root <cr> --answers <file.json|-> [--force]`.
  Exit 0 prints the scaffolded tree summary, the exact `run` command, and
  the tier's run-time prerequisites (Docker for hardened/enterprise, the
  builder CLI, approver keys for enterprise custody). Exit 2 prints the
  specific validation failure (an inert scenario, uncovered behavior,
  orphan scenario, or spec leak) and removes the invalid tree unless
  `--force-keep` is passed.
- **Honest scope:** `init` validates STRUCTURE — it cannot judge whether
  your scenarios truly capture what you meant by the spec (that's still
  your call — review the generated `scenarios/*.json` before trusting
  them). `init` **itself** never auto-generates scenarios from spec text —
  it scaffolds only the scenarios you supply in `answers` — and it never runs
  a build (it prints the `run` command instead). (The SEPARATE
  `author-scenarios` step CAN generate the hidden scenarios with an agent — a
  distinct-adapter author (a different resolved path, not a proven different
  *model* unless you pin `adapter_sha256` / assert `model_identity`), optionally
  plus an independent critic — see the next
  bullet and `references/authoring.md`.) See `references/authoring.md` for the
  full interview and scenario-writing guidance.
- **Offer agent-authored scenarios (M40).** If the user doesn't want to hand-
  write the hidden scenarios, an **agent** can — with the same barrier. The
  human still owns `spec.md` + `behaviors.json`; the agent (a **different
  model than the builder**, enforced fail-closed) writes only
  `scenarios/*.json`. Set `answers.author_adapter` (a path to any protocol-0.1
  adapter distinct from `builder_adapter`) and supply behaviors with **zero**
  scenarios; `init` scaffolds a scenarios-pending control root, then
  `supervisor.py author-scenarios --control-root <cr> [--review]` has the
  agent write them (validated through the identical discrimination/coverage/
  spec-leak gates, bounded retry on impoverished feedback, fail-closed).
  `run` refuses until they're installed. The manifest records `authored_by`.
  Reviewing the generated scenarios stays RECOMMENDED — the gates prove
  discrimination/coverage/no-leak but cannot prove intent-fit. See
  `references/authoring.md` ("Agent-authored scenarios").
- **Offer class-typed adequacy + a decorrelated critic (M42).** Offer the
  user: (1) **class coverage** — each behavior covered by happy + boundary +
  failure scenarios (agent authors default to all three; override with
  `answers.scenario_adequacy.required_classes`; the adequacy gate fails
  closed on a gap); (2) the automatic **sharpness battery** (every assertion
  must reject near-miss mutant observations); (3) a **decorrelated critic**
  (`answers.critic_adapter`, a distinct adapter identity from builder AND
  author, fail-closed) whose blocking findings drive a bounded revision loop
  while advisories go to `scenario_review.md` for the operator, never
  auto-applied. Details + honest scope: `references/scenario-adequacy.md`.
- **Offer property / fuzz scenarios (M43a/M43b).** A scenario can assert an
  INVARIANT over many seeded generated inputs (`when.property` — round_trip /
  idempotent / deterministic / robust / error_contract / monotonic;
  deterministic, bounded, counterexamples stay control-plane-only), and may
  add a `concurrency` block running steps in parallel (one strike = fail; a
  PASS is probabilistic detection, not a race-freedom proof). Format and
  semantics: `references/scenario-format.md` (`when.property`).

This on-ramp only produces the control-plane files; the rest of this
skill's workflow (running, checkpoints, tiers, security gates, etc.) is
unchanged below.

## Workflow (create one todo per step)

1. **Engage.** Announce the skill; offer opt-out. Ask which directory to use as
   the control root (MUST be outside the project repo and outside any workspace
   tree; suggest `~/.dark-factory/<project-name>`).
   Also ask (optional, default none): do you have a **knowledge base** to draw on
   and record to? — a markdown **wiki** (give a directory path) or an **open-brain
   / MCP** memory. If a wiki: set `knowledge_base` in config.json; on `write_back:
   true` the supervisor appends a barrier-safe run summary (no scenario text) to
   `<path>/dark-factory-runs.md`. If open-brain: you (this session) may read it for
   grounding and, only with the user's OK, `capture_thought` the run outcome — the
   supervisor does not touch MCP. Absence of a KB is never an error.
   Also ask (optional, default none): should the workflow **continue past the
   sealed artifact into ship actions** (merge/deploy/migrate)? If yes, add a
   `ship` block (see `references/ship.md`) — each action is plain operator argv,
   `reversible` is a REQUIRED per-action bool. **Frame the safety honestly:**
   ship actions run with real network + credentials and are NOT sandboxed — the
   protection is that they run only on a *qualified* artifact, on the *sealed*
   bytes, gated + audited, with rollback. Any **irreversible** action
   (`reversible:false`) additionally needs `assurance: hardened|enterprise` and a
   signed K-of-N `ship.approval` policy (which forces `audit.signing`), and will
   fail-closed to `SHIP_APPROVAL_PENDING` — including under H4 lights-out — until
   an authorized human signs a `df-release` approval. Credentials are env-var
   NAMES (`creds.env`) resolved host-side, never values in config/logs.
2. **Spec.** Interview the user → write `<control_root>/spec.md`. The user
   approves it. Behaviors should be numbered (BHV-001, BHV-002, …).
3. **Acceptance world — SEPARATE CONTEXT.** Author the holdout scenarios in
   `<control_root>/scenarios/*.json` (oracle IR v0 — see
   `references/scenario-format.md`) **in a different session/subagent than any
   builder work**, deriving them ONLY from spec.md. Never echo scenario content
   into the main conversation if the same conversation will drive the builder.
   - **dev vs final cohorts.** Each scenario carries an optional `"cohort"`
     (default `"dev"`). `dev` scenarios are what the loop iterates against
     every step — their pass/fail drives ID+taxonomy feedback back to the
     builder. `"cohort":"final"` scenarios are the **sealed exam**: held out
     of every iteration, run **exactly once** after dev fully converges, and
     their results are **never fed back** — only their behavior-IDs (never
     content) reach the journal/manifest. A final failure is terminal
     (`FINAL_EXAM_FAILED`, exit 3): the artifact is rejected, not iterated on.
     A control root with **no** `final` scenarios administers no sealed exam
     at all — the manifest honestly records `final_exam.ran = false` so an
     absent exam is never mistaken for a passed one. Author `final` scenarios
     for the behaviors you most want protected from teaching-to-the-test.
   - **Declare behaviors (`behaviors.json`, recommended).** Author
     `<control_root>/behaviors.json` from the spec's BHV list — one entry
     per behavior ID (see `references/coverage-gates.md` for the schema).
     This makes coverage a **hard, fail-closed pre-build gate**: before the
     builder is ever invoked, the supervisor rejects a run whose scenarios
     leave any declared behavior without a `dev` scenario, or whose
     scenarios reference a behavior ID never declared (orphan). It also
     mutation-validates every scenario's `then` regardless of
     `behaviors.json` — an inert/tautological check (e.g.
     `{"stdout_contains": ""}`, which matches any output) fails the gate
     too. Either failure aborts the run (exit 2, `GATE_FAILED`, no build
     ever runs). No `behaviors.json` → coverage is skipped, honestly
     recorded in the manifest as `coverage.checked = false`.
4. **Config.** Write `<control_root>/config.json` per
   `references/config-reference.md`.
   - **Choose the builder model.** Run
     `python3 -c "import sys; sys.path.insert(0,'<skill_dir>/scripts'); import df_adapters, json; print(json.dumps(df_adapters.available_builders()))"`
     to see which of claude / codex / gemini are installed. Ask the user which model should BUILD; offer only the available
     ones. Set `roles.builder.adapter` to `<skill_dir>/scripts/adapters/<name>`.
     **No silent fallback** — if the chosen model's CLI is absent the run fails
     closed (`resolve_builder` raises; the run aborts). Verification stays the
     deterministic scenario runner regardless of builder — dark-factory has no LLM
     judge to swap.
     - **Also offer the direct-API builders (no CLI needed).** Two adapters,
       `api_anthropic` and `api_openai`, drive a real model over the provider's
       HTTP API using only the Python stdlib — so they run even where no
       `claude`/`codex`/`gemini` binary is installed (notably **inside the
       hardened/enterprise container**, which the CLI builders can't), and they
       report **real token usage → cost** (the CLI builders can't). Offer these
       when the user wants OpenAI as the builder, wants a real-model build inside
       the hardened container, or wants authoritative cost metering. Point
       `roles.builder.adapter` at `<skill_dir>/scripts/adapters/api_anthropic`
       (needs `ANTHROPIC_API_KEY`, optional `DF_API_MODEL`) or `.../api_openai`
       (needs `OPENAI_API_KEY`). They aren't in `available_builders()` (that only
       probes for CLIs on PATH) — select them by path directly. See
       `references/role-adapters.md`.
   - **Vendor diversity (recommended, not required).** Author the spec and the
     holdout scenarios with a *different* model/session than the builder (e.g.
     Claude authors, Codex builds). Different vendors have different blind spots,
     which hardens the holdout — the "second librarian from a different library."
     Never author scenarios in the same session that will drive the builder.
   - `assurance`: `cooperative` (works everywhere, unqualified), `standard` (real OS
     read-denial sandbox → qualified; needs macOS `sandbox-exec` or Linux `bwrap`, and a
     passing startup denial probe), or `hardened` (builder runs in a Docker container with
     the control root never mounted — denial by construction, plus a passing container
     probe; needs a running Docker daemon AND a working OS sandbox, since the verifier
     still uses the latter). If the chosen tier can't be honored, the run fails closed
     unless you pass `run --allow-downgrade` (hardened → standard if the OS sandbox is
     still healthy, else → cooperative; standard → cooperative).
   - **`candidate_network` (optional, M27; requires `standard`+).**
     `"unrestricted"` (default) / `"deny"` / `"loopback"` — restricts the
     CANDIDATE only, never the builder's own API egress, and is live-probed
     fail-closed before the candidate runs. **At `standard`+ an
     `"unrestricted"` candidate is DISQUALIFYING** (seals
     `CANDIDATE_EGRESS_OPEN`, not `COMPLETE_QUALIFIED`) — set `"deny"`, or
     `"loopback"` for twins (macOS-only; `"deny"` is refused with twins/http
     scenarios). An app that serves its OWN loopback listeners needs
     `candidate_service_ports: N` (qualifying; ports exported to scenarios as
     `DF_SERVICE_PORTS`) — `candidate_loopback_outbound: "any"` is dev-grade
     and never qualifies. See `references/isolation.md`.
   - **`candidate_host_read` (optional, M29b/M29c, DF-02; `standard`+).** At
     standard+ the CANDIDATE runs under a default-deny host-read sandbox on
     macOS AND Linux (workspace-only writes; `~/.ssh`/dotfiles/other repos
     OS-denied), live-probed per run and sealed as manifest `host_isolation`.
     Opt out with `"allow_host_read"` only if the app truly must read the
     host (`host_isolation.qualified` is then honestly `false`). Linux
     `loopback`/twins remain macOS-only until M29c-2 — use
     `candidate_network: "deny"` for a qualifying host-isolated Linux run.
     Mechanics: `references/isolation.md`.
   - **`hardened` (optional block, only under `assurance: hardened`).** Set
     `hardened.image` / `.network` / `.memory` / `.pids` (defaults:
     `python:3.12-alpine`, `"none"`, `"2g"`, `256`; a real cross-model builder
     needs a user-supplied image with that CLI + credentials baked in, and
     `"bridge"` egress — honestly recorded on the manifest). `hardened` forces
     `audit.signing: true` (explicit `false` rejected) and requires
     `roles.builder.adapter` be an absolute path outside the control root (the
     adapter FILE is bind-mounted read-only). Builds needing third-party
     packages under `--network none` use the **pinned read-only dependency
     cache** (M26): provision once with `df_depcache.py`, set
     `hardened.dep_cache_dir`; anything not cached fails closed. Full model,
     TCB honesty, and dep-cache details: `references/hardened.md`.
   - **H4 `lights_out` (fully unattended; legacy `autonomy: 5`).** Requires
     `assurance: "hardened"` (or `enterprise`) — H4/`autonomy: 5` at any other tier is
     rejected at config load. Under H4 the loop runs unattended to
     convergence/cap/failure in one CLI call with no per-iteration pause, and any
     human-needed condition (e.g. a budget cap) becomes a fail-closed TERMINAL
     (`BUDGET_HALTED`, exit 3) rather than a pause. (Legacy compatibility: the pair
     `autonomy: 5` + `checkpoint: auto` maps to H4 — same lights-out semantics,
     including the `BUDGET_HALTED` terminal — via `df_modes.legacy_mode` /
     `df-migrate-config`. See `references/modes.md`.)
   - **Budget (optional).** Set `budget.billing`: `"subscription"` (default — no dollar
     metering possible, so it's alert-only) or `"api"` (enforces a dollar cap via an
     estimate). For `"api"`, also set `budget.max_usd` and `budget.per_call_usd`
     (estimated $ reserved per builder call — a cap without `per_call_usd` is honestly
     downgraded to alert-only). `budget.max_calls` is an exact, non-estimated cap
     enforced under any billing. See `references/budget.md` for the full model
     (85% alert, 100% phase-boundary pause, raise-and-resume) and its honest caveat:
     dollars are an **estimate**, not metered usage.
   - **Security gates (opt-in at cooperative; MANDATORY at standard+).** Set
     `security_gates.enabled: true` to
     run a mandatory secret scan + dangerous-pattern scan + SBOM (plus any configured
     external tool, e.g. `bandit`/`semgrep`) on the **converged artifact**, once, after
     the final exam passes and before `CONVERGED` — **independent of scenario
     pass-rate**: because no human reviews the built code, a fully-passing build with a
     planted secret still gets rejected. A finding on a `fail_on` gate (default
     `["secret_scan", "dangerous_scan"]`) makes the run terminal `SECURITY_GATE_FAILED`
     (exit 3, never qualified) — the artifact is rejected, not iterated on. **At
     `standard`/`hardened`/`enterprise` (M33a) `secret_scan` + `dangerous_scan` are
     forced on and `qualified` folds in `app_security_qualified`** — a standard+ run
     can't qualify unless the mandatory gates ran and passed. If a standard+ run hits
     a finding you've **accepted**, don't disable the gate: issue a signed, scoped,
     **expiring** waiver (`security_gates.waivers` + the `df-waiver`
     findings→sign→attach→verify CLI; expiry is re-checked at every verify). See
     `references/security-gates.md` for the built-ins, the external-gate interface,
     the mandatory-at-standard+ policy, the full waiver workflow, and the honest
     heuristic/floor caveat (false positives are the safe direction; false negatives
     mean it's a floor, not a proof).
   - **Credentials (optional).** If the builder needs a real provider credential (e.g.
     an API key for the CLI it wraps), set `credentials.source` (`"env-file"` —
     recommended, an absolute path to a `KEY=VALUE` file OUTSIDE the control root and
     workspace; `"keychain"` — macOS `security` CLI only in M11; or `"env"` — the
     launcher's own environment) and `credentials.allowlist` (the exact variable names
     the builder may receive — nothing else is ever brokered). **Never put a
     credential in `config.json`, `spec.md`, or a scenario file** — an `env-file` must
     be `.gitignore`d if it lives inside any git repo, or the run refuses closed with
     the exact remedy (`git rm --cached` / add to `.gitignore` / `chmod 600`) before
     anything else happens. Every credential value is scrubbed
     (`***REDACTED***`) from the journal, every manifest, and every checkpoint/verify
     report before it's written to disk; the manifest's `credentials` field records
     only the source + allowlisted names, never a value. See
     `references/credentials.md` for the containment model and its honest limits (no
     rotation; `-e` argv `ps`-visibility at `hardened`; at `enterprise` the host-side
     credential proxy keeps the token out of the sandbox entirely and kernel-locks
     egress to an allowlist — see `references/enterprise.md`).
4a. **Off-box audit sink (optional, recommended for supply-chain integrity).** Every run
    already appends one linked entry to `<control_root>/audit-chain.jsonl` (M13, always-on —
    no config needed). To also ship each entry off-box, set `audit.sink.kind` to
    `"http-append"` (an append-only receiver, `df_audit_receiver.py`) or `"s3-objectlock"`
    (a WORM S3-compatible bucket) and `audit.sink.required: true` to fail the run closed
    (`AUDIT_SINK_FAILED`, nonzero exit) if the push fails, or `false` to only warn
    (`AUDIT_SINK_WARN`) and let the run converge normally either way. **Honesty:** the chain
    alone is tamper-evident, not tamper-proof — a local process that can rewrite the chain
    can also forge a fresh, internally-consistent one over it. The genuine anchor is a sink
    living in a DIFFERENT trust domain than the runner (a separate host/account); running
    the reference receiver on the same box is a protocol demo, not the production
    guarantee. See `references/audit.md` for the full model.
4b. **Twins (optional).** If the task's code talks to external services, define behavioral mocks in `<control_root>/twins/*.json` (see `references/digital-twins.md`) and set `twins.enabled: true` in config.json. The builder develops against the twins, and the verifier resets them fresh before each verify pass for deterministic verification. Results are **twin-observed** — you must validate against the real service or staging before shipping.
   - **Twin evidence (M12, optional, recommended when a behavior depends on genuinely calling a twin).** Add a scenario `then` assertion — `twin_observed: {twin, contains}` (the twin's own observation log, not the candidate's output, must show the call) or `stdout_echoes_twin: {twin}` (the candidate's stdout must echo a token the twin served *this pass*) — and set `"supports_variants": true` on the twin def to make the served token fresh and unpredictable every verify pass. Both assertions fail closed with taxonomy `no_twin_evidence` if the candidate never really invoked the twin (e.g. a hardcoded response) — catching teaching-to-the-test that plain output-matching would miss. See `references/digital-twins.md` for the observation contract, seed semantics, and honest scope (filesystem-authority channel; network-graph enforcement and off-box sinks remain deferred).
4c. **Brownfield (optional, only relevant when `--project-src` points at an already-existing codebase).** Detection is automatic and fail-safe toward brownfield: `brownfield.mode` defaults to `"auto"`, which classifies the run as `brownfield` the moment `--project-src` has ≥1 file — an existing tree is never silently treated as greenfield. To actually GUARD existing behavior against regression, supply `brownfield.probes` — real, deterministic commands (e.g. `python3 app.py add 2 3`) run against the CURRENT artifact before the builder ever touches anything; each is frozen into a holdout `BHV-REGRESS-<n>` scenario the builder never sees, and a build that breaks one fails verification exactly like a missed new-behavior scenario. **A brownfield run with zero probes configured is a valid but UNGUARDED no-op** — the supervisor says so loudly (stderr WARN + a distinct `BROWNFIELD_UNGUARDED` journal entry + an unambiguous manifest note), so it is never mistaken for "regressions checked." Characterization guards only what the probes exercise, never full semantics — see `references/brownfield.md` for the incremental workflow, the reduced-guarantee honesty, and how to write good probes.
4d. **Builder confinement (optional, recommended, largest value at `cooperative`/`standard`).** Set `builder_confinement.enabled: true` to confine the BUILDER subprocess (not this orchestrating session) to an explicit build-tool allowlist — no MCP servers, no sub-agents, no web tools — enforced at the adapter boundary. Only **claude** has a probe-verified profile today; **codex** and **gemini** have none, and `required` defaults to `enabled`, so with confinement on they refuse fail-closed (`CONFINEMENT_REFUSED`, exit 2, builder never spawned) unless you set `required: false` to warn and run unconfined. So: pick claude as the builder to run confined. Threat model, claude's exact flags, the codex-unsupported finding, and honest scope vs. `hardened`'s container barrier: `references/builder-confinement.md`.
4e. **Resume overrides (optional, M36b).** If ops needs a *governed* way to raise a
    BUDGET-PAUSE'd run's budget ceiling at resume (an authorized policy change, not a raw
    `config.json` edit), set `resume_overrides: {approvers:[pubkey_hex,...], threshold:N}`.
    Approvers are ed25519 public keys (`df-override keygen`); a paused run is then cleared
    with `df-override sign --run-dir <run_dir> --new-usd-ceiling <x> --expires <iso>` →
    `resume --override <file>`. Each override is bound to one `run_id`, expires, and is
    single-use (a `<control_root>/override-nonces.json` nonce ledger refuses replays). A
    non-empty policy REQUIRES `audit.signing: true`. Absent the block, no override is ever
    accepted (fail-closed). Credential-value refresh needs NO override — resume re-resolves
    credentials every time. See `references/budget.md`.
5. **Run.** `python3 <skill_dir>/scripts/supervisor.py run --control-root <control_root> [--project-src <dir>]`
   - **Spec-fork from a prior artifact (optional, M36b).** To iterate on a shipped artifact
     rather than rebuild from scratch, adjust `spec.md`/scenarios and start the child run
     with `supervisor.py df-fork <control_root> --parent-run <parent_run_dir>` instead of
     `run`. The parent must verify clean and bind an artifact; its frozen object seeds the
     child workspace, the child manifest records `lineage`, and the parent is marked
     superseded (still verifies, but `verify-manifest` prints the supersession so a stale
     artifact isn't shipped unknowingly). See `references/audit.md`.
   Exit 0 = converged/accepted · 3 = a non-converged terminal a human must evaluate
   (`CAP_REACHED`, `FINAL_EXAM_FAILED`, or **`SECURITY_GATE_FAILED`** — the converged
   artifact tripped a mandatory security gate, see `references/security-gates.md`) ·
   2 = config/build/abort error (**including a pre-build gate failure** — coverage gap
   or inert scenario; `GATE_FAILED`, no build ever ran, see
   `references/coverage-gates.md`) ·
   **10 = paused** — either at an intervention checkpoint (a mode that pauses: H1
   directed, H2 supervised, or H3 guarded — legacy `checkpoint: pause`/autonomy 4) or
   at a **budget cap** (`journal` has `BUDGET_PAUSE`; fires under H1–H3 even in the
   run-through H3/`checkpoint: auto` mode). Under **H4 lights-out** the loop never
   returns paused — a budget cap is the `BUDGET_HALTED` terminal (exit 3) instead.
6. **At a checkpoint (exit 10).** Show the user `runs/<id>/checkpoint_iter_N.md` (per-behavior
   pass/fail — no scenario text). Then, on their decision, run:
   - **continue** → `supervisor.py resume --control-root <cr> --decision continue`
   - **adjust spec** → edit `<control_root>/spec.md`, then `resume --decision continue`
   - **accept** (stop, waived/unverified) → `resume --decision accept`
   - **abort** → `resume --decision abort`
   Repeat until exit 0/2/3.
   - **At an UNKNOWN_OUTCOME crash-recovery halt (exit 11, journal `UNKNOWN_OUTCOME`, M35/DF-08).**
     If the supervisor was hard-killed (SIGKILL/OOM/power loss) DURING a model dispatch,
     the crashed call's outcome is unknown and its reserved spend is already counted (never
     understated). A plain `resume --decision continue` fail-closes here (exit 11) rather
     than silently re-issuing a possibly-already-charged paid call. To proceed, reconcile
     explicitly: `resume --decision reconcile` re-dispatches that iteration (accepting
     possible duplicate spend — journaled `DISPATCH_RECONCILED`), or `--decision abort`
     to stop. See `references/budget.md`.
   - **At a budget pause (exit 10, journal `BUDGET_PAUSE`).** This is resumable, not
     terminal: raise `budget.max_usd` and/or `budget.max_calls` in `config.json`, then
     `supervisor.py resume --control-root <cr> --decision continue` — the run re-reads
     the raised cap and continues from where it paused (builder-call/estimate counts
     persist, no reset, no double-count). For a **governed** ceiling raise, configure a
     `resume_overrides: {approvers, threshold}` policy (M36b) and pass a signed
     `resume --override <file>` (`df-override sign`) instead of a raw config edit.
     See `references/budget.md`.
   - **At a before-ship pause (exit 10, journal `CHECKPOINT` phase `AWAIT_SHIP`; H1/H2 only).**
     The build converged and the artifact is frozen; a human approves the ship.
     `resume --decision continue` seals it WITHOUT rebuilding (no builder call);
     `resume --decision abort` seals `SHIP_DECLINED` (not shipped). See `references/modes.md`.
6b. **Ship phase (optional, M41).** If a `ship` block is configured, a qualified
    run continues into a governed ship phase (`references/ship.md`): reversible
    actions run unattended (auto-after-seal, incl. H4); the ship outcome is a
    SEPARATE `ship_result.json` (`SHIPPED`/`SHIP_FAILED`/`SHIP_APPROVAL_PENDING`),
    never a manifest rewrite (the run stays `qualified`). On `SHIP_APPROVAL_PENDING`
    (an irreversible action awaits sign-off): have K approvers `df-release sign`
    a claim bound to the run+artifact, collect into `<control_root>/release-approval.json`,
    `df-release attach`, then `ship <control_root> --run-dir <run_dir>`. On
    `SHIP_UNKNOWN_OUTCOME` (exit 11, a crash left a forward action's — or a
    rollback's — effect unknown): inspect the target, then `ship --decision
    reconcile` (accept a possible duplicate) or `--decision abort`. On
    `SHIP_AUDIT_PENDING` (exit 12, SHIPPED but required off-box evidence not yet
    anchored): plain re-`ship` re-anchors. On `SHIP_EVIDENCE_PENDING` (exit 13, a
    completed action's signed evidence could not be committed — the action RAN and
    is NEVER re-run): verify its real-world state, then `ship --decision
    repair-evidence` once the signer is available. Enterprise ships ONLY after
    `df-custody attach` (it seals `CUSTODY_PENDING`, not a before-ship pause).
7. **Report.** Outcome, iterations, per-behavior status from `journal.jsonl`, the workspace
   path, and `verify-manifest --run-dir <run_dir>`. `verify-manifest` (DF-01/M28a) now also
   re-verifies the manifest's bound artifact object against the content-addressed store at
   `<control_root>/objects/` — pass `--object-store <path>` when checking a `run_dir` copied
   away from its original control root. Exit codes: `0` OK · `4` TAMPERED/UNVERIFIED (manifest
   byte-integrity/signature) · `5` ARTIFACT MISMATCH/UNAVAILABLE (bound object drifted or
   missing) · `6` UNBOUND (manifest never bound an artifact — expected for `CAP_REACHED`/gate
   aborts/pre-M28a manifests, not itself a failure of the run). See `references/audit.md`'s
   "Artifact binding (DF-01)" section for the full table and the honest detection-grade scope.
   State that cooperative tier is unqualified.
   Every run — regardless of config — also appends one linked entry to
   `<control_root>/audit-chain.jsonl`; check the WHOLE control root's chain with
   `verify-chain <control_root> [--key-path <keyfile>]` (`OK: N entries` / exit 0, or the
   first break / exit 1). If `audit.sink` is configured, also check `runs/<id>/audit_sink_receipt.json`
   exists (its absence with `required: true` means the run already failed closed — see
   `references/audit.md`).

## Hard rules

- Scenario files and their content NEVER enter: the builder prompt, the
  workspace, the main builder-driving conversation, or any feedback.
- Never feed final-exam results back into the builder loop — a final
  failure is terminal (`FINAL_EXAM_FAILED`), not another feedback round.
- Never author `final` scenarios in a session that is also driving the
  builder — same separation as step 3 for the dev cohort, and it matters
  more here: `final` is the sealed exam that must stay unseen even by you.
- Only the supervisor writes run state. Do not hand-edit `runs/`.
- Secrets: never put credentials in config.json/spec.md/scenarios; the claude
  adapter uses your ambient login. If a builder needs a real provider credential,
  use the `credentials` config block (env-file/keychain, allowlisted, gitignore
  enforced, artifact-scrubbed — see `references/credentials.md`), never a bare
  env var baked into the adapter script or config.
- Qualification is judged on the manifest's **`effective_tier`**, never the configured one (`manifest.tier` echoes the configured assurance; M57 also seals `requested_tier`/`effective_tier`, and every downstream decision — qualification, custody, release, ship — consumes the EFFECTIVE tier). An effective-cooperative run is always UNQUALIFIED — say so; standard/hardened/enterprise qualify only with passing startup probes (`qualified: true` / `COMPLETE_QUALIFIED`, or `CUSTODY_PENDING`→attested at enterprise). Report the manifest's actual `qualified` value.
- Verify signatures fail-closed: `verify-manifest --key-path <path>` and `verify-chain <control_root> [--key-path]` print UNVERIFIED and exit non-zero when a signed manifest/chain entry is checked without its key — never treat UNVERIFIED as OK. Signing is opt-in at cooperative/standard, mandatory at hardened+. Details + off-box sink: `references/audit.md`.
- `hardened` is fail-closed on BOTH halves (Docker + container probe, AND a working OS sandbox for the verifier); either missing refuses (exit 2) unless `--allow-downgrade`. See `references/hardened.md`.
- Security gates are MANDATORY at standard+ and fail-closed on the converged artifact (`SECURITY_GATE_FAILED`, exit 3, even when every scenario passed); an accepted finding is cleared only by a signed, scoped, expiring waiver (`df-waiver`), never by disabling the gate. `checked: false` means gates never ran, not that the artifact is clean. See `references/security-gates.md`.

## Composing with other skills (control-plane only)

dark-factory's *builder* is an external sandboxed CLI that loads no skills — so
composition applies only to THIS orchestrating session's own steps, which run
around the builder, never inside it:

| Step | Prefer, if available | Barrier note |
|---|---|---|
| Author the spec (step 2) | `superpowers:brainstorming`, `grill-me-codex`, `writing-plans` | fine — spec is SHARED with the builder |
| Author scenarios (step 3) | keep manual, in a **separate session** | never delegate this into a builder-driving session |
| Stuck loop (cap reached, likely spec ambiguity) | `superpowers:systematic-debugging` | operates on spec + behavior IDs only, never scenario internals |
| Cleanup an accepted artifact | `/simplify`, `code-review` on the workspace | post-acceptance, outside the barrier |

**Honesty:** at every tier — including `hardened` — this is *guidance*, not
enforcement of THIS orchestrating session. `hardened` sandboxes the **builder**
(container barrier) and the **verifier** (OS sandbox); it does not sandbox the
Claude session running this skill. An **enforced** per-tier skill/tool allowlist
that constrains the orchestrator itself (spec §3B) **cannot be done in skill
code** — a skill cannot sandbox the session executing it — so it is an
**operator step at the harness layer**. If your threat model needs it, follow
`references/orchestrator-lockdown.md` **before you run a build**: it gives the
Claude Code recipe (session tool allow/deny, `--strict-mcp-config`, a
`PreToolUse` hook as the hard gate, and OS-level containment of the orchestrator)
plus how to probe that the allowlist actually holds. Never author or reveal
holdout scenarios in a session that will also drive the builder.

## References

Each doc below is the authoritative detail for its area — open it when that
area is in play. `OVERVIEW.md` glosses every one in plain language.

- `README.md` — human-facing quickstart, tier table, repo layout
- `OVERVIEW.md` — plain-language overview + what each reference covers
- `GLOSSARY.md` — every term/tier/mode/outcome in one place
- `references/authoring.md` — the init interview; writing holdout scenarios
- `references/scenario-adequacy.md` — class coverage, sharpness, decorrelated critic
- `references/scenario-format.md` — oracle IR v0; when.property generative scenarios
- `references/config-reference.md` — config schema
- `references/modes.md` — H1–H4 pause-point table; legacy mapping; df-migrate-config
- `references/audit.md` — manifest signing, hash chain, off-box sink, FSM checkpoints
- `references/ship.md` — governed ship phase, df-release approvals, crash recovery
- `references/isolation.md` — standard tier sandbox; candidate network/host authority
- `references/hardened.md` — container barrier, H4, image/dep-cache rules
- `references/enterprise.md` — egress lockdown, seccomp, split custody
- `references/credentials.md` — credential broker and its honest limits
- `references/security-gates.md` — mandatory gates, fail_on, df-waiver
- `references/budget.md` — budget model; signed resume overrides
- `references/digital-twins.md` — twin lifecycle, observations, variant seeds
- `references/brownfield.md` — detection, regression probes, unguarded honesty
- `references/builder-confinement.md` — per-CLI confinement profiles and the live probe
- `references/coverage-gates.md` — behaviors.json coverage/mutation gates
- `references/role-adapters.md` — adapter protocol; api_anthropic/api_openai
- `references/knowledge-base.md` — KB integration
- `references/reproducibility.md` — what is reproducible today vs. owner TODO
- `references/live-validation.md` — live H4/enterprise runbook; evidence-bundle
- `references/orchestrator-lockdown.md` — locking down the orchestrating session
- `references/prevention-grade-roadmap.md` — detection-grade vs. prevention-grade
- `references/support-matrix.md` — app × host OS × tier support matrix
- `references/linux-ci.md` — the Linux-container full-suite harness
- `references/example-cross-model.md` — a worked cross-model authoring example
