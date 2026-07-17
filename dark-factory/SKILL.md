---
name: dark-factory
description: Use when the user wants to build a task/feature "dark-factory style" — the human writes a spec, an isolated builder agent implements it WITHOUT ever seeing the hidden acceptance scenarios, a verifier runs those scenarios, and only behavior-ID + failure-taxonomy feedback crosses back until convergence. Triggers on "dark factory", "dark-factory", "hidden tests", "holdout scenarios", "build without seeing the tests", or requests to prevent an AI builder from teaching to the test. Tiers: `cooperative` (honor-system, unqualified), `standard` (OS read-denial sandbox — macOS/Linux — probe-verified and qualified), and `hardened` (builder runs in a Docker container with the control root never mounted — denial by construction, probe-verified — and unlocks fully unattended L5/autonomy-5 runs). Per-iteration human checkpoints (pause/resume) at autonomy 4.
---

# dark-factory

Runs a StrongDM-style dark-factory loop: **spec in → hidden holdout scenarios
→ isolated builder (spec-only) → verifier → deterministic ID feedback → loop →
outcome**. Design spec: `docs/superpowers/specs/2026-07-13-dark-factory-skill-design.md`
(Codex-approved). Four assurance tiers ship: **cooperative** (honor-system isolation — every run is explicitly UNQUALIFIED), **standard** (OS read-denial sandbox on macOS/Linux, verified by a fail-closed startup denial probe — a converged run is QUALIFIED), **hardened** (the builder runs inside a Docker container that never has the control root mounted — denial by *construction*, not a deny-rule — still probe-verified fail-closed; see `references/hardened.md`), and **enterprise** (hardened + kernel-locked egress to a host-side credential proxy + seccomp + **split-custody sign-off**: a run is qualified only via a separate K-of-N ed25519 approver attestation bound to the sealed manifest — no single operator can ship; see `references/enterprise.md`). `hardened` (and `enterprise`) unlock **L5** (`autonomy: 5`, fully unattended/lights-off — spec §2.2).

## Authoring a run (`init`) — the on-ramp for "provide context and specs"

When the user's ask is "here's my spec/context, build me a dark-factory
run" rather than a from-scratch interview, `dark-factory init` scaffolds a
**ready-to-run control root** — validated `config.json`, builder-visible
`spec.md`, `behaviors.json`, and holdout `scenarios/*.json` — from a small
`answers` JSON document, instead of hand-writing every control-plane file
across workflow steps 2-4 below. It reuses the exact same validators `run`
does (`df_config.load_config`, oracle discrimination, coverage, plus a
barrier check that no scenario's exact expected output leaked into
`spec.md`), so a control root `init` blesses is one `run` accepts — and it
refuses (removing the invalid tree) rather than leaving a broken control
root to fail confusingly later.

- **The interview.** `references/authoring.md` is the script to follow:
  what the app does + its interface (the spec), which assurance tier and
  why, the must-pass behaviors with 1-3 holdout scenarios each (with
  guidance on writing scenarios that are actually discriminating and don't
  leak the answer into the spec), and the optional config blocks
  (`security_gates`/`twins`/`budget`/`knowledge_base`).
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
  them), it does not auto-generate scenarios from spec text, and it never
  runs a build (it prints the `run` command instead). See
  `references/authoring.md` for the full interview and scenario-writing
  guidance.

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
   - **`hardened` (optional block, only under `assurance: hardened`).** Set
     `hardened.image` (default `python:3.12-alpine` — a real cross-model builder needs a
     user-supplied image with that CLI + credentials baked in), `hardened.network`
     (default `"none"`; `"bridge"` is unrestricted egress, needed for a real builder CLI's
     API calls, and is honestly recorded on the manifest), `hardened.memory` (default
     `"2g"`) and `hardened.pids` (default `256`). `hardened` also forces
     `audit.signing: true` by default (an explicit `false` is rejected) and requires
     `roles.builder.adapter` to be an absolute path to an existing file outside the
     control root (its directory is bind-mounted read-only into the container). See
     `references/hardened.md` for the full model — what it adds over `standard`, the TCB
     growth (the Docker daemon), image/credential/network honesty, and the deferred list
     (credential broker, egress allowlists, off-box audit).
   - **L5 (`autonomy: 5`, lights-off).** Requires `assurance: "hardened"` — any other
     tier with `autonomy: 5` is rejected at config load. At hardened + L5, `checkpoint`
     defaults to `auto`: the loop runs unattended to convergence/cap/failure in one CLI
     call, with no per-iteration pause (a budget cap can still pause — that's a separate,
     financial safety rail, see `references/budget.md`).
   - **Budget (optional).** Set `budget.billing`: `"subscription"` (default — no dollar
     metering possible, so it's alert-only) or `"api"` (enforces a dollar cap via an
     estimate). For `"api"`, also set `budget.max_usd` and `budget.per_call_usd`
     (estimated $ reserved per builder call — a cap without `per_call_usd` is honestly
     downgraded to alert-only). `budget.max_calls` is an exact, non-estimated cap
     enforced under any billing. See `references/budget.md` for the full model
     (85% alert, 100% phase-boundary pause, raise-and-resume) and its honest caveat:
     dollars are an **estimate**, not metered usage.
   - **Security gates (optional, recommended).** Set `security_gates.enabled: true` to
     run a mandatory secret scan + dangerous-pattern scan + SBOM (plus any configured
     external tool, e.g. `bandit`/`semgrep`) on the **converged artifact**, once, after
     the final exam passes and before `CONVERGED` — **independent of scenario
     pass-rate**: because no human reviews the built code, a fully-passing build with a
     planted secret still gets rejected. A finding on a `fail_on` gate (default
     `["secret_scan", "dangerous_scan"]`) makes the run terminal `SECURITY_GATE_FAILED`
     (exit 3, never qualified) — the artifact is rejected, not iterated on. See
     `references/security-gates.md` for the built-ins, the external-gate interface,
     and the honest heuristic/floor caveat (false positives are the safe direction;
     false negatives mean it's a floor, not a proof).
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
4d. **Builder confinement (optional, recommended, largest value at `cooperative`/`standard`).** Set `builder_confinement.enabled: true` to confine the BUILDER subprocess (not this orchestrating session) to an explicit build-tool allowlist — no MCP servers, no sub-agents, no web tools — enforced at the adapter boundary and **probe-verified**, not just flag-asserted. Only **claude** is supported/probe-verified today (its Bash tool is provably not loaded under the confinement flags). **codex** is UNSUPPORTED as of M14: the live probe caught that `-c mcp_servers={}` does NOT actually close codex's MCP surface on installs where the ChatGPT desktop-app runtime injects an `mcp__` tool bridge (the probe created a denied-tool proof file via a real `mcp__` tool), so codex fail-closes like gemini — this is the airtight probe doing its job, refusing rather than trusting a flag that doesn't hold. `builder_confinement.required` defaults to `.enabled` (turning confinement on defaults to REQUIRING it): a builder CLI with no probe-verified profile (`codex`, `gemini`) then refuses the run fail-closed (`CONFINEMENT_UNSUPPORTED` journaled, terminal manifest `outcome: "CONFINEMENT_REFUSED"`, exit 2, the builder CLI never spawned) rather than running it unconfined. Set `required: false` to instead warn (`CONFINEMENT_WARN`) and fall back to an unconfined run for that CLI. So today: pick **claude** as the builder to run confined; codex/gemini can only run unconfined (`enabled: false`, or `required: false` to auto-downgrade). See `references/builder-confinement.md` for the threat, claude's exact flags and what the live probe proved (Bash never loaded), the full codex-unsupported finding, and the honest note that `hardened`'s container barrier already confines heavily via `hardened.network: "none"` — so this config block's biggest win is at tiers without that barrier.
5. **Run.** `python3 <skill_dir>/scripts/supervisor.py run --control-root <control_root> [--project-src <dir>]`
   Exit 0 = converged/accepted · 3 = a non-converged terminal a human must evaluate
   (`CAP_REACHED`, `FINAL_EXAM_FAILED`, or **`SECURITY_GATE_FAILED`** — the converged
   artifact tripped a mandatory security gate, see `references/security-gates.md`) ·
   2 = config/build/abort error (**including a pre-build gate failure** — coverage gap
   or inert scenario; `GATE_FAILED`, no build ever ran, see
   `references/coverage-gates.md`) ·
   **10 = paused** — either at a checkpoint (autonomy 4 / `checkpoint: pause`) or at a
   **budget cap** (`journal` has `BUDGET_PAUSE`; fires even at `checkpoint: auto`).
6. **At a checkpoint (exit 10).** Show the user `runs/<id>/checkpoint_iter_N.md` (per-behavior
   pass/fail — no scenario text). Then, on their decision, run:
   - **continue** → `supervisor.py resume --control-root <cr> --decision continue`
   - **adjust spec** → edit `<control_root>/spec.md`, then `resume --decision continue`
   - **accept** (stop, waived/unverified) → `resume --decision accept`
   - **abort** → `resume --decision abort`
   Repeat until exit 0/2/3.
   - **At a budget pause (exit 10, journal `BUDGET_PAUSE`).** This is resumable, not
     terminal: raise `budget.max_usd` and/or `budget.max_calls` in `config.json`, then
     `supervisor.py resume --control-root <cr> --decision continue` — the run re-reads
     the raised cap and continues from where it paused (builder-call/estimate counts
     persist, no reset, no double-count). See `references/budget.md`.
7. **Report.** Outcome, iterations, per-behavior status from `journal.jsonl`, the workspace
   path, and `verify-manifest --run-dir <run_dir>`. State that cooperative tier is unqualified.
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
- A **cooperative** run is always UNQUALIFIED — say so. A **standard** or **hardened** run is qualified ONLY when its startup probe(s) passed (manifest `qualified: true` / outcome `COMPLETE_QUALIFIED`); never call a cooperative, downgraded, aborted, or capped run a qualified ship-candidate — report the manifest's actual `qualified` value. Note: `manifest.tier` always echoes the *configured* assurance, even on a downgraded run — read `qualified` plus the journal's `DOWNGRADE` entry for what actually happened.
- Signed audit is opt-in at `cooperative`/`standard` (`audit.signing: true` in config) but **mandatory** at `hardened` (an explicit `audit.signing: false` is a `ConfigError`). Verify with `verify-manifest --key-path <path>`. A signed manifest with no key prints UNVERIFIED and exits non-zero (fail-closed) — never treat it as OK.
- Every run also chains its manifest into `<control_root>/audit-chain.jsonl` (always-on, M13); check it with `verify-chain <control_root> [--key-path <path>]`, which fails closed the same way — a chain carrying a signed entry, checked without `--key-path`, is UNVERIFIED, not OK. An optional `audit.sink` ships each entry off-box; see `references/audit.md` for what it does and does not prove.
- `hardened` is fail-closed on **both** halves: a working Docker daemon + passing container probe, AND a working OS sandbox for the verifier. Either missing refuses (exit 2) unless `--allow-downgrade` is passed. See `references/hardened.md`.
- Security gates are opt-in (`security_gates.enabled: true`) but, once enabled, mandatory and fail-closed: a `fail_on` finding on the converged artifact rejects it (`SECURITY_GATE_FAILED`, exit 3) even when every scenario passed. Report the manifest's `security` field honestly — `checked: false` means gates never ran, not that the artifact is clean.

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

- `references/authoring.md` — the `init` interview script: spec, tier choice, writing discriminating holdout scenarios (dev vs. sealed final), and the optional config blocks; see also `examples/kv-service/answers.json` (M19)
- `references/config-reference.md` — config schema
- `references/audit.md` — manifest signing, the hash chain (`verify-chain`), off-box sink (`http-append`/`s3-objectlock`), and the honest trust-domain limits of each (M5a, M13)
- `references/isolation.md` — the `standard` tier: OS read-denial sandbox, backends, probe discipline
- `references/hardened.md` — the `hardened` tier: container barrier (denial by construction), hardening flags, L5, TCB growth, image/credential/network honesty, deferred scope (M10)
- `references/orchestrator-lockdown.md` — enforcing a skill/tool allowlist on the ORCHESTRATOR session (spec §3B): why the skill can't self-sandbox, the harness-layer recipe (session allow/deny, strict MCP, a PreToolUse hook, OS containment), and how to probe it holds
- `references/budget.md` — budget model: admission control, 85% alert, 100% pause, raise-and-resume, honest estimate caveat (M8)
- `references/security-gates.md` — mandatory security gates on the converged artifact: built-ins, external-gate interface, fail_on/strict_unavailable, `SECURITY_GATE_FAILED` semantics, honest heuristic/floor caveat (M9)
- `references/credentials.md` — the credential broker: allowlist-only injection, scrubbed artifacts, gitignore/permission gates, launcher-scoped standard-tier env, and honest limits (no rotation, `ps`-visibility, egress) (M11)
- `references/digital-twins.md` — twin definition, lifecycle, and honest scope (M3a); observation log, evidence assertions, and verifier-only variant seeds (M12)
- `references/brownfield.md` — greenfield/brownfield detection, characterization into holdout regression guards, and the probe-coverage-bounded honest scope (M15)
- `references/builder-confinement.md` — BUILDER-subprocess capability confinement: threat, adapter-boundary enforcement, per-CLI profiles (claude probe-verified; codex unsupported — the live probe falsified its flag-based confinement; gemini refused-until-probed), the airtight live probe (two-call + DENIED_CALL_RAN non-vacuity), fail-closed tier gating, and honest scope vs. `hardened`'s container barrier (M14)
- `references/knowledge-base.md` — KB integration (optional, spec §3A)
- `references/scenario-format.md` — oracle IR v0
- `references/coverage-gates.md` — behaviors.json schema + the fail-closed pre-build coverage/mutation gates (M7)
- `references/role-adapters.md` — adapter protocol
