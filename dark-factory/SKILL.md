---
name: dark-factory
description: Use when the user wants to build a task/feature "dark-factory style" — the human writes a spec, an isolated builder agent implements it WITHOUT ever seeing the hidden acceptance scenarios, a verifier runs those scenarios, and only behavior-ID + failure-taxonomy feedback crosses back until convergence. Triggers on "dark factory", "dark-factory", "hidden tests", "holdout scenarios", "build without seeing the tests", or requests to prevent an AI builder from teaching to the test. Tiers: `cooperative` (honor-system, unqualified), `standard` (OS read-denial sandbox — macOS/Linux — probe-verified and qualified), and `hardened` (builder runs in a Docker container with the control root never mounted — denial by construction, probe-verified — and unlocks fully unattended L5/autonomy-5 runs). Per-iteration human checkpoints (pause/resume) at autonomy 4.
---

# dark-factory

Runs a StrongDM-style dark-factory loop: **spec in → hidden holdout scenarios
→ isolated builder (spec-only) → verifier → deterministic ID feedback → loop →
outcome**. Design spec: `docs/superpowers/specs/2026-07-13-dark-factory-skill-design.md`
(Codex-approved). Three assurance tiers ship: **cooperative** (honor-system isolation — every run is explicitly UNQUALIFIED), **standard** (OS read-denial sandbox on macOS/Linux, verified by a fail-closed startup denial probe — a converged run is QUALIFIED), and **hardened** (the builder runs inside a Docker container that never has the control root mounted — denial by *construction*, not a deny-rule — still probe-verified fail-closed; see `references/hardened.md`). `hardened` is also the only tier that unlocks **L5** (`autonomy: 5`, fully unattended/lights-off — spec §2.2). `enterprise` is not yet backed and is refused.

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
     rotation; `-e` argv `ps`-visibility at `hardened`; bridge-network exfiltration is
     out of scope until the enterprise credential proxy).
4b. **Twins (optional).** If the task's code talks to external services, define behavioral mocks in `<control_root>/twins/*.json` (see `references/digital-twins.md`) and set `twins.enabled: true` in config.json. The builder develops against the twins, and the verifier resets them fresh before each verify pass for deterministic verification. Results are **twin-observed** — you must validate against the real service or staging before shipping.
   - **Twin evidence (M12, optional, recommended when a behavior depends on genuinely calling a twin).** Add a scenario `then` assertion — `twin_observed: {twin, contains}` (the twin's own observation log, not the candidate's output, must show the call) or `stdout_echoes_twin: {twin}` (the candidate's stdout must echo a token the twin served *this pass*) — and set `"supports_variants": true` on the twin def to make the served token fresh and unpredictable every verify pass. Both assertions fail closed with taxonomy `no_twin_evidence` if the candidate never really invoked the twin (e.g. a hardcoded response) — catching teaching-to-the-test that plain output-matching would miss. See `references/digital-twins.md` for the observation contract, seed semantics, and honest scope (filesystem-authority channel; network-graph enforcement and off-box sinks remain deferred).
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
Claude session running this skill. An **enforced** per-tier skill allowlist with
content-hash pinning (spec §3B) that constrains the orchestrator itself is an
`enterprise` capability (not yet built). Never author or reveal holdout scenarios
in a session that will also drive the builder.

## References

- `references/config-reference.md` — config schema
- `references/isolation.md` — the `standard` tier: OS read-denial sandbox, backends, probe discipline
- `references/hardened.md` — the `hardened` tier: container barrier (denial by construction), hardening flags, L5, TCB growth, image/credential/network honesty, deferred scope (M10)
- `references/budget.md` — budget model: admission control, 85% alert, 100% pause, raise-and-resume, honest estimate caveat (M8)
- `references/security-gates.md` — mandatory security gates on the converged artifact: built-ins, external-gate interface, fail_on/strict_unavailable, `SECURITY_GATE_FAILED` semantics, honest heuristic/floor caveat (M9)
- `references/credentials.md` — the credential broker: allowlist-only injection, scrubbed artifacts, gitignore/permission gates, launcher-scoped standard-tier env, and honest limits (no rotation, `ps`-visibility, egress) (M11)
- `references/digital-twins.md` — twin definition, lifecycle, and honest scope (M3a); observation log, evidence assertions, and verifier-only variant seeds (M12)
- `references/knowledge-base.md` — KB integration (optional, spec §3A)
- `references/scenario-format.md` — oracle IR v0
- `references/coverage-gates.md` — behaviors.json schema + the fail-closed pre-build coverage/mutation gates (M7)
- `references/role-adapters.md` — adapter protocol
