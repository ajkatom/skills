# dark-factory — skill design spec (v2, tiered)

**Date:** 2026-07-13
**Status:** Approved design → ready for implementation planning
**Repo:** personal `skills` (symlinked into `~/.claude/skills`, like `loop-designer`)
**History:** v2 consolidates the design around an **assurance dial** after adversarial
review by Codex (`gpt-5.6-sol`), rounds 1–2 (see `…-review-log.md`). It replaces the
v1 draft that appended a hardening section (§15) as an override on top of a softer
`§§1–14` — the "two incompatible architectures" Codex flagged. There is now **one tiered
architecture**, default `standard`.

## 1. Summary

`dark-factory` is a **process skill** that wraps any task/plan into a "dark factory" run
(StrongDM's Level-5 model): the human writes/approves a spec and evaluates outcomes;
**agents build and review the code behind an information barrier**. Pipeline:

> **spec → hidden holdout scenarios + digital twins → isolated builder (spec-only) →
> verifier runs scenarios in the twin universe → deterministic ID feedback → loop →
> outcome checkpoint (human evaluates twin-observed results).**

Two non-negotiable requirements (from the user):

1. **Tests are scenarios** — behavioral acceptance specs, not unit tests of internals.
2. **The builder cannot see the tests** before/while building, so it cannot overfit
   ("teach to the test"). Enforced by an isolation boundary, not an honor-system note.

Behaviour is set by **two orthogonal dials** (§2): the **autonomy dial** (how far the
human steps back, L4/L5) and the **assurance dial** (how hardened the isolation is,
`standard`/`hardened`/`enterprise`). The skill is **self-contained and transferable** —
no dependency on the user's second brain or any other skill.

### 1.1 Goals
- Turn a spec into a shipped-*candidate* via an autonomous build/verify loop the human
  supervises at outcome checkpoints.
- Make the acceptance criteria **hard to game** by hiding them from the builder and
  enforcing isolation at build *and* verification time (residual risk stated per tier).
- Test against a **digital-twin** universe; label results **twin-observed**, never
  "actual"; require a human-gated real check before "ship-ready."
- **Pluggable roles across tools/models** (Claude/Codex/Gemini) — the user's decision.
- **Compose** with other skills when available; fall back to built-in behaviour.
- **Scale assurance** from a pragmatic single-user default up to enterprise **without a
  redesign** — the higher tiers are specified and probe-gated, never a cosmetic flag.

### 1.2 Design provenance (not a runtime dependency)
Informed by the user's vault (`~/Projects/ai_projects/second_brain/`), from *"The 5
Levels of AI Coding"* (Nate B Jones; Dan Shapiro's ladder; StrongDM): `dark-factory.md`,
`vibe-coding-levels.md`, `strongdm.md`, `verification-loop.md`,
`cross-model-orchestration.md`, `ai-coding-adoption-gap.md`. Concepts are embedded in the
skill's own `references/`; the skill does **not** read the vault at runtime.

### 1.3 Non-goals
- Not a general test framework (scenarios are acceptance-level, behavioral).
- Does **not** merge or deploy (human action).
- Does **not** run unbounded/unattended loops (bounded by iteration + budget caps).
- Does **not** claim a hardening tier the environment can't substantiate — it probes and
  **fails closed** (§2.3).
- Requires **no** external knowledge system or other skill (both optional, §9/§10).

### 1.4 Threat model & trusted computing base (per tier)
The barrier is only meaningful against a stated adversary. Each assurance tier names
what it defends and what it does not.

| | **standard** | **hardened** | **enterprise** |
|---|---|---|---|
| **Setting** | single user, own machine | team / CI, shared runners | multi-tenant / compliance |
| **Adversary** | an LLM builder that **overfits/drifts or errs** (not actively malicious) | **semi-trusted** code; accidental damage | **actively malicious** builder + insider |
| **Trusted (TCB)** | host OS, the human, the supervisor, model providers | + container runtime, dependency proxy | **only** supervisor + signing key + broker; providers/registry semi-trusted |
| **Out of scope** | a builder that *deliberately* exfiltrates; host compromise | provider compromise; kernel escape | side-channels; nation-state; supply-chain of the runtime itself |

Raising the tier narrows the TCB and adds enforced mechanisms (§7). The default
`standard` is honest about its limit: it defends the **overfitting/leak** vector (the
skill's whole point) and reasonable accident containment — **not** a determined malicious
builder. That protection needs `hardened`+.

Every tier's TCB also includes the **unavoidable base** it runs on (kernel, container/OS-
sandbox runtime, filesystem, network stack) — "trust only the supervisor" means *among
dark-factory's own components*, not literally. The **human is always trusted** to read the
holdout and authorize downgrades; `enterprise` may add split-custody for that authority.

## 2. The two dials

### 2.1 Autonomy dial (from `vibe-coding-levels`)
The L5 *machinery* (agents write **and** review code) always runs; how far the human
steps back is the dial:
- **L4 — product manager (default):** human evaluates twin-observed outcomes at **every
  iteration checkpoint** and may adjust the spec mid-run.
- **L5 — lights-off:** the loop runs to convergence/cap untouched; human evaluates
  **once at the end**.
- Optional **L4→L5 ramp** as trust builds.

### 2.2 Assurance dial (new)
`assurance: standard | hardened | enterprise`. Each tier **adds** enforced mechanisms
(§7) and a narrower TCB (§1.4). `standard` is the default and ships fully in v1;
`hardened`/`enterprise` are specified and enforced when selected **and** the substrate is
present.

### 2.3 Cross-rules & fail-closed
- **L5 requires ≥ `hardened`** — and is **unavailable until a conforming hardened backend
  ships** (below).
- **A tier needs both substrate *and* a conforming implementation.** The skill keeps a
  versioned **`supported_tiers` registry** of conformance-tested backends and **rejects any
  tier without one**, regardless of whether Docker / a signing key happens to be installed.
- **Probes run where and when they matter:** substrate probes at startup; **environment-
  specific denial probes after each role/candidate environment is assembled; and a re-probe
  at every phase boundary** (policy can drift mid-run). Probe policy hashes are pinned.
- **Fail closed.** A missing substrate/backend aborts, or — with explicit consent —
  **downgrades as a new configuration transaction** that revalidates the autonomy dial
  (e.g. L5→standard is invalid), the notification sink, threat assumptions, and any run
  state already created. A tier is never a cosmetic label.

## 3. The pipeline and the information barrier

Three planes; the design turns on **what each can see**.

### 3.1 Visibility matrix (the core invariant)

| Artifact | Planner | Test authority | Builder | Verifier | Human |
|---|:--:|:--:|:--:|:--:|:--:|
| **Spec** | writes | reads | reads | reads | owns/approves |
| **Contracts + dev stubs** | | writes | reads (builds against) | reads | |
| **Scenarios + verifier-only twin variants (holdout)** | | writes | **✗ HIDDEN** | reads (runs) | reads |
| **Twin-observed outcomes** | | | **✗ ID feedback only** | writes | reads |

The ML analogy done properly: the **contracts/dev-stubs are shared** so the builder can
develop; the **test set + verifier-only twin variants are held out** (§5.1) so it can't
overfit. The invariant holds only if the builder never receives the holdout **in context
or on its filesystem**, *and* the candidate is executed under isolation at **verification**
time so its code can't read the holdout either (§7.4).

## 4. Roles (pluggable) and separation

Four agent roles + the human. Each maps to a tool the user chooses via a thin **adapter**
(§7.8). Every role runs as a **separate process** (not an in-process subagent).

| Role | Responsibility | Default | Constraint |
|---|---|---|---|
| **Planner** | interviews the human, drafts the spec (Karpathy: uncover goal, agile, precise) | Claude | — |
| **Test authority** | owns the hidden acceptance world: **scenarios + twins** (incl. verifier-only variants) | Claude | **≠ Builder** — separate context per tier (process→sandbox→principal, §7.2), not a name-compare |
| **Builder** | implements from the **spec + contracts/dev-stubs only**, in the sandbox | Claude (separate process) | never receives holdout |
| **Verifier** | runs scenarios against the candidate in a fresh twin universe; writes twin-observed outcomes | Claude | separate execution context from the candidate (§7.4) |

**Pre-holdout freeze (guards a subtle leak):** the shared **public contracts + dev-stubs are
authored and frozen read-only in a session *before* the holdout exists**; scenario/twin
authoring happens after. Any later change to a public artifact **regenerates the holdout** —
otherwise an erring test-authority model could copy scenario literals into files the builder
is allowed to read, and filesystem probes would still pass.

**Cross-model defaults** (from `cross-model-orchestration`): strongest reasoner plans;
different-vendor test authority for blind-spot diversity; token-efficient model builds.
The user's "Claude plans, Codex builds, Gemini tests" is a config edit. **No silent
fallback** — a substitution needs explicit approval (§7.8).

## 5. Two verification pillars

### 5.1 Holdout scenarios (the *what*)
- **Format & oracle:** authored as behavioral `Given/When/Then` (the human view) that
  **compile to a deterministic, executable check contract** with a **versioned oracle IR +
  runner-conformance contract** (so generated-check and a future enterprise DSL are
  interchangeable backends — the "no redesign" promise). Checks are **frozen and hashed
  before building** and **mutation-validated** (known-bad mutants must fail; reference
  implementations optional, harness self-tests + injected faults required) so traceability
  can't approve inert tests.
- **Coverage gate (before any build):** every spec behavior maps to **≥1 dev family and
  ≥1 final family** (stratified — not a single shared case); critic-reviewed (a different
  model or the human).
- **Two-tier holdout:** **dev scenarios** drive feedback; a **sealed final-exam set**
  runs **once** at the end and is never fed back. **Generators, distributions, variants,
  and cohort membership are frozen+hashed before building;** only the final **secret
  seeds** are drawn by the supervisor *after* the artifact is hashed and **stored raw in the
  restricted immutable control snapshot** (only their hashes reach exported audit, so an
  identical-artifact infra-retry or resume is reproducible without leaking them). Dev seeds
  stay **stable across iterations** (so green→red is a real regression, not input variance).
- **Storage:** control plane only, outside the build workspace, never mounted to it.

### 5.2 Digital twins (the *where*)
- **What:** behavioral clones of the external services the software touches — a safe,
  reproducible, prod-free world. Scaled to the task (full clones ↔ a minimal deterministic
  harness), but always present.
- **Split visibility:** the builder gets **contracts + developer stubs**; the verifier
  reserves **hidden variants/fixtures** (frozen+hashed *before* build, per §5.1) plus the
  final **secret seeds** drawn only *after* the artifact hash commits.
- **Network authority (§7.4):** the candidate reaches only **twin data-plane** endpoints;
  **observer/control/reset** endpoints are verifier-only; evidence lands in an append-only
  channel the candidate can't address.
- **Fidelity, not faith:** results are **twin-observed outcomes** with a per-service
  **fidelity score + drift evidence + unsupported-behavior inventory**. Indistinguishability
  from prod is *not* claimed (endpoints/timing/certs differ) — instead there are
  **detection-resistance tests** and stated residual risk. **Nothing is "ship-ready"
  without a human-gated real contract/staging check.**

## 6. The build/verify loop (state machine)

**Ordering is explicit** (fixes the earlier FSM contradiction):

```
build snapshot → dev checks → mandatory gates (§7.6) → ARTIFACT FREEZE
   → final-exam once → human staging check → ship-candidate
```

- Each iteration runs **dev** scenarios only. A **regression** (green→red on stable dev
  seeds) blocks a candidate.
- Mandatory gates run **before freeze**; any **post-freeze failure is terminal** and
  requires a **new sealed generation** (you cannot legitimately rerun a sealed exam after
  changing code).
- **Failed final-exam is terminal** for that artifact; disclosed finals promote to dev and
  a fresh sealed set is generated.
- **Infra-error state:** a twin startup race, lost observer event, or runner failure is a
  **distinct outcome** (not pass/fail). It permits **bounded retries of the identical
  artifact+env+seed**; inconsistent results **invalidate the run** rather than fail the
  candidate (so a flake can't sink a valid artifact, and "runs once" stays truthful).
- **Termination:** full pass, iteration cap (default 5), or budget cap (§6.2). A persistent
  failure at the cap surfaces as **"likely spec ambiguity — human decision"** (may delegate
  to `systematic-debugging`), not a bare "failed."
- **Checkpoints:** per the autonomy dial; the human sees twin-observed outcomes and chooses
  **accept · adjust spec · continue · abort**. An outcome-derived spec edit **taints** the
  run — restart with a new scenario generation, fresh sealed set, and reset status history.

### 6.1 Feedback (anti-gaming)
- **`ids` (default):** a **schema-validated, deterministic mapping** from frozen scenario
  metadata to a **behavior-ID + a fixed error-taxonomy enum**. No LLM in the default
  channel (a model summariser is itself a leak/injection surface).
- **`behavioral` / `full`:** richer, model-mediated declassification — **opt-in only**, and
  using them **taints** the touched scenarios (moved to dev, sealed set rotated). `full`
  is debugging-only.

### 6.2 Budget, alerts, resuming
- **Admission, not just accounting:** **reserve worst-case cost before each call**; a call
  that could cross the cap is **rejected at the phase boundary**. For non-authoritative
  providers, state the **exact single-call overage bound**; per-role/per-adapter budgets.
- **`billing: api`** (metered): **85% alert**; pause at the **next atomic phase boundary**
  after the cap; offer **raise-and-resume from the last committed snapshot**, accept, or
  abort. **`billing: subscription`:** alert-only.
- **L5 requires a tested notification sink** before enabling (an unattended alert with no
  delivery channel is useless).
- **Crash-safety:** persist an `in-flight/unknown-outcome` state **before** dispatch;
  **never auto-retry** it without provider idempotency/reconciliation or human
  authorization (else a crash after a provider accepts a call risks a duplicate charge).

## 7. Isolation & assurance mechanisms (tier-tagged)

Each mechanism lists the **minimum tier** at which it is enforced. `standard` is the honest
baseline; `hardened`/`enterprise` add to it. All tiers are **probe-verified** (§2.3).

### 7.1 Source & workspace  *(standard)*
Builder works from an **explicitly-approved, history-free source snapshot** (approved
dirty/untracked changes included), **hashed**, in a fresh repo **without remotes** — not a
`git worktree` (a worktree's `.git` links into the parent repo and leaks history/objects).
The snapshot is built from an **`lstat`-based manifest that rejects special files
(devices/sockets) and escaping sym/hardlinks and never dereferences outside the approved
root**; the canonical exported content is what gets hashed.

### 7.2 Sandbox & principals
- *(standard)* Builder = **separate OS process under a dedicated UID or an OS read-denial
  primitive** (`sandbox-exec` on macOS, `bwrap`/`unshare` on Linux) so the scenario store is
  genuinely unreachable and the denial probe is *meaningful*; fresh ephemeral
  `HOME`/config/session, hooks/plugins/MCPs/skill-auto-discovery **off**; only allowlisted
  skills copied in may run. If no read-denial primitive exists, the isolation claim
  **downgrades to best-effort (not probe-proven)** and says so.
- *(hardened)* Enforced **container/VM** with a **per-role capability profile** (rootless,
  dropped caps, no docker socket / host PID, read-only rootfs, no stray device
  nodes/sockets); egress **default-deny**.
- *(enterprise)* **Per-role immutable capability/mount/network manifests** + seccomp; a
  single global profile is insufficient — builder, verifier, and test-authority get
  distinct manifests. **Role separation is enforced by distinct principals**; a
  holdout-bearing session is never reused as builder, even same-vendor.
- **Denial tests** (all tiers, scaled): probe mounts, namespaces, sockets, devices, caps,
  env, process visibility, egress, and read/write ownership; **fail closed**.

### 7.3 Secrets
- *(standard)* `.gitignore` **plus** `git check-ignore` + `git ls-files` verification;
  provider credentials are **launcher-scoped and excluded from the builder's env allowlist**
  (an erring LLM can `env`/echo a token — prevent, not just detect); log redaction;
  secret-scan before/after each phase. Honest limit: does **not** stop a determined malicious
  builder.
- *(hardened)* **Brokered short-lived, role-scoped credentials**; raw tokens scrubbed from
  role env; a **read-only pinned dependency proxy/cache** (no direct registry/DNS).
- *(enterprise)* **Host-side credential proxy** — raw tokens **never enter any sandbox**;
  all provider/registry access via an authenticated broker with query-level egress control.

### 7.4 Verification-time isolation & network authority
- *(standard)* Candidate executed as a **separate process** with the **scenario store
  unmounted**; evidence read from twin/observer state, not from anything the candidate
  writes; all builder-produced text treated as **untrusted data, never instructions**.
- *(hardened+)* **Authenticated network graph:** candidate → twin **data-plane only**;
  verifier alone reaches **observer/control**; evidence in an **append-only channel the
  candidate cannot address**. Vary twin inputs the candidate can't predict.

### 7.5 Audit
- *(standard)* **Local hashed manifest** per run: artifact hashes, role/model/adapter
  versions, sandbox policy + **denial-probe results**, commands, exit codes, costs,
  timestamps; seeds/prompts **redacted or referenced by hash**, never inlined raw (holdout
  leakage).
- *(hardened)* **Signed, chained** append-only records (supervisor-only key); restricted
  evidence separated from a redacted export, with a `verify` command.
- *(enterprise)* **Off-box append-only / remote sink** as the tamper-evidence anchor
  (a local process that can rewrite the manifest can also recompute an unsigned chain).

### 7.6 Mandatory security gates  *(standard+, non-negotiable)*
Because no human reviews the code, these run **independent of scenario pass-rate** and are
**schema constants, not user-toggled booleans**: **static review, dependency
provenance/SBOM, secret scanning, license policy, negative security invariants, resource
limits** — with **pinned tool/policy hashes and deterministic pass criteria**. An isolated
LLM static reviewer (which reads hostile source and is injection-prone) counts as
**additional evidence, never the sole blocking oracle**.

### 7.7 State machine, concurrency, crash-safety  *(standard)*
A single **deterministic `supervisor` executable** owns this — the **sole state-changing
entry point** (`SKILL.md` is only its conversational front end). It runs a **locked,
journaled FSM** with **immutable per-run snapshots**, atomic writes, an **invocation ID**,
process-group cancellation, and content **hashes for spec, artifact, scenarios, twins,
adapter, and phase** — so concurrent invocations/crashes can't verify a moving tree,
overwrite a generation, redispatch a call, or resume mismatched artifacts. Control state
lives **outside Git**. A crash after a provider accepted a call is journaled
**`unknown-outcome`**: the supervisor **prevents automatic re-dispatch** but cannot prove the
provider didn't charge — leaving that state needs reconciliation or explicit human
authorization.

### 7.8 Adapter protocol  *(standard)*
A **versioned JSON adapter protocol**: capability probes, **pinned model/CLI versions**,
and defined timeout/cancel/usage/report semantics. **No silent fallback** — a substitution
(e.g. Codex→Claude) needs explicit user approval (it changes role separation + billing).

### 7.9 Honest residual risk
Every tier ships a plain statement of what it does **not** defend (per §1.4). Claims are
**probe-backed** (a passing denial-probe set), never asserted. Words like "un-gameable" and
"actual outcomes" are avoided by design.

## 8. Greenfield vs. brownfield
The skill **detects** which it is and never treats legacy as greenfield. Brownfield runs the
**incremental path** first (reverse-engineer a spec + holdout suite + twins from the running
system) and states the reduced guarantees. Note: mutation validation (§5.1) doesn't assume a
known-good reference — reference implementations are **optional**, harness self-tests +
injected faults are required.

## 9. Optional knowledge-base integration
Self-contained by default. At invocation the skill asks whether the user has a **wiki**
(path) or **open-brain/MCP** DB; if present it *reads* for grounding and, **opt-in only**,
*writes* a run summary back. Absence is never an error.

## 10. Skill composition (orchestrate, don't reinvent)
At each step the skill **prefers an available specialized skill** (`brainstorming`/`grill-me`
for the spec; `codex-build` for a Codex builder; `/verify`, `e2e`, `security-review` for
checks; `systematic-debugging` for a stuck loop), else built-in behaviour. **Rules:**
(1) a skill invoked in the build plane inherits its **restricted context** — copied into the
sandbox, holdout unreachable; (2) a delegated **gated action** (commit/push/deploy) still
pauses for the human; (3) no self-recursion. **Only skills on a per-tier allowlist** — frozen content hash,
declared capabilities, role eligibility, conformance-reviewed — may be copied into a run;
auto-preferring an arbitrary installed skill is not allowed. Records which skills ran (audit).

## 11. Packaging & layout

**Hybrid** (chosen): a single **deterministic `supervisor` executable** is the sole
state-changing entry point (owns the FSM, locks, budget admission, journaling, freeze rules,
cancellation); `SKILL.md` is its **conversational front end** (judgment steps in prose); the
**helper scripts** it invokes own the deterministic, security-critical steps — sandbox/probes,
snapshot+hash, the deterministic ID-feedback projection, the scenario runner, adapters, and
the audit writer.

```
dark-factory/
  SKILL.md
  references/  threat-model.md · assurance-tiers.md · scenario-oracle.md · digital-twins.md
               role-adapters.md · isolation.md · secrets.md · audit.md · brownfield.md
               knowledge-base.md · config-reference.md · example-run.md
  scripts/     supervisor (sole state-changer), sandbox-*, probe-denial.*, snapshot-source.*,
               id-feedback.*, run-scenarios.*, audit-write.*, adapters/{claude,codex,gemini}
```

Control plane (outside Git, outside the build workspace): `config.yml`, `spec.md`,
`contracts/`, `twins/` (+ verifier-only `twins-sealed/`), `scenarios/` (dev + sealed),
per-run immutable `runs/<invocation-id>/` snapshots + manifest.

### 11.1 Config schema (sketch)
```yaml
autonomy: 4                    # 4 = checkpoint each iteration; 5 = lights-off (requires assurance ≥ hardened)
assurance: standard            # standard | hardened | enterprise (probe-verified, fail-closed)
feedback: ids                  # ids (default, deterministic) | behavioral | full  (latter two taint)
max_iterations: 5
final_exam_fraction: 0.3       # ≥1 dev family AND ≥1 final family per behavior (stratified)
# pass is unconditional 100% of dev + final + no-regression (not configurable)
budget:
  billing: api                 # api (metered → admission-controlled) | subscription (alert only)
  per_role_usd: { planner: 2, test_authority: 3, builder: 15, verifier: 3, delegated: 2 }
  total_usd: 25                # hard total cap across all roles + delegated ops
  max_calls_per_invocation: 40 # adapters enforce a hard call/token ceiling (bounds overage)
  alert_at: 0.85
  notification_sink: ""        # required before L5
roles:
  planner:        { tool: claude }
  test_authority: { tool: claude }     # ≠ builder (enforced by principal, §7.2)
  builder:        { tool: claude }     # separate process; e.g. { tool: codex }
  verifier:       { tool: claude }     # e.g. { tool: gemini }
prefer_skills: true
knowledge_base:  { kind: none, path: "", write_back: false }
# security gates are schema constants (§7.6), not toggled here; config may only pin tool/policy versions
```

## 12. Workflow (one todo per step)
1. **Engage.** Announce + opt-out. Ask: wiki/open-brain? `billing` mode? **`assurance`
   tier?** Detect greenfield/brownfield; infer twin services.
2. **Probe.** Run the tier's denial probes; **fail closed** or downgrade-with-consent (§2.3).
3. **Spec (Planner).** Interview → `spec.md`; human approves.
4. **Config.** Write/confirm `config.yml` (enforce L5 ⇒ assurance ≥ hardened, and a
   notification sink).
5. **Acceptance world (Test authority).** Author **contracts + dev-stubs** (shared) and
   **scenarios + twin variants** (holdout, dev+final families); compile the executable
   oracle; **freeze + hash** generators/cohorts. Run the **coverage gate**.
6. **Isolate.** Snapshot+hash source into the sandboxed workspace (no holdout).
7. **Loop (§6):** build → dev checks → mandatory gates → freeze → final once → human
   staging; deterministic ID feedback; budget admission; checkpoints per autonomy dial.
8. **Outcome checkpoint / hand-off.** Present twin-observed outcomes + fidelity + audit;
   human evaluates. **`ship-candidate` is reserved for the successful FSM terminal state**
   (dev + gates + freeze + final + staging all passed); a human `accept` before that is
   recorded as **waived/unverified** in hand-off and audit, never qualified. Handed back
   (human merges).
9. **Record.** Write the per-run audit manifest; opt-in KB capture.

## 13. Guardrails
- **Two non-negotiables:** scenarios are behavioral; builder never receives the holdout
  (context *or* filesystem) — enforced by isolation, probe-verified.
- **Tiered, fail-closed:** never claim an assurance tier the environment can't substantiate;
  L5 ⇒ ≥ hardened.
- **Adversarial verifier:** pass/fail from observed twin state only; builder text is
  untrusted; candidate runs in a **separate execution context** (per tier, §7.2/§7.4) with
  the holdout unreachable.
- **`ship-candidate` = FSM terminal only** — a human override before dev+gates+freeze+final+
  staging is logged as waived/unverified, never qualified.
- **Deterministic default feedback** (`ids`); richer channels taint.
- **Mandatory gates + audit** every run, independent of pass-rate; gates are constants.
- **Secrets scale by tier** (§7.3); raw tokens leave the sandbox only at `standard`, and
  even there `.gitignore` is verified, not trusted.
- **No silent fallback; no self-recursion; no auto-retry on unknown-outcome calls.**
- **Twin-observed, not "actual";** no "ship-ready" without a human-gated real check.
- **Brownfield honesty;** **stated residual risk** per tier.

## 14. Success criteria
- Builder demonstrably never receives the holdout — verified by **denial probes** at the
  selected tier (scenario store unreachable from builder *and* from the executing candidate),
  not by a copy-check; at `standard` this requires the OS read-denial primitive (§7.2), else
  the claim is explicitly best-effort.
- Selecting a higher `assurance` tier **enforces** its mechanisms or **fails closed**;
  downgrade requires explicit consent + an audit note. A tier without a conforming backend in
  `supported_tiers` is rejected even with the substrate present; **L5 is unavailable until a
  hardened backend ships**.
- Default feedback is a **deterministic ID/taxonomy projection** (no model call); richer
  channels taint and rotate the sealed set.
- The oracle is **frozen pre-build and mutation-validated**; the final set runs **once**;
  the FSM enforces the build→gates→freeze→final→staging order; infra-errors don't fail valid
  artifacts.
- Runs **standalone** (no KB, no other skills); cross-model + skill delegation work when
  present, and a build-plane delegation never receives the holdout.
- Every run emits an audit manifest with denial-probe results; at `hardened`+ it is signed;
  at `enterprise` it is off-box.

## 15. Phasing — what v1 ships
- **v1:** the full **`standard` tier** enforced end-to-end **+ the tier framework, probes,
  and fail-closed downgrade** + the deterministic oracle/feedback + FSM + audit + mandatory
  gates + the user's cross-model / skill-composition / KB features.
- **`hardened` / `enterprise`:** specified here and **enforced when selected and both the
  substrate and a conforming backend (`supported_tiers`) are present**; until a hardened
  backend ships, **L5 is unavailable**. Their heavier mechanisms (host-side credential proxy,
  per-role seccomp manifests, signed/off-box audit, network-authority graph, oracle DSL) land
  as the backends are built. Raising the tier later is **config + substrate + backend**, not
  a redesign.

## 16. Open items to resolve during planning
- Concrete sandbox backends per platform (macOS vs Linux container runtimes) and the exact
  per-role capability manifests for `hardened`/`enterprise`.
- The executable-oracle representation (capability-limited DSL vs generated checks) and its
  fault catalog + mutation-score threshold.
- Adapter protocol schema (I/O, timeout/cancel/usage) shared by claude/codex/gemini.
- Credential-broker/proxy choice for `hardened`/`enterprise`.
- Whether the worked example ships greenfield-only or also brownfield.
- **(From Codex R3, for the plan):** the versioned oracle IR + runner-conformance schema; the
  `lstat` snapshot manifest rules; the per-tier **skill allowlist** format (content hash +
  capabilities + role eligibility); exact per-role/adapter budget ceilings + delegated-op
  attribution; the restricted raw-seed store layout; the transactional-downgrade revalidation
  set; and the `standard` OS read-denial primitive per platform.
