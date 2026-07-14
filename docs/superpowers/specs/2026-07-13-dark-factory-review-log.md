# Plan Review Log: dark-factory skill design

Started 2026-07-13 (session). MAX_ROUNDS=5.
Critic: Codex / `gpt-5.6-sol-ultra` (read-only, reasoning effort xhigh).
Plan under review: `docs/superpowers/specs/2026-07-13-dark-factory-skill-design.md`

## Round 1 — Codex (gpt-5.6-sol, read-only)

Thread: 019f5dfc-3f9c-71a0-b21c-92f0f29babdc

The core concept is viable, but the current spec does not support its strongest claims: “real information barrier,” “un-gameable,” “exact resume,” and “ship-candidate” are materially overstated.

1. **P0 — A worktree is not an information barrier.** `cwd`, `.gitignore`, and “operate only within your workspace” do not prevent filesystem traversal; a worktree’s `.git` also points into the parent repository. The proposed success check proves only that scenarios were not copied, not that they were never accessed. [§2.1](/Users/alonadelson/Projects/ai_projects/skills/docs/superpowers/specs/2026-07-13-dark-factory-skill-design.md:98), [§8](/Users/alonadelson/Projects/ai_projects/skills/docs/superpowers/specs/2026-07-13-dark-factory-skill-design.md:323), [success criterion](/Users/alonadelson/Projects/ai_projects/skills/docs/superpowers/specs/2026-07-13-dark-factory-skill-design.md:496)

   **Fix:** Require an externally enforced sandbox containing a standalone clone with only approved mounts, and fail closed or disable L5 when filesystem-denial probes fail.

2. **P0 — The candidate can steal the holdout at verification time.** Even if the builder never saw scenarios, its untrusted code is later executed by the holdout-bearing verifier and can scan files/environment, alter twins, exploit admin endpoints, or forge evidence. The “treat output as untrusted” instruction does not address this. [loop](/Users/alonadelson/Projects/ai_projects/skills/docs/superpowers/specs/2026-07-13-dark-factory-skill-design.md:253), [adversarial verifier](/Users/alonadelson/Projects/ai_projects/skills/docs/superpowers/specs/2026-07-13-dark-factory-skill-design.md:348)

   **Fix:** Run the DUT, verifier, twins, and scenario store as separate principals/containers, exposing only production-shaped network interfaces to the DUT and never mounting scenarios or report destinations into it.

3. **P0 — Shared agent state and delegated skills puncture the barrier.** Same-machine CLIs can expose session transcripts, caches, auto-loaded rules, hooks, MCPs, credentials, and global skills under a shared home; an arbitrary delegated skill does not magically “inherit” a security plane. [composition claim](/Users/alonadelson/Projects/ai_projects/skills/docs/superpowers/specs/2026-07-13-dark-factory-skill-design.md:163), [delegation rule](/Users/alonadelson/Projects/ai_projects/skills/docs/superpowers/specs/2026-07-13-dark-factory-skill-design.md:180)

   **Fix:** Give every role a fresh ephemeral HOME/config/session, disable hooks/plugins/MCPs/auto-discovery, and allow only audited skills copied into and executed inside the same sandbox.

4. **P0 — The final-exam state machine is contradictory.** Step 2 says every iteration runs “all scenarios,” while step 3 says final scenarios run once only after dev passes; no behavior is defined for a failed final exam that may neither be fed back nor rerun. [final split](/Users/alonadelson/Projects/ai_projects/skills/docs/superpowers/specs/2026-07-13-dark-factory-skill-design.md:212), [loop ordering](/Users/alonadelson/Projects/ai_projects/skills/docs/superpowers/specs/2026-07-13-dark-factory-skill-design.md:253)

   **Fix:** Make final failure terminal for that artifact, promote disclosed failures into the next run’s dev set, generate a fresh sealed set, and require the runner to reject final-cohort execution before artifact freeze.

5. **P0 — Behavioral feedback is cumulative holdout disclosure.** A semantic description of the failed behavior is effectively an assertion-level oracle; repeated reports and regression counts let the builder probe it. Literal-string stripping plus an LLM cannot reliably prevent semantic leakage or prompt injection. [feedback policy](/Users/alonadelson/Projects/ai_projects/skills/docs/superpowers/specs/2026-07-13-dark-factory-skill-design.md:275)

   **Fix:** Emit only pre-approved spec behavior IDs and a fixed error taxonomy; any richer declassification must taint those scenarios, move them to dev, and rotate the sealed set.

6. **P0 — The final holdout is correlated and twin-aware, not “un-gameable.”** The same authority authors scenarios and the exact twins the builder can inspect, so both sets share blind spots and mock quirks; a percentage split does not create independent evidence. [role ownership](/Users/alonadelson/Projects/ai_projects/skills/docs/superpowers/specs/2026-07-13-dark-factory-skill-design.md:118), [shared twins](/Users/alonadelson/Projects/ai_projects/skills/docs/superpowers/specs/2026-07-13-dark-factory-skill-design.md:218)

   **Fix:** Share only contracts and developer stubs, while reserving verifier-only twin variants, fixtures, property generators, and secret seeds selected after the candidate artifact is frozen.

7. **P0 — The verification oracle is not designed yet.** Markdown Given/When/Then text is not executable, and the scenario interpreter versus generated-check decision remains open despite being the heart of correctness and isolation. Traceability alone can approve tautological or inert tests. [open items](/Users/alonadelson/Projects/ai_projects/skills/docs/superpowers/specs/2026-07-13-dark-factory-skill-design.md:518)

   **Fix:** Define a deterministic executable scenario contract before implementation, freeze checks before building, and validate them against known-good references plus known-bad mutants.

8. **P0 — Passing twins says too little about production.** There is no contract calibration, drift monitoring, unsupported-behavior inventory, failure-injection fidelity, or staging/provider-sandbox check; code can also identify the twin environment and behave differently. Calling these “actual outcomes” invites false confidence. [twins](/Users/alonadelson/Projects/ai_projects/skills/docs/superpowers/specs/2026-07-13-dark-factory-skill-design.md:218), [twins-only guardrail](/Users/alonadelson/Projects/ai_projects/skills/docs/superpowers/specs/2026-07-13-dark-factory-skill-design.md:467)

   **Fix:** Report “twin-observed outcomes,” attach a per-service fidelity score and drift evidence, and require a human-gated real contract/staging check before anything is called ship-ready.

9. **P0 — `.gitignore` is not a secrets guarantee.** It does not protect already tracked/staged files, subprocess environment, CLI histories, transcripts, logs, nested repositories, or secrets printed by generated code; giving adapters ambient API keys also gives an autonomous shell an exfiltration target. [secrets guardrail](/Users/alonadelson/Projects/ai_projects/skills/docs/superpowers/specs/2026-07-13-dark-factory-skill-design.md:470)

   **Fix:** Store control state outside Git, scrub role environments, broker short-lived role-scoped credentials, verify index/staging with `git check-ignore` and `git ls-files`, redact logs, and run secret scans before and after every phase.

10. **P0 — Budget enforcement cannot work as stated.** Usage is often known only after a model call, so one invocation can cross 100%; mixed adapters may use API, subscription, cached tokens, or unknown pricing simultaneously, and a mid-call stop cannot preserve a coherent “exact point.” [budget](/Users/alonadelson/Projects/ai_projects/skills/docs/superpowers/specs/2026-07-13-dark-factory-skill-design.md:293)

   **Fix:** Track billing per adapter, require authoritative usage or downgrade the guarantee, reserve worst-case cost before each call, pause only at atomic phase boundaries, and state the maximum possible overshoot.

11. **P0 — Resume and concurrency state are insufficient.** Spec, scenarios, twins, and config are mutable project-global files while only reports/status are run-scoped; crashes or concurrent invocations can verify a moving tree, overwrite a scenario generation, double-charge a call, or resume with mismatched artifacts. [control layout](/Users/alonadelson/Projects/ai_projects/skills/docs/superpowers/specs/2026-07-13-dark-factory-skill-design.md:395), [resume claim](/Users/alonadelson/Projects/ai_projects/skills/docs/superpowers/specs/2026-07-13-dark-factory-skill-design.md:305)

   **Fix:** Use a locked, journaled finite-state machine with immutable per-run snapshots, atomic writes, invocation IDs, process-group cancellation, and hashes for spec, code artifact, scenarios, twins, adapter, and phase.

12. **P0 — Cross-model behavior is undefined and fallback is unsafe.** The adapter contract is still open, yet the plan promises portable execution, cancellation, usage accounting, isolation, and structured reports; silently falling back to Claude can violate role separation and billing assumptions. The installed Codex CLI also does not document `--yolo` as a sandbox—the spec’s reliance on it is unsafe. [adapter promise](/Users/alonadelson/Projects/ai_projects/skills/docs/superpowers/specs/2026-07-13-dark-factory-skill-design.md:112), [fallback](/Users/alonadelson/Projects/ai_projects/skills/docs/superpowers/specs/2026-07-13-dark-factory-skill-design.md:137), [isolation claim](/Users/alonadelson/Projects/ai_projects/skills/docs/superpowers/specs/2026-07-13-dark-factory-skill-design.md:328)

   **Fix:** Specify a versioned JSON adapter protocol with capability probes, pinned model/CLI versions, timeout/cancel/usage semantics, and explicit user approval for substitutions; never treat `--yolo` as isolation.

13. **P1 — “Builder ≠ test authority” is not enforceable from this config.** The defaults assign both to Claude, while the workflow compares tool names and merely warns; vendor diversity is useful for blind spots but is neither identity separation nor a security boundary. [defaults](/Users/alonadelson/Projects/ai_projects/skills/docs/superpowers/specs/2026-07-13-dark-factory-skill-design.md:125), [config](/Users/alonadelson/Projects/ai_projects/skills/docs/superpowers/specs/2026-07-13-dark-factory-skill-design.md:424)

   **Fix:** Enforce distinct ephemeral role sessions/principals and transcript stores, allow the same vendor only under that isolation, and reject reuse of any holdout-bearing session as builder.

14. **P1 — Auditability is deferred even though it is required to substantiate the product.** A mutable local report cannot demonstrate which code, scenario set, twin, prompt, model, seed, or skill produced a result—or that the builder was denied access. [future audit schema](/Users/alonadelson/Projects/ai_projects/skills/docs/superpowers/specs/2026-07-13-dark-factory-skill-design.md:527)

   **Fix:** Move an append-only, tamper-evident audit manifest into v1, including artifact hashes, role/session IDs, model and adapter versions, prompts, seeds, sandbox policy and denial probes, commands, exit codes, costs, timestamps, and redactions.

15. **P1 — Outcome-only verification can approve malicious or unsafe code.** With no human code review and security, performance, accessibility, and supply-chain gates deferred, a candidate can satisfy positive twin scenarios while containing dormant exfiltration, unsafe dependencies, or production-only behavior. [non-functional deferral](/Users/alonadelson/Projects/ai_projects/skills/docs/superpowers/specs/2026-07-13-dark-factory-skill-design.md:531)

   **Fix:** Make agent static review, dependency provenance/SBOM, secret scanning, license policy, negative security invariants, and resource limits mandatory v1 gates independent of scenario pass rate.

16. **P1 — L4 checkpoints can leak the holdout through the human and spec.** The human sees detailed outcomes, can edit the spec, and the same orchestrator then dispatches another builder; merely regenerating scenarios does not remove leaked knowledge or make previous statuses comparable. [checkpoints](/Users/alonadelson/Projects/ai_projects/skills/docs/superpowers/specs/2026-07-13-dark-factory-skill-design.md:232), [resynchronization](/Users/alonadelson/Projects/ai_projects/skills/docs/superpowers/specs/2026-07-13-dark-factory-skill-design.md:245)

   **Fix:** Route all builder input through a deterministic broker, mark outcome-derived spec edits as tainting the run, and restart with a new scenario generation, status history, and sealed exam.

17. **P1 — Split and pass semantics have unsafe edge cases.** `final_exam_fraction: 0.3` can yield zero or unrepresentative final cases for small suites, while configurable `pass_threshold < 1` conflicts with “must pass both” and “no regression shipped.” [config](/Users/alonadelson/Projects/ai_projects/skills/docs/superpowers/specs/2026-07-13-dark-factory-skill-design.md:410)

   **Fix:** Require minimum stratified dev/final coverage per behavior and remove configurable partial passing from v1—final and regression gates should be unconditionally 100%.

18. **P1 — The proposed v1 is broader and weaker than necessary.** A prose-led skill combining arbitrary skill delegation, three CLIs, two billing modes, KB integration, generic Markdown scenarios, and universal twins creates a combinatorial security surface before the core runner and adapter contracts exist. [hybrid choice](/Users/alonadelson/Projects/ai_projects/skills/docs/superpowers/specs/2026-07-13-dark-factory-skill-design.md:358)

   **Fix:** Build v1 as a deterministic supervisor with one hardened adapter, executable black-box checks, one external sandbox profile, count/spec-ID feedback, and no arbitrary delegation or KB integration; add providers and twin types only after adversarial isolation tests pass.

VERDICT: REVISE
### Claude's response (Round 1)

Accepted nearly all of it — a strong review. Folded into a new **§15 Threat model &
hardening** plus inline fixes:

- **P0-1/3/12, P1-13 → §15.1** sandbox-enforced isolation: standalone clone (not a
  worktree — its `.git` links to the parent), ephemeral HOME per role, hooks/MCPs/plugins
  disabled, fail-closed denial probes, principal-enforced role separation. Removed every
  "`--yolo` = sandbox" claim (it is `danger-full-access`).
- **P0-2 → §15.2** verification-time isolation: candidate/verifier/twins/scenario-store as
  separate principals; scenario store unmounted from the executing candidate.
- **P0-5/6, P1-16/17 → §15.3** default feedback now **spec-behavior IDs + error taxonomy**;
  builder gets only contracts + dev stubs; verifier-only twin variants/seeds chosen
  post-freeze; taint semantics; removed configurable partial passing; stratified minimums.
- **P0-4/7 → §15.4** executable, mutation-validated oracle contract; **fixed the final-exam
  FSM contradiction** (dev each iteration, final once, failed-final terminal).
- **P0-8 → §15.5** "twin-observed outcomes" + fidelity/drift + human-gated real check.
- **P0-9 → §15.6** brokered short-lived role-scoped creds, control state outside Git,
  secret scans, log redaction (`.gitignore` alone is insufficient).
- **P0-10 → §15.7** phase-boundary budget, worst-case reservation, stated overshoot.
- **P0-11 → §15.8** locked journaled FSM, immutable per-run snapshots, artifact hashes.
- **P0-12 → §15.9** versioned adapter protocol, pinned versions, no silent fallback.
- **P1-14/15 → §15.10** mandatory v1 security gates + tamper-evident audit (promoted from
  "future"). Also softened overstated wording throughout (un-gameable → hard-to-game).

**Not auto-applied:** P1-18 (re-scope v1 to a single-adapter hardened core, deferring
cross-model / skill-composition / KB to v2). Captured as a **recommended phasing in
§15.11** but flagged for the human's sign-off — the user explicitly wants those features,
so they are *sequenced*, not cut.

## Round 2 — Codex (gpt-5.6-sol, read-only, resumed)

The revision closes most conceptual holes, but it is still not implementation-ready. The main problem is that §15 was appended as an override while the earlier normative workflow still specifies the insecure design.

1. **P0 — The document contains two incompatible architectures.** Earlier sections still require a worktree, in-repo control state, shared twins, ambient credentials, behavioral-default feedback, Claude subagents, automatic skill delegation, and silent fallback; §15 requires the opposite. Examples include the [file layout](/Users/alonadelson/Projects/ai_projects/skills/docs/superpowers/specs/2026-07-13-dark-factory-skill-design.md:394), [config](/Users/alonadelson/Projects/ai_projects/skills/docs/superpowers/specs/2026-07-13-dark-factory-skill-design.md:432), [workflow](/Users/alonadelson/Projects/ai_projects/skills/docs/superpowers/specs/2026-07-13-dark-factory-skill-design.md:470), and [success criteria](/Users/alonadelson/Projects/ai_projects/skills/docs/superpowers/specs/2026-07-13-dark-factory-skill-design.md:535).

   **Fix:** Rewrite §§1–14 to embody §15 directly and delete every superseded worktree, ambient-key, behavioral-default, silent-fallback, and in-repo-state instruction.

2. **P0 — The v1 architecture is explicitly undecided.** §15.11 says the hardened narrow v1 still “needs your sign-off,” while goals, config, workflow, and success criteria continue to require cross-model adapters, KB integration, arbitrary skills, and universal twins. [§15.11](/Users/alonadelson/Projects/ai_projects/skills/docs/superpowers/specs/2026-07-13-dark-factory-skill-design.md:679)

   **Fix:** Record the sign-off decision now and make the v1 feature set, configuration schema, success criteria, and packaging match that single decision.

3. **P0 — “Threat model” still does not identify the trusted computing base.** It never states whether the host, container runtime, supervisor, test authority, verifier, model providers, package registry, or human is trusted, compromised, or merely fallible; therefore “tamper-evident,” “unreachable,” and cross-vendor isolation have no precise attacker model. [§15 introduction](/Users/alonadelson/Projects/ai_projects/skills/docs/superpowers/specs/2026-07-13-dark-factory-skill-design.md:585)

   **Fix:** Add an explicit assets/adversaries/trust-assumptions table covering every role, host component, provider, credential broker, dependency source, and out-of-scope attack.

4. **P0 — A standalone clone remains the wrong source boundary.** It exposes Git history, objects, remote configuration, and possibly historical tests/secrets, while omitting approved dirty or untracked user changes; the old default still launches a Claude “subagent,” which is not a separate OS principal. [builder default](/Users/alonadelson/Projects/ai_projects/skills/docs/superpowers/specs/2026-07-13-dark-factory-skill-design.md:121), [standalone clone](/Users/alonadelson/Projects/ai_projects/skills/docs/superpowers/specs/2026-07-13-dark-factory-skill-design.md:592)

   **Fix:** Export an explicitly approved, history-free source snapshot, hash it, initialize a fresh repository without remotes, and invoke every builder through a separate sandboxed adapter process rather than an in-process subagent.

5. **P0 — “Container” is not a sufficient sandbox specification.** There is no per-role mount/network/capability matrix, and no requirements covering rootless execution, dropped capabilities, Docker socket, host PID namespace, device nodes, Unix sockets, seccomp, read-only rootfs, or container escape surfaces; one global `sandbox.profile` cannot serve builder, verifier, and test-authority permissions. [sandbox config](/Users/alonadelson/Projects/ai_projects/skills/docs/superpowers/specs/2026-07-13-dark-factory-skill-design.md:446), [isolation rules](/Users/alonadelson/Projects/ai_projects/skills/docs/superpowers/specs/2026-07-13-dark-factory-skill-design.md:592)

   **Fix:** Define immutable per-role capability manifests and denial tests for mounts, namespaces, sockets, devices, capabilities, environment, process visibility, egress, and read/write ownership.

6. **P0 — Short-lived credentials remain stealable if the sandbox receives them.** An autonomous shell can read and exfiltrate a role-scoped token before it expires, including through permitted model or package-registry traffic; “brokered” does not say that raw credentials remain outside the sandbox. [§15.6](/Users/alonadelson/Projects/ai_projects/skills/docs/superpowers/specs/2026-07-13-dark-factory-skill-design.md:643), [registry egress](/Users/alonadelson/Projects/ai_projects/skills/docs/superpowers/specs/2026-07-13-dark-factory-skill-design.md:358)

   **Fix:** Put authentication in a host-side request proxy that never exposes raw tokens, and replace direct registry access with a read-only pinned dependency cache/proxy with direct DNS and arbitrary query egress denied.

7. **P0 — Verification isolation lacks a network authority model.** The candidate must reach twin data-plane APIs, but the spec does not separate those from twin observer/admin/reset interfaces; a hostile candidate could mutate evidence or attack the mock rather than satisfy the behavior. [§15.2](/Users/alonadelson/Projects/ai_projects/skills/docs/superpowers/specs/2026-07-13-dark-factory-skill-design.md:605)

   **Fix:** Specify an authenticated network graph where the candidate can reach only twin data-plane endpoints, the verifier alone can reach observer/control endpoints, and evidence is recorded in an append-only channel the candidate cannot address.

8. **P0 — Post-freeze selection permits adaptive grading and invalid regression comparisons.** §15.3 says twin variants, generators, and seeds are chosen after the candidate freezes, whereas §15.4 says executable checks freeze before building; if variants are chosen after seeing code, the grader can target the artifact, and if dev seeds vary per iteration, green→red may reflect input variance rather than regression. [§15.3](/Users/alonadelson/Projects/ai_projects/skills/docs/superpowers/specs/2026-07-13-dark-factory-skill-design.md:613), [§15.4](/Users/alonadelson/Projects/ai_projects/skills/docs/superpowers/specs/2026-07-13-dark-factory-skill-design.md:627)

   **Fix:** Freeze and hash generators, distributions, variants, and cohort membership before building; let the deterministic supervisor draw only final secret seeds after artifact hashing, while keeping dev seeds stable across iterations.

9. **P1 — The coverage rules contradict each other.** The original gate requires only one scenario per behavior, but stratified dev and final coverage per behavior necessarily requires at least two independent cases or families per behavior. [coverage gate](/Users/alonadelson/Projects/ai_projects/skills/docs/superpowers/specs/2026-07-13-dark-factory-skill-design.md:203), [split minimums](/Users/alonadelson/Projects/ai_projects/skills/docs/superpowers/specs/2026-07-13-dark-factory-skill-design.md:623)

   **Fix:** Require at least one independent dev family and one final family per behavior, or explicitly define a risk-stratified exception that prevents unsupported “full coverage” claims.

10. **P0 — Mandatory gate ordering is missing from the final-exam FSM.** If static/security gates run after the final and demand a code change, the sealed exam cannot legitimately be rerun; the same problem occurs when the human-gated staging check fails after a final pass. [loop FSM](/Users/alonadelson/Projects/ai_projects/skills/docs/superpowers/specs/2026-07-13-dark-factory-skill-design.md:258), [mandatory gates](/Users/alonadelson/Projects/ai_projects/skills/docs/superpowers/specs/2026-07-13-dark-factory-skill-design.md:671)

   **Fix:** Define the order as build snapshot → dev checks → mandatory gates → artifact freeze → final once → human staging, with any post-freeze failure terminal and requiring a new sealed generation.

11. **P1 — A one-shot final exam has no infrastructure-error state.** Flake handling remains post-v1, so a twin startup race, lost observer event, or runner failure can permanently fail an otherwise valid artifact, while retrying informally violates the “runs once” audit claim. [future flake handling](/Users/alonadelson/Projects/ai_projects/skills/docs/superpowers/specs/2026-07-13-dark-factory-skill-design.md:572), [final FSM](/Users/alonadelson/Projects/ai_projects/skills/docs/superpowers/specs/2026-07-13-dark-factory-skill-design.md:627)

   **Fix:** Add a distinct infrastructure-error state allowing bounded retries of the identical artifact, environment, and seed; inconsistent outcomes invalidate the run rather than pass or fail the candidate.

12. **P0 — The default feedback channel is still contradictory and unnecessarily model-mediated.** Prose says `ids`, but config and success criteria still say `behavioral`; the filter still includes an LLM call even though ID/taxonomy feedback should be a pure structural projection. [feedback policy](/Users/alonadelson/Projects/ai_projects/skills/docs/superpowers/specs/2026-07-13-dark-factory-skill-design.md:284), [config default](/Users/alonadelson/Projects/ai_projects/skills/docs/superpowers/specs/2026-07-13-dark-factory-skill-design.md:434), [success criterion](/Users/alonadelson/Projects/ai_projects/skills/docs/superpowers/specs/2026-07-13-dark-factory-skill-design.md:544)

   **Fix:** Make default feedback a schema-validated deterministic mapping from frozen scenario metadata to behavior-ID plus enum, with the model declassifier isolated to explicitly tainting modes.

13. **P1 — Twin fidelity remains undefined and one requirement is impossible.** No scoring rubric, threshold, calibration source, or expiry policy is given, and “the candidate must not be able to detect the twin” cannot be guaranteed because endpoints, certificates, timing, and behavior inevitably differ. [§15.5](/Users/alonadelson/Projects/ai_projects/skills/docs/superpowers/specs/2026-07-13-dark-factory-skill-design.md:637)

   **Fix:** Define measurable fidelity dimensions, minimum thresholds, calibration evidence and expiry, and replace indistinguishability with detection-resistance tests plus explicit residual risk.

14. **P1 — Budget enforcement remains internally inconsistent.** A correct worst-case reservation should reject a call before it can cross the cap, whereas the spec both reserves worst case and permits overshoot; billing is described per adapter but configured globally, and an L5 “alert” has no required delivery channel. [budget behavior](/Users/alonadelson/Projects/ai_projects/skills/docs/superpowers/specs/2026-07-13-dark-factory-skill-design.md:305), [budget config](/Users/alonadelson/Projects/ai_projects/skills/docs/superpowers/specs/2026-07-13-dark-factory-skill-design.md:440)

   **Fix:** Define per-role adapter budgets and an admission formula, state the exact single-call overage bound for non-authoritative providers, and require a tested notification sink before enabling L5.

15. **P1 — An invocation ID cannot prevent duplicate charges after a crash.** If a provider accepts a request and the supervisor crashes before journaling its result, an automatic retry may charge twice unless that provider supports idempotency or usage reconciliation. [§15.8](/Users/alonadelson/Projects/ai_projects/skills/docs/superpowers/specs/2026-07-13-dark-factory-skill-design.md:658)

   **Fix:** Persist an `in-flight/unknown-outcome` state before dispatch and never retry it automatically without provider idempotency, reconciliation, or explicit human authorization.

16. **P0 — “Tamper-evident” has no trust anchor.** A local process that can rewrite the manifest can also recompute an unsigned hash chain, while storing prompts and seeds in the same manifest risks leaking holdout material and secrets. [audit requirements](/Users/alonadelson/Projects/ai_projects/skills/docs/superpowers/specs/2026-07-13-dark-factory-skill-design.md:671)

   **Fix:** Sign chained audit records with a supervisor-only key or remote append-only sink, and separate encrypted restricted evidence from a redacted export with an explicit verification command.

17. **P1 — Mandatory security gates are names, not enforceable policies.** Configurable booleans can disable supposedly mandatory gates, no tools or thresholds are pinned, and an LLM static reviewer reading hostile source remains prompt-injectable. [gate config](/Users/alonadelson/Projects/ai_projects/skills/docs/superpowers/specs/2026-07-13-dark-factory-skill-design.md:449), [§15.10](/Users/alonadelson/Projects/ai_projects/skills/docs/superpowers/specs/2026-07-13-dark-factory-skill-design.md:671)

   **Fix:** Make mandatory gates schema constants with pinned policy/tool hashes and deterministic pass criteria, treating isolated LLM review as additional evidence rather than the sole blocking oracle.

18. **P1 — The executable oracle still trusts generated code too much.** A model-generated “compiled” check can itself be malicious or faulty, and “known-good reference” is often unavailable in greenfield work; mutation validation has no required fault catalog or score. [oracle design](/Users/alonadelson/Projects/ai_projects/skills/docs/superpowers/specs/2026-07-13-dark-factory-skill-design.md:627), [remaining runner decision](/Users/alonadelson/Projects/ai_projects/skills/docs/superpowers/specs/2026-07-13-dark-factory-skill-design.md:562)

   **Fix:** Use a capability-limited declarative DSL, require harness self-tests and per-assertion injected faults with a defined mutation threshold, and make reference implementations optional rather than assumed.

VERDICT: REVISE
### Claude's response (Round 2)

Codex confirms the hardening closed most *conceptual* holes. The two blocking items — (P0-1) §15 was appended as an override while §§1–14 still describe the old design, and (P0-2) the v1 scope (§15.11) is undecided — are gated on a **human scope decision**. Pausing the loop at Round 2 to get that sign-off before rewriting §§1–14 into ONE coherent architecture; the remaining findings (trust-computing-base table, per-role capability/network manifests, host-side credential proxy, freeze-ordering, signed audit, oracle DSL, budget admission formula, infra-error/idempotency states) are folded in during that rewrite at the chosen ambition level.

## Round 3 — Codex (gpt-5.6-sol, read-only, resumed)

The tier model is substantially cleaner, but `standard` still cannot satisfy its own probe-backed isolation claim, and several upgrade/gating guarantees remain underspecified.

1. **P0 — Standard cannot prove the scenario store is unreachable.** A separate same-user process and ephemeral HOME do not prevent opening arbitrary host paths; “unmounted” has no enforcement meaning without a mount namespace or OS sandbox. Yet success requires denial probes to prove both builder and candidate cannot reach the store. [standard sandbox](/Users/alonadelson/Projects/ai_projects/skills/docs/superpowers/specs/2026-07-13-dark-factory-skill-design.md:228), [verification isolation](/Users/alonadelson/Projects/ai_projects/skills/docs/superpowers/specs/2026-07-13-dark-factory-skill-design.md:250), [success criterion](/Users/alonadelson/Projects/ai_projects/skills/docs/superpowers/specs/2026-07-13-dark-factory-skill-design.md:388)

   **Fix:** Require a minimal OS-enforced read-denial boundary or dedicated UID/ACL for builder and candidate at standard, while reserving containers, egress control, and capability manifests for higher tiers.

2. **P0 — The test authority can leak the holdout through allowed shared artifacts.** It writes both contracts/dev stubs and hidden scenarios/twins, so an erring test-authority model can copy scenario literals, fixtures, or variant quirks into files the builder is explicitly allowed to read; filesystem probes will still pass. [role ownership](/Users/alonadelson/Projects/ai_projects/skills/docs/superpowers/specs/2026-07-13-dark-factory-skill-design.md:125), [acceptance-world workflow](/Users/alonadelson/Projects/ai_projects/skills/docs/superpowers/specs/2026-07-13-dark-factory-skill-design.md:363)

   **Fix:** Freeze public contracts/stubs in a separate pre-holdout session, make them read-only before scenario authoring, and invalidate/regenerate the holdout after any public-artifact change.

3. **P0 — The TCB table is technically impossible as written.** Enterprise cannot trust “only supervisor + signing key + broker” while executing atop an OS kernel, hypervisor/container runtime, filesystem, and network stack; “insider” is also undefined even though the human can read the holdout and authorize downgrades. [threat-model table](/Users/alonadelson/Projects/ai_projects/skills/docs/superpowers/specs/2026-07-13-dark-factory-skill-design.md:60)

   **Fix:** Include unavoidable infrastructure in each TCB and define exactly which insider privileges, humans, providers, and cross-role accounts remain trusted or require split custody.

4. **P0 — Role-separation language exceeds lower-tier enforcement.** The role table and guardrails promise separate principals, but standard provides only separate processes and hardened provides containers; distinct principals are explicitly enterprise-only. [role table](/Users/alonadelson/Projects/ai_projects/skills/docs/superpowers/specs/2026-07-13-dark-factory-skill-design.md:120), [tier mechanisms](/Users/alonadelson/Projects/ai_projects/skills/docs/superpowers/specs/2026-07-13-dark-factory-skill-design.md:228), [guardrail](/Users/alonadelson/Projects/ai_projects/skills/docs/superpowers/specs/2026-07-13-dark-factory-skill-design.md:373)

   **Fix:** Use tier-specific terms consistently—session/process at standard, sandbox principal at hardened, immutable distinct security principal at enterprise—and state the resulting guarantee at each tier.

5. **P0 — The deterministic supervisor is missing from the package.** The supervisor is in the TCB and is supposed to own locks, budgets, journaling, transitions, cancellation, and freeze rules, but packaging gives orchestration to prose in `SKILL.md` and lists only independent helper scripts. [FSM requirement](/Users/alonadelson/Projects/ai_projects/skills/docs/superpowers/specs/2026-07-13-dark-factory-skill-design.md:276), [packaging](/Users/alonadelson/Projects/ai_projects/skills/docs/superpowers/specs/2026-07-13-dark-factory-skill-design.md:313)

   **Fix:** Add one deterministic supervisor executable as the sole state-changing entry point, with `SKILL.md` acting only as its conversational front end.

6. **P0 — Higher-tier availability is ambiguous.** The plan says hardened/enterprise are enforced whenever substrate exists, but also says their backends “land as” they are built; installed Docker or a signing key does not mean dark-factory has a conforming implementation. Because L5 requires hardened, v1’s L5 availability is consequently unclear. [tier selection](/Users/alonadelson/Projects/ai_projects/skills/docs/superpowers/specs/2026-07-13-dark-factory-skill-design.md:87), [phasing](/Users/alonadelson/Projects/ai_projects/skills/docs/superpowers/specs/2026-07-13-dark-factory-skill-design.md:404)

   **Fix:** Maintain a versioned `supported_tiers` registry backed by conformance-tested implementations, reject unimplemented tiers regardless of substrate, and state that L5 remains unavailable until a hardened backend ships.

7. **P1 — Probes run too early and only once.** Workflow probes before the scenario store, role sandboxes, mounts, candidate, and network topology exist, so it cannot validate the actual environments whose isolation matters; policy drift later in an L5 run is undetected. [startup probe](/Users/alonadelson/Projects/ai_projects/skills/docs/superpowers/specs/2026-07-13-dark-factory-skill-design.md:93), [workflow ordering](/Users/alonadelson/Projects/ai_projects/skills/docs/superpowers/specs/2026-07-13-dark-factory-skill-design.md:356)

   **Fix:** Run substrate probes at startup and environment-specific denial probes after every role/candidate environment is assembled, pin their policy hashes, and re-probe at every phase boundary.

8. **P1 — Downgrade is not transactional with autonomy.** Downgrading an L5 request from hardened to standard would leave an invalid dial combination unless autonomy is independently changed; the current downgrade rule mentions only assurance. [cross-rules](/Users/alonadelson/Projects/ai_projects/skills/docs/superpowers/specs/2026-07-13-dark-factory-skill-design.md:93)

   **Fix:** Treat downgrade as a new configuration transaction that revalidates autonomy, notification, threat assumptions, and already-created run state before requiring explicit consent.

9. **P1 — The source snapshot can itself cross the barrier.** “History-free snapshot” does not define handling of symlinks, hardlinks, device nodes, sockets, archive traversal, or dereferencing an approved untracked link into the control store. [source snapshot](/Users/alonadelson/Projects/ai_projects/skills/docs/superpowers/specs/2026-07-13-dark-factory-skill-design.md:223)

   **Fix:** Build snapshots from an `lstat`-based manifest, reject special files and escaping links, never dereference outside the approved root, and hash the canonical exported content.

10. **P1 — Standard credentials are insufficiently protected against its stated adversary.** An erring LLM can accidentally run `env`, echo a provider token, or pass it to a child process; redaction and post-phase scans detect this only after disclosure. [standard secrets](/Users/alonadelson/Projects/ai_projects/skills/docs/superpowers/specs/2026-07-13-dark-factory-skill-design.md:241)

   **Fix:** At standard, keep authentication launcher-scoped and give every model-generated child process an explicit environment allowlist excluding provider credentials, or state that accidental credential disclosure remains in scope and unsupported.

11. **P1 — Twin-variant freezing remains contradictory.** §5.1 freezes variants before building and permits only final seeds post-artifact, while §5.2 says variants and fixtures are chosen post-freeze. [holdout freeze](/Users/alonadelson/Projects/ai_projects/skills/docs/superpowers/specs/2026-07-13-dark-factory-skill-design.md:139), [twin visibility](/Users/alonadelson/Projects/ai_projects/skills/docs/superpowers/specs/2026-07-13-dark-factory-skill-design.md:155)

   **Fix:** State uniformly that generators, variants, fixtures, distributions, and cohorts freeze before building and only final random seeds are drawn after the artifact hash commits.

12. **P1 — “No redesign” is unsupported by the oracle phasing.** Standard may ship generated checks while enterprise later introduces a capability-limited DSL, but the representation remains an open item; changing it can alter scenario storage, compilers, mutation testing, hashes, and runner APIs. [scaling goal](/Users/alonadelson/Projects/ai_projects/skills/docs/superpowers/specs/2026-07-13-dark-factory-skill-design.md:33), [oracle open item](/Users/alonadelson/Projects/ai_projects/skills/docs/superpowers/specs/2026-07-13-dark-factory-skill-design.md:414)

   **Fix:** Define a versioned oracle IR and runner conformance contract in v1 so generated-check and enterprise-DSL backends are interchangeable implementations of the same boundary.

13. **P1 — Budget coverage omits expensive actors.** `per_role_usd` excludes the test authority and does not define attribution for delegated skills, security reviewers, oracle compilation, or twin generation; an autonomous CLI may also make multiple calls, defeating a “single-call” bound unless adapters enforce hard ceilings. [budget rule](/Users/alonadelson/Projects/ai_projects/skills/docs/superpowers/specs/2026-07-13-dark-factory-skill-design.md:205), [budget config](/Users/alonadelson/Projects/ai_projects/skills/docs/superpowers/specs/2026-07-13-dark-factory-skill-design.md:341)

   **Fix:** Budget every model-using role and delegated operation plus a total cap, and require adapters to enforce maximum calls/output tokens per invocation before claiming a bounded overage.

14. **P1 — Crash safety still overclaims charge prevention.** Journaling an unknown outcome prevents automatic redispatch but cannot prove whether the provider charged; §7.7 still says crashes “can’t … double-charge.” [unknown-outcome rule](/Users/alonadelson/Projects/ai_projects/skills/docs/superpowers/specs/2026-07-13-dark-factory-skill-design.md:205), [FSM claim](/Users/alonadelson/Projects/ai_projects/skills/docs/superpowers/specs/2026-07-13-dark-factory-skill-design.md:276)

   **Fix:** Claim prevention of automatic duplicate dispatch only, and require reconciliation or an explicit potentially-duplicate authorization before leaving `unknown-outcome`.

15. **P1 — Final seeds need recoverable restricted storage.** A hash-only audit reference cannot reproduce an identical-artifact infra retry or resume after a crash unless the raw seed is durably stored somewhere inaccessible to the builder. [infra retry](/Users/alonadelson/Projects/ai_projects/skills/docs/superpowers/specs/2026-07-13-dark-factory-skill-design.md:186), [audit policy](/Users/alonadelson/Projects/ai_projects/skills/docs/superpowers/specs/2026-07-13-dark-factory-skill-design.md:258)

   **Fix:** Atomically store raw seeds in the restricted immutable control snapshot before execution and put only their hashes in exported audit records.

16. **P1 — “Audited skills” has no enforceable meaning.** Automatically preferring any available skill allows mutable third-party instructions/scripts into builder, verifier, or holdout-authority contexts without a tier-compatibility or capability contract. [skill composition](/Users/alonadelson/Projects/ai_projects/skills/docs/superpowers/specs/2026-07-13-dark-factory-skill-design.md:305)

   **Fix:** Require a per-tier skill allowlist with frozen content hashes, declared capabilities, role eligibility, and conformance review before copying any skill into a run.

17. **P1 — Human acceptance can bypass qualification semantics.** Iteration and budget checkpoints offer `accept` before the FSM has passed dev, gates, final, and staging, while workflow later calls the result an “accepted candidate.” [checkpoint choices](/Users/alonadelson/Projects/ai_projects/skills/docs/superpowers/specs/2026-07-13-dark-factory-skill-design.md:193), [budget choices](/Users/alonadelson/Projects/ai_projects/skills/docs/superpowers/specs/2026-07-13-dark-factory-skill-design.md:209), [handoff](/Users/alonadelson/Projects/ai_projects/skills/docs/superpowers/specs/2026-07-13-dark-factory-skill-design.md:369)

   **Fix:** Reserve `ship-candidate` for the fully successful FSM terminal state and label every human override as failed/waived/unverified in both handoff and audit.

VERDICT: REVISE
### Claude's response (Round 3)

Codex: "the tier model is substantially cleaner." Folded R3's design-level fixes **in place** (no appended section): pre-holdout contract freeze (P0-2), tier-consistent separation terms (P0-4), standard-tier OS read-denial so probes are meaningful (P0-1), deterministic `supervisor` as sole state-changer (P0-5), `supported_tiers` registry + L5-until-hardened (P0-6), TCB unavoidable-infra + insider (P1-3), the §5.1/§5.2 freeze contradiction resolved (P1-11), ship-candidate = FSM-terminal semantics (P1-17), crash 'prevents automatic re-dispatch' not 'no double-charge' (P1-14), credential env-scrub at standard (P1-10), lstat snapshot manifest (P1-9), oracle IR (P1-12), budget-all-roles + adapter ceilings (P1-13), restricted seed storage (P1-15), per-tier skill allowlist (P1-16). Deeper implementation specifics carried to §16 for /writing-plans. **Trajectory: R1 conceptually-broken → R2 two-architectures → R3 implementation-altitude precision — the design has converged.** Pausing the Codex loop at R3 (of 5): remaining points are plan-altitude; recommending /writing-plans.

## Round 4 — Codex (gpt-5.6-sol, read-only, resumed)

The design is now close, and I am not treating enterprise controls as requirements for standard. The remaining issues are tier-claim and lifecycle contradictions, not implementation-schema details.

1. **P0 — “Best-effort standard” contradicts fail-closed tiering.** Standard requires an OS read-denial primitive, but if none exists it retains the standard path while merely downgrading the claim to best-effort; that conflicts with the non-negotiable barrier, the `supported_tiers` registry, and “never claim a tier the environment cannot substantiate.” [standard isolation](/Users/alonadelson/Projects/ai_projects/skills/docs/superpowers/specs/2026-07-13-dark-factory-skill-design.md:253), [success criterion](/Users/alonadelson/Projects/ai_projects/skills/docs/superpowers/specs/2026-07-13-dark-factory-skill-design.md:437)

   **Fix:** Either abort when standard read denial is unavailable or introduce an explicitly lower `cooperative/best_effort` mode that cannot claim probe-proven isolation or produce a qualified ship-candidate.

2. **P0 — Standard verification does not inherit standard filesystem enforcement.** §7.2 applies the UID/read-denial primitive specifically to the builder, while §7.4 gives the candidate only a separate process and says the store is “unmounted,” which is not meaningful outside a mount namespace; success nevertheless requires candidate denial too. [builder boundary](/Users/alonadelson/Projects/ai_projects/skills/docs/superpowers/specs/2026-07-13-dark-factory-skill-design.md:253), [candidate boundary](/Users/alonadelson/Projects/ai_projects/skills/docs/superpowers/specs/2026-07-13-dark-factory-skill-design.md:281)

   **Fix:** Apply the standard UID/OS read-denial policy independently to both the builder agent and every executing candidate process.

3. **P0 — Network-authority claims are still tier-inconsistent.** §5.2 unconditionally says the candidate can reach only twin data-plane endpoints and cannot address observer evidence, but authenticated enforcement begins only at hardened+, so standard cannot make that absolute claim. [global twin claim](/Users/alonadelson/Projects/ai_projects/skills/docs/superpowers/specs/2026-07-13-dark-factory-skill-design.md:183), [tiered enforcement](/Users/alonadelson/Projects/ai_projects/skills/docs/superpowers/specs/2026-07-13-dark-factory-skill-design.md:281)

   **Fix:** Describe standard as logical endpoint separation with residual reachability risk, or require basic observer authentication at standard while reserving enforced network topology for hardened+.

4. **P1 — The normative workflow still collapses the pre-holdout freeze.** The role section correctly requires public artifacts to freeze before holdout creation, but workflow step 5 again tells one test-authority step to author public and hidden artifacts together. [pre-holdout rule](/Users/alonadelson/Projects/ai_projects/skills/docs/superpowers/specs/2026-07-13-dark-factory-skill-design.md:143), [workflow](/Users/alonadelson/Projects/ai_projects/skills/docs/superpowers/specs/2026-07-13-dark-factory-skill-design.md:399)

   **Fix:** Split workflow step 5 into public-authoring/freeze and fresh holdout-authoring phases, with the supervisor revoking public-write capability between them.

5. **P1 — Critical public-boundary artifacts are missing from FSM hashes.** The journal hashes spec, artifact, scenarios, twins, adapter, and phase, but omits contracts/dev stubs, oracle IR, cohort manifest, gate policies, and skill allowlist—the exact inputs whose mutation can invalidate isolation or results. [FSM hashes](/Users/alonadelson/Projects/ai_projects/skills/docs/superpowers/specs/2026-07-13-dark-factory-skill-design.md:307)

   **Fix:** Include every shared/public artifact and every executable policy or extension in the immutable run-input manifest and invalidate the generation on any hash change.

6. **P1 — Mid-run assurance downgrade remains unsafe.** Phase-boundary re-probes can discover drift after the holdout exists, but transactional “revalidation” does not say whether a weaker tier may inherit that sealed generation; doing so can expose a holdout created under stronger assumptions. [downgrade rule](/Users/alonadelson/Projects/ai_projects/skills/docs/superpowers/specs/2026-07-13-dark-factory-skill-design.md:93)

   **Fix:** Permit assurance downgrade only before holdout creation; afterward, terminate the run and start a fresh generation under the newly consented tier.

7. **P1 — Enterprise’s insider/provider boundary remains ambiguous.** The human is trusted and can read the holdout, yet enterprise claims protection from an “insider”; providers are “semi-trusted” while the default can use the same provider for test authority and builder, without defining whether cross-session leakage or provider compromise is in scope. [TCB table](/Users/alonadelson/Projects/ai_projects/skills/docs/superpowers/specs/2026-07-13-dark-factory-skill-design.md:60)

   **Fix:** Define the enterprise insider’s exact privileges and either trust provider session isolation explicitly or require separate provider security domains/accounts for holdout-bearing and builder roles.

8. **P1 — Infra retries do not specify pristine state.** Retrying the same artifact, environment, and seed can preserve candidate/twin writable state, allowing an enterprise-malicious candidate to learn during one attempt and influence the next. [infra-error transition](/Users/alonadelson/Projects/ai_projects/skills/docs/superpowers/specs/2026-07-13-dark-factory-skill-design.md:206)

   **Fix:** Define an infra retry as fresh candidate and twin instances restored from immutable snapshots, with the same configuration and seed but no writable state carried across attempts.

9. **P1 — Twin fidelity remains informative rather than decisive.** A fidelity score and unsupported-behavior inventory are produced, but no FSM rule prevents qualification when a required behavior is unsupported or the evidence is stale. [twin fidelity](/Users/alonadelson/Projects/ai_projects/skills/docs/superpowers/specs/2026-07-13-dark-factory-skill-design.md:187)

   **Fix:** Make unsupported required behavior or expired calibration a blocking state unless the human records an explicit scoped fidelity waiver in the audit.

VERDICT: REVISE
### Claude's response (Round 4)

Codex: "the design is now close, and I am not treating enterprise controls as requirements for standard." Folded **all 9** (design-level, cheap, no implementation-schema). P0s were standard-tier overclaims: added an explicit **`cooperative`** sub-standard mode so standard **fails closed** when no OS read-denial primitive exists (P0-1); applied read-denial to the **candidate** too, not just the builder (P0-2); **tiered** the network-authority claim (logical separation at standard, enforced at hardened+) (P0-3). P1s: split workflow step 5 into **public-freeze then holdout** phases (P1-4); expanded the FSM run-input hash set to **every shared/public artifact + policy** (P1-5); **downgrade only before holdout creation**, else terminate + fresh generation (P1-6); defined the enterprise insider + **separate provider accounts** for holdout vs builder (P1-7); infra-retry uses **fresh instances from immutable snapshots**, no writable state carried (P1-8); **unsupported-required-behavior / expired-calibration is now blocking** absent a human fidelity waiver (P1-9). Findings shrank 18 -> 18 -> 17 -> 9, all design-level.

## Round 5 — Codex (gpt-5.6-sol, read-only, resumed) — FINAL (MAX_ROUNDS)

Round 4 closes the prior architectural blockers. Three residual design issues remain; the first is material.

1. **P0 — The denial boundary protects only `scenarios/`, not the complete holdout-bearing control plane.** Sealed twins, raw final seeds, verifier outcomes, and holdout-bearing role transcripts live outside the scenario store, yet standard probes and success criteria require only that `scenarios/` be unreachable. [hidden artifacts](/Users/alonadelson/Projects/ai_projects/skills/docs/superpowers/specs/2026-07-13-dark-factory-skill-design.md:127), [raw seeds](/Users/alonadelson/Projects/ai_projects/skills/docs/superpowers/specs/2026-07-13-dark-factory-skill-design.md:174), [control layout](/Users/alonadelson/Projects/ai_projects/skills/docs/superpowers/specs/2026-07-13-dark-factory-skill-design.md:386), [denial rule](/Users/alonadelson/Projects/ai_projects/skills/docs/superpowers/specs/2026-07-13-dark-factory-skill-design.md:264)

   **Fix:** Deny builder/candidate access to the entire control root and all holdout-bearing role state, exporting only hashed allowlisted copies of spec, contracts, stubs, and filtered feedback.

2. **P1 — Cooperative is simultaneously an assurance tier and a non-probe mode.** It appears in the assurance enum, while §7 says all tiers are probe-verified and the config describes the entire enum as probe-verified/fail-closed. [assurance dial](/Users/alonadelson/Projects/ai_projects/skills/docs/superpowers/specs/2026-07-13-dark-factory-skill-design.md:97), [tier claim](/Users/alonadelson/Projects/ai_projects/skills/docs/superpowers/specs/2026-07-13-dark-factory-skill-design.md:254), [config](/Users/alonadelson/Projects/ai_projects/skills/docs/superpowers/specs/2026-07-13-dark-factory-skill-design.md:392)

   **Fix:** Classify cooperative explicitly outside the assurance-tier ordering and `supported_tiers` registry, or mark it structurally as `qualified: false` and exclude it from probe-backed tier claims.

3. **P1 — Enterprise’s “insider” remains self-contradictory.** The threat table names an insider as adversarial, while the following text calls the human sign-off authority the trusted insider, leaving unclear which insider privileges enterprise actually defends against. [enterprise threat model](/Users/alonadelson/Projects/ai_projects/skills/docs/superpowers/specs/2026-07-13-dark-factory-skill-design.md:64)

   **Fix:** Define the adversarial insider as a builder-side operator without control-plane, sign-off, broker, or signing-key authority, and list the human sign-off authority solely in the TCB.

VERDICT: REVISE
### Claude's response (Round 5) — resolution

Codex: "Round 4 closes the prior architectural blockers. Three residual design issues remain." All 3 folded (I agree with each; no counter-position): (P0) the denial boundary now covers the **entire holdout-bearing control root** — scenarios, sealed twins, raw seeds, verifier outcomes, role transcripts — not just `scenarios/`; the builder/candidate get only hashed allowlisted exports. (P1) `cooperative` is reclassified **outside** the probe-verified tier ordering + `supported_tiers` (structurally `qualified: false`). (P1) the enterprise **adversarial insider** is defined as a builder-side operator without control-plane/sign-off/broker/signing-key authority, with the human sign-off authority solely in the TCB.

**Outcome:** hit MAX_ROUNDS=5 at VERDICT:REVISE, but findings converged **18 -> 18 -> 17 -> 9 -> 3**, all 3 final points were valid and folded, and there are **no open disagreements** between Claude and Codex. Not a false 'approved' and not a real deadlock — a converged plan with every surfaced point addressed. Ready for human sign-off.
