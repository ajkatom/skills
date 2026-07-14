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
