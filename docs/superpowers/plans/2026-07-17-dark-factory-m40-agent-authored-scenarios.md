# M40 — agent-authored holdout scenarios (the `author` role)

## Goal
Let an **agent** write the hidden acceptance scenarios instead of a human,
with the SAME information barrier the builder already runs under, and with the
authoring agent kept independent of the builder. Owner decisions:
- **Scenarios only.** The human still writes `spec.md` + `behaviors.json`
  (the ground truth — WHAT the app must do). The agent writes only
  `scenarios/*.json` (HOW to test each behavior). Nothing else moves to the
  agent — an agent that invented the spec, the behaviors, AND the tests would
  just grade itself.
- **Strongest anti-snooping.** The author must resolve to a **different model
  than the builder** (fail-closed), and its output is sealed into the control
  root through the EXACT existing path so the runtime barrier (builder
  sandboxed away from `scenarios/`) is byte-for-byte unchanged — no new
  channel by which the builder could see the tests.

## The integrity model (why this is safe)
1. **Author ≠ builder, enforced.** `roles.author.adapter` must differ from
   `roles.builder.adapter` (by resolved path); for the shipped adapters
   (`claude`/`codex`/`gemini`/`api_anthropic`/`api_openai`) distinct path ⇒
   distinct model. Same adapter with a different `DF_API_MODEL` is a
   same-adapter case → refuse unless an explicit
   `roles.author.allow_same_model_ack: true` records the weaker guarantee in
   the manifest. Default = refuse. This is the owner's "different model / no
   snooping" choice.
2. **Barrier unchanged.** Authoring is a PRE-RUN step. The agent's scenarios
   are validated then written into `<control_root>/scenarios/` exactly like
   human-authored ones; `run` then applies the identical sandbox barrier. The
   author never runs concurrently with, shares a process/context with, or
   feeds anything to the builder. The only builder-visible artifact remains
   `spec.md`, which the author never touches.
3. **The author sees only public inputs.** spec.md (builder-visible anyway) +
   behaviors.json + the scenario-format contract. There is no holdout yet at
   authoring time, so there is nothing for the author to leak. Its scratch
   workdir is discarded after scenarios are extracted.
4. **Validation is now load-bearing, not advisory.** With no human writing the
   tests, the machine gates that were a floor for humans become the primary
   guard for the agent's output: oracle discrimination
   (`df_gates.is_discriminating`), behavior coverage (`check_coverage` — every
   declared behavior needs a dev scenario), the spec-leak barrier check
   (`df_init._find_spec_leaks` — no `then` value verbatim in spec.md), and
   full oracle-IR schema validity (`build_scenarios`). Output failing ANY gate
   is rejected fail-closed and never installed.

## Honest limitation (must be documented, not hidden)
The gates prove the agent's scenarios are schema-valid, discriminating, cover
every behavior, and don't leak — they CANNOT prove the scenarios capture the
human's *intent* (the same limit that exists for humans, minus the human's
presumed knowledge of their own intent). So with an agent author and no human
review, "discriminating + covers behaviors + faithful to the spec's stated
contract" is the ceiling. The human still owns spec+behaviors, and reviewing
the generated scenarios stays RECOMMENDED (a `--review` gate that prints them
and requires confirmation is offered, off by default).

## Approach (5 tasks)

### Task 1 — `df_author.py` (new): prompt + output contract + validate/retry
- `compose_author_prompt(spec_text, behaviors, *, attempt_feedback=None) ->
  str`: instructs the model to emit ONLY the hidden scenarios as a single
  JSON document with the exact `answers.scenarios[]` schema
  (`{cohort, run, then, title, given?}` per `references/scenario-format.md`),
  embedding the authoring rules from `references/authoring.md` §3 (one
  behavior per scenario; every `then` discriminating and specific to the
  scenario's own data; never assert a value that appears verbatim in the
  spec — that leaks the answer; don't over-assert unspecified details; every
  behavior needs ≥1 dev scenario; reserve `final` cohort for the
  most-protected behaviors). Output contract: the agent writes exactly one
  file `scenarios.json` into its workdir containing `{"scenarios": [...]}`
  (the CLI adapters write files natively; the api adapters already honor a
  `{"files": {"scenarios.json": "..."}}` return — so NO adapter code
  changes, the difference is entirely the prompt + which file we read back).
- `parse_author_output(workdir) -> list`: read `workdir/scenarios.json`,
  fail-closed on missing/unparseable/wrong-shape (never a partial/empty
  install).
- `validate_authored(scenarios, spec_text, behaviors) -> (ok, report)`:
  run them through the SAME validators `init` uses — reuse
  `df_init.build_scenarios`-equivalent normalization + `df_gates`
  discrimination/coverage + `df_init._find_spec_leaks`. Return an
  IMPOVERISHED, barrier-safe report (behavior-ids uncovered, scenario-titles
  non-discriminating, leak values) suitable to feed back to the author.
- `WaiverError`-style `AuthorError`; all guards `raise`, never `assert`.

### Task 2 — supervisor `author-scenarios` subcommand + bounded retry loop
- `supervisor.py author-scenarios --control-root <cr> [--attempts N]
  [--review]`: load `spec.md` + `behaviors.json` from the control root (must
  already be scaffolded — Task 4 lets `init` scaffold without scenarios when
  an author role is configured); resolve `roles.author.adapter` (fail-closed
  if absent / equal to builder); invoke it via the existing `invoke_adapter`
  in a fresh scratch workdir with `role="author"`; parse + validate; on
  failure, re-invoke with `attempt_feedback` (impoverished, same spirit as
  builder feedback) up to `--attempts` (default 3); on success, atomically
  write `scenarios/*.json` into the control root (one file per scenario, same
  layout `df_init.scaffold` produces) and print the validation report +
  "review then run". Fail-closed + exit 2 if no attempt validates (control
  root left with NO scenarios, never a bad partial set). Journal an
  `AUTHORED_SCENARIOS` control-plane event (adapter, attempts, counts — never
  scenario CONTENT into any builder-reachable place).
- `--review`: print each generated scenario and require an interactive
  confirmation before install (off by default; honors the "recommended human
  review" limitation without forcing it).

### Task 3 — config: the `author` role + different-model enforcement
- `df_config.py`: optional `roles.author = {adapter, timeout_s?,
  allow_same_model_ack?}`. Validate the adapter path like the builder's
  (absolute+existing at hardened+, disjoint-from-control-root — an author
  adapter dir is NOT mounted into any container, but keep the same hygiene).
  Enforce `realpath(author.adapter) != realpath(builder.adapter)` ⇒
  `ConfigError` unless `allow_same_model_ack`. Seal a manifest field
  `authored_by = {adapter, same_model_ack}` at run time so an audit shows the
  scenarios were agent-written and by which independent model. Absent
  `roles.author` ⇒ today's behavior exactly (human-authored, no author role).

### Task 4 — `init` may scaffold without scenarios when an author is configured
- `df_init.build_scenarios`/`scaffold`: when `answers` has a `roles.author`
  (or `answers.author_adapter`) AND zero `scenarios`, scaffold spec.md +
  behaviors.json + config with an EMPTY `scenarios/` and mark the control
  root `scenarios_pending_author: true` (a marker file). `validate_scaffold`
  in this state passes structure but prints "scenarios pending — run
  author-scenarios". `run` refuses a scenarios-pending control root
  (fail-closed: `no scenarios; run author-scenarios first`). A control root
  with human scenarios is unchanged. (Enforce: you can't have BOTH pending
  and human scenarios.)

### Task 5 — tests + docs
- `test_author.py`: prompt composition; output parse fail-closed
  (missing/garbage/empty/wrong-shape); validate_authored catches
  non-discriminating / uncovered-behavior / spec-leak and passes a good set;
  retry loop consumes feedback and succeeds on a later attempt; exhausted
  attempts ⇒ fail-closed, no install.
- `test_author_config.py`: author==builder ⇒ ConfigError; ack overrides;
  absent role unchanged; manifest `authored_by`.
- e2e (`test_e2e_author.py`, stub author adapter — deterministic, no paid
  call): a fake `author` adapter emits a valid scenarios.json for the
  kv-service spec → `author-scenarios` installs them → a normal
  fake-builder `run` converges against the agent-authored holdout, barrier
  intact (builder never reads scenarios/). Plus: a fake author that emits a
  non-discriminating set ⇒ author-scenarios exits 2, no scenarios installed.
- Docs: `references/authoring.md` (new "Agent-authored scenarios" section —
  the author role, the different-model requirement, the workflow init→
  author-scenarios→review→run, and the honest intent-capture limit),
  `references/role-adapters.md` (the `author` role alongside builder/verifier;
  any adapter can author), `references/audit.md` (`authored_by` field),
  SKILL.md (offer agent-authoring in the interview), `references/config-reference.md`
  (`roles.author`), OVERVIEW/README (one line: scenarios can be written by an
  independent agent, not just a human).

## Out of scope (documented)
- A second **reviewer agent** grading the author's scenarios for intent-fit
  (a natural follow-on; today intent-fit stays a human/recommended check).
- Agent-authored spec or behaviors (owner chose scenarios-only).
- The author generating twins/fixtures (separate concern).

## Key decisions
- Reuse the adapter framework wholesale — the author is a prompt + an output
  file + the EXISTING validators; no adapter code changes.
- Different-model is a hard config gate (owner's anti-snooping choice), with
  an explicit, audited same-model override.
- Validation is fail-closed and identical to `init`'s human-scenario gates —
  agent output earns no more trust than a human's, and arguably gets the
  stricter treatment (bounded auto-retry on impoverished feedback, then
  refuse).
- Barrier is untouched: authoring is a clean pre-run step; scenarios seal via
  the existing path; `run` is unchanged.
