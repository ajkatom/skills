# dark-factory M8 — Budget Controls Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Bound a run's cost. **Admission control** reserves a per-call estimate before each builder call; at **85% of the cap the run alerts** (warns, continues); at **100% it pauses at the phase boundary** and offers **raise-and-resume** (reusing the M2a pause/resume machinery — a budget pause is a pause with reason `budget`). `billing: subscription` can't meter dollars, so it is **alert-only** (milestone alerts, never a $ pause). `billing: api` enforces the cap via the estimate, and **downgrades to alert-only when no estimate is configured** (honest — authoritative token usage isn't available from the CLIs, which report `usage.known=false`). The budget pause fires **even at `checkpoint: auto` / L5** — a cost overrun is not something to run past unattended.

**Architecture:** Cost is **estimated**, not authoritative: `budget.per_call_usd` × builder-call-count (verifier runs are local/free). Because we **reserve before each call** (admission control), we never exceed the estimate — the only "overshoot" is estimate-vs-reality, which the manifest states. The supervisor tracks `builder_calls` + `estimated_usd`, persists them in `state.json`, and on `resume` reloads them and re-reads the (possibly raised) config cap. A 100% hit does `save_state(reason="budget")` + `return 10` (the existing PAUSED code); `resume --decision continue` re-enters the loop with the raised cap.

**Honest scope (stated in docs):** dollars are an **estimate** from a human-supplied `per_call_usd`, not real metered usage — dark-factory's adapters return `usage.known=false`, so true metering waits on adapters that report token/cost (a later refinement). `max_calls` is an exact, non-estimated alternative cap. L5 + a configured `notification_sink` (where the alert is delivered) is recorded but delivery is a stub in M8 (the alert is journaled + printed); a tested delivery sink is deferred.

**Tech Stack:** Python stdlib only. pytest. `.venv/bin/python -m pytest dark-factory/tests -v` from repo root `/Users/alonadelson/Projects/ai_projects/skills`.

## Global Constraints

- **Runtime stdlib only.** Back-compatible: absent `budget` block, or `billing: subscription` with no caps → today's behavior (no pause), plus honest milestone alerts. Existing tests stay green.
- **Admission control:** the estimate is reserved BEFORE each builder call; a call that would cross `max_usd` (or `max_calls`) is NOT made — the run pauses at that phase boundary. We therefore never spend past the cap on the estimate; the manifest states the estimate-vs-actual caveat.
- **85% alert then 100% pause:** at ≥`alert_at`×cap → `BUDGET_ALERT` (journal + stderr, once); at the next call that would cross the cap → `BUDGET_PAUSE` (save_state reason=budget, exit 10). Fires regardless of `checkpoint` mode (even auto/L5).
- **subscription = alert-only:** never a $ pause; emits milestone `BUDGET_ALERT`s (every N builder calls). `max_calls` (if set) still enforces a hard pause under any billing (it's exact, not $-estimated).
- **Resume:** `estimated_usd` + `builder_calls` persist in state.json and reload on resume; resume re-reads the current config cap (so raising `budget.max_usd` and resuming continues). A resumed run doesn't double-count.
- **Exit codes unchanged (0/2/3/10):** a budget pause is exit 10 (PAUSED), resumable exactly like a checkpoint pause.
- **Barrier untouched:** budget is control-plane accounting; nothing new reaches the builder.
- **Commit messages end with:** `Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>`.

## File Structure

```
dark-factory/
  scripts/
    df_config.py     # Task 1 — validate budget block; inject cfg["_budget"]
    supervisor.py    # Task 2 — accounting, admission, alert/pause, state persist, manifest budget
  references/
    budget.md        # Task 3 — budget model + honest estimate caveat
    config-reference.md
  SKILL.md           # Task 3 — budget step
  tests/
    test_budget_config.py   # Task 1
    test_budget.py          # Task 2
    test_e2e_budget.py       # Task 3
```

---

### Task 1: Budget config validation

**Files:** modify `df_config.py` + `config-reference.md`; create `test_budget_config.py`.

**Interfaces:** Read the current `budget` handling in `df_config.py` (today it only carries `billing`). Extend to inject `cfg["_budget"]`:
```
{"billing": "api"|"subscription",   # existing; default "subscription"
 "max_usd": float|None,             # optional; enforced only when billing=="api" AND set
 "per_call_usd": float|None,        # optional; estimate reserved per builder call
 "max_calls": int|None,             # optional; exact hard cap on builder calls (any billing)
 "alert_at": float,                 # 0<alert_at<=1, default 0.85
 "notification_sink": str}          # optional, default "" (recorded; delivery stubbed)
```
Validation: `billing` in {api,subscription}; `max_usd`/`per_call_usd` if present are numbers > 0; `max_calls` if present int ≥ 1; `alert_at` a float in (0,1]; **if billing=="api" and max_usd set but per_call_usd is NOT set → that's the "no authoritative usage" case: allowed, but record it (the supervisor will downgrade the $ cap to alert-only)**; `max_calls` may be set under any billing. Malformed → ConfigError.

- [ ] TDD: `test_budget_config.py` — absent block → sensible defaults (billing subscription, caps None, alert_at 0.85); api+max_usd+per_call_usd valid; api+max_usd without per_call_usd valid (downgrade case); bad billing/negative max_usd/alert_at out of range/max_calls 0 → ConfigError. Implement; config-reference rows; full suite green (233 + new). Commit `feat(dark-factory): budget config (caps, per-call estimate, alert threshold)`.

---

### Task 2: Supervisor budget accounting + admission + alert/pause

**Files:** modify `supervisor.py`; create `test_budget.py`.

**Interfaces:** Read `_run_loop`, `invoke_adapter`, `save_state`/`load_state`/`resume`. Add:
1. Thread `builder_calls` (int) + `estimated_usd` (float) through `_run_loop` (params default 0/0.0; loaded from state on resume). 
2. **Before each builder `invoke_adapter` call (admission):**
   - Compute the reservation: `est_after = estimated_usd + (per_call_usd or 0.0)`; `calls_after = builder_calls + 1`.
   - **Hard `max_calls` pause (any billing):** if `max_calls` set and `calls_after > max_calls` → BUDGET_PAUSE (below).
   - **`api` $ cap:** if billing=="api" and `max_usd` set and `per_call_usd` set: if `est_after > max_usd` → BUDGET_PAUSE. If `per_call_usd` NOT set → no $ enforcement (downgraded); still count.
   - **85% alert (once):** if a cap is enforced and the *current* `estimated_usd`/`builder_calls` has reached `alert_at`×cap and no alert emitted yet → `journal.write("BUDGET_ALERT", estimated_usd=..., builder_calls=..., cap=...)` + stderr; set a flag. For subscription, emit a milestone `BUDGET_ALERT` every, say, 5 builder calls (informational).
   - **BUDGET_PAUSE:** `journal.write("BUDGET_PAUSE", estimated_usd, builder_calls, cap, reason)`, `save_state(run_dir, next_iter=i, feedback=feedback, workspace=workspace, ..., builder_calls=builder_calls, estimated_usd=estimated_usd, reason="budget")`, print "budget cap reached — raise budget.max_usd (or max_calls) and `resume --decision continue`", **return 10**. Do NOT make the call. (Budget pause fires regardless of `checkpoint` mode.)
   - Otherwise: make the call; on success `builder_calls = calls_after`, `estimated_usd = est_after`.
3. Persist `builder_calls`/`estimated_usd` in `save_state` (extend it) and reload in `resume()` (default 0/0.0 for old state). Resume re-reads `cfg["_budget"]` (the live, possibly-raised cap).
4. Manifest: add `budget={"billing":..., "builder_calls":..., "estimated_usd":..., "cap_usd": max_usd, "max_calls": max_calls, "enforced": <bool>, "estimate_caveat": "estimated from per_call_usd; not metered usage"}` to every terminal (thread via manifest_base).

- [ ] TDD: `test_budget.py`:
  - `test_api_budget_pause_and_resume` — api, `per_call_usd=1.0`, `max_usd=1.0`, a builder that needs ≥2 iterations (stubborn-then-fixed): iteration 1 makes 1 call (est 1.0), iteration 2's admission would hit 2.0 > 1.0 → BUDGET_PAUSE exit 10, journal BUDGET_PAUSE, state.json has estimated_usd/builder_calls + reason budget. Then raise max_usd to 10.0 in config, `resume --decision continue` → completes (exit 0), and total builder_calls in the manifest reflects both segments (no double count).
  - `test_85_percent_alert` — api, `per_call_usd=0.85`, `max_usd=1.0`, alert_at 0.85: after the first call (est 0.85 ≥ 0.85×1.0) a BUDGET_ALERT is journaled once (not repeated every iteration).
  - `test_subscription_never_pauses` — subscription + a builder needing several iterations: never BUDGET_PAUSE; converges; milestone BUDGET_ALERT may appear but exit is 0.
  - `test_max_calls_hard_cap` — max_calls=1 under subscription: iteration 2's admission (2nd call) → BUDGET_PAUSE exit 10 (exact cap, no $ needed).
  - `test_no_budget_block_unchanged` — no budget block → no pause, converges, manifest budget.enforced False.
  Reuse setup_control/FAKE/STUBBORN; write configs with the budget block.
- [ ] Implement; full suite green (existing pause/resume/manifest tests: budget fields additive; if a state.json-shape test breaks, update additively). Commit `feat(dark-factory): budget admission control — 85% alert, phase-boundary pause, resumable`.

---

### Task 3: e2e + docs

**Files:** create `test_e2e_budget.py`; `references/budget.md`; modify `SKILL.md`.

- [ ] `test_e2e_budget.py` (CLI subprocess): an api run with a low cap + stubborn builder → exit 10 at the budget pause; assert stderr/journal show BUDGET_PAUSE and the raise-and-resume instruction; then rewrite config with a higher `max_usd`, `resume --decision continue` → exit 0/3 (completes); assert manifest `budget.builder_calls` counts all calls across the pause. A subscription control with the same builder → never pauses on budget.
- [ ] `budget.md`: the model (admission, 85% alert, 100% phase-boundary pause, raise-and-resume), subscription=alert-only, `max_calls` exact cap, and the **honest caveat**: dollars are an estimate from `per_call_usd`, not metered; L5 alert delivery (`notification_sink`) is recorded but stubbed. SKILL.md: budget config sub-step + note that a budget pause is resumable after raising the cap.
- [ ] Verify docs vs code; full suite green; commit `feat(dark-factory): e2e budget pause/resume; budget docs`.

---

## Self-Review Notes (plan ↔ spec)

**Covered (M8):** admission control (reserve worst-case before each call), the **85% alert** and **100% phase-boundary pause with raise-and-resume** (§6.2/§15.7 — the user's explicit early ask), `subscription`=alert-only vs `api`=enforced, an exact `max_calls` cap, budget pause firing regardless of checkpoint mode (even L5), and budget accounting persisted across resume + recorded on every manifest.

**Deliberately deferred (honest, in budget.md):** **authoritative** token/cost metering (adapters return `usage.known=false` — M8 uses a human `per_call_usd` estimate; real metering needs adapter usage reporting); a **tested `notification_sink` delivery** for L5 alerts (M8 journals + prints; delivery is stubbed); per-role budgets across planner/test-authority/verifier (M8 budgets the builder calls — the only model-cost driver in the current architecture).

**Honesty note:** because cost is estimated and reserved-before-call, the run cannot exceed the *estimated* cap, but real spend may differ from the estimate; the manifest carries `estimate_caveat` so no one reads `estimated_usd` as metered truth.
```
