# dark-factory M25 — Real Cost Metering (authoritative token usage) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Close the long-standing `usage.known=false` gap for adapters that CAN report real usage. The `api_anthropic` adapter (M24) receives a real `usage` block from the Messages API; surface it through the adapter protocol, accumulate **authoritative token counts** in the supervisor, and — when the operator configures per-token pricing — compute a real **`actual_usd`** alongside M8's estimate. The M8 budget's admission/alert/pause keep working; this makes the numbers real for adapters that report them, and stays honestly `known:false` (estimate-only) for adapters that don't (the CLI builders). Fully back-compatible and fail-soft: a malformed/absent usage block never fails a run.

**Architecture:** `api_anthropic` parses `response["usage"]` → returns `usage: {"known": true, "input_tokens": N, "output_tokens": M}` in its protocol-0.1 response (today it returns `{"known": false}`). The supervisor's builder-call accounting reads `resp["usage"]`; when `known`, it accumulates `builder_input_tokens`/`builder_output_tokens` and, if `budget.token_pricing` is configured (`{model_or_default: {input_per_mtok, output_per_mtok}}`), a real `actual_usd`. These are recorded on every terminal manifest as `usage = {"known": bool, "input_tokens", "output_tokens", "actual_usd": float|None}` (threaded like M8's `budget`, fresh + resume). The M8 `estimated_usd`/admission path is unchanged; `actual_usd` is additive and never gates (an estimate can pause a run before real usage exists; real usage is recorded, not used for admission — documented, since you can't reserve what you haven't spent yet).

**Honest scope (stated in docs):** authoritative usage is only as good as what the adapter reports — `api_anthropic` reports real API `usage`; the `claude`/`codex`/`gemini` CLI adapters still report `known:false` (their headless output doesn't expose token counts reliably) and remain estimate-only. `actual_usd` requires operator-supplied `token_pricing` (dark-factory does not embed or fetch prices — prices change and fetching them is network egress); absent pricing, tokens are recorded but `actual_usd` is null. `actual_usd` is a **recorded** truth, not an admission control (admission still uses the pre-call estimate — you can't reserve spend you haven't incurred).

**Tech Stack:** Python stdlib. pytest. `.venv/bin/python -m pytest dark-factory/tests -v` from repo root `/Users/alonadelson/Projects/ai_projects/skills`.

## Global Constraints

- **Back-compat + fail-soft:** an adapter returning `{"known": false}` (or a malformed/absent usage block) → today's behavior byte-identical (estimate-only, `usage.known=false` on the manifest); never raises, never fails a run. All 1083 tests stay green.
- **Additive:** new `usage` manifest field + optional `budget.token_pricing` config; the M8 `budget` field + admission/alert/pause are unchanged. `actual_usd` never gates admission (documented).
- **No secret / no network:** metering reads token counts only; no price fetching (operator supplies pricing); nothing new reaches the builder.
- **Commit messages end with:** `Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>`.

## File Structure

```
dark-factory/
  scripts/
    adapters/api_anthropic   # Task 1 — report real usage {known,input_tokens,output_tokens}
    supervisor.py            # Task 1 — accumulate real usage; Task 2 actual_usd + manifest
    df_config.py             # Task 2 — budget.token_pricing config
  references/
    budget.md                # Task 2 — real metering + honest scope (supersedes the "deferred" note)
    config-reference.md
  tests/
    test_usage_metering.py    # Tasks 1-2
```

---

### Task 1: api_anthropic reports real usage + supervisor accumulates tokens

**Files:** modify `adapters/api_anthropic`, `supervisor.py`; create `dark-factory/tests/test_usage_metering.py`.

- `api_anthropic`: after a successful parse, read `parsed.get("usage")` (the Messages API returns `{"input_tokens":N,"output_tokens":M,...}`); emit `usage: {"known": True, "input_tokens": int(iN), "output_tokens": int(oM)}` in the ok response. If usage is absent/malformed → `{"known": False}` (never fail the build over metering). The stub fixture gains a usage block in its canned response so tests are deterministic. Key/path-safety behavior unchanged.
- `supervisor.py`: where the builder `invoke_adapter` result is handled (M8 budget accounting), read `resp.get("usage")`; when `known`, accumulate run totals `builder_input_tokens += input_tokens`, `builder_output_tokens += output_tokens`, and set a run flag `usage_known=True`. Persist these in `save_state` + reload on `resume` (default 0 / False for old state — additive). Do NOT change the estimated_usd admission path.

- [ ] **Step 1 (TDD):** `test_usage_metering.py` — api_anthropic (via the stub with a usage block) → protocol response `usage.known True` + the right token counts; stub with NO usage block → `known False`, build still ok. Supervisor (monkeypatched invoke_adapter returning a usage block): a converged run accumulates the token totals; an adapter returning `known:false` → totals 0 + usage_known False; resume reloads the accumulated tokens (no double count); a malformed usage block never raises.
- [ ] **Step 2:** Implement → green. Full suite (1083 + new).
- [ ] **Step 3:** Commit `feat(dark-factory): api_anthropic reports real token usage; supervisor accumulates authoritative tokens`.

---

### Task 2: token_pricing → actual_usd + manifest + docs

**Files:** modify `df_config.py`, `supervisor.py`, `references/budget.md`, `config-reference.md`; extend `test_usage_metering.py`.

- `df_config`: `budget.token_pricing` optional — `{"<model>"|"default": {"input_per_mtok": float, "output_per_mtok": float}}` (dollars per million tokens); validate (numbers ≥ 0). Inject into `cfg["_budget"]`.
- `supervisor`: at finalize, compute `actual_usd` = (input_tokens/1e6 * input_per_mtok + output_tokens/1e6 * output_per_mtok) using the run's model's pricing (or `default`) when `usage_known` AND pricing configured; else `None`. Record on EVERY terminal manifest: `usage = {"known": usage_known, "input_tokens", "output_tokens", "actual_usd"}` (threaded like `budget`, fresh + resume, all terminals; `known:false`/zeros/null when not reported).
- [ ] **Step 1 (TDD):** extend `test_usage_metering.py` — config: valid token_pricing injected; negative price → ConfigError; absent → no pricing. actual_usd math: known tokens + pricing → correct actual_usd on the manifest; known tokens + NO pricing → actual_usd null but tokens recorded; unknown usage → known:false + null actual_usd. Manifest `usage` on converged + an abort terminal + resume. e2e-ish (CLI, fake adapter reporting usage via a fixture) that manifest.usage carries real tokens.
- [ ] **Step 2:** Implement → green. Full suite.
- [ ] **Step 3:** budget.md: real metering (authoritative tokens from api_anthropic; CLI adapters still estimate-only known:false; operator-supplied token_pricing → actual_usd; actual_usd is recorded not admission-gating). REMOVE/УPDATE the old "cost metering deferred (usage.known=false)" note to reflect it's now wired for reporting adapters. config-reference rows. Commit `feat(dark-factory): token_pricing -> actual_usd + authoritative usage on the manifest + docs`.

---

## Self-Review Notes (plan ↔ spec)

**Covered (M25):** authoritative token metering for adapters that report it (api_anthropic), threaded from the API response → adapter protocol → supervisor accounting → manifest, with operator-priced `actual_usd`; closes the M8 `usage.known=false` deferral for reporting adapters while staying honest (CLI adapters remain estimate-only) and fail-soft (metering never breaks a run) and back-compatible (admission/alert/pause unchanged).

**Deliberately deferred (honest, in budget.md):** token usage from the CLI builders (claude/codex/gemini headless output doesn't expose it reliably — they stay `known:false`); embedded/fetched pricing (prices change + fetching is network egress — operator supplies `token_pricing`); using `actual_usd` for admission control (you can't reserve spend you haven't incurred — admission stays estimate-based; `actual_usd` is recorded truth).

**Honesty note:** `usage.known` is only true when the adapter actually reported counts; `actual_usd` is null unless the operator supplied pricing; neither is faked, and neither changes the M8 admission behavior the budget cap relies on.
