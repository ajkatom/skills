# dark-factory budget controls — admission, alert, pause, resume (M8)

Bounds a run's builder-call cost. Cost is **estimated**, never metered: dark-factory's
adapters return `usage.known=false`, so there is no authoritative token/dollar count to
enforce against. Everything below is built on a human-supplied `budget.per_call_usd`
estimate, reserved *before* each builder call. Schema + validation rules:
`references/config-reference.md` (`budget.*` rows).

## The model

**Admission control (reserve-before-call).** Before every builder invocation, the
supervisor computes the reservation it would make — `est_after = estimated_usd +
per_call_usd` and `calls_after = builder_calls + 1` — and decides whether to admit the
call *before* it is made. Because the reservation happens first, a run can never spend
past the estimated cap; the only "overshoot" possible is estimate-vs-reality (see
Honest caveat, below).

**85% alert.** Once the *current* `estimated_usd`/`builder_calls` (before this call)
reaches `alert_at` × the enforced cap (default `alert_at: 0.85`), the supervisor writes
a `BUDGET_ALERT` journal entry and prints a warning to stderr — once per run (a
`budget_alerted` flag, persisted across resume, suppresses repeats). The run **continues**;
an alert never blocks a call.

**100% phase-boundary pause.** If admitting the next call would cross the enforced cap
(`calls_after > max_calls`, or — under `billing: "api"` with both `max_usd` and
`per_call_usd` set — `est_after > max_usd`), the supervisor does **not** make that call.
Instead it:
1. Journals `BUDGET_PAUSE` with `estimated_usd`, `builder_calls`, `cap_usd`, `max_calls`
   (the values *before* the blocked call).
2. Calls `save_state(..., builder_calls=, estimated_usd=, budget_alerted=, reason="budget")`
   — the same `state.json` pause mechanism M2a built for checkpoint pauses.
3. Prints (stdout) the raise-and-resume instruction:
   `dark-factory: PAUSED — budget cap reached (estimated_usd=..., builder_calls=...).
   Raise budget.max_usd (or max_calls) in config.json and run: supervisor.py resume
   --control-root <cr> --decision continue`
4. Returns exit **10** (`PAUSED`) — the same code as a checkpoint pause.

The budget pause fires **regardless of `checkpoint` mode**, including `auto` /
autonomy 5: an estimated cost overrun is not something to run past unattended, even
when checkpoint pauses are otherwise disabled.

**Raise-and-resume.** A budget pause is a pause with `reason: "budget"` — it reuses the
M2a pause/resume machinery exactly. To continue:
1. Edit `<control_root>/config.json` — raise `budget.max_usd` and/or `budget.max_calls`.
2. Run `supervisor.py resume --control-root <control_root> --decision continue`.

`resume()` reloads `builder_calls`/`estimated_usd`/`budget_alerted` from `state.json`
(no reset) and re-reads `cfg["_budget"]` fresh from the (now-raised) config — so the
next admission check runs against the new cap. Calls made before the pause are never
re-counted; calls made after resume accumulate on top. `resume --decision accept` or
`--decision abort` also carry the accumulated `builder_calls`/`estimated_usd` into their
terminal manifest, honestly, without re-entering the loop.

## `subscription` billing — alert-only

`billing: "subscription"` (the default) cannot meter dollars, so it **never triggers a
$ pause** — `BUDGET_PAUSE` is impossible on cost alone under subscription billing. It
still emits informational milestone `BUDGET_ALERT`s every 5 builder calls when no cap is
enforced (`journal.write("BUDGET_ALERT", milestone=True, ...)`), purely for visibility.

## `max_calls` — exact, non-estimated cap

`budget.max_calls`, if set, is an **exact** integer cap on builder-call count — it is
enforced under **any** billing mode (including `subscription`), because it needs no
dollar estimate. It participates in both the 85% alert and the 100% pause exactly like
the dollar cap: `builder_calls >= alert_at * max_calls` alerts; `calls_after >
max_calls` pauses.

## `api` billing without `per_call_usd` — downgrade to alert-only

`billing: "api"` with `max_usd` set but **no** `per_call_usd` has no per-call estimate
to reserve against. Rather than silently ignoring the cap, the supervisor **records the
downgrade**: on the first affected admission check it journals
`BUDGET_DOWNGRADE` (`reason: "max_usd set without per_call_usd; no estimate to reserve
against — $ cap downgraded to alert-only"`) once per run, and the `$` cap never pauses
the run. `max_calls`, if also set, is unaffected and still enforces exactly.

## Manifest `budget` field

Every terminal manifest (`COMPLETE_QUALIFIED`/`COMPLETE_UNQUALIFIED`, `CAP_REACHED`,
`GATE_FAILED`, `ABORTED_BUILD_ERROR`, `FINAL_EXAM_FAILED`, `ABORTED_BY_HUMAN`,
`ACCEPTED_WAIVED`) carries:

```json
"budget": {
  "billing": "api" | "subscription",
  "builder_calls": <int>,
  "estimated_usd": <float>,
  "cap_usd": <float | null>,
  "max_calls": <int | null>,
  "enforced": <bool>,
  "estimate_caveat": "estimated from per_call_usd; not metered usage"
}
```

`enforced` is `true` if either the dollar cap or the calls cap is actively enforceable
(`billing=="api"` with both `max_usd` and `per_call_usd` set, and/or `max_calls` set);
`false` for a plain `subscription` run with no `max_calls` (today's pre-M8 behavior —
back-compatible: an absent `budget` block, or `subscription` with no caps, never
pauses). A `BUDGET_PAUSE` never reaches a manifest directly — a pause is non-terminal
(no `manifest.json` is written until the run later converges, caps out, or is resumed
with `accept`/`abort`); `builder_calls`/`estimated_usd` on the eventual terminal
manifest reflect the full run, across every pause/resume segment.

## Honest caveat — estimate, not metered usage

**`estimated_usd` is a human-supplied estimate (`per_call_usd` × `builder_calls`), not
authoritative metered spend.** dark-factory's adapters (`claude`, `codex`, `gemini`) all
report `usage.known: false` — none of them currently return real token counts or costs.
Because admission reserves *before* each call, the run can never exceed the *estimated*
cap, but actual billing may differ from the estimate (a call can cost more or less than
`per_call_usd` in reality). The manifest's `estimate_caveat` string exists precisely so
nobody mistakes `estimated_usd` for metered truth. True metering is deferred to a later
milestone that adds real usage reporting to the adapter protocol.

**L5 alert delivery (`notification_sink`) is recorded, not delivered.** `budget.
notification_sink` (default `""`) is validated and carried in config, but M8 does not
implement any delivery integration — alerts are **journaled and printed to stderr**
only, the same as at any other autonomy level. A configured `notification_sink` string
is inert in M8; a tested delivery sink (email/Slack/webhook/etc.) is deferred.

**Per-role budgets are out of scope.** M8 budgets only builder calls — the only
model-cost driver in the current architecture (verification is local, deterministic
scenario execution, not an LLM call). Planner/test-authority/verifier-role budgets are
not modeled because those roles don't exist yet as separate LLM invocations.

## See also

- `references/config-reference.md` — `budget.*` schema + validation
- M2a pause/resume (checkpoint pauses) — the same `state.json`/`resume` machinery a
  budget pause reuses; `reason` in `state.json` distinguishes `"checkpoint"` from
  `"budget"`.
