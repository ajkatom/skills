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
`GATE_FAILED`, `ABORTED_BUILD_ERROR`, `FINAL_EXAM_FAILED`, `SECURITY_GATE_FAILED`,
`ABORTED_BY_HUMAN`, `ACCEPTED_WAIVED`) carries:

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

**Cost metering stays `usage.known=false` — deferred, not faked.** Honest per-call
dollar metering needs the builder CLIs (`claude`, `codex`, `gemini`) to emit a
parseable token/cost usage report in headless mode; none of them do today, so there is
no authoritative number to meter against. Rather than fabricate one, dark-factory keeps
`estimated_usd` clearly labeled as an estimate (see above) and waits on adapter usage
reporting before claiming real metering. This is the one flagged budget gap M18 does
**not** close.

## Notification delivery (M18) — fail-soft, best-effort

`budget.notification_sink` (default `""`, no delivery) now actually **delivers** the
`BUDGET_ALERT`/`BUDGET_PAUSE` event to an operator channel, via `df_notify.deliver()`:

- `http://` / `https://` — `POST` `json.dumps(event)` with `Content-Type:
  application/json` to the sink URL.
- `file:///abs/path` — append one ndjson line to the (absolute, no host component)
  file, creating it and its parent directories if needed.

The delivered event is `{"event": "BUDGET_ALERT"|"BUDGET_PAUSE", "invocation":
<run id>, "estimated_usd":, "builder_calls":, "cap": {"max_usd":, "max_calls":},
"ts":}`. When a credentials/redactor is configured for the run (M11), the event is
passed through `redactor.redact_obj()` **before** it ever leaves the process — the
same discipline every other persisted/transmitted artifact follows. No secret value
configured for the run can reach the sink.

**CRITICAL: fail-SOFT, the opposite of the M13 audit sink.** `deliver()` never raises —
every failure (unreachable host, non-2xx response, an unwritable file path, an unknown
scheme) comes back as `(False, reason)`, journaled as `NOTIFY_FAILED` with that reason.
The run's exit code and outcome are **never** affected by a delivery failure: an alert
channel being down is an operator inconvenience, not an integrity failure, in sharp
contrast to the audit sink (M13), which is fail-**closed** when required (a broken
audit chain *does* fail the run). A successful delivery journals `NOTIFY_SENT`.

Notification is **best-effort, fire-and-forget** — a single POST/append attempt with a
short timeout (`timeout_s=10` default), not a guaranteed-delivery queue with retries or
backoff. Absent `notification_sink` (the default `""`), `df_notify.deliver()` is never
called — behavior is byte-identical to pre-M18 (journal + stderr print only).

`budget.notification_sink`, when set, is validated at config-load time: it must be
`http://`, `https://`, or `file://<abs path, no host>`; anything else (a bare path, an
unsupported scheme like `ftp://`, a `file://` URL with a host component or a relative
path) is a `ConfigError` at load time, not a silent no-op or a runtime surprise.

**Per-role budgets are out of scope.** M8 budgets only builder calls — the only
model-cost driver in the current architecture (verification is local, deterministic
scenario execution, not an LLM call). Planner/test-authority/verifier-role budgets are
not modeled because those roles don't exist yet as separate LLM invocations.

## Durable notification delivery (M22) — at-least-once, still fail-soft

M18's `deliver()` is best-effort, fire-and-forget: a single attempt with a short
timeout, and a transient sink outage silently drops the alert (journaled
`NOTIFY_FAILED`, nothing more). `budget.notification_durable: true` (default `false`)
opts a run into **at-least-once** delivery instead: `df_notify.deliver_durable(sink,
event, spool_dir, *, attempts, timeout_s, redactor)` retries `deliver()` up to
`budget.notification_attempts` times (default `3`, must be an int `>= 1`), and only if
**every** attempt fails does it append the event to a local disk spool —
`<control_root>/.notify-spool/pending.ndjson`, one ndjson line per event — and return
`(False, "spooled")` instead of dropping it. The spooled copy goes through the same
`redactor.redact_obj()` choke point as an in-flight delivery **before** it ever touches
disk, so a spooled file carries no secret value configured for the run, exactly like
the in-flight event.

**At run start**, if `notification_durable` is set and a `notification_sink` is
configured, the supervisor calls `df_notify.flush_spool(sink, spool_dir,
redactor=redactor)` before doing anything else: it re-attempts every spooled event via
`deliver()` and rewrites `pending.ndjson` with only what's still undelivered. The
supervisor journals `NOTIFY_FLUSH` with `{"flushed": <int>, "remaining": <int>}` on
every durable run — `0`/`0` when the spool is empty (the common case), whatever a prior
run left behind otherwise. A `BUDGET_ALERT`/`BUDGET_PAUSE` that spools (rather than
delivers or hard-fails) journals `NOTIFY_SPOOLED` in place of `NOTIFY_FAILED`.

**STILL fail-soft — this is at-least-once delivery, not a guarantee the run waits for
it.** `deliver_durable()` and `flush_spool()` NEVER raise, same discipline as
`deliver()`, and neither ever changes the run's exit code or outcome: a permanently-down
sink just leaves events sitting in the spool (journaled, visible to an operator who
looks), while the run itself proceeds and converges/pauses/caps out exactly as it would
have under M18. The spool only raises the odds an alert eventually reaches its
destination — it does not make notification a correctness gate on the run.

**Honest scope — a local disk spool, NOT a real message queue.** `pending.ndjson` lives
on the same host/filesystem as the control root: there is no cross-host durability
(losing the disk loses the spool), no ordering guarantee beyond append-order, and no
deduplication beyond "this file has this line once." It is a bounded-retry-plus-local-
buffer, adequate for "don't silently drop an alert because the sink hiccuped for a few
seconds," not a substitute for a real broker (Kafka/SQS/etc.) with cross-host
replication, exactly-once semantics, or consumer offsets. An operator who needs those
guarantees should point `notification_sink` at a real queue's HTTP ingestion endpoint,
not rely on this spool to provide them.

Absent `notification_durable` (the default `false`), every notification code path is
byte-identical to M18: no spool directory is ever created, no `NOTIFY_FLUSH`/
`NOTIFY_SPOOLED` journal entries appear, and a delivery failure still journals only
`NOTIFY_FAILED` — the durable path is purely additive.

## See also

- `references/config-reference.md` — `budget.*` schema + validation
- M2a pause/resume (checkpoint pauses) — the same `state.json`/`resume` machinery a
  budget pause reuses; `reason` in `state.json` distinguishes `"checkpoint"` from
  `"budget"`.
