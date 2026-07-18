# Oracle IR v0 (M1) — hidden holdout scenario format

One JSON file per scenario in `<control_root>/scenarios/`. HOLDOUT: these files
never enter the build workspace, the builder prompt, or feedback.

Fields: `ir_version` (`"0.1"` / `"0.2"` / `"0.3"` — additive bumps, all
accepted at load time; `"0.1"` is the baseline CLI-only shape, `"0.2"`
added twin-evidence `then` keys, `"0.3"` added the `when.http` scenario
type below), `id`, `behavior_id` (`^BHV-[A-Za-z0-9-]{1,32}$`), `title`/
`given` (human view only), `when` (**exactly one** of `run` or `http` —
see below; both or neither is an `OracleError` naming the scenario id,
caught at load time before any build), `then` (>= 1 assertion key; equality
strips one trailing newline), optional `cohort` (`"dev"` | `"final"`;
default `"dev"` when absent; any other value is an `OracleError`).

## `when.run` — CLI scenario (the original type)

`when.run` (argv list executed with cwd = build workspace, `when.timeout_s`
default 30), `then` (>= 1 of: `exit_code`, `stdout_equals`,
`stdout_contains`, `stderr_equals`, `stderr_contains`, plus the twin-evidence
keys documented in `references/digital-twins.md`). A CLI scenario's `then`
must NOT use any `when.http` key (below) — mismatched then/when is an
`OracleError`.

## `when.http` — HTTP scenario (M20)

An additive, opt-in scenario type: instead of running a CLI command, the
verifier **starts a real service, issues one real HTTP request, and asserts
on the real response** (status/body/JSON), then always reaps the service —
no inline `handle()`-harness needed.

```json
"when": {
  "http": {
    "start": ["python3", "service.py"],
    "port_env": "PORT",
    "ready_path": "/health",
    "request": {"method": "GET", "path": "/echo",
                "headers": {"Content-Type": "application/json"},
                "body": "{\"hello\": \"world\"}"}
  },
  "timeout_s": 10
}
```

- **`start`** (required) — the argv that launches the service, executed the
  same way `when.run` is (same cwd, same exec-wrapper/twin-env, so the
  control root/holdout stays exactly as unreachable to it as to a CLI
  scenario).
- **`port_env`** (optional) — the verifier picks a free ephemeral port and
  sets this env var to it before `start` runs, so the service can bind it.
  This is the **primary (and only v1) port-location mechanism** — a service
  that binds `:0` and self-reports its port back to the harness is out of
  scope v1; if you need a fixed port instead, omit `port_env` and hardcode
  it in the service (less safe under parallel runs).
- **`ready_path`** (optional, default `"/"`) — polled on
  `127.0.0.1:<port>` until ANY response (not just 2xx) or a deadline.
  Bounded, fail-closed: a service that never becomes ready never produces a
  vacuous pass (see taxonomy below).
- **`request`** (required) — the ONE request issued once the service is
  ready: `method` + `path` (both required, non-empty strings), optional
  `headers` (dict) and `body` (string, sent as-is).

An http scenario's `then` must use **>= 1 of the http keys** below (a CLI
`then` on an http scenario, or vice-versa, is a mismatched then/when
`OracleError`, load-time, before any build):

| key | checks | mismatch taxonomy |
|---|---|---|
| `http_status` (int) | exact response status code | `wrong_exit_code` (the http analogue of an exit code) |
| `body_contains` (str) | substring of the raw response body | `wrong_output` |
| `json_equals` (any) | parsed JSON body equals exactly | `wrong_output` |
| `json_contains` (dict) | parsed JSON body is a superset of this (recursive subset match; extra keys in the response are fine) | `wrong_output` |
| `json_path` (`{"<path>": <value>}`) | each path resolves to the given value (see mini-syntax below) | `wrong_output` |
| `twin_observed` (same shape as the CLI key, `digital-twins.md`) | the started service's own twin-delta evidence | `no_twin_evidence` |

No response at all (the service never started, never became ready within
`timeout_s`, or died before answering) → **`crash`**, regardless of what
`then` asks for — fail-closed, checked FIRST, before `http_status`.
`json_*` assertions against a non-JSON (or absent) body are always a
mismatch, never a silent skip. Priority on failure: `crash` > `http_status`
mismatch (`wrong_exit_code`) > body/json/json_path mismatch
(`wrong_output`) > `twin_observed` mismatch (`no_twin_evidence`) — same
"first mismatch wins" discipline as the CLI oracle, and the SAME fixed
taxonomy vocabulary (no new constant, so the barrier + id_feedback are
untouched). `stdout_echoes_twin` has no http analogue (an http scenario has
no "stdout" to echo into) and is rejected at load time on an http scenario.

**`json_path` mini-syntax** — NOT full JSONPath, just a small dotted-key +
`[i]`-index accessor, composable in any order: `"a.b[0]"`, `"a[0].b"`,
`"a[0][1]"`. A missing key, an out-of-range index, a type mismatch (index
into a non-list, key into a non-dict), or a malformed path string (empty,
unterminated bracket, non-numeric index, …) is always treated as a
**mismatch** (`wrong_output`) — `evaluate_http` never raises on a malformed
`json_path`, it fails closed instead.

**Isolation note:** the http service runs under the exact same
tier-sandbox wrapper (`cooperative`/`standard`/`hardened`) and twin-env as
a CLI scenario's `when.run` command — reaching localhost to serve a
request does not open any hole to the control root or the holdout
scenarios.

**Honest scope (v1):** ONE service instance per scenario, started fresh and
always reaped by process group in a `finally` (even on assertion failure or
timeout — no orphan, ever); ONE request per scenario (no multi-request
session / stateful HTTP flow — that's a later refinement); the small
`json_path` accessor above, not full JSONPath; the port is located via
`port_env` only (no ephemeral-port self-reporting); no non-HTTP protocols.

`cohort` is the train/dev/test split: `dev` scenarios are the ones the
loop iterates against every step (feedback is drawn from these). `final`
scenarios are the sealed holdout — run **once**, only after the dev
cohort fully converges, and their results are **never** fed back into
the builder loop. A control root with no `final` scenarios administers
no sealed exam at all (this is the honest, back-compatible default —
everything behaves exactly as before `cohort` existed). `run_all(...,
cohort="dev"|"final")` filters to one cohort; `cohort=None` (the
default) runs everything, unchanged for existing callers.

`class` (M42) is an OPTIONAL, ORTHOGONAL axis: `"happy"` | `"boundary"` |
`"failure"`. Where `cohort` is feedback-vs-sealed, `class` is what-KIND-of-case:
a normal path (`happy`), an edge — empty/max/duplicate/missing/wrong-type
(`boundary`), or the error contract (`failure`). Absent ⇒ `happy` (back-compat:
every pre-M42 scenario is implicitly happy). The class label only matters to the
**adequacy gate** (`df_gates.check_adequacy`, `references/scenario-adequacy.md`),
which can require each behavior to be covered by a set of classes; a bad value is
rejected at load like a bad `cohort`.

Failure taxonomy (the ONLY thing that crosses the barrier, with the
behavior_id): `timeout` > `crash` > `wrong_exit_code` > `wrong_output` >
`no_twin_evidence` (priority order when several assertions fail; an http
scenario never produces `timeout` — its own bounded readiness/response
polling maps a never-ready or dead service onto `crash` instead, see
above). Coarse by design — the taxonomy is leak-resistant, not diagnostic.
Fixed vocabulary: the http scenario type (M20) reuses these SAME constants
rather than adding new ones, so this list and `id_feedback`'s taxonomy are
unchanged by it.

The versioned IR + this runner contract is the seam where M2+ swaps in
richer backends (spec section 5.1) without redesign.

**Discrimination requirement (M7):** a scenario's `then` must be
*discriminating* — it must reject a deliberately-wrong observation, not
just accept the right one. A tautological check (e.g.
`{"stdout_contains": ""}`, which matches any stdout) passes regardless
of what the build actually does, so a green run against it proves
nothing. Before a build starts, every scenario's `then` is
mutation-validated (`df_gates.is_discriminating`): it is evaluated
against a constructed adversarial mutant observation
(`exit_code` off-by-one, `stdout`/`stderr` replaced with a fixed
marker string), and must reject it. Any scenario whose `then` fails to
reject the mutant (`df_gates.validate_oracle`) is inert and aborts the
run before the builder is invoked (fail-closed pre-build gate). An http
scenario's `then` is gated the same way, against an adversarial mutant
HTTP response (`http_status` off-by-one-or-599, body/JSON replaced with a
mutant marker) — so an inert http check (e.g. `{"body_contains": ""}`) is
caught pre-build exactly like a CLI one.
