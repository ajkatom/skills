# Oracle IR v0 (M1) — hidden holdout scenario format

One JSON file per scenario in `<control_root>/scenarios/`. HOLDOUT: these files
never enter the build workspace, the builder prompt, or feedback.

Fields: `ir_version` ("0.1"), `id`, `behavior_id` (`^BHV-[A-Za-z0-9-]{1,32}$`),
`title`/`given` (human view only), `when.run` (argv list executed with
cwd = build workspace, `when.timeout_s` default 30), `then` (>= 1 of:
`exit_code`, `stdout_equals`, `stdout_contains`, `stderr_equals`,
`stderr_contains`; equality strips one trailing newline), optional
`cohort` (`"dev"` | `"final"`; default `"dev"` when absent; any other
value is an `OracleError`).

`cohort` is the train/dev/test split: `dev` scenarios are the ones the
loop iterates against every step (feedback is drawn from these). `final`
scenarios are the sealed holdout — run **once**, only after the dev
cohort fully converges, and their results are **never** fed back into
the builder loop. A control root with no `final` scenarios administers
no sealed exam at all (this is the honest, back-compatible default —
everything behaves exactly as before `cohort` existed). `run_all(...,
cohort="dev"|"final")` filters to one cohort; `cohort=None` (the
default) runs everything, unchanged for existing callers.

Failure taxonomy (the ONLY thing that crosses the barrier, with the
behavior_id): `timeout` > `crash` > `wrong_exit_code` > `wrong_output`
(priority order when several assertions fail). Coarse by design — the
taxonomy is leak-resistant, not diagnostic.

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
run before the builder is invoked (fail-closed pre-build gate).
