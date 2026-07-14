# Oracle IR v0 (M1) — hidden holdout scenario format

One JSON file per scenario in `<control_root>/scenarios/`. HOLDOUT: these files
never enter the build workspace, the builder prompt, or feedback.

Fields: `ir_version` ("0.1"), `id`, `behavior_id` (`^BHV-[A-Za-z0-9-]{1,32}$`),
`title`/`given` (human view only), `when.run` (argv list executed with
cwd = build workspace, `when.timeout_s` default 30), `then` (>= 1 of:
`exit_code`, `stdout_equals`, `stdout_contains`, `stderr_equals`,
`stderr_contains`; equality strips one trailing newline).

Failure taxonomy (the ONLY thing that crosses the barrier, with the
behavior_id): `timeout` > `crash` > `wrong_exit_code` > `wrong_output`
(priority order when several assertions fail). Coarse by design — the
taxonomy is leak-resistant, not diagnostic.

The versioned IR + this runner contract is the seam where M2+ swaps in
richer backends (spec section 5.1) without redesign.
