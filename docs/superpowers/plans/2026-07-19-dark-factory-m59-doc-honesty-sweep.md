# M59 — R5 doc-honesty sweep (Codex R5 DF-R5-11)

Every remaining R5 documentation-vs-implementation inconsistency. Docs-only (plus one docstring),
no behavior changes; full-suite regression gate still applies.

From the audit table (audit/08 §DF-R5-11) minus items already fixed by code in M56–M58:

1. `scripts/df_modes.py:15-18` docstring: says H2 has NO before-ship gate — STALE since M54's
   authoritative pause table + e2e tests include the H2 before-ship pause. Fix the docstring to
   match df_modes' own pause table.
2. `SKILL.md:36-48` "init uses the exact same validators / every blessed root is accepted by run"
   — TRUE after M58 (DF-R5-05 shared validator); re-read and keep, but qualify the environment
   prerequisites sentence if it overclaims (docker/sandbox availability is still run-time-only).
3. `SKILL.md:50-57` `hardened.dep_cache_dir` "part of the init interview" — TRUE after M58
   (options.hardened passes through). Verify wording matches the actual answers.options.hardened
   shape and fix if it describes a prompt-style interview that doesn't exist.
4. `SKILL.md:348` confinement "probe-verified" — no run invokes probe_confinement; manifest says
   `unverified`. Reword to structural/identity-verified (M52/M57 gate) + honest probe status.
5. `OVERVIEW.md:58-63` + `references/enterprise.md:7-8` "enterprise always requires a separate
   group / no one can ship alone" — custody.threshold:1 is valid; distinct keys ≠ distinct humans.
   Reword: K-of-N split custody SUPPORTS separation; threshold 1 is permitted config, and key
   custody, not the engine, establishes who holds them.
6. `references/audit.md:97` "legacy_allow_host_read is the Linux state until M29c" — M29c shipped.
   Update to present-tense default-deny description.
7. `supervisor.py:~1615-1624` `_sink_readback`-area docstring says inconclusive readback "is not
   rejected" — required receipts now demand POSITIVE readback (M53/M56). Fix docstring.
8. SKILL.md length note (503 lines > 500 guideline): trim if a natural cut exists while editing
   items 2-4; not a blocker.
9. `policy_digest` hashes config image string — FIXED in M58 (uses _effective_image); confirm no
   doc still describes the old behavior.

Process: grep each location, fix wording to match verified behavior (verify in code first, never
soften code to match docs), full suite, opus review OPTIONAL (docs-only; skip unless a docstring
change touches a security claim — item 4/5 wording gets a self-check against the actual gates).
