# Credential broker (M11) — containment, not rotation

**Honest scope up front:** M11 gives a builder a safe way to *receive*
provider credentials without raw tokens touching run artifacts, git, or
roles that don't need them. It cannot make a static API key "short-lived" —
provider keys have provider lifetimes. What M11 guarantees is
**containment** (allowlist-only, artifact-scrubbed, git-ignored), never
rotation. If you need short-lived credentials, that's a provider-side
concern (issue a scoped, expiring token yourself and put *that* in the
env-file) — the broker has no opinion on token lifetime.

## The containment model

Three enforced properties, independent of assurance tier:

1. **Allowlist-only injection.** The builder's env receives *exactly* the
   variable names in `credentials.allowlist` — nothing else is ever
   brokered. At `hardened`, nothing outside the allowlist enters the
   container env at all (`HOME=/tmp`, forced by `df_container.build_argv`
   for every hardened run regardless of credentials, is the sole
   exception). At `standard`/`cooperative`, the builder still inherits the
   launcher's environment (M10 behavior, unchanged) — M11 additionally
   strips every credential-*shaped* var (`(_API_KEY|_TOKEN|_SECRET|_PASSWORD)$`)
   that is NOT allowlisted, so an ambient `STRIPE_API_KEY` sitting in your
   shell doesn't leak into the builder just because dark-factory happened
   to be launched from that shell. See `df_creds.launcher_scoped_env`.

2. **Scrubbing.** Every resolved credential VALUE is redacted
   (`***REDACTED***`) out of the journal, every manifest, checkpoint
   reports, `state.json`, and captured verifier/final-exam reports
   *before* any of them is serialized to disk — one shared choke point
   (`supervisor._redacted_write` / `Journal.write`) that every writer
   funnels through, via a `df_creds.Redactor` built from the resolved
   values. Absent a `credentials` block, the redactor is `None` — a
   strict no-op, zero behavior change from pre-M11 runs. This is
   defense in depth, not the only line: if a builder ever writes a
   credential value into the **workspace artifact itself** (not a
   run-directory artifact), M9's mandatory `secret_scan` gate (if enabled)
   is the backstop — it flags the finding by rule name, never by value,
   the same way it does for any other planted secret.

3. **gitignore verification.** An `env-file` living inside a git work tree
   must be `git check-ignore`-clean, or the run refuses closed before
   anything else happens (`df_creds.check_gitignored`; also checks the
   file isn't already git-**tracked**, since ignoring a tracked path
   doesn't retroactively scrub it from history). A file entirely outside
   any git work tree needs no ignore rule — there's no repository for it
   to leak into. `env-file` permissions are enforced too: group/world
   readable (`mode & 0o077 != 0`) is a refusal with a `chmod 600` remedy.

## Sources

- **`env-file`** — `KEY=VALUE` lines (comments, blank lines, `export `
  prefix, and quoted values all accepted), read fresh at every run start
  (never cached, never touched at config-load time). Must be an absolute
  path, disjoint from both the control root and `workspace_root` (a run
  must never be able to read its own credential file through either
  tree), and pass the gitignore/permission checks above.
- **`keychain`** — macOS only in M11, via the `security` CLI
  (`security find-generic-password -s <service_prefix><NAME> -w`). Linux
  `secret-tool` is a natural future addition but isn't implemented — using
  `source: "keychain"` on a non-macOS host is a `CredsError`, not a
  silent no-op.
- **`env`** — the launcher's own environment (`os.environ`) at run start.
  Useful for CI where the credential is already injected by the runner.

Every source resolves through the same fail-closed discipline: a missing
env-file, a missing key inside it, an empty value, a missing keychain
item, or an unset launcher var is a `CredsError` — never a silent empty
string. The supervisor resolves credentials **before any builder call**,
in both a fresh `run` and every `resume` (never cached in `state.json`);
a `CredsError` there prints `dark-factory: credentials: <detail>` to
stderr and exits 2 with nothing written to `run_dir` at all.

## Guidance: never commit credentials

The standing rule this whole broker exists to make machine-enforced,
fail-closed: **credentials never go in `config.json`, `spec.md`, or
scenario files**, and an `env-file` never gets committed. Point
`credentials.env_file` at a path outside your project tree (e.g.
`~/.dark-factory/<project>/creds.env`) or use the macOS keychain. If the
file must live inside a repo for some reason, `.gitignore` it —
dark-factory will refuse to run otherwise, with the exact remedy in the
error message.

## Honest limits (deferred, not shipped in M11)

- **No rotation.** A static API key stays static for as long as the
  provider says it's valid. M11 contains the blast radius of a leak; it
  does not change the credential's lifetime.
- **`-e` argv is visible to a local `ps`.** At `hardened`, resolved values
  reach the container via `-e NAME=value` flags baked into the `docker
  run` invocation (`df_container.build_argv`) — never through the docker
  *client* process's own environment, but the argv of the `docker run`
  process itself is enumerable by anything that can run `ps` on the same
  host (other processes owned by the same user, primarily). This is a
  known, disclosed residual, not a secret weakness papered over. The
  alternative — piping credentials through `docker run --env-file
  <tmpfile>` so they never appear in argv at all — is a real mitigation
  M11 does not implement; `-e` was chosen because it matches
  `build_argv`'s existing, already-tested contract. If `ps`-visibility on
  the host is part of your threat model, don't run dark-factory
  `hardened` on a shared host you don't trust, or track the `--env-file`
  alternative as a follow-up.
- **Bridge-network exfiltration is out of scope until the enterprise
  credential proxy.** A malicious (or compromised) builder that receives
  a credential and has `hardened.network: "bridge"` (unrestricted egress)
  can still exfiltrate that credential over the network — nothing in M11
  inspects outbound traffic. Query-level egress control (only allow the
  specific API calls a credential is meant for) needs a real
  authenticating proxy sitting between the container and the internet;
  that's the enterprise tier's core function and is not part of M11.
  `network: "none"` (the default) has no egress at all, so this residual
  only applies if you've explicitly opted into `"bridge"`.
- **No transitive-dependency or supply-chain awareness.** The broker
  contains the credential's path from source to builder; it says nothing
  about what a legitimately-received credential is used *for* once inside
  the builder process (e.g. an npm postinstall script that phones home
  with it). That's outside a credential broker's job — see
  `references/security-gates.md` for what dark-factory *does* check on
  the converged artifact.

## See also

- `references/config-reference.md` — `credentials.*` schema + validation
  rules
- `references/hardened.md` — the container barrier `credentials` is
  brokered into (TCB growth, image/network honesty)
- `references/security-gates.md` — the `secret_scan` backstop for a
  credential a builder writes into the workspace artifact itself
