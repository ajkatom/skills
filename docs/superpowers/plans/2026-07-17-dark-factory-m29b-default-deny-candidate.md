# M29b — DF-02 (host-read half): default-deny candidate sandbox at `standard` (macOS) + port-pinned loopback

_Scoped slice of the approved remediation plan's M29: sub-items **29c**
(host-read isolation at standard via default-deny) and **29e-macOS**
(loopback restricted to a run-specific exact-port allowlist), for the
macOS `sandbox-exec` backend — the one live-verifiable on this host.
The Linux counterparts (mount+PID namespace default-deny, netns-local
verifier/twins, per-scenario PID-namespace reaping, 29f candidate
container) land in M29c as code + skipped tests + documented CI. 29d
(copy-on-run scratch) is its own follow-up milestone._

## Goal

Today the `standard`-tier CANDIDATE wrapper is `(allow default)` + deny
control-root: the candidate (the built artifact under test — the least
trusted code in the system) can freely READ the operator's entire host —
`~/.ssh`, browser profiles, cloud credentials, other repos — and, in
`loopback` network mode, reach EVERY host loopback service (local DBs,
debug ports, the enterprise credential proxy). Audit DF-02/#13/#15. After
M29b: the candidate at standard runs under a **default-deny** macOS
profile — nothing readable except a designed runtime allowlist + the
workspace; nothing writable except the workspace + scratch; loopback (when
enabled) reachable ONLY on the run's own twin/candidate ports — all
probe-verified fail-closed, with the honest residuals measured and
documented, and the result surfaced as a manifest `host_isolation` field
(the `host_isolation_qualified` signal M36's qualification FSM will
consume).

## Non-goals / blast-radius containment

- The BUILDER wrapper is untouched (CLI builders legitimately need HOME,
  keychain, DNS; their isolation story is the hardened/enterprise
  container). This milestone is about the CANDIDATE/verifier wrapper only —
  exactly the M27 `candidate_network` precedent.
- The overall `qualified` boolean is NOT re-derived here (that is M36's
  single qualification state machine). M29b computes and seals the honest
  `host_isolation` field; M36 folds it in.
- Linux: `wrap_candidate_prefix` on the bwrap backend keeps its CURRENT
  behavior (ro-bind / + tmpfs mask) and reports
  `host_isolation.mode="legacy_allow_host_read"` — flagged, documented,
  fixed in M29c. Do not half-build a Linux default-deny now.

## Approach (5 tasks)

### Task 1 — `df_sandbox.py`: default-deny candidate profile + probes
New, SEPARATE function `wrap_candidate_prefix(deny_root, workspace,
network, allowed_loopback_ports=None, scratch_dirs=())` on the macOS
backend (leave `wrap_prefix` — the builder/back-compat wrapper — exactly
as is; run_scenarios/verify callers migrate in Task 3):

- Profile skeleton `(version 1) (deny default)` then explicit allows,
  developed EMPIRICALLY on this machine (the implementer MUST iterate
  live: run `sandbox-exec -p <profile> python3 -c ...` until the Python
  runtime + a subprocess + a loopback client/server work; use
  `(trace ...)`-free minimal profiles, note each allow's reason in a
  comment). Expected shape (verify, don't trust this list):
  - `file-read*` on system runtime subpaths: `/usr`, `/bin`, `/sbin`,
    `/System`, `/Library`, `/private/etc`, `/opt/homebrew` (Python may
    live there), `/var/db/dyld`, `/dev` basics, plus the WORKSPACE subpath
    and each entry of `scratch_dirs` (e.g. the run's tmp dir); allow
    `file-read-metadata` more broadly if required for path resolution
    (document why). NEVER a subpath of `deny_root` and never `$HOME`
    outside the workspace: add explicit `(deny file-read* (subpath
    "<real deny_root>"))` and `(deny file-read* (subpath "<real $HOME>"))`
    AFTER the allows as belt-and-suspenders (deny wins over allow in SBPL;
    verify precedence live).
  - `file-write*` ONLY on workspace + scratch_dirs + `/dev/null`,
    `/dev/dtracehelper`, `/private/var/folders` tmp subpath if the runtime
    demands it (measure; keep as narrow as possible; anything added must
    be justified in a comment).
  - `process-exec*`/`process-fork` on the allowed read paths (candidate
    apps spawn `python3`).
  - `mach-lookup` DEFAULT-DENIED (this is the win: under `(deny default)`
    Mach services are denied unless allowed). Allow ONLY the global names
    the Python runtime demonstrably needs to start (measure live; expected
    to be few — e.g. `com.apple.system.notification_center`,
    `com.apple.system.logger`; add exactly what's needed with a comment
    each). Explicitly DO NOT allow `com.apple.SecurityServer` /
    `com.apple.securityd*` (keychain) or
    `com.apple.mDNSResponder`/`com.apple.dnssd.service` (DNS). If the
    runtime turns out to hard-require the resolver/keychain services to
    even start, fall back to allowing them and set the residual flags
    honestly (see Task 2's `residuals`) — measured truth over aspiration.
  - `network*`: mode `deny` → nothing; mode `loopback` → allow ONLY
    `(remote ip "localhost:<port>")` for each port in
    `allowed_loopback_ports` (exact ports, never `localhost:*`) plus what
    a LISTENING candidate needs (`network-bind`/`network-inbound` on
    localhost — measure which primitives inbound requires under deny-
    default; the M20 HTTP oracle must still work). `unrestricted` at
    standard becomes `(allow network*)` (unchanged semantics, still
    default-deny on files).
- `probe_candidate_confinement(backend, deny_root, workspace, network,
  allowed_loopback_ports, scratch_dirs) -> (ok, report_dict)` — the
  fail-closed live probe, run per-run before scenarios (like
  `probe_denial`). Wrapped child attempts, each line a marker:
  1. read control-root canary → must DENY;
  2. read a canary planted in a temp dir OUTSIDE workspace/system paths
     (stand-in for `~/.ssh`) → must DENY;
  3. read `$HOME/.ssh` (real path; ANY outcome except explicit
     PermissionError/denial counts as leak — missing file raises
     FileNotFoundError which is NOT proof of denial: treat ENOENT by
     probing `$HOME` listing instead; design this carefully and
     fail-closed) → must DENY;
  4. write into workspace → must ALLOW (non-vacuity: the sandbox isn't
     just broken);
  5. write outside workspace (temp canary dir) → must DENY;
  6. keychain: `security find-generic-password -s df-probe` (or a direct
     `SecItemCopyMatching` via ctypes if `security` is denied exec —
     acceptable: exec-denial of /usr/bin/security IS denial) → must DENY
     (denied exec, denied mach-lookup, or error exit all count as denied;
     a successful query = leak);
  7. DNS: `socket.getaddrinfo("dark-factory-probe.invalid", 80)` with a
     short timeout → must FAIL (denied resolver = immediate error; if it
     resolves/times-out-through-the-resolver, record residual
     `dns_mach_ipc_open`) — probe distinguishes hard-deny from open
     residual;
  8. network per mode (reuse `probe_network_denial`'s external/loopback
     discipline, plus in loopback mode: connect to an ALLOWED port
     succeeds AND connect to a fresh NOT-allowed loopback listener is
     DENIED — the port-pinning must be proven non-vacuously).
  Returns a structured report `{checks: {...}, residuals: [...]}` for the
  manifest. ANY ambiguity → not ok.
- Linux backend: `wrap_candidate_prefix` returns the CURRENT
  `wrap_prefix` argv (legacy) and `probe_candidate_confinement` returns
  `(ok_from_legacy_probes, report(mode="legacy_allow_host_read"))` —
  honest, no fake default-deny claim.

### Task 2 — config + manifest surface
- New config value under the existing candidate axis: `candidate_host_read:
  "default_deny" | "allow_host_read"`, default **`default_deny` at
  standard+** (this IS the remediation; existing configs get the stronger
  behavior automatically), rejected at cooperative (no sandbox exists
  there — mirror `candidate_network`'s tier rules). `allow_host_read` is
  the explicit, honest opt-out (some candidate legitimately needs host
  reads) — allowed, but the manifest marks
  `host_isolation.qualified=false, mode="allow_host_read_optout"`.
- Manifest field `host_isolation` (sealed alongside `candidate_network`):
  `{mode, probed, passed, residuals: [...], qualified: bool}` where
  `qualified` is true ONLY for `default_deny` + probe-passed + empty
  hard residuals (dns/keychain open ⇒ listed in residuals; decide + doc
  whether each residual is disqualifying: keychain-open ⇒ disqualifying;
  dns-open ⇒ disqualifying at `deny`/`loopback` network modes since the
  whole point is no exfil channel — document the reasoning either way).
  At hardened/enterprise the candidate runs where it always did (this
  field records `mode="container"` semantics unchanged — wire honestly,
  minimal change).
- Fail-closed at run start (standard tier, default_deny): probe fails →
  refuse the run (distinct stderr + journal event
  `CANDIDATE_CONFINEMENT_PROBE_FAILED`, exit 2), mirroring the existing
  sandbox-probe refusal; `--allow-downgrade` may downgrade to
  `allow_host_read` (journaled, manifest-marked unqualified) — mirror the
  existing downgrade UX exactly.

### Task 3 — supervisor + run_scenarios wiring
- Where `resolve_candidate_prefix` builds the candidate wrapper, switch to
  `wrap_candidate_prefix`, passing: the run's twin ports + any HTTP-oracle
  candidate port as `allowed_loopback_ports` (twins are started by the
  supervisor BEFORE scenarios run, so ports are known; the HTTP scenario's
  candidate port — find how M20 assigns it — must be included; if a port
  is assigned per-scenario at runtime, thread the wrapper construction to
  where the port is known, or pre-allocate the port before wrapping — pick
  the design that keeps ONE wrapper per verification pass if possible and
  document it), and the scenario scratch dirs.
- Run `probe_candidate_confinement` once per run (standard tier) before
  the first verification pass; journal + manifest per Task 2.
- The verifier's OWN poll client (`_run_http_scenario`'s ready-poll and
  the oracle's HTTP calls) runs OUTSIDE the wrapper today (only the
  candidate `start` argv is wrapped) — verify that's still true and keep
  it that way (the wrapper confines the CANDIDATE, not the verifier).

### Task 4 — tests (live on macOS, in-suite)
- Unit: profile construction (ports appear exactly; deny_root/$HOME denied
  clauses present; unknown mode raises; Linux legacy passthrough).
- Live (skip-if-no-sandbox-exec, like existing M2b/M27 live tests):
  - default-deny probe passes on this machine with a real workspace;
  - host-read canary (temp dir) unreadable; workspace writable;
  - port-pinning: allowed loopback port reachable, second unallowed
    loopback listener denied (non-vacuous);
  - keychain + DNS probe outcomes recorded; assert the manifest residuals
    match measured reality (whatever it is — the test asserts
    HONESTY, not a wished-for outcome: if DNS turns out open, the test
    asserts `dns` ∈ residuals and `qualified` false accordingly).
  - e2e standard run (fake builder) → CONVERGED with
    `host_isolation.mode="default_deny"`, probe-passed, and the existing
    suite's standard-tier e2e tests still green (they may need the new
    field asserted/tolerated).
  - opt-out e2e: `candidate_host_read: "allow_host_read"` →
    `host_isolation.qualified=false` on the manifest.
- The whole existing suite stays green: notably M20 HTTP-oracle live
  tests, M3a/M12 twin tests, M27 candidate_network tests — these all
  exercise the candidate wrapper and WILL break if the default-deny
  profile is too tight; fixing the profile (not loosening the tests) is
  the job.

### Task 5 — docs
- `references/isolation.md`: the default-deny candidate profile — what's
  allowed and why, the probe checklist, the measured residuals on macOS,
  the `allow_host_read` opt-out, Linux legacy status (fixed in M29c).
- `references/audit.md`: `host_isolation` manifest field semantics + that
  M36 will fold it into `qualified`.
- SKILL.md: one interview line (candidate host-read is default-deny at
  standard; opt out only if the app truly needs host reads, at the cost of
  host-isolation qualification).
- `references/prevention-grade-roadmap.md`: update the DF-02 entry (env
  half merged in M29a; host-read half now detection+prevention at
  standard-macOS; Linux + container variants → M29c).

## Key decisions & tradeoffs
- Default-deny is the DEFAULT at standard (remediation, not opt-in);
  explicit `allow_host_read` opt-out keeps legitimate use cases working
  but visibly unqualified.
- Candidate-only: builder wrapper untouched.
- Mach services default-denied — this potentially CLOSES the keychain and
  DNS side channels M27 documented as open; but the profile allowlist is
  developed empirically and the probes assert measured truth (if the
  runtime forces resolver/keychain open, the manifest says so).
- One wrapper per verification pass with pre-known ports, rather than
  per-scenario wrappers, unless the port-assignment plumbing forces
  otherwise.

## Risks
- Default-deny SBPL profiles are notoriously fiddly; the implementer must
  iterate live and may need `file-read-metadata` breadth. Budget time.
- HTTP-oracle inbound (candidate LISTENS) under deny-default needs the
  right network-bind/inbound allows — measure on this macOS version.
- Existing live tests are the canary for over-tightening.
