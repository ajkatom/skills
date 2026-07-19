# dark-factory isolation (standard tier)

`standard` runs the builder AND the candidate under an OS read-denial sandbox that
cannot read the control root (scenarios/runs). Backends: macOS `sandbox-exec`
(`(allow default)(deny file-read* (subpath control_root))(deny file-write* ...)`),
Linux `bwrap` (masks the control root with a tmpfs, then **seals that mask
read-only** with `--remount-ro`). Windows: no backend yet → unsupported.

The Linux mask is three ordered steps: `--tmpfs <control_root>` shadows the real
control-root content with an empty overlay (reads denied — the real scenarios/
journal are gone from the wrapped view), `--remount-ro <control_root>` remounts
that overlay `MS_RDONLY` (defeats permission-bit / `CAP_DAC_OVERRIDE` writes — a
read-only MOUNT is kernel-enforced regardless of DAC), and `--cap-drop ALL`
(defeats the `CAP_SYS_ADMIN` remount escape). All three are required:

- A bare `--tmpfs` alone leaves an owner-writable overlay, so the write half of
  `probe_denial` fails — the backend would fail its own fail-closed startup
  probe and the tier would be unusable on Linux.
- `--remount-ro` alone is still escapable: a child holding **ambient
  `CAP_SYS_ADMIN`** (setuid-root bwrap, as Debian/Ubuntu package it, or a
  supervisor running as root) can `mount -o remount,rw <control_root>` and then
  write, because privileged bwrap does not strip caps from the child unless told.
  `--cap-drop ALL` makes that remount fail ("permission denied, are you root?").
- The `--bind` workspace stays read-write throughout, so the builder can still
  write its artifact.

Together these give Linux the same read AND write denial macOS already had,
satisfying M12's dual-denial probe on a real kernel.

`probe_denial` proves all of this and is itself hardened against the escape: on
Linux its wrapped child performs a FOURTH check beyond the naive fresh-file
write and canary truncation — it attempts a rw remount of the masked control
root (`mount(..., MS_REMOUNT, ...)` via ctypes) and treats a successful remount
as a leak. So dropping `--cap-drop ALL` makes `probe_denial` return False rather
than false-PASS (regression-guarded by `test_probe_catches_cap_sys_admin_remount_escape`).

A tier is claimed only when **probe-verified**: at startup a canary is planted in
the control root and a wrapped process must fail to read it AND fail to write
there (a fresh file, and a truncation of the canary). If the backend is
missing or the probe fails, the run **fails closed** (exit 2) unless
`--allow-downgrade` drops it to `cooperative` (unqualified) with a warning + a
`DOWNGRADE` audit entry. The denial probe is the guarantee that a backend is never
trusted without proof on the actual host.

## Candidate network authority (§7.4)

The read-denial sandbox above answers "can the process read/write the
control root?" — a separate, orthogonal question is "can the process reach
the network at all?" M27's `candidate_network` config answers that one, for
the **candidate only**.

**What it restricts.** `wrap_prefix(deny_root, workspace, network=...)`'s new
`network` parameter is applied EXCLUSIVELY to the verifier/candidate exec
wrapper (`resolve_candidate_prefix` in `supervisor.py`) — never to the
builder's wrapper (`exec_prefix`), which is threaded through completely
unchanged. The builder keeps whatever network access its tier already grants
(needed for its provider API calls: Claude/Codex/Gemini CLIs, or the stdlib
HTTP adapters); only the already-built candidate, at verify time, can have
its network authority narrowed. `cfg["candidate_network"] == "unrestricted"`
(the default) is a total no-op — `resolve_candidate_prefix` returns
`exec_prefix` unchanged, byte-identical to pre-M27 behavior.

**Unrestricted candidate egress is DISQUALIFYING at standard+ (M47 RA-08(a)).**
`unrestricted` remains the config DEFAULT (so no config errors, and cooperative
— which has no sandbox to enforce anything — is unaffected), but it is no longer
*non-disqualifying*. A qualifying-tier run (standard/hardened/enterprise) whose
candidate egress is left wide open ships an artifact that can reach anywhere,
which no `COMPLETE_QUALIFIED` seal should certify. The single qualification
state machine (`df_qualify.derive`) now folds a `candidate_egress` sub-state
into the qualification AND: it is True iff `candidate_network ∈ {deny,
loopback}`. An `unrestricted` candidate at a qualifying tier therefore seals the
distinct terminal code `CANDIDATE_EGRESS_OPEN` (qualified = False) — the run
still CONVERGES (the build succeeded), it just isn't qualified. To qualify a
standard+ run, set `candidate_network` to `deny` (no egress needed) or
`loopback` (digital twins on localhost stay reachable). This can only ever
NEWLY FAIL a run, never newly pass one (the superset invariant).

**Three modes** (`df_sandbox._NETWORK_MODES`):
- `unrestricted` (default) — no restriction; candidate and builder share the
  same network authority, exactly as before M27. At a qualifying tier this now
  seals `CANDIDATE_EGRESS_OPEN` (unqualified) per RA-08(a) above.
- `deny` — blocks ALL network I/O for the wrapped candidate, including
  loopback. macOS: `(deny network*)` appended to the sandbox-exec profile.
  Linux: `--unshare-net` (a fresh network namespace with no interfaces
  configured, not even a usable loopback).
- `loopback` — blocks everything except localhost, so host-bound digital
  twins stay reachable while real external egress is cut off. macOS only
  (see the Linux limit below): `(deny network*)(allow network* (remote ip
  "localhost:*"))`. Note (see `df_sandbox.py`'s module docstring): because
  macOS routes the host's OWN non-loopback addresses (its LAN IP) via `lo0`,
  the `localhost` allow-clause also permits reaching this host on its own
  addresses — that is still not external egress (which the live probe proves
  is cut against a real external target), just a slightly broader "local"
  than literal `127.0.0.1`.

**The live probe.** No mode beyond `unrestricted` is ever trusted without
proof: `probe_network_denial(backend, deny_root, workspace, mode)` spawns a
wrapped subprocess that attempts a real external connect (must fail for
`deny`/`loopback`) and a real loopback connect to a host-bound listener
(must succeed for `loopback`, must also fail for `deny`). It is fail-closed
end to end — any spawn failure, timeout, or ambiguous output is `(False,
reason)`, never a guess — and it is **non-vacuous by construction**: a
BASELINE unwrapped connect to the external target must succeed first, or
the probe refuses outright (`"baseline connect ... failed — probe
environment unusable"`) rather than reporting a meaningless "denial" against
a host with no egress to begin with. `resolve_candidate_prefix` calls this
probe before anything relies on the restriction; a failing probe raises
`SandboxError` (journaled `PROBE_FAILED`) and the run refuses (exit 2)
rather than proceeding with an unproven restriction.

**Fail-closed refusals** (all at config-load or pre-build gate time, never a
silent downgrade):
- **`candidate_network != "unrestricted"` at `cooperative`** — `df_config`
  rejects at load time (`"candidate_network requires assurance: standard or
  above (cooperative has no sandbox to enforce it)"`): there is no sandbox
  at that tier to enforce anything.
- **`deny` + `twins.enabled`** — `df_config` rejects at load time
  (`"candidate_network 'deny' would make configured twins unreachable; use
  'loopback' (macOS) or remove twins"`): a twin is a host-bound
  `127.0.0.1` server, which `deny` blocks along with everything else.
- **`deny` + an http scenario** — a separate `supervisor.py` pre-build gate
  (scenarios aren't loaded yet at config-load time) refuses BEFORE any build
  runs, naming every offending scenario id: an http scenario polls the
  candidate's own service over `127.0.0.1`, which `deny` blocks exactly like
  external egress (only `loopback` keeps that reachable).
- **`loopback` on Linux** — `_LinuxBackend.wrap_prefix` raises `SandboxError`
  outright: `bwrap`'s `--unshare-net` namespace has its own private
  loopback interface, disconnected from the host's, so there is no way to
  express "deny external, allow the host's 127.0.0.1" with this primitive
  (see the Linux limit below).
- **A configured restriction that resolves to `cooperative` at runtime**
  (e.g. via `--allow-downgrade` when the base OS-sandbox probe fails) — there
  is no sandbox left to enforce the restriction, so this fails closed exactly
  like a failed isolation probe (`PROBE_FAILED`, `SandboxError`, clean exit
  2), never silently runs the candidate unrestricted.

**Honest limit — macOS DNS/mDNSResponder side channel.** `(deny network*)`
denies the wrapped process's OWN socket-level network operations, and the
probe proves that for TCP connects. `getaddrinfo()` is serviced by
`mDNSResponder`, a separate, unconfined system daemon reached over Mach IPC
— not a `network*` operation performed by the wrapped process itself — so
the daemon may still issue real DNS queries on the candidate's behalf even
under `deny`. A hostile candidate could therefore exfiltrate bits via DNS
query names despite the socket-level denial holding. Closing that gap would
require denying Mach IPC to the resolver (a much broader, app-breaking
profile) — a documented limit, not silently ignored. Linux's
`--unshare-net` has neither gap: the namespace has no route to the resolver
or anything else. UDP and other socket types are denied by the same
`network*` primitive by construction on macOS but are not separately probed
(only TCP connects are). **M29b update:** this limit now applies only to the
`(allow default)` wrapper (the builder's, and the candidate's under the
`allow_host_read` opt-out or the legacy fallback wrapper) — the M29b/M29c
default-deny
CANDIDATE profile default-denies Mach IPC, which was measured to CLOSE the
resolver channel for the candidate at `deny`/`loopback` (see "Default-deny
candidate host isolation" below).

**Honest limit — Linux `loopback` is unsupported, not silently degraded.**
`bwrap --unshare-net` gives the candidate its own private network
namespace, which includes its own private loopback — a host-bound twin
server on the HOST's `127.0.0.1` is simply not reachable from inside that
namespace at all, restricted or not. Bridging the two (a veth pair plus a
NAT/slirp userspace network, e.g. `slirp4netns`) is out of scope for M27 —
it's a materially larger primitive than a `wrap_prefix` argv tweak, and YAGNI
until a real need for Linux-loopback-plus-twins shows up. Use `deny` on
Linux when you don't need twins/http scenarios reachable, or run on macOS
when you do.

## Candidate process + env containment (DF-02)

The read-denial sandbox and `candidate_network` above answer "can the process
read/write the control root?" and "can it reach the network?" — two further,
orthogonal questions are "what host environment does the candidate's own
process inherit?" and "does anything the candidate spawns outlive the
scenario that started it?" M29a Task 1/2 (`run_scenarios.py`) answer those,
at **every tier**, independent of which sandbox backend (if any) is active.

**Minimal allowlisted environment (`candidate_env`).** Every candidate/verifier
scenario — CLI (`run_scenario`) and HTTP (`_run_http_scenario`) alike — used to
launch its subprocess with `dict(os.environ, **env_extra)`, i.e. the operator's
full ambient shell environment plus whatever the supervisor injected.
`candidate_env(env_extra)` replaces that with:
- an explicit **allowlist** of host vars a normal program needs to run at all —
  `PATH`, `HOME`, `LANG`, `LANGUAGE`, `TMPDIR`, `TMP`, `TEMP`, `TERM`, `TZ`,
  `PWD`, `SHELL`, `USER`, `LOGNAME` (`_CANDIDATE_ENV_ALLOWLIST_NAMES`), plus
  every `LC_*` locale variable by prefix — UNION
- `env_extra`, the supervisor-injected, trusted portion (twin endpoints, the
  M11 credential allowlist), passed through unfiltered since the supervisor
  already decided what belongs there.

A **denylist** is applied as a belt-and-suspenders scrub to the allowlisted
host portion (never to `env_extra`, which is supervisor-controlled), covering
known-dangerous names (`SSH_AUTH_SOCK`, `SSH_AGENT_PID`, `SSH_CONNECTION`,
`GH_TOKEN`, `GITHUB_TOKEN`, `DOCKER_HOST`, `KUBECONFIG`), whole cloud/provider
credential prefix families (`AWS_`, `GOOGLE_`, `GCP_`, `AZURE_`, `ANTHROPIC_`,
`OPENAI_`, `GEMINI_`), and a case-insensitive substring check
(`PROXY`, `SECRET`, `TOKEN`, `PASSWORD`, `APIKEY`, `API_KEY`, `CREDENTIAL`) —
so `*_PROXY` and any vendor's `*TOKEN*`/`*SECRET*`/`*API_KEY*` are caught
regardless of prefix. If a denylisted name somehow shows up in `env_extra`
(the supervisor itself injecting something it shouldn't), `candidate_env`
fails closed with a real `raise ValueError` rather than an `assert` — the
latter compiles out under `python -O`/`PYTHONOPTIMIZE`, which would silently
let the leak through. Net effect: generated candidate code no longer inherits
the operator's SSH agent socket, proxy config, cloud credentials, or CLI API
keys just by being spawned — only the minimal runtime env plus whatever the
supervisor explicitly threaded through.

**Full process-group teardown.** Both scenario launchers now start their
subprocess with `start_new_session=True` (a fresh session/process group, PGID
== PID at launch) and capture that PGID immediately, before anything else can
happen to the child. `_reap_process_group` is always invoked from a `finally`
— on normal completion, on an oracle timeout, and on a launch failure — and
mirrors `df_twins.TwinSet.stop()`'s discipline: `SIGTERM` the whole captured
process group, wait up to 3s for the direct child to exit, then `SIGKILL` the
group if anything is still alive (checked via `os.killpg(pgid, 0)`), polling
up to 2s more for the group to actually clear. Because the PGID is captured
once at launch and never re-resolved later via `os.getpgid(proc.pid)`, an
already-exited direct child (e.g. a shell wrapper) can't cause a
still-running grandchild in the same group to leak. A candidate that merely
backgrounds or detaches a child WITHIN its process group is still in that
group and still gets killed. Applies identically to CLI scenarios
(`run_scenario`) and HTTP scenarios (`_run_http_scenario`, which additionally
reaps the started service regardless of whether it ever became ready or
answered the request).

**Honest residual — process-group escape on a HOST backend (M47 RA-08(b)).**
`killpg` reaps a process *group*. A candidate that deliberately calls
`setsid()` (or double-forks) creates its OWN new session/process group, which
is NOT the captured PGID — so on a HOST backend (macOS `sandbox-exec`, and the
standard-tier host path) that escaped process is not guaranteed to be reaped.
This is a real, named residual, not a closed hole. It is fully closed only by
a backend that gives the candidate its own **PID namespace** — Linux
`--unshare-pid` (M29c netns) or a hardened/enterprise container — where every
descendant, setsid'd or not, dies with the namespace by construction. The
manifest records this honestly in the `host_isolation` block:

- `process_containment: "namespace"` — a PID-namespace backend; no escape.
- `process_containment: "process_group_besteffort"` — a host backend; the
  reap is best-effort, and the block carries the SOFT residual
  `process_group_escape` (soft = auditable but NON-disqualifying; it does not
  flip `host_isolation.qualified`, which gates on host-READ containment).

So a host-backend run is not silently claimed to fully contain a hostile
candidate's descendants — an auditor sees the exact ceiling in the sealed
manifest. Detection-grade, not prevention-grade, for this specific vector on a
host backend; use a hardened/enterprise (or Linux netns) backend to close it.

**Honest scope.** This is the env/IPC + process half of DF-02. The host-READ
half — a candidate reading the operator's home directory, dotfiles, other
repos — is closed by M29b's default-deny candidate profile on macOS and
M29c's on Linux (next two sections).
Copy-on-run scratch per scenario (so a candidate's writes never touch a
shared workspace across scenarios) remains tracked for M29d. What IS closed
by M29a Tasks 1-2: a candidate can no longer read the operator's ambient
secrets via environment variables, and a candidate can no longer leave a
surviving background/daemon process behind after its scenario ends.

**Validation runs against the SEALED object (M44 RA-01).** The M29d note above
is now NARROWER. As of M44 the post-convergence security gates and the sealed
final exam no longer run against the mutable `workspace`: after the artifact is
frozen, the supervisor materializes two throwaway copies of the SEALED object
(`R_gates` for the gates, `R_exam` as the final cohort's cwd; both siblings of
`workspace`, so candidate confinement — which denies the control root — still
allows them) and validates THOSE. A final-cohort scenario side effect (or a
hostile candidate) that scrubs `workspace` after the freeze can no longer
launder a gate result: the gates scan a copy of the shipped bytes. The
remaining M29d residual is strictly per-SCENARIO copy-on-run WITHIN the final
cohort (one final scenario mutating state a later one in the same cohort sees);
the shipped-vs-validated-bytes gap that M44 RA-01 addressed is closed.

## Default-deny candidate host isolation (M29b, DF-02 host-read half)

Everything above wraps the candidate in `(allow default)` + deny-control-root
— which still lets the least-trusted code in the system (the BUILT ARTIFACT
under test) read `~/.ssh`, browser profiles, cloud credentials, keychain
files, brew service configs, other repos,
and, in `loopback` mode, reach EVERY host loopback service. M29b replaces the
CANDIDATE wrapper (builder wrapper untouched — CLI builders legitimately need
HOME/keychain/DNS; their isolation story is the hardened/enterprise
container) with a **default-deny** profile on macOS:
`df_sandbox.wrap_candidate_prefix` builds `(version 1)(deny default)` + an
empirically developed minimal allowlist. Config: `candidate_host_read:
"default_deny" | "allow_host_read"`, **default `default_deny` at standard+**
(the remediation is the default; existing configs get the stronger behavior
automatically); `allow_host_read` is the explicit, honest opt-out for
candidates that genuinely need host reads — allowed, but the manifest marks
`host_isolation.qualified: false`.

**What the profile allows, and why** (each measured live on macOS 26.5;
SBPL is last-match-wins, so clause ORDER is load-bearing — see the profile
builder's comments for the full experiment notes):
- system runtime reads: `/usr /bin /sbin /usr/local /opt/homebrew /System
  /Library /private/etc /private/var/db/timezone /dev`, plus
  `file-read-data` on `/` itself (dyld reads the root dir; SIGABRT in
  `dyld4::CacheFinder` without it) and the active Xcode/CLT developer
  bundle (the `/usr/bin/python3`-style xcrun shims dlopen `libxcrun` and
  sibling frameworks out of it) — then a last-match-wins **carve-out deny**
  of the sensitive DATA leaves that sit inside those broad roots but are not
  `$HOME` (so the `$HOME` deny misses them) and not runtime code:
  `/Library/Keychains` (System/apsd keychain FILES — the Mach keychain
  channel is closed but the files are world-readable root-owned data),
  `/opt/homebrew/etc` + `/opt/homebrew/var` and the Intel `/usr/local`
  equivalents (brew service configs like `redis.conf requirepass` and live
  DB data). Both leaks were proven readable pre-carve-out; the per-run probe
  now reads back whichever of these exist and asserts DENIED, so the
  carve-outs can't silently regress;
- broad `file-read-metadata` (PATH search + exec-time `realpath()` break
  outright without it) — metadata is stat/existence only, contents stay
  denied, and `$HOME`/control-root metadata is still denied by their later
  `file-read*` denies; the leftover stat-visibility outside `$HOME` is
  surfaced honestly as the `file_metadata_outside_home` residual;
- a belt-and-suspenders `$HOME` read+write deny, then (after it — last
  match wins) the workspace (read+write+exec), the verifier interpreter's
  own realpath'd prefixes (a venv may live under `$HOME`), and any
  characterize scratch dir;
- process plumbing: fork; exec on the system/runtime/workspace paths;
  `file-map-executable`; `sysctl-read`; `signal`/`process-info*` scoped
  `(target same-sandbox)` (`self` broke `subprocess.run(timeout=...)`
  killing its own child); `/dev/null` + `/dev/dtracehelper` write;
  `mach-lookup com.apple.bsd.dirhelper` (per-user dir resolution —
  `confstr` fails without it and every xcrun shim degrades) and the
  `xcrun_db*` toolchain cache paths (tool-name→path map, no user data —
  never the whole per-user temp dir).
- network per `candidate_network` mode: `deny` → nothing; `loopback` →
  `network-outbound` pinned to **exact run-specific ports** (this run's twin
  ports, re-derived per verify pass since twins bind fresh ephemeral ports
  on every reset — never `localhost:*`), plus `network-bind`/
  `network-inbound` on localhost so an M20 HTTP-oracle candidate can still
  LISTEN (bind/inbound specifically — the `(allow network* (local ip ...))`
  form was measured in M27 to re-open external egress); `unrestricted` →
  `(allow network*)` plus a `com.apple.dnssd.service` mach-lookup so DNS
  works (unchanged network semantics; files stay default-deny).
- DEAD LAST: the control-root read+write denies, so nothing can override
  them.

**Side channels measured CLOSED.** Because `(deny default)` also
default-denies Mach IPC, the two channels M27 documented as open are closed
for the candidate on this backend, measured via `bootstrap_look_up` (kr=0
reachable unwrapped, kr=1100 denied wrapped): **keychain**
(`com.apple.SecurityServer` — note `security find-generic-password` exit
codes cannot prove this: measured rc 44 "not found" both wrapped and
unwrapped) and **DNS** (`com.apple.dnssd.service` — `getaddrinfo()` errors
immediately instead of reaching the resolver daemon, so the DNS-exfil
residual documented for the builder wrapper above does NOT apply to the
candidate at `deny`/`loopback`).

**Per-run fail-closed probe.** `probe_candidate_confinement` runs before the
first verify pass (and on every resume): a wrapped child must be DENIED
reading a control-root canary, an outside-workspace canary (temp-dir
stand-in for `~/.ssh` — the real `~/.ssh` is ENOENT-ambiguous when absent,
so the unambiguous check is a LISTING of `$HOME` itself), and `$HOME`; must
SUCCEED writing the workspace and spawning a subprocess (non-vacuity: a
sandbox that denies everything would "pass" every denial check); must be
DENIED writing outside; keychain/DNS Mach lookups per the measured-closed
expectations; DENIED reading the real sensitive system-data files
(keychains, brew service dir — non-vacuously: each is asserted readable
UNWRAPPED first); and in `loopback` mode the port-pinning is proven
non-vacuous against two LIVE listeners (allowed port reachable AND a second
live-but-unallowed listener denied). Probe failure refuses the run
(`CANDIDATE_CONFINEMENT_PROBE_FAILED`, exit 2); `--allow-downgrade` falls
back to the legacy wrapper as `mode: "allow_host_read_downgrade"`
(journaled, unqualified). A keychain-OPEN measurement is treated as a LEAK
(probe fails); a DNS-OPEN measurement at `deny`/`loopback` is recorded as
the `dns_mach_ipc_open` residual and disqualifies without refusing (file
isolation is independently proven — measured truth over aspiration).

**Manifest.** Every terminal manifest carries `host_isolation: {mode,
probed, passed, residuals, qualified}` (sealed alongside
`candidate_network`); `qualified` is true only for `default_deny` +
probe-passed + no disqualifying residuals (`file_metadata_outside_home` and
`network_unrestricted_open` are the two structural, non-disqualifying ones).
M36's qualification FSM will fold this into the overall `qualified` boolean.

**Honest limits.** (a) The Linux default-deny profile is a SEPARATE backend
with its own probe (next section, M29c). The real Linux backend now
advertises `supports_default_deny` UNCONDITIONALLY, so a host where bwrap
cannot create the namespace (too old, or unprivileged with user namespaces
disabled) does NOT silently fall back to a host-readable legacy wrapper — the
live confinement probe FAILS and the run is REFUSED
(`CANDIDATE_CONFINEMENT_PROBE_FAILED`, exit 2), or, with `--allow-downgrade`,
drops to `mode: "allow_host_read_downgrade"` (journaled, unqualified). The
`legacy_allow_host_read` path now only applies to a backend WITHOUT
`supports_default_deny` (e.g. a test double). (b) Candidates using an
interpreter/runtime outside the
system paths + the verifier interpreter's prefixes need the
`allow_host_read` opt-out — the honest tradeoff, not a silent widening.
(c) `network-bind`/`network-inbound` on localhost are port-wildcarded (the
HTTP oracle assigns the candidate's own port per scenario); LISTENING on a
loopback port is not a host-read/exfil channel, and outbound pinning is
what protects host loopback services. (d) stat/existence metadata outside
`$HOME` stays visible (see the residual above).

## Default-deny candidate host isolation on Linux (M29c, DF-02 Linux half)

The Linux parallel of M29b: `_LinuxBackend.wrap_candidate_prefix` no longer
falls back to the legacy `--ro-bind / /` passthrough. It now builds a REAL
default-deny **mount + PID + IPC + UTS namespace** (plus `--unshare-net` at
`network: "deny"`) from EXPLICIT minimal binds, and the backend advertises
`supports_default_deny = True`, so the supervisor flows it through the exact
same backend-agnostic path M29b built (probe → seal `host_isolation`). A
passing Linux `standard` run now reports `host_isolation.mode:
"default_deny"`, `qualified: true` — where it previously reported
`legacy_allow_host_read` and could not qualify.

**The final argv** (developed and proven live under `docker run --privileged
ubuntu:24.04`, bwrap 0.9.0), each bind justified:
- `--unshare-pid --unshare-ipc --unshare-uts` — private PID/IPC/UTS namespaces
  (the candidate cannot see or signal host processes, or read host SysV IPC).
- `--proc /proc` — a PRIVATE proc for the new PID ns, **not** a host
  `--ro-bind` (which would leak every host process's `cmdline`/`environ`/root
  via `/proc/<pid>`).
- `--dev /dev` — minimal private devtmpfs (`null`/`zero`/`urandom`/`tty`…);
  host disks and other ttys stay absent.
- `--tmpfs /tmp` — private empty `/tmp`; the host `/tmp` (other processes'
  scratch files and unix sockets) is unreadable.
- `--ro-bind` of `/usr /bin /sbin /lib` (+ the `/lib64,/lib32,/libx32`
  variants that exist) and `/etc` — the minimum a runtime needs to START,
  proven by removal live (drop `/lib` and every dynamic binary dies `execvp:
  No such file` because its ELF loader is gone). `/etc` is system config
  (resolv.conf, nsswitch, ld.so.cache, localtime) — a candidate reading it is
  standard and mirrors the macOS `/private/etc` allow; it is NOT `$HOME`
  secrets. The verifier interpreter's own realpath'd prefixes (a venv may live
  outside `/usr`) are ro-bound too, so the wrapped child can launch.
- **Secret-leaf masks** (last-apply-wins, AFTER the `/usr` + `/etc` ro-binds;
  each emitted only when the host path exists) — the Linux parallel of the
  macOS `system_read_carveouts`, closing sensitive DATA that falls inside the
  broad ro-binds but is not runtime code: `--tmpfs` over `/usr/local/etc`
  `/usr/local/var` (service confs like `redis.conf requirepass` + live DB
  data — exactly the macOS `/usr/local` carve-out), `/etc/ssl/private` (TLS
  private keys), `/etc/kubernetes` `/etc/rancher` (cluster admin creds); and
  `--ro-bind /dev/null` over `/etc/shadow` `/etc/gshadow` (+ `-` backups). The
  shadow mask is **load-bearing and proven so**: strip it and a candidate
  running as euid 0 (privileged CI runs as root, so DAC does not save it) reads
  the real password hashes back; with it the read is denied. Without these
  masks a Linux run would qualify on strictly WEAKER isolation than macOS for
  the identical layout.
- `--bind <workspace> <workspace> --chdir <workspace>` (+ `--bind` each
  scratch dir) — the workspace and scratch are the only read-WRITE mounts.
- `--cap-drop ALL` — drop every capability, so the candidate cannot
  `mount`/`remount`/`pivot_root` to re-expose the host (measured live:
  `mount(MS_REMOUNT)` on a ro system bind → `EPERM`; strip this pair and the
  same remount SUCCEEDS, which is exactly the non-vacuity the probe asserts).
- `--die-with-parent` — the candidate is reaped if the supervisor dies.
- **NO `--ro-bind / /`.** The control root, `$HOME`, `/root`, other users'
  homes, `/var`, `/run`, `/opt`, `/mnt` are simply not in the namespace →
  a candidate `open()` of any of them returns `ENOENT`. Denial is by
  **ABSENCE**, not a policy line.

Before mounting, a **realpath disjointness gate** refuses (fail-closed
`SandboxError`) if any bind would expose the control root — i.e. the control
root sits under a bind, or a bind sits under it. In the normal layout the
control root and workspace are siblings, disjoint from the system dirs, so no
mask is needed (the control root is absent, not masked).

**ENOENT-is-denial (and how the probe tells it from a bug).**
`probe_candidate_confinement` runs a Linux-specific body (there are no Mach
services on Linux, so the macOS keychain/DNS IPC checks do not apply). Because
absence yields `ENOENT`, a naive "open failed" could equally mean "the sandbox
removed it" OR "the probe never planted the canary". To disambiguate, the
parent plants each canary (control-root, an outside-workspace temp file, and a
temp-named file directly in `$HOME`) and **confirms it is readable UNWRAPPED
first** — only a canary that provably exists on the host yet is unreadable
inside the wrapper counts as denial. The `$HOME` check reads a planted file
(not a `listdir`) so it stays correct even when a bound venv leaves a skeleton
dir under `$HOME`. The child also proves: workspace write SUCCEEDS (physically
verified back on the host — non-vacuity), outside write DENIED, subprocess
spawn SUCCEEDS, the `CAP_SYS_ADMIN` remount-escape is DENIED, the
**system-data carve-outs** are DENIED (non-vacuously: the parent plants a
token inside each maskable dir it can write and includes the real
`/etc/shadow`/`/etc/gshadow` when readable-unwrapped, then asserts each reads
back absent/empty inside — so a regressed mask surfaces as
`system_data_file_open` and fails the run), and at
`network: "deny"` external egress is DENIED (`ENETUNREACH`). At `deny`,
`--unshare-net` also closes DNS (the net ns has no route to any resolver), so
there is no DNS residual — and no `file_metadata_outside_home` residual either
(absence leaves nothing stat-visible), so a passing Linux `deny` run has **no
hard residuals** and qualifies. `network: "unrestricted"` records the soft
`network_unrestricted_open` residual (egress open by design of the mode).

**Deferred (own follow-ons, refused fail-closed today).**
`network: "loopback"` on bwrap raises `SandboxError` — `--unshare-net` gives
the namespace its own empty loopback, so host-bound twins are unreachable and
there is no port-pinned host-loopback passthrough like macOS's; loopback +
netns-local twins is **M29c-2**. The hardened/enterprise candidate container
is **M29c-3**. `allowed_loopback_ports` is accepted and validated for
signature parity but unused until M29c-2.

**Live proof (privileged CI).** bwrap cannot run on the macOS dev host and
default Docker blocks unprivileged user namespaces, so the Linux confinement
tests (`tests/test_candidate_confinement_linux.py`) are gated on a
`_privileged_linux_bwrap()` helper: True only when `sys.platform` is Linux AND
a trivial `bwrap --unshare-pid --unshare-net /bin/true` (with the loader
bound) actually succeeds. They self-skip on macOS and on unprivileged Linux CI
and RUN on a privileged-Linux runner (native or `docker run --privileged`),
driving the production `df_sandbox` code path. The argv-SHAPE unit tests (no
`--ro-bind / /`, workspace rw, control-root/`$HOME` not bound, disjointness
raises, loopback raises, `supports_default_deny is True`) run everywhere,
including macOS.

## Linux live-coverage harness

The maintainer's daily machine is macOS, so the Linux `bwrap` backend was
previously only *platform-skipped* unit coverage — never exercised on a real
kernel. `dark-factory/tests/test_linux_harness.py` (skipped when no Docker
daemon is present) closes that gap by running targeted probes
(`dark-factory/scripts/df_linux_probes.py`) inside a real Linux kernel (Docker
Desktop's linuxkit VM).

**What it proves (live, on a real kernel):**
- **bwrap read+write denial via the PRODUCTION code path.** The bwrap probe
  imports `df_sandbox` and drives the real `BACKENDS["linux"]` +
  `probe_denial` inside the container — not a reimplementation — so the live
  PASS covers the exact code the standard tier runs on Linux. This is what
  surfaced (and now guards against a regression of) the writable-tmpfs bug:
  without `--remount-ro`, this probe FAILS its write half live.
- **iptables egress denial** (`NET_ADMIN`) — an M17 enterprise-tier primitive —
  with a mandatory non-vacuity half: the probe connects out BEFORE the DROP
  rule (must succeed, else a dead network would make the "denial" meaningless)
  and again AFTER (must fail).
- **no-new-privs** self-application (`prctl(PR_SET_NO_NEW_PRIVS)`, confirmed by
  re-read) — the other M17 primitive.

**What it does NOT claim:** it is not a full native-Linux CI run of the suite
(a real Linux host running the entire suite remains the gold standard; this
harness is the honest *local* substitute for the Linux-only claims). The bwrap
probe container needs `--cap-add SYS_ADMIN --security-opt seccomp=unconfined`
purely so bwrap can create its namespaces inside Docker — this is a
TEST-HARNESS posture only and is **never** a production isolation setting
(`df_sandbox` itself requests no capabilities).
