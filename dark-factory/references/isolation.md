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

**Three modes** (`df_sandbox._NETWORK_MODES`):
- `unrestricted` (default) — no restriction; candidate and builder share the
  same network authority, exactly as before M27.
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
(only TCP connects are).

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
still-running grandchild in the same group to leak. This closes the
`setsid`/double-fork escape: a candidate that backgrounds or detaches a child
process to survive past its own exit is still in the same process group, and
still gets killed. Applies identically to CLI scenarios (`run_scenario`) and
HTTP scenarios (`_run_http_scenario`, which additionally reaps the started
service regardless of whether it ever became ready or answered the request).

**Honest scope.** This is the env/IPC + process half of DF-02, not the whole
of it. What it does NOT do: a `standard`-tier candidate can still **read**
host files today — the current sandbox profile (top of this doc) is
allow-default with the control root denied, not a default-deny profile that
would also block reads of the operator's home directory, dotfiles, etc.
Copy-on-run scratch per scenario (so a candidate's writes never touch a
shared workspace across scenarios) and a network-namespace egress topology
finer than `candidate_network`'s three modes (§7.4 above) are likewise not
delivered by this work. All three are tracked for M29b/M29c. What IS closed
by Tasks 1-2: a candidate can no longer read the operator's ambient secrets
via environment variables, and a candidate can no longer leave a surviving
background/daemon process behind after its scenario ends.

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
