# M29c-1 — DF-02 (Linux host-read): default-deny candidate mount+PID namespace (bwrap)

_Linux parallel of M29b. Gives `_LinuxBackend` a REAL default-deny
`wrap_candidate_prefix` (explicit minimal binds instead of `--ro-bind / /`),
sets `supports_default_deny=True`, and makes `probe_candidate_confinement`
prove it fail-closed on a real Linux kernel. This closes the Linux host-read
gap that M36a's single qualification SM now ENFORCES: today a native-Linux
`standard` run reports `host_isolation.mode="legacy_allow_host_read"` →
`host_isolation` substate False → `qualified` False (HOST_ISOLATION_LIMITED).
After M29c-1 a Linux standard run can be genuinely host-isolated + qualified._

## Verification reality (read first)
This macOS host cannot run bwrap natively. It CAN run it inside a Linux
Docker container, but ONLY under `docker run --privileged` (default Docker
blocks unprivileged user namespaces; `--cap-add SYS_ADMIN` alone still fails
pivot_root). Confirmed live during planning: under `--privileged ubuntu:24.04`
+ `apt-get install bubblewrap`, bwrap creates mount+PID+net namespaces and a
127.0.0.1 listener binds inside `--unshare-net`. So:
- The Linux default-deny code + probe are REAL and run on a real kernel.
- Their tests are gated `@skipUnless(_privileged_linux_bwrap())` — they do
  NOT run in the normal macOS suite (which is unprivileged), matching the
  M16 harness precedent. CI on a privileged-Linux runner exercises them.
- The implementer MUST do at least one live proof run inside
  `docker run --privileged` and paste the transcript into the task report
  (host-read canary denied, workspace writable, control-root denied,
  remount-escape denied) — "code that should work" is not acceptable for an
  isolation boundary; it must be shown working once.

## Scope
IN: default-deny candidate mount+PID namespace (host-read isolation),
`network` `deny`/`unrestricted` (unchanged semantics), probe, config/manifest
wiring reuse (the M29b `candidate_host_read` field + `host_isolation`
manifest field already exist — Linux just stops reporting legacy and starts
reporting `default_deny` when the probe passes).

OUT (documented deferrals, own follow-ons):
- **29e-Linux netns-local verifier + twins** (`loopback` network mode on
  Linux): still raises "not supported by bwrap" as today. The candidate can
  be host-read-isolated with `network:"deny"` now; twin/HTTP-scenario
  loopback under a private netns is M29c-2.
- **29f candidate container** at hardened/enterprise: M29c-3.

## Approach (4 tasks)

### Task 1 — `_LinuxBackend.wrap_candidate_prefix` real default-deny
Replace the legacy passthrough with an explicit-bind argv. Develop LIVE in
`docker run --privileged`. Expected shape (verify each bind is needed):
```
bwrap
  --unshare-pid --unshare-ipc --unshare-uts        # private PID/IPC/UTS ns
  --clearenv? NO — env is handled by run_scenarios candidate_env (M29a);
                    do not clearenv here (would drop the sanitized allowlist)
  --proc /proc                                      # PRIVATE /proc (not host --ro-bind)
  --dev /dev                                        # minimal private devtmpfs
  --tmpfs /tmp                                       # private /tmp (no host /tmp read)
  --ro-bind /usr /usr  --ro-bind /bin /bin --ro-bind /sbin /sbin
  --ro-bind /lib /lib  [--ro-bind /lib64 /lib64 if present]
  --ro-bind /etc /etc  (needed for resolv/nsswitch/ld.so; a candidate
                        reading /etc is standard — but NOT /etc that holds
                        secrets; document that /etc is allowed, matching the
                        macOS profile's /private/etc allow)
  [--ro-bind each of scratch_dirs read-only? NO: scratch is writable]
  --bind <workspace> <workspace>  --chdir <workspace>
  [--bind <scratch_dir> <scratch_dir> for each]     # writable scratch
  --cap-drop ALL
  --die-with-parent
  [--unshare-net if network=="deny"]
  --
```
Key point vs. legacy: there is NO `--ro-bind / /`, so `$HOME`, `/root`,
other users' homes, `/var`, and the CONTROL ROOT are simply NOT in the
mount namespace → unreadable by construction (not merely masked). Because
the control root is disjoint from workspace/system binds it is absent; still
add an explicit tmpfs+remount-ro mask over `deny_root` IF `deny_root` happens
to sit under an allowed bind (it should not — assert/realpath-check
disjointness and raise SandboxError if a bind would expose it). Keep the
`--cap-drop ALL` + remount-ro reasoning from the existing `wrap_prefix` where
a mask is used. `allowed_loopback_ports` is accepted but only meaningful once
29e lands; document. `network=="loopback"` still raises (deferred).
Set `supports_default_deny = True`.

### Task 2 — `probe_candidate_confinement` for Linux default-deny
The shared probe (df_sandbox.py:785) currently delegates non-default-deny
backends to legacy. Now the Linux backend advertises default-deny, so the
probe's real body runs for it. Ensure the wrapped-child check set works on
Linux and add the Linux-specific proofs:
- host-read canary planted OUTSIDE workspace/system (e.g. under a temp dir
  that is NOT bound) → must be absent/unreadable (FileNotFoundError from the
  missing mount is ACCEPTABLE proof here — unlike macOS where the path still
  exists; document the difference: on Linux "not in the namespace" is the
  denial mechanism, so ENOENT IS denial, but distinguish it from a genuine
  probe-setup bug by ALSO planting a canary the parent confirms exists on the
  host first).
- control-root canary → unreadable (absent from ns).
- workspace write → allowed (non-vacuity).
- write outside workspace → denied.
- CAP_SYS_ADMIN remount-escape over any masked path → denied (reuse the
  existing Linux 4th-check remount logic).
- $HOME read → denied (absent from ns).
Return the same `{checks, residuals}` structure M29b defined. Fail-closed on
any ambiguity. Keychain/DNS Mach checks are macOS-only — skip them on Linux
(no Mach); DNS residual on Linux `deny` is closed by `--unshare-net` (no
route), note it.

### Task 3 — wiring + honest manifest
The supervisor already consumes `supports_default_deny` +
`probe_candidate_confinement` + seals `host_isolation` (M29b/M36a). With the
Linux backend now advertising default-deny, a passing probe yields
`host_isolation.mode="default_deny"`, `qualified=True` → the M36a SM folds it
into `qualified`. Verify NO supervisor change is needed beyond confirming the
Linux path flows through the same code (it should — M29b made it
backend-agnostic). If `network=="loopback"` is requested on Linux (twins/HTTP
at standard), the existing SandboxError refusal stands; ensure the failure is
a clean config-time/again fail-closed refusal, not a crash. Add the
`legacy_allow_host_read` fallback ONLY for a bwrap too old to create
namespaces (probe fails → refuse the run or downgrade per existing UX).

### Task 4 — tests + docs
- `test_candidate_confinement_linux.py` (all `@skipUnless` a live
  privileged-linux-bwrap helper): default-deny probe passes; host-read /
  control-root / $HOME canaries denied; workspace writable; remount-escape
  denied; `network=="deny"` external + loopback both denied; `loopback`
  raises. A helper `_privileged_linux_bwrap()` returns True only when
  `sys.platform=="linux"` AND bwrap can actually create a namespace (probe a
  trivial `bwrap --unshare-pid true`), so the tests self-skip everywhere they
  can't run — including unprivileged Linux CI.
- Unit tests (run everywhere): argv construction — no `--ro-bind / /`;
  workspace bound rw; control-root/$HOME NOT bound; disjointness SandboxError
  when a bind would expose deny_root; `loopback` raises;
  `supports_default_deny is True`.
- Docs: `references/isolation.md` (Linux default-deny section: the explicit
  binds, why ENOENT-is-denial on Linux, the privileged-CI note, 29e/29f
  deferrals), `references/hardened.md` if it references the Linux candidate,
  `references/prevention-grade-roadmap.md` (DF-02 Linux host-read now
  detection+prevention at standard; netns-loopback + container = M29c-2/3),
  SKILL.md (Linux standard now host-isolates the candidate; loopback/twins at
  standard remain macOS-only until M29c-2).

## Risks
- bwrap version/needs vary; the explicit bind list must be developed live
  and each bind justified. `/etc` breadth is the main judgement call
  (needed for runtime, but don't over-bind).
- Must actually run under `--privileged` once and show the transcript.
- Do not regress the existing `wrap_prefix` (builder / M12 write-denial) —
  it stays exactly as is; only `wrap_candidate_prefix` changes.
