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
