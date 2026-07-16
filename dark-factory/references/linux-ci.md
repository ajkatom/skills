# dark-factory Linux-container full-suite harness

The maintainer's daily machine is macOS. On macOS, every test gated
`@pytest.mark.skipif(sys.platform != "linux", ...)` — chiefly the `standard`
tier's Linux `bwrap` sandbox backend coverage in
`dark-factory/tests/test_sandbox.py` — SKIPS. `test_linux_harness.py` (see
`dark-factory/references/isolation.md`) closes part of that gap by running
*targeted probes* inside a Docker container, but it is not the full pytest
suite, and it doesn't say whether the rest of the suite is even importable
or collectible on Linux, or whether other tests carry a hidden macOS-ism.

`dark-factory/scripts/run_tests_linux.sh` closes the remaining gap: it runs
the **entire** `dark-factory/tests` suite inside a real Linux kernel, so the
Linux-only branches — bwrap read+write denial through the actual `standard`
tier code path — execute for real instead of platform-skipping.

## Running it

```
dark-factory/scripts/run_tests_linux.sh
```

Requires a working Docker daemon on the host (this script drives Docker from
the *outside*; it does not itself need docker-in-docker). It:

1. Builds a `python:3.12` (Debian, not Alpine — needed for `apt-get`,
   `bubblewrap`, and `iptables`; Debian is also the safe base for the
   `cryptography` wheel even though `cryptography` ships manylinux wheels and
   pip should not need to compile) image with `bubblewrap` and `iptables`
   installed, plus a venv with the suite's only two non-stdlib deps
   (`pytest`, `cryptography` — the same two the macOS `.venv` has).
2. Runs the suite inside that container with
   `--cap-add SYS_ADMIN --security-opt seccomp=unconfined` — required purely
   so `bwrap` can create Linux namespaces inside Docker. This is a
   **TEST-HARNESS posture only**, matching the note in
   `dark-factory/references/isolation.md`; `df_sandbox` itself requests no
   capabilities in production, and the `standard` tier's actual runtime
   footprint is unaffected by this file.
3. Prints a pass/fail/skip summary and explicitly greps the run log to
   confirm a fixed list of bwrap-path tests RAN (not SKIPPED) and PASSED.

## What it proves

The Linux `bwrap` standard-tier sandbox path executes for real, through the
suite's actual tests (not a reimplementation, not a hand-rolled probe):

- `test_sandbox.py::test_linux_backend_denies_deny_root_read` — Linux-only
  (`skipif sys.platform != "linux"`); this test literally cannot execute on
  the maintainer's macOS machine. Under this harness it runs and passes.
- `test_sandbox.py::test_probe_passes_with_the_real_backend` — runs on
  darwin or linux; on Linux it now exercises `BACKENDS["linux"]` /
  `probe_denial` for real instead of the macOS `sandbox-exec` backend.
- `test_sandbox_write_denial.py::test_probe_passes_and_leaves_no_write_artifacts`
  — same dual read+write denial probe, now against the real bwrap backend.
- `test_standard_tier.py::test_standard_run_converges_qualified_when_probe_passes`
  and `test_e2e_standard.py::test_standard_run_is_qualified_and_holdout_is_os_denied`
  — integration/e2e level: a full `standard`-tier run qualifies through the
  real Linux backend and the holdout scenario is OS-denied on a real kernel.

## What it deliberately excludes

Docker-in-Docker tests cannot run inside this container (no nested Docker
daemon) and are already exercised live by running the suite directly on the
macOS Docker host (`.venv/bin/python -m pytest dark-factory/tests -q`, where
`docker_available()` is `True`). Deselected individually so every *other*
test in the same file — including the bwrap sandbox tests above — still
runs:

- `test_container.py::test_live_probe_denies_unmounted_root`,
  `test_live_workspace_writable`, `test_live_network_none_blocks_egress` —
  M10 hardened-container live tests; each launches a Docker container.
- `test_e2e_hardened.py::test_live_hardened_convergence_and_barrier`,
  `test_live_l5_lights_off_no_pause` — M10 hardened-tier live
  convergence/barrier and L5 unattended-run tests; both launch containers.
- `test_enterprise_config.py::test_probe_enterprise_egress_live` — M17 live
  egress/seccomp probe; launches a container.

And excluded wholesale:

- `test_linux_harness.py` (M16) — every live test in this file launches a
  *nested* Docker container from inside the harness's own probe container,
  which needs docker-in-docker. Its one test that doesn't need Docker
  (`test_probe_drivers_fail_closed_on_macos`) explicitly `skipif
  sys.platform == "linux"` — it targets the off-platform fail-closed guard,
  so it would be a no-op here even if collected. The file is `--ignore`d
  rather than deselected test-by-test.

All of the above remain covered — just by the macOS Docker-host run, not by
this container-inside-a-container path, which Docker does not support
without an explicit docker-in-docker setup this harness does not attempt.

## Live result (2026-07-16)

Run inside `python:3.12` on Docker Desktop's Linux VM (linux/aarch64):

- All non-deselected, non-ignored tests passed. See the commit for the exact
  passed/skipped/deselected counts recorded at run time.
- The bwrap Linux sandbox tests listed above ran (not skipped) and passed —
  confirmed by grepping the run log for
  `<nodeid> PASSED` (not `SKIPPED`) for each one.
- No product or test portability bugs were found; the suite required no
  changes to run green on Linux.
