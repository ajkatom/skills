#!/usr/bin/env bash
# dark-factory Linux-container full-suite harness.
#
# Runs the ENTIRE dark-factory pytest suite inside a real Linux kernel (a
# Debian-based `python:3.12` Docker container with `bubblewrap` + `iptables`
# installed), so the Linux-only paths — chiefly the `standard`-tier bwrap
# sandbox backend — EXECUTE for real instead of platform-skipping the way
# they do on the maintainer's macOS machine. See
# dark-factory/references/linux-ci.md for what this covers and excludes.
#
# Usage:
#   dark-factory/scripts/run_tests_linux.sh
#
# Requires: a working Docker daemon on the host (this script drives docker
# from the OUTSIDE; it does not need docker-in-docker).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DF_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"       # .../dark-factory
REPO_ROOT="$(cd "$DF_ROOT/.." && pwd)"        # repo root, so `dark-factory/tests` resolves inside the container

IMAGE_TAG="dark-factory-linux-ci:latest"

echo "== [1/2] building Linux test image ($IMAGE_TAG): python:3.12 (Debian) + bubblewrap + iptables =="
docker build -t "$IMAGE_TAG" - <<'DOCKERFILE'
FROM python:3.12
RUN apt-get update \
    && apt-get install -y --no-install-recommends bubblewrap iptables \
    && rm -rf /var/lib/apt/lists/*
# The only two non-stdlib deps the dark-factory suite needs (see
# dark-factory/requirements-enterprise.txt and the macOS .venv).
RUN python -m venv /opt/df-venv \
    && /opt/df-venv/bin/pip install --no-cache-dir --upgrade pip \
    && /opt/df-venv/bin/pip install --no-cache-dir pytest cryptography
DOCKERFILE

# ---------------------------------------------------------------------------
# Docker-in-Docker tests: cannot run inside this container (no nested docker
# daemon here) and are already exercised live against the macOS Docker host.
# Deselected individually (not whole files) so every non-docker test in the
# same file — including the bwrap sandbox tests — still runs.
# ---------------------------------------------------------------------------
DESELECT=(
  # test_container.py — M10 hardened-container live tests (launch containers)
  --deselect "dark-factory/tests/test_container.py::test_live_probe_denies_unmounted_root"
  --deselect "dark-factory/tests/test_container.py::test_live_workspace_writable"
  --deselect "dark-factory/tests/test_container.py::test_live_network_none_blocks_egress"
  # test_e2e_hardened.py — M10 hardened-tier live convergence/barrier/L5 tests
  --deselect "dark-factory/tests/test_e2e_hardened.py::test_live_hardened_convergence_and_barrier"
  --deselect "dark-factory/tests/test_e2e_hardened.py::test_live_l5_lights_off_no_pause"
  # test_enterprise_config.py — M17 live egress/seccomp probe (launches a container)
  --deselect "dark-factory/tests/test_enterprise_config.py::test_probe_enterprise_egress_live"
)
# test_linux_harness.py (M16) is itself the "run probes inside a container"
# harness — every live test in it launches a *nested* Docker container, which
# needs docker-in-docker. Its one test that doesn't (test_probe_drivers_fail_closed_on_macos)
# explicitly skips on native Linux (it targets the off-platform guard). So the
# whole file is a no-op here; ignore it outright rather than deselect item by item.
IGNORE=(
  --ignore "dark-factory/tests/test_linux_harness.py"
)

# Headline tests this run must prove EXECUTE (not skip) and PASS on this real
# Linux kernel — the Linux bwrap standard-tier sandbox path.
BWRAP_TESTS=(
  "dark-factory/tests/test_sandbox.py::test_linux_backend_denies_deny_root_read"
  "dark-factory/tests/test_sandbox.py::test_probe_passes_with_the_real_backend"
  "dark-factory/tests/test_sandbox_write_denial.py::test_probe_passes_and_leaves_no_write_artifacts"
  "dark-factory/tests/test_standard_tier.py::test_standard_run_converges_qualified_when_probe_passes"
  "dark-factory/tests/test_e2e_standard.py::test_standard_run_is_qualified_and_holdout_is_os_denied"
)

echo "== [2/2] running dark-factory/tests inside the container (real Linux kernel) =="
docker run --rm -i \
  --cap-add SYS_ADMIN \
  --security-opt seccomp=unconfined \
  -v "$REPO_ROOT:/src:ro" \
  "$IMAGE_TAG" \
  bash -s -- "${DESELECT[@]}" "${IGNORE[@]}" <<'INNER'
set -uo pipefail  # not -e: we want to run the full suite and report, even on failure

# The repo is bind-mounted read-only at /src; copy it to a writable working
# dir so pytest/pyc caches etc. have somewhere to write.
cp -r /src /work
cd /work

LOGFILE=/work/.pytest-linux.log
/opt/df-venv/bin/python -m pytest dark-factory/tests -v "$@" 2>&1 | tee "$LOGFILE"
PYTEST_RC=${PIPESTATUS[0]}

echo
echo "=================================================================="
echo "SUMMARY"
echo "=================================================================="
tail -n 20 "$LOGFILE" | grep -E "passed|failed|error|^=" || true

echo
echo "=================================================================="
echo "bwrap Linux sandbox test confirmation (must show RAN + PASSED, not SKIPPED)"
echo "=================================================================="
BWRAP_TESTS=(
  "dark-factory/tests/test_sandbox.py::test_linux_backend_denies_deny_root_read"
  "dark-factory/tests/test_sandbox.py::test_probe_passes_with_the_real_backend"
  "dark-factory/tests/test_sandbox_write_denial.py::test_probe_passes_and_leaves_no_write_artifacts"
  "dark-factory/tests/test_standard_tier.py::test_standard_run_converges_qualified_when_probe_passes"
  "dark-factory/tests/test_e2e_standard.py::test_standard_run_is_qualified_and_holdout_is_os_denied"
)
ALL_CONFIRMED=1
for t in "${BWRAP_TESTS[@]}"; do
  node_id="${t#dark-factory/tests/}"
  if grep -qF "${t} PASSED" "$LOGFILE"; then
    echo "  PASSED (ran for real on Linux): $node_id"
  elif grep -qF "${t} SKIPPED" "$LOGFILE"; then
    echo "  SKIPPED (did NOT execute — this is a failure of the harness's purpose): $node_id"
    ALL_CONFIRMED=0
  else
    echo "  NOT FOUND / FAILED: $node_id"
    ALL_CONFIRMED=0
  fi
done

echo
if [ "$PYTEST_RC" -eq 0 ] && [ "$ALL_CONFIRMED" -eq 1 ]; then
  echo "RESULT: full suite green AND bwrap Linux sandbox tests confirmed executed+passed."
else
  echo "RESULT: see failures/skips above (pytest exit code $PYTEST_RC)."
fi
exit "$PYTEST_RC"
INNER
