"""M16 — Linux live-coverage harness: proves the Linux-only security claims on a
real Linux kernel (Docker Desktop's linuxkit VM), via `df_linux_probes.py`
driving the PRODUCTION `df_sandbox` code path (not a copy) plus the two kernel
primitives M17's enterprise tier needs (iptables egress denial, no-new-privs).

Honest scope: this harness proves the *mechanisms* live on a real kernel; it is
NOT a full native-Linux CI run of the suite (that remains the gold standard —
see dark-factory/references/isolation.md). SYS_ADMIN is required here only
because bwrap needs it to create namespaces inside the test container; it is
never granted in production (df_sandbox itself never requests capabilities).

skipif no docker at module level, mirroring test_container.py, so the suite
stays green on docker-less machines.
"""
import os
import subprocess
import sys

import pytest

import df_container
import df_linux_probes


SCRIPTS_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "scripts"))

DOCKER_LIVE = df_container.docker_available()

# Inline Dockerfile: alpine + bubblewrap (bwrap probe) + iptables (egress probe).
# `docker build -q -` reads this from stdin with an empty build context; the
# resulting image is content-addressed and cached by Docker across runs, so
# only the first invocation on a machine pays the ~60s apk-install cost.
_DOCKERFILE = """FROM python:3.12-alpine
RUN apk add --no-cache bubblewrap iptables
"""


@pytest.fixture(scope="session")
def linux_probe_image():
    if not DOCKER_LIVE:
        pytest.skip("docker daemon unavailable")
    proc = subprocess.run(
        ["docker", "build", "-q", "-"],
        input=_DOCKERFILE, capture_output=True, text=True, timeout=180,
    )
    assert proc.returncode == 0, f"image build failed: {proc.stderr}"
    image_id = proc.stdout.strip()
    assert image_id, "docker build -q produced no image id"
    return image_id


def _run_probe(image, docker_args, probe_args, timeout=60):
    argv = (
        ["docker", "run", "--rm"]
        + docker_args
        + ["-v", f"{SCRIPTS_DIR}:/df:ro", image]
        + probe_args
    )
    return subprocess.run(argv, capture_output=True, text=True, timeout=timeout)


@pytest.mark.skipif(not DOCKER_LIVE, reason="docker daemon unavailable")
def test_bwrap_denial_live_on_linux(linux_probe_image):
    """Live coverage for the standard tier's Linux backend: drives the REAL
    df_sandbox.BACKENDS["linux"] + df_sandbox.probe_denial inside a real Linux
    kernel, not a reimplementation. Until now this path was only platform-
    skipped unit coverage on macOS."""
    proc = _run_probe(
        linux_probe_image,
        ["--cap-add", "SYS_ADMIN", "--security-opt", "seccomp=unconfined"],
        ["sh", "-c", "mkdir -p /tmp/deny /tmp/ws && python3 /df/df_linux_probes.py bwrap /tmp/deny /tmp/ws"],
    )
    assert proc.returncode == 0, f"stdout={proc.stdout!r} stderr={proc.stderr!r}"
    assert "DF-PROBE bwrap PASS" in proc.stdout


# M47 condition #10: this probe makes a REAL external baseline connect to
# 1.1.1.1 (the non-vacuity half), so it is gated behind DF_ALLOW_NETWORK_TESTS to
# keep the default suite hermetic. The primitive is still exercised in the
# opt-in/CI run.
@pytest.mark.skipif(not os.environ.get("DF_ALLOW_NETWORK_TESTS"),
                    reason="reaches 1.1.1.1; set DF_ALLOW_NETWORK_TESTS=1")
@pytest.mark.skipif(not DOCKER_LIVE, reason="docker daemon unavailable")
def test_egress_denial_live(linux_probe_image):
    """Live coverage for the M17 iptables-egress-denial primitive. The probe
    itself enforces the non-vacuity half (baseline connect must succeed before
    the DROP rule is applied)."""
    proc = _run_probe(
        linux_probe_image,
        ["--cap-add", "NET_ADMIN"],
        ["python3", "/df/df_linux_probes.py", "egress", "1.1.1.1", "443"],
    )
    assert proc.returncode == 0, f"stdout={proc.stdout!r} stderr={proc.stderr!r}"
    assert "DF-PROBE egress PASS" in proc.stdout


# Weaken the Linux backend by stripping the "--cap-drop ALL" pair from
# wrap_prefix, then assert probe_denial FAILS — proving the probe catches the
# CAP_SYS_ADMIN remount escape (the pre-fix backend would false-PASS without
# this coverage).
_CAP_DROP_REGRESSION_SNIPPET = (
    "import sys\n"
    "sys.path.insert(0, '/df')\n"
    "import df_sandbox\n"
    "backend = df_sandbox.BACKENDS['linux']\n"
    "orig = backend.wrap_prefix\n"
    "def weakened(deny_root, workspace):\n"
    "    argv = orig(deny_root, workspace)\n"
    "    i = argv.index('--cap-drop')\n"
    "    del argv[i:i+2]\n"
    "    return argv\n"
    "backend.wrap_prefix = weakened\n"
    "result = df_sandbox.probe_denial(backend, '/tmp/deny', '/tmp/ws')\n"
    "print('PROBE_RESULT', result)\n"
    "sys.exit(0 if result is False else 1)\n"
)


@pytest.mark.skipif(not DOCKER_LIVE, reason="docker daemon unavailable")
def test_probe_catches_cap_sys_admin_remount_escape(linux_probe_image):
    """Regression guard: with ambient CAP_SYS_ADMIN, a bwrap child whose backend
    forgot "--cap-drop ALL" can `mount -o remount,rw` the masked control root and
    write. probe_denial's Linux 4th check (remount vector) must catch that — so
    the weakened backend must make probe_denial return False. If this test ever
    goes green with the escape working, the fail-closed guarantee is broken."""
    proc = _run_probe(
        linux_probe_image,
        ["--cap-add", "SYS_ADMIN", "--security-opt", "seccomp=unconfined"],
        ["sh", "-c", "mkdir -p /tmp/deny /tmp/ws && python3 -c "
                     + "\"" + _CAP_DROP_REGRESSION_SNIPPET.replace('"', '\\"') + "\""],
    )
    assert proc.returncode == 0, f"stdout={proc.stdout!r} stderr={proc.stderr!r}"
    assert "PROBE_RESULT False" in proc.stdout


@pytest.mark.skipif(not DOCKER_LIVE, reason="docker daemon unavailable")
def test_no_new_privs_live(linux_probe_image):
    """Live coverage for the M17 no-new-privs self-application primitive. No
    extra capabilities are granted — prctl(PR_SET_NO_NEW_PRIVS) needs none."""
    proc = _run_probe(
        linux_probe_image,
        [],
        ["python3", "/df/df_linux_probes.py", "nnp"],
    )
    assert proc.returncode == 0, f"stdout={proc.stdout!r} stderr={proc.stderr!r}"
    assert "DF-PROBE nnp PASS" in proc.stdout


@pytest.mark.skipif(
    sys.platform == "linux",
    reason="targets the off-platform fail-closed behavior; on native Linux this "
           "would exercise the real backend instead of the platform guard",
)
def test_probe_drivers_fail_closed_on_macos(tmp_path):
    """The bwrap probe driver must never false-pass off-platform: run directly
    on this Mac (no container, no docker), it must fail closed and say why."""
    deny_root = tmp_path / "deny"
    workspace = tmp_path / "ws"
    deny_root.mkdir()
    workspace.mkdir()
    ok, reason = df_linux_probes.probe_bwrap(str(deny_root), str(workspace))
    assert ok is False
    assert "linux" in reason.lower()
