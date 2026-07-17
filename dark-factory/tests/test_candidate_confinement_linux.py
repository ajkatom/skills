"""M29c (DF-02 Linux host-read half): LIVE proof that the bwrap default-deny
CANDIDATE wrapper isolates the host on a REAL kernel.

Every test here is gated on `_privileged_linux_bwrap()` — True ONLY when
`sys.platform` is Linux AND bwrap can actually create a mount+PID+net namespace
on this machine (probed live). So the file:
  - self-skips on macOS (this dev host: bwrap absent) — the argv-shape unit
    tests in test_candidate_confinement.py cover construction there;
  - self-skips on UNPRIVILEGED Linux CI (default Docker / userns-disabled
    kernels, where bwrap cannot create the namespace);
  - RUNS on a privileged-Linux runner (native, or `docker run --privileged`),
    driving the PRODUCTION df_sandbox code path — not a reimplementation.

This mirrors the M16 harness precedent (test_linux_harness.py): the mechanism
is proven live on a real kernel; the full native-Linux suite run remains the
gold standard (see references/isolation.md).
"""
import os
import shutil
import subprocess
import sys

import pytest

import df_sandbox

_linux = df_sandbox.BACKENDS["linux"]


def _privileged_linux_bwrap():
    """True only where the live tests can actually run: Linux, bwrap present,
    and a trivial namespace (pid+net) creation SUCCEEDS. `/bin/true` is dynamic,
    so its ELF loader (/lib[64]) and /usr must be bound or execvp fails ENOENT
    — mirroring why the real wrapper binds them. `--unshare-net` is probed too
    (not just --unshare-pid): the deny-mode tests need it, and some restricted
    environments create a PID ns fine but fail to configure the net ns's
    loopback (measured under docker `--cap-add SYS_ADMIN` without NET_ADMIN),
    which must skip, not fail."""
    if not sys.platform.startswith("linux"):
        return False
    if shutil.which("bwrap") is None:
        return False
    argv = ["bwrap", "--ro-bind", "/usr", "/usr", "--ro-bind", "/bin", "/bin",
            "--ro-bind", "/lib", "/lib"]
    for variant in ("/lib64", "/lib32", "/libx32"):
        if os.path.exists(variant):
            argv += ["--ro-bind", variant, variant]
    argv += ["--unshare-pid", "--unshare-net", "--", "/bin/true"]
    try:
        return subprocess.run(argv, capture_output=True, timeout=20).returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


live = pytest.mark.skipif(not _privileged_linux_bwrap(),
                          reason="privileged Linux bwrap (real namespace) required")


@pytest.fixture
def dirs(tmp_path):
    deny = tmp_path / "control-root"
    ws = tmp_path / "workspace"
    deny.mkdir()
    ws.mkdir()
    (deny / "holdout.json").write_text("SECRET-SCENARIO", encoding="utf-8")
    return str(deny), str(ws)


@live
def test_default_deny_probe_passes_and_qualifies(dirs):
    """The real probe against the real backend: every host-read canary denied,
    workspace writable, remount-escape denied, external egress denied — and NO
    hard residuals, so host_isolation qualifies."""
    deny, ws = dirs
    ok, report = df_sandbox.probe_candidate_confinement(_linux, deny, ws, "deny")
    assert ok is True, report
    assert report["mode"] == "default_deny"
    c = report["checks"]
    assert c["control_root_read"] == "DF-READ-DENIED"
    assert c["outside_read"] == "DF-READ-DENIED"
    assert c["home_read"] == "DF-READ-DENIED"
    assert c["workspace_write"] == "DF-WS-WRITE-OK"
    assert c["outside_write"] == "DF-WRITE-DENIED"
    assert c["subprocess_spawn"] == "DF-SPAWN-OK"
    assert c["remount_escape"] == "DF-REMOUNT-DENIED"
    assert c["net_external"] == "DF-NET-EXTERNAL-DENIED"
    # sensitive /usr/local + /etc secret leaves are masked (DENIED), or SKIP if
    # this host has no probeable target (non-root, no /usr/local) — never leaked.
    assert c["system_data_carveout"] in ("DF-SYSDATA-DENIED", "DF-SYSDATA-SKIP")
    # deny closes DNS via --unshare-net → no residual at all.
    assert report["residuals"] == []


@live
def test_default_deny_unrestricted_passes_with_net_residual(dirs):
    """network=='unrestricted': host reads still denied, but egress is open BY
    DESIGN of the configured mode → the soft RESIDUAL_NET_UNRESTRICTED, still
    qualifying on the host-read axis."""
    deny, ws = dirs
    ok, report = df_sandbox.probe_candidate_confinement(_linux, deny, ws, "unrestricted")
    assert ok is True, report
    assert report["checks"]["control_root_read"] == "DF-READ-DENIED"
    assert report["checks"]["net_external"] == "DF-NET-SKIP"
    assert report["residuals"] == [df_sandbox.RESIDUAL_NET_UNRESTRICTED]


@live
def test_loopback_is_refused_cleanly(dirs):
    """loopback on bwrap is deferred (M29c-2): the probe must fail CLOSED with a
    clear reason, never crash or false-pass."""
    deny, ws = dirs
    ok, report = df_sandbox.probe_candidate_confinement(_linux, deny, ws, "loopback")
    assert ok is False
    assert "loopback" in report["detail"].lower()


@live
def test_raw_wrap_cannot_read_a_planted_host_canary(dirs, tmp_path):
    """End-to-end denial demo independent of the probe machinery: plant a canary
    OUTSIDE the workspace (unbound), run the real wrap argv, and confirm the
    candidate cannot read it while it CAN read the workspace."""
    deny, ws = dirs
    secret_dir = tmp_path / "elsewhere"
    secret_dir.mkdir()
    canary = secret_dir / "canary.txt"
    canary.write_text("HOST-ONLY-SECRET", encoding="utf-8")
    with open(os.path.join(ws, "ws.txt"), "w", encoding="utf-8") as f:
        f.write("WORKSPACE-OK")

    prefix = _linux.wrap_candidate_prefix(deny, ws, network="deny")
    code = (
        "import os, sys\n"
        "canary, ws_file = sys.argv[1], sys.argv[2]\n"
        "try:\n"
        "    open(canary).read(); print('LEAKED')\n"
        "except OSError:\n"
        "    print('DENIED')\n"
        "print('WS', open(ws_file).read())\n"
    )
    proc = subprocess.run(
        prefix + [sys.executable, "-c", code, str(canary), os.path.join(ws, "ws.txt")],
        capture_output=True, text=True, timeout=60)
    assert proc.returncode == 0, proc.stderr
    assert "DENIED" in proc.stdout
    assert "LEAKED" not in proc.stdout
    assert "WS WORKSPACE-OK" in proc.stdout


@live
def test_probe_catches_missing_cap_drop_remount_escape(dirs, monkeypatch):
    """Regression guard (mirrors test_linux_harness): strip `--cap-drop ALL`
    from the wrapper and the candidate — holding ambient CAP_SYS_ADMIN in the
    bwrap userns — can mount(MS_REMOUNT) a ro system bind. The probe's
    remount-escape check MUST then make probe_candidate_confinement return
    False. If this ever passes with the escape working, the boundary is broken."""
    orig = _linux.wrap_candidate_prefix

    def weakened(deny_root, workspace, **kw):
        argv = orig(deny_root, workspace, **kw)
        i = argv.index("--cap-drop")
        del argv[i:i + 2]
        return argv

    monkeypatch.setattr(_linux, "wrap_candidate_prefix", weakened)
    deny, ws = dirs
    ok, report = df_sandbox.probe_candidate_confinement(_linux, deny, ws, "deny")
    assert ok is False
    assert report["checks"].get("remount_escape") == "DF-REMOUNT-LEAKED", report


@live
def test_probe_catches_missing_secret_leaf_masks(dirs, monkeypatch, tmp_path):
    """Regression guard for the macOS-parity fix: strip the sensitive-leaf
    masks (`--tmpfs` over /usr/local + /etc secret dirs, `--ro-bind /dev/null`
    over shadow) and the probe MUST catch the leak. Ensures /usr/local/etc
    exists so the probe has a writable-dir target even off-root; the probe
    plants + cleans its own canary there."""
    created = None
    if not os.path.isdir("/usr/local/etc"):
        try:
            os.makedirs("/usr/local/etc")
            created = "/usr/local/etc"
        except OSError:
            pass
    secret = "/usr/local/etc/df-regression-secret.conf"
    try:
        with open(secret, "w", encoding="utf-8") as f:
            f.write("requirepass=REGRESSION-SECRET")
    except OSError:
        pytest.skip("cannot plant a system-data secret to probe on this host")

    orig = _linux.wrap_candidate_prefix

    def unmasked(deny_root, workspace, **kw):
        argv = orig(deny_root, workspace, **kw)
        out, i = [], 0
        while i < len(argv):
            if argv[i] == "--tmpfs" and argv[i + 1].startswith(("/usr/local", "/etc/ssl",
                                                                "/etc/kubernetes", "/etc/rancher")):
                i += 2; continue
            if argv[i] == "--ro-bind" and argv[i + 1] == "/dev/null" and \
                    argv[i + 2].startswith("/etc/"):
                i += 3; continue
            out.append(argv[i]); i += 1
        return out

    monkeypatch.setattr(_linux, "wrap_candidate_prefix", unmasked)
    deny, ws = dirs
    try:
        ok, report = df_sandbox.probe_candidate_confinement(_linux, deny, ws, "deny")
        assert ok is False
        assert report["checks"].get("system_data_carveout", "").startswith("DF-SYSDATA-LEAKED"), report
        assert df_sandbox.RESIDUAL_SYSTEM_DATA_OPEN in report["residuals"]
    finally:
        try:
            os.unlink(secret)
        except OSError:
            pass
        if created:
            try:
                os.rmdir(created)
            except OSError:
                pass
