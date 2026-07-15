"""Docker-backed builder isolation for dark-factory hardened tier. Stdlib only.

The builder runs inside a Docker container where the control root is unreachable
BY CONSTRUCTION (never mounted) — dropped capabilities, no host PID/docker socket,
read-only rootfs, resource limits, and (by default) no network. No backend is
trusted without a passing `probe_container` (the fail-closed safety net, same
discipline as `df_sandbox.probe_denial`).
"""
import os
import shutil
import subprocess
import uuid


class ContainerError(RuntimeError):
    pass


BACKEND_NAME = "container-docker"
DEFAULT_IMAGE = "python:3.12-alpine"

# Reuse df_sandbox's marker discipline: a wrapped read that raises must report this
# literal, never propagate the read content. See df_sandbox._DENIAL_MARKER.
_DENIAL_MARKER = "DF-READ-DENIED"


def docker_available(runner=subprocess.run) -> bool:
    """Fail-closed: True only if the `docker` binary exists AND `docker info`
    exits 0 within 10s. Any exception (missing binary, daemon down, timeout,
    permission error) → False."""
    if shutil.which("docker") is None:
        return False
    try:
        proc = runner(
            ["docker", "info"],
            capture_output=True, text=True, timeout=10,
        )
    except Exception:
        return False
    return proc.returncode == 0


def _resolve_mount_path(path, label):
    # Require an absolute input path outright: realpath() would silently resolve a
    # relative path against the process cwd (ambiguous/dangerous for a security-
    # sensitive mount list), so relative input is rejected before resolution.
    if not os.path.isabs(path):
        raise ContainerError(f"{label} must be an absolute path: {path}")
    if not os.path.exists(path):
        raise ContainerError(f"{label} does not exist: {path}")
    real = os.path.realpath(path)
    if not os.path.isabs(real):
        raise ContainerError(f"{label} is not absolute after realpath: {real}")
    if ":" in real:
        raise ContainerError(f"{label} contains ':' (would corrupt -v spec): {real}")
    return real


def build_argv(image, workspace, ro_mounts, *, network="none", memory="2g",
               pids=256, env=None) -> list:
    """Pure. Build the `docker run` argv for the hardened builder container.

    Raises ContainerError if workspace or any ro_mount does not exist, is not
    absolute after realpath, or contains ':'. df_container does not know the
    control root — the CALLER guarantees the control root is never passed as a
    mount; nothing else can appear in the resulting -v flags."""
    if not isinstance(image, str) or not image or image.startswith("-"):
        raise ContainerError(
            f"image must be a non-empty string not starting with '-' "
            f"(got {image!r}); a leading '-' could be parsed as a docker flag"
        )
    ws = _resolve_mount_path(workspace, "workspace")
    real_ro_mounts = sorted({
        _resolve_mount_path(p, "ro_mount") for p in (ro_mounts or [])
    })

    argv = [
        "docker", "run", "--rm", "-i",
        "--network", network,
        "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges",
        "--pids-limit", str(pids),
        "--memory", memory,
        "--read-only",
        "--tmpfs", "/tmp",
        "-e", "HOME=/tmp",
        "-v", f"{ws}:{ws}",
    ]
    for p in real_ro_mounts:
        argv += ["-v", f"{p}:{p}:ro"]
    argv += ["-w", ws]
    for k in sorted((env or {}).keys()):
        argv += ["-e", f"{k}={env[k]}"]
    argv += [image]
    return argv


def probe_container(image, deny_root, workspace, *, timeout_s=180, runner=subprocess.run) -> bool:
    """Fail-closed: True ONLY IF the container provably launched (rc == 0) AND the
    canary planted in deny_root was provably unreachable (stdout is exactly the
    denial marker). Any error/timeout/nonzero rc/leaked token → False. Canary is
    always unlinked."""
    token = "DF-CANARY-" + uuid.uuid4().hex
    canary = os.path.join(deny_root, ".probe-canary-" + uuid.uuid4().hex)
    try:
        try:
            with open(canary, "w", encoding="utf-8") as f:
                f.write(token)
        except OSError:
            return False
        try:
            argv = build_argv(image, workspace, [])
        except ContainerError:
            return False
        code = (
            "import sys\n"
            "try:\n"
            "    sys.stdout.write(open(sys.argv[1]).read())\n"
            "except Exception:\n"
            f"    sys.stdout.write({_DENIAL_MARKER!r})\n"
        )
        try:
            proc = runner(
                argv + ["python3", "-c", code, canary],
                capture_output=True, text=True, timeout=timeout_s,
            )
        except Exception:
            return False
        # Fail-closed: True only if the container provably ran AND hit the denial
        # branch. Vacuous stdout from a launch failure (nonzero exit) must NOT be
        # mistaken for a proven denial.
        return proc.returncode == 0 and proc.stdout.strip() == _DENIAL_MARKER
    finally:
        try:
            os.unlink(canary)
        except OSError:
            pass
