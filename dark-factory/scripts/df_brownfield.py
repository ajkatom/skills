"""Greenfield/brownfield detection + behavioral characterization (spec section
8). Stdlib only.

`detect_mode` classifies a run as greenfield or brownfield, fail-safe toward
brownfield: an existing, non-empty `project_src` is never silently treated as
greenfield under `mode: "auto"`.

`characterize` observes the CURRENT system at human-supplied probe points
(before the builder touches anything) and freezes each observation into a
holdout regression scenario (`cohort: "dev"`, `behavior_id: "BHV-REGRESS-<n>"`)
whose `then` pins the exact exit_code/stdout/stderr seen. It runs each probe
against a throwaway copy of `src_root` (made via `snapshot_source.snapshot`,
so the same no-symlink/no-special-file/no-multilink hygiene applies) and
ALWAYS removes that copy afterward, success or failure.

Honest scope: characterization captures OBSERVED behavior at exactly the
probes the human supplies -- it is not semantic reverse-engineering, and
unprobed behavior can still regress silently (spec section 8; see
references/brownfield.md).
"""
import re
import shutil
import subprocess
import tempfile

import df_gates
import snapshot_source

_PROBE_ID_RE = re.compile(r"^[a-z0-9-]{1,32}$")


class BrownfieldError(ValueError):
    pass


def detect_mode(configured_mode: str, project_src: str | None,
                 snapshot_manifest: dict | None) -> str:
    """Classify a run as "greenfield" or "brownfield".

    `configured_mode` in {"auto", "greenfield", "brownfield"}.
    `snapshot_manifest` is `snapshot_source.build_manifest(project_src)` or
    None (no project_src / not yet built).

    - "auto": "brownfield" iff project_src is set AND the manifest has >=1
      file, else "greenfield". Fail-safe toward brownfield: a non-empty
      existing tree is never classified as greenfield under auto.
    - "brownfield": requires both project_src and a non-empty manifest,
      else BrownfieldError (nothing to characterize).
    - "greenfield": always "greenfield" (the caller records
      `legacy_ignored` if project_src has files -- an explicit human
      override of detection).
    """
    if configured_mode not in ("auto", "greenfield", "brownfield"):
        raise BrownfieldError(
            f"mode must be one of 'auto', 'greenfield', 'brownfield', got {configured_mode!r}"
        )

    has_legacy = bool(project_src) and snapshot_manifest is not None and bool(
        snapshot_manifest.get("files")
    )

    if configured_mode == "greenfield":
        return "greenfield"

    if configured_mode == "brownfield":
        if not has_legacy:
            raise BrownfieldError(
                "mode 'brownfield' requires project_src with a non-empty "
                "snapshot manifest (nothing to characterize)"
            )
        return "brownfield"

    # auto
    return "brownfield" if has_legacy else "greenfield"


def _validate_probes(probes) -> None:
    # The per-probe shape rules here (slug id regex, unique id, non-empty
    # list[str] `run`, int timeout_s 1..120) are mirrored by df_config's
    # inline brownfield.probes validation — the two MUST stay in sync. df_config
    # cannot simply call this function because it permits an EMPTY probe list as
    # the default (this one requires non-empty) and raises ConfigError (this one
    # raises BrownfieldError).
    if not isinstance(probes, list) or not probes:
        raise BrownfieldError("probes must be a non-empty list")

    seen_ids = set()
    for probe in probes:
        if not isinstance(probe, dict):
            raise BrownfieldError(f"probe must be an object: {probe!r}")

        pid = probe.get("id")
        if not isinstance(pid, str) or not _PROBE_ID_RE.match(pid):
            raise BrownfieldError(
                f"probe id must match {_PROBE_ID_RE.pattern!r}: {pid!r}"
            )
        if pid in seen_ids:
            raise BrownfieldError(f"duplicate probe id: {pid}")
        seen_ids.add(pid)

        run = probe.get("run")
        if not isinstance(run, list) or not run or not all(
            isinstance(x, str) for x in run
        ):
            raise BrownfieldError(f"probe {pid!r}: run must be a non-empty list of strings")

        timeout_s = probe.get("timeout_s")
        if (
            not isinstance(timeout_s, int)
            or isinstance(timeout_s, bool)
            or not (1 <= timeout_s <= 120)
        ):
            raise BrownfieldError(f"probe {pid!r}: timeout_s must be an int in 1..120")


def _observe(probe: dict, cwd: str, exec_wrapper: list | None) -> dict:
    command = (list(exec_wrapper) if exec_wrapper else []) + probe["run"]
    try:
        proc = subprocess.run(
            command,
            cwd=cwd,
            capture_output=True,
            text=True,
            timeout=probe["timeout_s"],
        )
    except subprocess.TimeoutExpired as e:
        raise BrownfieldError(
            f"probe {probe['id']!r} timed out after {probe['timeout_s']}s "
            "(can't freeze a guard that couldn't be observed)"
        ) from e
    except (FileNotFoundError, PermissionError, OSError) as e:
        raise BrownfieldError(
            f"probe {probe['id']!r} could not be observed: {e}"
        ) from e
    return {
        "exit_code": proc.returncode,
        "stdout": proc.stdout,
        "stderr": proc.stderr,
    }


def characterize(src_root: str, probes: list[dict], exec_wrapper=None) -> list[dict]:
    """Snapshot `src_root` into a throwaway copy, run each probe there, and
    return one dev-cohort regression scenario per probe capturing the
    OBSERVED exit_code/stdout/stderr.

    `probes`: `[{"id": "<slug>", "run": [cmd, ...], "timeout_s": int}]`
    (human-supplied). `exec_wrapper` is an optional list prefix (the same
    isolation wrapper used for verification) -- the probe runs as
    `(exec_wrapper or []) + probe["run"]`.

    Raises BrownfieldError on: invalid probe shapes; a probe that times out
    or can't be observed (naming the probe); a generated `then` that fails
    the M7 mutation gate (`df_gates.is_discriminating`) -- a degenerate
    probe fails loudly here rather than freezing an inert guard.

    The temporary copy is always removed, on success, error, or timeout.
    """
    _validate_probes(probes)

    tmp_dir = tempfile.mkdtemp(prefix="df-brownfield-")
    try:
        snapshot_source.snapshot(src_root, tmp_dir)

        scenarios = []
        for i, probe in enumerate(probes):
            observed = _observe(probe, tmp_dir, exec_wrapper)
            then = {
                "exit_code": observed["exit_code"],
                "stdout_equals": observed["stdout"],
                "stderr_equals": observed["stderr"],
            }
            # Defense in depth: the three keys above are ALWAYS populated from a
            # real observation, so `then` is discriminating by construction and
            # this branch cannot currently fire (is_discriminating only rejects a
            # `then` with none of its recognized keys). Kept so that if the
            # captured shape ever changes, a degenerate guard fails loudly here
            # rather than silently freezing false assurance.
            if not df_gates.is_discriminating(then):
                raise BrownfieldError(
                    f"probe {probe['id']!r} produced a non-discriminating "
                    "(degenerate) guard -- refusing to freeze it"
                )
            scenarios.append(
                {
                    "ir_version": "0.1",
                    "id": f"BHV-REGRESS-{i}-S1",
                    "behavior_id": f"BHV-REGRESS-{i}",
                    "cohort": "dev",
                    "title": f"regression guard: {probe['id']}",
                    "given": "captured from the pre-change system",
                    "when": {"run": probe["run"], "timeout_s": probe["timeout_s"]},
                    "then": then,
                }
            )
        return scenarios
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)
