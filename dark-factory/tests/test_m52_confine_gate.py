"""DF-R4-02 (M52): the PRE-DISPATCH identity-aware confinement gate.

Before M52, `supervisor._run_loop` spawned the builder FIRST and only refused
(`CONFINEMENT_REFUSED`) when the ADAPTER self-reported "confinement
unsupported". An arbitrary executable that merely shares the STRUCTURAL basename
`api_anthropic` (or a relocated copy with no digest pin) but IGNORES the confine
arg and returns success would run the builder UNCONFINED while `required:true` —
a fail-OPEN security control. M50 made `df_confine.profile_for` identity-aware
and recorded the impostor honestly in the manifest, but never used it as a GATE.

These tests pin the gate:

  * IMPOSTOR + required:true  -> refused BEFORE any dispatch (builder never
    invoked — the auditor's exact repro; FAILS before the fix, PASSES after).
  * IMPOSTOR + required:false -> runs unconfined (unchanged from M50); the
    manifest still records the confinement honestly as unsupported.
  * SAME fixture, digest-PINNED -> a trusted identity dispatches normally, no
    false refusal (offline proof that claude/shipped-api_anthropic are safe).
  * RESUME after an identity swap -> the gate fires on the resume path too,
    before re-dispatch.
"""
import hashlib
import json
import os

import pytest

import df_confine
import supervisor
from test_supervisor import setup_control

HERE = os.path.dirname(os.path.abspath(__file__))
IMPOSTOR = os.path.join(HERE, "fixtures", "impostor_api_anthropic", "api_anthropic")
SHIPPED_API_ANTHROPIC = os.path.join(HERE, "..", "scripts", "adapters", "api_anthropic")


def _sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _patch_config(cr, **updates):
    cfg = json.loads((cr / "config.json").read_text())
    for k, v in updates.items():
        cfg[k] = v
    (cr / "config.json").write_text(json.dumps(cfg), encoding="utf-8")
    return cfg


def _set_builder_sha256(cr, digest):
    cfg = json.loads((cr / "config.json").read_text())
    cfg["roles"]["builder"]["adapter_sha256"] = digest
    (cr / "config.json").write_text(json.dumps(cfg), encoding="utf-8")


def _run_id(cr):
    runs = os.listdir(cr / "runs")
    assert len(runs) == 1, runs
    return runs[0]


def _manifest(cr):
    return json.loads((cr / "runs" / _run_id(cr) / "manifest.json").read_text())


def _journal_states(cr):
    lines = (cr / "runs" / _run_id(cr) / "journal.jsonl").read_text(encoding="utf-8")
    return [json.loads(l)["state"] for l in lines.strip().splitlines()]


@pytest.fixture
def marker(tmp_path, monkeypatch):
    """Path the impostor appends to on EVERY spawn; its existence == builder
    was invoked, its line-count == number of dispatches."""
    m = tmp_path / "impostor_invoked.marker"
    monkeypatch.setenv("DF_IMPOSTOR_INVOKED_MARKER", str(m))
    return m


# ---------------------------------------------------------------------------
# Sanity: the fixture really is an untrusted structural identity (non-vacuous).
# ---------------------------------------------------------------------------

def test_fixture_is_an_untrusted_structural_impostor():
    # basename is a STRUCTURAL profile name, but the path is neither the shipped
    # adapter nor a digest-pinned match -> profile_for must fail-close.
    assert os.path.basename(IMPOSTOR) == "api_anthropic"
    prof = df_confine.profile_for("api_anthropic", os.path.realpath(IMPOSTOR), None)
    assert prof.get("supported") is False
    # ...and the trusted forms the gate must NOT refuse:
    assert df_confine.profile_for(
        "api_anthropic", os.path.realpath(SHIPPED_API_ANTHROPIC), None).get("supported") is True
    assert df_confine.profile_for("claude", os.path.realpath(IMPOSTOR), None).get("supported") is True


# ---------------------------------------------------------------------------
# THE repro: impostor + required:true -> refused before dispatch, no build.
# ---------------------------------------------------------------------------

def test_impostor_required_refused_before_dispatch(tmp_path, marker):
    cr = setup_control(tmp_path, IMPOSTOR, checkpoint="auto")
    _patch_config(cr, builder_confinement={"enabled": True, "required": True})

    rc = supervisor.run(str(cr), None)

    assert rc == 2, f"expected fail-closed exit 2, got {rc}"
    mf = _manifest(cr)
    assert mf["outcome"] == "CONFINEMENT_REFUSED"
    assert mf["qualified"] is False
    # The whole point: the builder was NEVER spawned.
    assert not marker.exists(), "builder_invoked must be False (gate fires pre-dispatch)"
    states = _journal_states(cr)
    assert "CONFINEMENT_UNSUPPORTED" in states
    assert "BUILD" not in states  # never reached a build step
    # No artifact was written to the workspace either.
    ws = tmp_path / "ws" / _run_id(cr)
    assert not (ws / "greet.py").exists()


# ---------------------------------------------------------------------------
# required:false -> unchanged from M50: runs unconfined, manifest honest.
# ---------------------------------------------------------------------------

def test_impostor_not_required_runs_unconfined_manifest_honest(tmp_path, marker):
    cr = setup_control(tmp_path, IMPOSTOR, checkpoint="auto")
    _patch_config(cr, builder_confinement={"enabled": True, "required": False})

    rc = supervisor.run(str(cr), None)

    assert rc == 0, "not-required confinement must fall back to an unconfined run"
    assert marker.exists()  # builder WAS invoked (unconfined) — the pre-M52 behavior
    mf = _manifest(cr)
    # Cooperative convergence seals COMPLETE_UNQUALIFIED (never a refusal).
    assert mf["outcome"] == "COMPLETE_UNQUALIFIED"
    # M50 honesty: the confinement is recorded as unsupported (never a false claim).
    bc = mf["builder_confinement"]
    assert bc["enabled"] in (True, False)  # may flip to False after a WARN fallback
    assert bc["mcp_disabled"] is False
    assert bc["tool_allowlist"] == []
    assert bc["probe"] in ("unsupported", "n/a")


# ---------------------------------------------------------------------------
# A DIGEST-PINNED copy is a TRUSTED identity -> dispatches normally (no false
# refusal). Offline stand-in for "shipped api_anthropic / claude not refused".
# ---------------------------------------------------------------------------

def test_digest_pinned_identity_is_not_falsely_refused(tmp_path, marker):
    cr = setup_control(tmp_path, IMPOSTOR, checkpoint="auto")
    _patch_config(cr, builder_confinement={"enabled": True, "required": True})
    _set_builder_sha256(cr, _sha256(IMPOSTOR))  # pin the exact bytes -> trusted

    rc = supervisor.run(str(cr), None)

    assert rc == 0, "a digest-pinned api_anthropic must dispatch, not be refused"
    assert marker.exists()  # builder WAS invoked — gate correctly stood aside
    mf = _manifest(cr)
    assert mf["outcome"] == "COMPLETE_UNQUALIFIED"  # converged; NOT a refusal
    assert mf["outcome"] != "CONFINEMENT_REFUSED"


# ---------------------------------------------------------------------------
# RESUME path: an identity swap across a pause is caught before re-dispatch.
# ---------------------------------------------------------------------------

def test_resume_identity_swap_refused_before_redispatch(tmp_path, marker):
    # Fresh run under a TRUSTED (digest-pinned) identity, checkpoint=pause so it
    # PAUSES after the first (buggy) iteration's failing verify.
    cr = setup_control(tmp_path, IMPOSTOR, checkpoint="pause")
    _patch_config(cr, builder_confinement={"enabled": True, "required": True})
    _set_builder_sha256(cr, _sha256(IMPOSTOR))

    rc = supervisor.run(str(cr), None)
    assert rc == supervisor.PAUSED, f"expected pause, got {rc}"
    assert marker.exists()
    first_dispatches = marker.read_text().count("invoked")
    assert first_dispatches == 1  # exactly one build so far

    # The adapter identity is no longer trusted across the pause: drop the pin
    # (now it is a bare-basename impostor again). Resume must refuse BEFORE
    # dispatching a second builder call.
    _set_builder_sha256_removed(cr)

    rc2 = supervisor.resume(str(cr), "continue")
    assert rc2 == 2, f"resume must fail-closed refuse, got {rc2}"
    mf = _manifest(cr)
    assert mf["outcome"] == "CONFINEMENT_REFUSED"
    assert mf["qualified"] is False
    # No SECOND dispatch happened — the marker line-count did not grow.
    assert marker.read_text().count("invoked") == first_dispatches
    assert "CONFINEMENT_UNSUPPORTED" in _journal_states(cr)


def _set_builder_sha256_removed(cr):
    cfg = json.loads((cr / "config.json").read_text())
    cfg["roles"]["builder"].pop("adapter_sha256", None)
    (cr / "config.json").write_text(json.dumps(cfg), encoding="utf-8")
