"""M62 (Codex R6): DF-R6-03 CLI confinement identity + DF-R6-04 dispatch-time
support-file byte binding.

  * DF-R6-03 — `profile_for` identity-bound only the STRUCTURAL profiles, so an
    ARBITRARY executable merely NAMED `claude` inherited the stock profile's
    mcp_disabled/tool_allowlist claims and could satisfy
    `builder_confinement.required: true` while proving nothing. Every
    `supported: True` claim is now bound to this skill's shipped adapter bytes.
  * DF-R6-04 — support-file digests were hashed ONCE at manifest assembly
    (time-of-CHECK); the mount loops re-checked only path disjointness, so the
    bytes a builder IMPORTS in-container could differ from the bytes the sealed
    manifest attests. They are now re-hashed and refused on drift at dispatch.
"""
import hashlib
import os
import tempfile

import pytest

import df_confine
import supervisor

HERE = os.path.dirname(os.path.abspath(__file__))
IMPOSTOR = os.path.join(HERE, "fixtures", "impostor_api_anthropic", "api_anthropic")
ADAPTERS = os.path.join(HERE, "..", "scripts", "adapters")


class _J:
    def __init__(self):
        self.events = []

    def write(self, state, **data):
        self.events.append((state, data))


# ---------------------------------------------------------------------------
# DF-R6-03 — every supported claim is identity-bound
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("cli", ["claude", "api_anthropic", "api_openai"])
def test_arbitrary_bytes_named_as_a_supported_cli_are_refused(cli):
    prof = df_confine.profile_for(cli, os.path.realpath(IMPOSTOR))
    assert prof.get("supported") is False
    assert prof.get("identity_verified") is False
    assert "shipped adapter identity" in prof.get("reason", "")


@pytest.mark.parametrize("cli", ["claude", "api_anthropic", "api_openai"])
def test_the_shipped_adapter_is_supported(cli):
    shipped = os.path.realpath(os.path.join(ADAPTERS, cli))
    assert df_confine.profile_for(cli, shipped).get("supported") is True


def test_a_byte_identical_relocated_copy_is_supported(tmp_path):
    shipped = os.path.join(ADAPTERS, "claude")
    copy = tmp_path / "claude"
    copy.write_bytes(open(shipped, "rb").read())
    copy.chmod(0o755)
    assert df_confine.profile_for("claude", str(copy)).get("supported") is True


def test_one_byte_of_drift_breaks_the_claim(tmp_path):
    shipped = os.path.join(ADAPTERS, "claude")
    tampered = tmp_path / "claude"
    tampered.write_bytes(open(shipped, "rb").read() + b"\n# injected\n")
    tampered.chmod(0o755)
    assert df_confine.profile_for("claude", str(tampered)).get("supported") is False


def test_no_adapter_path_is_backcompat_identical():
    # Pre-M62 callers that pass no path still get the exact PROFILES object.
    for cli in ("claude", "api_anthropic", "api_openai"):
        assert df_confine.profile_for(cli) is df_confine.PROFILES[cli]


def test_unsupported_clis_stay_unsupported_even_when_shipped():
    # codex/gemini have no probe-verified profile; shipped identity does not
    # manufacture support.
    for cli in ("codex", "gemini"):
        shipped = os.path.realpath(os.path.join(ADAPTERS, cli))
        assert df_confine.profile_for(cli, shipped).get("supported") is False


# ---------------------------------------------------------------------------
# DF-R6-04 — bytes at DISPATCH, not bytes at snapshot
# ---------------------------------------------------------------------------

def _sealed(path, digest):
    return {"builder_identity": {"support_files": [{"path": path, "sha256": digest}]}}


def test_unchanged_support_file_passes_dispatch_verification(tmp_path):
    p = tmp_path / "helper.py"
    p.write_text("V = 1\n", encoding="utf-8")
    digest = hashlib.sha256(b"V = 1\n").hexdigest()
    err = supervisor._verify_support_files_at_dispatch(
        {"_support_files": [str(p)]}, _sealed(str(p), digest), _J())
    assert err is None


def test_support_file_changed_after_seal_is_refused_at_dispatch(tmp_path):
    p = tmp_path / "helper.py"
    p.write_text("V = 1\n", encoding="utf-8")
    digest = hashlib.sha256(b"V = 1\n").hexdigest()
    p.write_text("V = 2  # tampered after the manifest snapshot\n", encoding="utf-8")
    j = _J()
    err = supervisor._verify_support_files_at_dispatch(
        {"_support_files": [str(p)]}, _sealed(str(p), digest), j)
    assert err is not None and "CHANGED after it was sealed" in err
    assert [s for s, _ in j.events] == ["SUPPORT_FILE_DRIFT_AT_DISPATCH"]


def test_support_file_swapped_to_a_directory_is_refused_at_dispatch(tmp_path):
    p = tmp_path / "helper.py"
    p.write_text("V = 1\n", encoding="utf-8")
    digest = hashlib.sha256(b"V = 1\n").hexdigest()
    p.unlink()
    p.mkdir()
    j = _J()
    err = supervisor._verify_support_files_at_dispatch(
        {"_support_files": [str(p)]}, _sealed(str(p), digest), j)
    assert err is not None
    assert [s for s, _ in j.events] == ["SUPPORT_FILE_UNREADABLE_AT_DISPATCH"]


def test_vanished_support_file_is_refused_at_dispatch(tmp_path):
    p = tmp_path / "helper.py"
    p.write_text("V = 1\n", encoding="utf-8")
    digest = hashlib.sha256(b"V = 1\n").hexdigest()
    p.unlink()
    err = supervisor._verify_support_files_at_dispatch(
        {"_support_files": [str(p)]}, _sealed(str(p), digest), _J())
    assert err is not None and "missing, unreadable" in err


def test_no_support_files_is_a_noop(tmp_path):
    assert supervisor._verify_support_files_at_dispatch({}, {}, _J()) is None


def test_required_confinement_refuses_an_untrusted_claude_named_adapter(tmp_path, monkeypatch):
    # The R6-03 CONTRACT at the supervisor level: a config whose builder adapter
    # is an arbitrary path merely NAMED `claude` must NOT satisfy
    # `builder_confinement.required: true`. Before M62 this dispatched with the
    # stock profile's claims sealed into the manifest (tests/test_confine_config
    # encoded exactly that with a fictional /usr/local/bin/claude).
    from test_supervisor import setup_control
    import json as _json
    fake = tmp_path / "bin" / "claude"
    fake.parent.mkdir(parents=True)
    fake.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    fake.chmod(0o755)
    cr = setup_control(tmp_path, str(fake), checkpoint="auto")
    cfg = _json.loads((cr / "config.json").read_text())
    cfg["builder_confinement"] = {"enabled": True, "required": True}
    (cr / "config.json").write_text(_json.dumps(cfg), encoding="utf-8")

    invoked = []
    monkeypatch.setattr(supervisor, "invoke_adapter",
                        lambda *a, **k: (invoked.append(1), ({}, None))[1])
    rc = supervisor.run(str(cr), None)
    assert rc == 2, "required confinement must refuse an untrusted adapter identity"
    assert not invoked, "and the builder must never be dispatched"
    run_id = os.listdir(cr / "runs")[0]
    mf = _json.loads((cr / "runs" / run_id / "manifest.json").read_text())
    assert mf["outcome"] == "CONFINEMENT_REFUSED"
