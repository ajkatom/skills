import os
import shutil
import sys

import pytest

import df_brownfield
import df_gates
import snapshot_source

FIXTURE_LEGACY_APP = os.path.join(
    os.path.dirname(__file__), "fixtures", "legacy_app"
)


def make_src(tmp_path):
    """A tiny brownfield source tree containing the legacy_app fixture."""
    src = tmp_path / "src"
    src.mkdir()
    shutil.copy(FIXTURE_LEGACY_APP, src / "legacy_app")
    return src


# ---------------------------------------------------------------------------
# detect_mode
# ---------------------------------------------------------------------------


def test_auto_with_empty_manifest_is_greenfield():
    manifest = {"manifest_version": "0.1", "files": []}
    assert df_brownfield.detect_mode("auto", None, manifest) == "greenfield"
    assert df_brownfield.detect_mode("auto", "/some/path", manifest) == "greenfield"


def test_auto_with_nonempty_manifest_is_brownfield(tmp_path):
    src = make_src(tmp_path)
    manifest = snapshot_source.build_manifest(str(src))
    assert df_brownfield.detect_mode("auto", str(src), manifest) == "brownfield"


def test_auto_with_no_project_src_is_greenfield():
    assert df_brownfield.detect_mode("auto", None, None) == "greenfield"


def test_brownfield_mode_with_empty_manifest_raises():
    manifest = {"manifest_version": "0.1", "files": []}
    with pytest.raises(df_brownfield.BrownfieldError):
        df_brownfield.detect_mode("brownfield", "/some/path", manifest)


def test_brownfield_mode_with_none_manifest_raises():
    with pytest.raises(df_brownfield.BrownfieldError):
        df_brownfield.detect_mode("brownfield", None, None)


def test_brownfield_mode_with_none_project_src_raises(tmp_path):
    src = make_src(tmp_path)
    manifest = snapshot_source.build_manifest(str(src))
    with pytest.raises(df_brownfield.BrownfieldError):
        df_brownfield.detect_mode("brownfield", None, manifest)


def test_brownfield_mode_with_project_src_and_files_succeeds(tmp_path):
    src = make_src(tmp_path)
    manifest = snapshot_source.build_manifest(str(src))
    assert df_brownfield.detect_mode("brownfield", str(src), manifest) == "brownfield"


def test_greenfield_mode_with_nonempty_project_is_always_greenfield(tmp_path):
    src = make_src(tmp_path)
    manifest = snapshot_source.build_manifest(str(src))
    assert df_brownfield.detect_mode("greenfield", str(src), manifest) == "greenfield"


def test_bad_configured_mode_raises():
    with pytest.raises(df_brownfield.BrownfieldError):
        df_brownfield.detect_mode("bogus", None, None)


# ---------------------------------------------------------------------------
# characterize
# ---------------------------------------------------------------------------


def test_characterize_two_probes_produce_observed_scenarios(tmp_path):
    src = make_src(tmp_path)
    probes = [
        {
            "id": "add-ok",
            "run": [sys.executable, "legacy_app", "add", "2", "3"],
            "timeout_s": 5,
        },
        {
            "id": "bad-args",
            "run": [sys.executable, "legacy_app", "nope"],
            "timeout_s": 5,
        },
    ]

    scenarios = df_brownfield.characterize(str(src), probes)

    assert [sc["id"] for sc in scenarios] == ["BHV-REGRESS-0-S1", "BHV-REGRESS-1-S1"]
    assert [sc["behavior_id"] for sc in scenarios] == ["BHV-REGRESS-0", "BHV-REGRESS-1"]
    for sc in scenarios:
        assert sc["cohort"] == "dev"
        assert sc["ir_version"] == "0.1"
        assert sc["given"] == "captured from the pre-change system"
        assert df_gates.is_discriminating(sc["then"])

    add_sc, bad_sc = scenarios
    assert add_sc["title"] == "regression guard: add-ok"
    assert add_sc["when"]["run"] == probes[0]["run"]
    assert add_sc["when"]["timeout_s"] == 5
    assert add_sc["then"]["exit_code"] == 0
    assert add_sc["then"]["stdout_equals"] == "5\n"
    assert add_sc["then"]["stderr_equals"] == ""

    assert bad_sc["then"]["exit_code"] == 2
    assert bad_sc["then"]["stdout_equals"] == ""
    assert bad_sc["then"]["stderr_equals"] == "legacy_app: unknown or bad args\n"


def test_characterize_removes_temp_copy_on_success(tmp_path, monkeypatch):
    src = make_src(tmp_path)
    probes = [
        {
            "id": "add-ok",
            "run": [sys.executable, "legacy_app", "add", "2", "3"],
            "timeout_s": 5,
        }
    ]
    created = {}
    orig_mkdtemp = df_brownfield.tempfile.mkdtemp

    def spy_mkdtemp(*a, **k):
        d = orig_mkdtemp(*a, **k)
        created["path"] = d
        return d

    monkeypatch.setattr(df_brownfield.tempfile, "mkdtemp", spy_mkdtemp)
    df_brownfield.characterize(str(src), probes)
    assert created["path"]
    assert not os.path.exists(created["path"])


def test_characterize_empty_probes_raises():
    with pytest.raises(df_brownfield.BrownfieldError):
        df_brownfield.characterize("/irrelevant", [])


def test_characterize_probes_not_a_list_raises():
    with pytest.raises(df_brownfield.BrownfieldError):
        df_brownfield.characterize("/irrelevant", {"id": "x"})


def test_characterize_duplicate_probe_id_raises(tmp_path):
    src = make_src(tmp_path)
    probes = [
        {"id": "dup", "run": [sys.executable, "legacy_app", "add", "1", "1"], "timeout_s": 5},
        {"id": "dup", "run": [sys.executable, "legacy_app", "add", "2", "2"], "timeout_s": 5},
    ]
    with pytest.raises(df_brownfield.BrownfieldError, match="dup"):
        df_brownfield.characterize(str(src), probes)


def test_characterize_bad_slug_id_raises(tmp_path):
    src = make_src(tmp_path)
    probes = [{"id": "Not_Valid!", "run": ["echo", "hi"], "timeout_s": 5}]
    with pytest.raises(df_brownfield.BrownfieldError):
        df_brownfield.characterize(str(src), probes)


def test_characterize_empty_run_raises(tmp_path):
    src = make_src(tmp_path)
    probes = [{"id": "empty-run", "run": [], "timeout_s": 5}]
    with pytest.raises(df_brownfield.BrownfieldError, match="empty-run"):
        df_brownfield.characterize(str(src), probes)


def test_characterize_non_string_run_raises(tmp_path):
    src = make_src(tmp_path)
    probes = [{"id": "bad-run", "run": ["echo", 123], "timeout_s": 5}]
    with pytest.raises(df_brownfield.BrownfieldError, match="bad-run"):
        df_brownfield.characterize(str(src), probes)


@pytest.mark.parametrize("bad_timeout", [0, 121, -1, "10", True, 3.5])
def test_characterize_bad_timeout_raises(tmp_path, bad_timeout):
    src = make_src(tmp_path)
    probes = [{"id": "bad-timeout", "run": ["echo", "hi"], "timeout_s": bad_timeout}]
    with pytest.raises(df_brownfield.BrownfieldError, match="bad-timeout"):
        df_brownfield.characterize(str(src), probes)


def test_characterize_slow_probe_times_out_and_names_probe(tmp_path):
    src = make_src(tmp_path)
    probes = [
        {
            "id": "too-slow",
            "run": [sys.executable, "-c", "import time; time.sleep(5)"],
            "timeout_s": 1,
        }
    ]
    with pytest.raises(df_brownfield.BrownfieldError, match="too-slow"):
        df_brownfield.characterize(str(src), probes)


def test_characterize_slow_probe_still_cleans_up_temp_copy(tmp_path, monkeypatch):
    src = make_src(tmp_path)
    probes = [
        {
            "id": "too-slow",
            "run": [sys.executable, "-c", "import time; time.sleep(5)"],
            "timeout_s": 1,
        }
    ]
    created = {}
    orig_mkdtemp = df_brownfield.tempfile.mkdtemp

    def spy_mkdtemp(*a, **k):
        d = orig_mkdtemp(*a, **k)
        created["path"] = d
        return d

    monkeypatch.setattr(df_brownfield.tempfile, "mkdtemp", spy_mkdtemp)
    with pytest.raises(df_brownfield.BrownfieldError):
        df_brownfield.characterize(str(src), probes)
    assert created["path"]
    assert not os.path.exists(created["path"])


def test_characterize_unobservable_probe_raises(tmp_path):
    src = make_src(tmp_path)
    probes = [
        {
            "id": "no-such-binary",
            "run": ["/no/such/binary-xyz", "arg"],
            "timeout_s": 5,
        }
    ]
    with pytest.raises(df_brownfield.BrownfieldError, match="no-such-binary"):
        df_brownfield.characterize(str(src), probes)


def test_characterize_wrapper_none_works(tmp_path):
    src = make_src(tmp_path)
    probes = [
        {
            "id": "add-ok",
            "run": [sys.executable, "legacy_app", "add", "4", "5"],
            "timeout_s": 5,
        }
    ]
    scenarios = df_brownfield.characterize(str(src), probes, exec_wrapper=None)
    assert scenarios[0]["then"]["stdout_equals"] == "9\n"


def test_characterize_exec_wrapper_prefix_is_prepended(tmp_path, monkeypatch):
    src = make_src(tmp_path)
    marker = tmp_path / "wrapper-used.marker"
    monkeypatch.setenv("DF_WRAP_MARKER", str(marker))
    wrapper_code = (
        "import os, subprocess, sys\n"
        "open(os.environ['DF_WRAP_MARKER'], 'w').write('used')\n"
        "sys.exit(subprocess.run(sys.argv[1:]).returncode)\n"
    )
    exec_wrapper = [sys.executable, "-c", wrapper_code]
    probes = [
        {
            "id": "add-ok",
            "run": [sys.executable, "legacy_app", "add", "2", "3"],
            "timeout_s": 5,
        }
    ]

    scenarios = df_brownfield.characterize(str(src), probes, exec_wrapper=exec_wrapper)

    assert marker.read_text(encoding="utf-8") == "used"
    assert scenarios[0]["then"]["exit_code"] == 0
    assert scenarios[0]["then"]["stdout_equals"] == "5\n"
