"""M15-2: brownfield `mode`/`probes` config (cfg["_brownfield"]) and the
supervisor's characterize-before-build wiring (mode detection -> generated
regression scenarios -> merged into the dev cohort -> additive manifest
fields), plus resume's "reuse the sealed cohort, never re-characterize"
contract.

Config matrix tests are pure df_config.load_config unit tests (no
supervisor involved). Supervisor tests drive real `supervisor.run`/`resume`
calls against a real subprocess builder + a real `legacy_app` project_src
copy -- mirroring test_supervisor.py's / test_creds_config.py's conventions
(no mocking of df_brownfield itself; it is exercised for real, cooperative
tier, no sandbox/docker needed).
"""
import json
import os
import shutil
import sys

import pytest

import df_config
import supervisor
from test_config import write_config
from test_supervisor import FAKE, read_journal, setup_control

HERE = os.path.dirname(os.path.abspath(__file__))
LEGACY_APP_FIXTURE = os.path.join(HERE, "fixtures", "legacy_app")
FAKE_BROWNFIELD_BREAK = os.path.join(HERE, "fixtures", "fake_builder_brownfield_break")

ADD_PROBE = {
    "id": "add-ok",
    "run": [sys.executable, "legacy_app", "add", "2", "3"],
    "timeout_s": 5,
}


def make_legacy_src(tmp_path, name="legacy_src"):
    src = tmp_path / name
    src.mkdir()
    shutil.copy(LEGACY_APP_FIXTURE, src / "legacy_app")
    return src


def set_brownfield(cr, brownfield):
    cfg_path = cr / "config.json"
    cfg = json.loads(cfg_path.read_text(encoding="utf-8"))
    cfg["brownfield"] = brownfield
    cfg_path.write_text(json.dumps(cfg), encoding="utf-8")


def _walk_all_files(root):
    for dirpath, _, filenames in os.walk(root):
        for name in filenames:
            yield os.path.join(dirpath, name)


# ---------------------------------------------------------------------------
# config matrix: cfg["_brownfield"]
# ---------------------------------------------------------------------------

def test_brownfield_absent_defaults_to_auto_no_probes(tmp_path):
    cr = tmp_path / "control"
    write_config(cr)
    cfg = df_config.load_config(str(cr))
    assert cfg["_brownfield"] == {"mode": "auto", "probes": []}


def test_brownfield_mode_auto_explicit_no_probes(tmp_path):
    cr = tmp_path / "control"
    write_config(cr, brownfield={"mode": "auto"})
    cfg = df_config.load_config(str(cr))
    assert cfg["_brownfield"] == {"mode": "auto", "probes": []}


def test_brownfield_mode_greenfield_explicit_no_probes(tmp_path):
    cr = tmp_path / "control"
    write_config(cr, brownfield={"mode": "greenfield"})
    cfg = df_config.load_config(str(cr))
    assert cfg["_brownfield"]["mode"] == "greenfield"


def test_brownfield_mode_brownfield_with_probes_valid(tmp_path):
    cr = tmp_path / "control"
    write_config(cr, brownfield={"mode": "brownfield", "probes": [ADD_PROBE]})
    cfg = df_config.load_config(str(cr))
    assert cfg["_brownfield"] == {
        "mode": "brownfield",
        "probes": [{"id": "add-ok", "run": ADD_PROBE["run"], "timeout_s": 5}],
    }


def test_brownfield_bad_mode_value_rejected(tmp_path):
    cr = tmp_path / "control"
    write_config(cr, brownfield={"mode": "bogus"})
    with pytest.raises(df_config.ConfigError, match="mode"):
        df_config.load_config(str(cr))


def test_brownfield_mode_brownfield_with_empty_probes_rejected(tmp_path):
    cr = tmp_path / "control"
    write_config(cr, brownfield={"mode": "brownfield", "probes": []})
    with pytest.raises(df_config.ConfigError, match="brownfield"):
        df_config.load_config(str(cr))


def test_brownfield_mode_brownfield_with_absent_probes_rejected(tmp_path):
    cr = tmp_path / "control"
    write_config(cr, brownfield={"mode": "brownfield"})
    with pytest.raises(df_config.ConfigError, match="brownfield"):
        df_config.load_config(str(cr))


def test_brownfield_mode_greenfield_with_probes_rejected(tmp_path):
    cr = tmp_path / "control"
    write_config(cr, brownfield={"mode": "greenfield", "probes": [ADD_PROBE]})
    with pytest.raises(df_config.ConfigError, match="greenfield"):
        df_config.load_config(str(cr))


def test_brownfield_block_not_a_dict_rejected(tmp_path):
    cr = tmp_path / "control"
    write_config(cr, brownfield="oops")
    with pytest.raises(df_config.ConfigError, match="brownfield"):
        df_config.load_config(str(cr))


def test_brownfield_probes_not_a_list_rejected(tmp_path):
    cr = tmp_path / "control"
    write_config(cr, brownfield={"mode": "auto", "probes": {"id": "x"}})
    with pytest.raises(df_config.ConfigError, match="probes"):
        df_config.load_config(str(cr))


def test_brownfield_probe_not_an_object_rejected(tmp_path):
    cr = tmp_path / "control"
    write_config(cr, brownfield={"mode": "auto", "probes": ["not-a-dict"]})
    with pytest.raises(df_config.ConfigError, match="probes"):
        df_config.load_config(str(cr))


def test_brownfield_probe_bad_slug_id_rejected(tmp_path):
    cr = tmp_path / "control"
    bad = dict(ADD_PROBE, id="Not_Valid!")
    write_config(cr, brownfield={"mode": "auto", "probes": [bad]})
    with pytest.raises(df_config.ConfigError, match="id"):
        df_config.load_config(str(cr))


def test_brownfield_probe_duplicate_id_rejected(tmp_path):
    cr = tmp_path / "control"
    write_config(cr, brownfield={"mode": "auto", "probes": [ADD_PROBE, dict(ADD_PROBE)]})
    with pytest.raises(df_config.ConfigError, match="duplicate"):
        df_config.load_config(str(cr))


def test_brownfield_probe_empty_run_rejected(tmp_path):
    cr = tmp_path / "control"
    bad = dict(ADD_PROBE, run=[])
    write_config(cr, brownfield={"mode": "auto", "probes": [bad]})
    with pytest.raises(df_config.ConfigError, match="run"):
        df_config.load_config(str(cr))


def test_brownfield_probe_non_string_run_item_rejected(tmp_path):
    cr = tmp_path / "control"
    bad = dict(ADD_PROBE, run=["echo", 123])
    write_config(cr, brownfield={"mode": "auto", "probes": [bad]})
    with pytest.raises(df_config.ConfigError, match="run"):
        df_config.load_config(str(cr))


@pytest.mark.parametrize("bad_timeout", [0, 121, -1, "10", True, 3.5])
def test_brownfield_probe_bad_timeout_rejected(tmp_path, bad_timeout):
    cr = tmp_path / "control"
    bad = dict(ADD_PROBE, timeout_s=bad_timeout)
    write_config(cr, brownfield={"mode": "auto", "probes": [bad]})
    with pytest.raises(df_config.ConfigError, match="timeout_s"):
        df_config.load_config(str(cr))


# ---------------------------------------------------------------------------
# supervisor wiring: characterize-before-build, dev cohort, manifest
# ---------------------------------------------------------------------------

def test_brownfield_run_generates_scenarios_journal_and_manifest(tmp_path):
    cr = setup_control(tmp_path, FAKE_BROWNFIELD_BREAK, max_iterations=1, checkpoint="auto")
    set_brownfield(cr, {"mode": "brownfield", "probes": [ADD_PROBE]})
    src = make_legacy_src(tmp_path)

    rc = supervisor.run(str(cr), str(src))
    assert rc == 3  # CAP_REACHED: the builder always breaks `add`

    entries, run_id = read_journal(cr)
    states = [e["state"] for e in entries]
    assert "MODE_DETECTED" in states
    assert "CHARACTERIZED" in states

    mode_entry = next(e for e in entries if e["state"] == "MODE_DETECTED")
    assert mode_entry["data"]["mode"] == "brownfield"
    assert mode_entry["data"]["legacy_ignored"] is False

    char_entry = next(e for e in entries if e["state"] == "CHARACTERIZED")
    assert char_entry["data"]["mode"] == "brownfield"
    assert char_entry["data"]["generated"] == 1
    assert char_entry["data"]["behavior_ids"] == ["BHV-REGRESS-0"]

    run_dir = cr / "runs" / run_id
    gen_dir = run_dir / "generated-scenarios"
    assert (gen_dir / "BHV-REGRESS-0-S1.json").exists()
    generated_sc = json.loads((gen_dir / "BHV-REGRESS-0-S1.json").read_text(encoding="utf-8"))
    assert generated_sc["cohort"] == "dev"
    assert generated_sc["then"]["stdout_equals"] == "5\n"

    # The generated scenario reached the dev cohort's verify pass and FAILED
    # (the builder's overwritten legacy_app computes 2-3, not 2+3).
    report = json.loads((run_dir / "verifier_report_iter_1.json").read_text(encoding="utf-8"))
    regress_result = next(r for r in report["results"] if r["behavior_id"] == "BHV-REGRESS-0")
    assert regress_result["pass"] is False
    assert regress_result["taxonomy"] == "wrong_output"

    manifest = json.loads((run_dir / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["outcome"] == "CAP_REACHED"
    assert manifest["mode"] == "brownfield"
    assert manifest["characterization"] == {
        "probes": 1,
        "generated": 1,
        "note": "behavioral snapshot at probe points; unprobed behavior may regress",
        "legacy_ignored": False,
    }


def test_auto_mode_with_project_src_autodetects_brownfield(tmp_path):
    cr = setup_control(tmp_path, FAKE_BROWNFIELD_BREAK, max_iterations=1, checkpoint="auto")
    set_brownfield(cr, {"probes": [ADD_PROBE]})  # mode absent -> "auto"
    src = make_legacy_src(tmp_path)

    supervisor.run(str(cr), str(src))

    _, run_id = read_journal(cr)
    manifest = json.loads(
        (cr / "runs" / run_id / "manifest.json").read_text(encoding="utf-8")
    )
    assert manifest["mode"] == "brownfield"


def test_auto_brownfield_with_zero_probes_warns_journals_and_flags_unguarded(tmp_path, capsys):
    # Auto-detected brownfield (project_src with files) but NO probes configured
    # -- the valid back-compat no-op. It must NOT read as "regressions checked":
    # stderr WARN + a distinct BROWNFIELD_UNGUARDED journal entry + an
    # unambiguous manifest note.
    cr = setup_control(tmp_path, FAKE, checkpoint="auto")
    # no brownfield block at all -> {"mode": "auto", "probes": []}
    src = make_legacy_src(tmp_path)

    rc = supervisor.run(str(cr), str(src))
    assert rc == 0  # FAKE still converges; the greet spec is unaffected

    err = capsys.readouterr().err
    assert "no probes configured" in err
    assert "NO regression guards were captured" in err

    entries, run_id = read_journal(cr)
    states = [e["state"] for e in entries]
    assert "BROWNFIELD_UNGUARDED" in states
    assert states.count("CHARACTERIZED") == 0  # nothing was characterized

    manifest = json.loads(
        (cr / "runs" / run_id / "manifest.json").read_text(encoding="utf-8")
    )
    assert manifest["mode"] == "brownfield"
    assert manifest["characterization"]["generated"] == 0
    assert "unguarded" in manifest["characterization"]["note"]
    assert "snapshot at probe points" not in manifest["characterization"]["note"]


def test_fresh_prebuild_abort_manifest_still_carries_mode_and_characterization(tmp_path):
    # An oracle-gate failure (inert `then`) finalizes a GATE_FAILED manifest
    # BEFORE brownfield detection ever runs. The additive mode/characterization
    # fields are seeded into manifest_base at construction (like credentials),
    # so even this early abort carries them -- honoring config-reference.md's
    # "every terminal manifest" claim.
    cr = setup_control(tmp_path, FAKE, checkpoint="auto")
    # Plant an inert scenario oracle: {"stdout_contains": ""} passes any output.
    inert = {
        "ir_version": "0.1", "id": "BHV-777-S1", "behavior_id": "BHV-777",
        "title": "inert", "given": "x",
        "when": {"run": ["python3", "greet.py", "X"], "timeout_s": 10},
        "then": {"stdout_contains": ""},
    }
    (cr / "scenarios" / "inert.json").write_text(json.dumps(inert), encoding="utf-8")
    src = make_legacy_src(tmp_path)

    rc = supervisor.run(str(cr), str(src))
    assert rc == 2  # pre-build gate failed, no build run

    _, run_id = read_journal(cr)
    manifest = json.loads(
        (cr / "runs" / run_id / "manifest.json").read_text(encoding="utf-8")
    )
    assert manifest["outcome"] == "GATE_FAILED"
    assert "mode" in manifest
    assert "characterization" in manifest
    # Detection never ran (aborted before it) -> the honest "unknown" seed.
    assert manifest["mode"] == "unknown"
    assert manifest["characterization"]["generated"] == 0
    assert "aborted before build" in manifest["characterization"]["note"]


def test_generated_scenario_content_never_reaches_builder_prompt_or_workspace(tmp_path):
    cr = setup_control(tmp_path, FAKE_BROWNFIELD_BREAK, max_iterations=1, checkpoint="auto")
    set_brownfield(cr, {"mode": "brownfield", "probes": [ADD_PROBE]})
    src = make_legacy_src(tmp_path)

    supervisor.run(str(cr), str(src))

    _, run_id = read_journal(cr)
    run_dir = cr / "runs" / run_id
    workspace = tmp_path / "ws" / run_id

    # Distinctive strings that only appear inside a generated scenario's
    # human-readable fields (title/given) -- never legitimate builder input.
    forbidden = ["regression guard: add-ok", "captured from the pre-change system"]

    checked_any = False
    for path in _walk_all_files(str(workspace)):
        checked_any = True
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            text = f.read()
        for marker in forbidden:
            assert marker not in text, f"generated scenario content leaked into {path}"
    assert checked_any, "workspace is empty -- scan would be vacuous"

    # The audit-copy prompts (control plane) legitimately never carry this
    # content either -- the barrier is upstream of compose_prompt, but this
    # closes the loop on the ONE place prompt text is persisted.
    for name in os.listdir(run_dir):
        if name.startswith("prompt_iter_"):
            text = (run_dir / name).read_text(encoding="utf-8")
            for marker in forbidden:
                assert marker not in text


def test_explicit_greenfield_with_legacy_project_src_sets_legacy_ignored(tmp_path):
    cr = setup_control(tmp_path, FAKE, checkpoint="auto")
    set_brownfield(cr, {"mode": "greenfield"})
    src = make_legacy_src(tmp_path)

    rc = supervisor.run(str(cr), str(src))
    assert rc == 0  # FAKE converges in 2 iterations regardless of project_src

    _, run_id = read_journal(cr)
    manifest = json.loads(
        (cr / "runs" / run_id / "manifest.json").read_text(encoding="utf-8")
    )
    assert manifest["mode"] == "greenfield"
    assert manifest["characterization"] == {
        "probes": 0,
        "generated": 0,
        "note": "behavioral snapshot at probe points; unprobed behavior may regress",
        "legacy_ignored": True,
    }


def test_default_auto_no_project_src_is_greenfield_backcompat(tmp_path):
    cr = setup_control(tmp_path, FAKE, checkpoint="auto")
    # no brownfield block at all -- exercises the default {"mode":"auto","probes":[]}

    rc = supervisor.run(str(cr), None)
    assert rc == 0

    _, run_id = read_journal(cr)
    entries, _ = read_journal(cr)
    states = [e["state"] for e in entries]
    assert states.count("CHARACTERIZED") == 0  # never triggers without project_src

    manifest = json.loads(
        (cr / "runs" / run_id / "manifest.json").read_text(encoding="utf-8")
    )
    assert manifest["mode"] == "greenfield"
    assert manifest["characterization"] == {"probes": 0, "generated": 0}


def test_resume_reuses_generated_scenarios_dir_without_recharacterizing(tmp_path):
    cr = setup_control(tmp_path, FAKE, max_iterations=5, checkpoint="pause")
    set_brownfield(cr, {"mode": "brownfield", "probes": [ADD_PROBE]})
    src = make_legacy_src(tmp_path)

    rc = supervisor.run(str(cr), str(src))
    assert rc == supervisor.PAUSED  # FAKE needs iteration 2 to converge

    _, run_id = read_journal(cr)
    run_dir = cr / "runs" / run_id
    gen_dir = run_dir / "generated-scenarios"
    before = {
        name: (gen_dir / name).read_text(encoding="utf-8")
        for name in sorted(os.listdir(gen_dir))
    }
    assert before  # non-vacuous: something was actually generated

    # The source changes between run and resume -- resume must NOT re-observe
    # it (resume() isn't even given project_src): if it did, the probe would
    # now capture a different `add` result and the sealed guard would change.
    (src / "legacy_app").write_text(
        "import sys\nprint('completely different legacy app now')\n", encoding="utf-8",
    )

    # M36b: FAKE converges on iteration 2 but H2 pauses before ship; seal it.
    rc2 = supervisor.resume(str(cr), "continue")
    assert rc2 == supervisor.PAUSED  # converged -> AWAIT_SHIP
    rc3 = supervisor.resume(str(cr), "continue")
    assert rc3 == 0  # seal-reentry

    after = {
        name: (gen_dir / name).read_text(encoding="utf-8")
        for name in sorted(os.listdir(gen_dir))
    }
    assert after == before  # byte-identical: no re-characterization happened

    entries, _ = read_journal(cr)
    states = [e["state"] for e in entries]
    assert states.count("CHARACTERIZED") == 1  # only from the original run

    manifest = json.loads((run_dir / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["outcome"] == "COMPLETE_UNQUALIFIED"
    assert manifest["mode"] == "brownfield"
    assert manifest["characterization"]["generated"] == 1
    assert manifest["characterization"]["probes"] == 1
