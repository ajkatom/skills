"""M54 (Codex R4 re-audit): DF-R4-05 init->H2 default, DF-R4-06 H4 must not
survive an effective-tier downgrade, DF-R4-07 builder support_files mount.
"""
import json
import os

import pytest

import df_config
import df_init
import supervisor
from test_init import _kv_answers
from test_supervisor import FAKE, setup_control, read_journal


# --- DF-R4-05: canonical init with no mode fields scaffolds H2 (not H3) ------
# (load_config's own no-fields default -> H2 is covered by test_modes.py; here
# we prove df_init.build_config emits the documented default explicitly rather
# than the old checkpoint:"auto" which resolved to H3.)

def test_init_no_mode_fields_scaffolds_h2(tmp_path):
    answers = _kv_answers(tmp_path)
    for k in ("intervention_mode", "autonomy", "checkpoint"):
        answers.pop(k, None)
    cfg = df_init.build_config(answers)
    assert cfg.get("intervention_mode") == "H2"
    assert "autonomy" not in cfg and "checkpoint" not in cfg


def test_init_explicit_legacy_checkpoint_still_honored(tmp_path):
    answers = _kv_answers(tmp_path)
    answers.pop("intervention_mode", None)
    answers["autonomy"] = 4
    answers["checkpoint"] = "auto"
    cfg = df_init.build_config(answers)
    assert cfg.get("checkpoint") == "auto" and cfg.get("autonomy") == 4
    assert "intervention_mode" not in cfg


def test_init_explicit_intervention_mode_still_honored(tmp_path):
    answers = _kv_answers(tmp_path)
    answers["intervention_mode"] = "H1"
    answers.pop("autonomy", None)
    answers.pop("checkpoint", None)
    cfg = df_init.build_config(answers)
    assert cfg.get("intervention_mode") == "H1"


# --- DF-R4-06: H4 must fail closed when the effective tier downgrades ---------

def _hardened_h4_control(tmp_path):
    cr = setup_control(tmp_path, FAKE)
    p = cr / "config.json"
    cfg = json.loads(p.read_text())
    cfg["assurance"] = "hardened"
    for k in ("autonomy", "checkpoint"):
        cfg.pop(k, None)
    cfg["intervention_mode"] = "H4"
    p.write_text(json.dumps(cfg))
    return cr


def test_h4_effective_downgrade_refused_before_dispatch(tmp_path, monkeypatch):
    cr = _hardened_h4_control(tmp_path)
    # Force the EFFECTIVE tier below hardened (the auditor's repro: docker
    # unavailable + --allow-downgrade). Deterministic via resolve_isolation.
    monkeypatch.setattr(supervisor, "resolve_isolation",
                        lambda *a, **k: ("standard", [], "fake-standard-backend", True))

    calls = []

    def recording_invoke(*a, **k):
        calls.append(True)
        return {"adapter_protocol": "0.1", "status": "ok"}, None

    monkeypatch.setattr(supervisor, "invoke_adapter", recording_invoke)

    rc = supervisor.run(str(cr), None, allow_downgrade=True)
    assert rc != 0
    assert calls == [], "H4 under a downgraded tier must NOT spawn the builder"
    run_dir = cr / "runs" / os.listdir(cr / "runs")[0]
    m = json.loads((run_dir / "manifest.json").read_text())
    assert m["outcome"] == "MODE_TIER_UNAVAILABLE"
    assert m["qualified"] is False
    journal_text = (run_dir / "journal.jsonl").read_text()
    assert "H4_TIER_DOWNGRADED" in journal_text


def test_h4_effective_tier_stays_hardened_is_not_refused(tmp_path, monkeypatch):
    cr = _hardened_h4_control(tmp_path)
    import test_hardened_config as H
    H._patch_hardened_probes(monkeypatch, os_ok=True, dk_ok=True)
    monkeypatch.setattr(supervisor, "resolve_isolation",
                        lambda *a, **k: ("hardened", [], "fake-hardened-backend", True))

    def fake_invoke(adapter, role, workdir, prompt_file, timeout_s,
                    exec_prefix=None, env_extra=None, **kw):
        with open(os.path.join(workdir, "greet.py"), "w", encoding="utf-8") as f:
            f.write(H.GREET_PY)
        return {"adapter_protocol": "0.1", "status": "ok"}, None

    monkeypatch.setattr(supervisor, "invoke_adapter", fake_invoke)
    supervisor.run(str(cr), None)
    run_dir = cr / "runs" / os.listdir(cr / "runs")[0]
    m = json.loads((run_dir / "manifest.json").read_text())
    assert m["outcome"] != "MODE_TIER_UNAVAILABLE"


# --- DF-R4-07: builder support_files validation ------------------------------
# adapter + support files live in an `adp/` subdir so the adapter DIRECTORY is
# disjoint from the `control/` control root (df_config's existing adapter-dir
# check), letting us exercise the support_files-specific validation.

def _hardened_support_control(tmp_path, support_files):
    from test_config import write_config
    adp = tmp_path / "adp"
    adp.mkdir(exist_ok=True)
    adapter = adp / "adapter"
    adapter.write_text("#!/bin/sh\n")
    cr = tmp_path / "control"
    write_config(
        cr, assurance="hardened",
        roles={"builder": {"adapter": str(adapter), "support_files": support_files}},
        hardened={"image": "python:3.12-alpine"})
    return cr, adp


def test_support_files_absolute_existing_disjoint_ok(tmp_path):
    (tmp_path / "adp").mkdir(exist_ok=True)
    sup = tmp_path / "adp" / "df_confine_stub.py"
    sup.write_text("# support file\n")
    cr, _ = _hardened_support_control(tmp_path, [str(sup)])
    cfg = df_config.load_config(str(cr))
    assert os.path.realpath(str(sup)) in cfg["_support_files"]


def test_support_files_absent_is_empty(tmp_path):
    cr, _ = _hardened_support_control(tmp_path, [])
    cfg = df_config.load_config(str(cr))
    assert cfg["_support_files"] == []


def test_support_files_nonexistent_rejected(tmp_path):
    cr, _ = _hardened_support_control(tmp_path, ["/no/such/support_file.py"])
    with pytest.raises(df_config.ConfigError, match="support_files"):
        df_config.load_config(str(cr))


def test_support_files_relative_rejected(tmp_path):
    cr, _ = _hardened_support_control(tmp_path, ["relative/df_confine.py"])
    with pytest.raises(df_config.ConfigError, match="support_files"):
        df_config.load_config(str(cr))


def test_support_files_appear_in_hardened_build_argv_ro_mounts(tmp_path, monkeypatch):
    # DF-R4-07: the declared support files must actually be ro-mounted into the
    # hardened builder container (not just validated) — capture the ro_mounts
    # df_container.build_argv is called with during a hardened run.
    import df_container
    import test_hardened_config as H

    cr = setup_control(tmp_path, FAKE)
    sup = tmp_path / "adp_support"
    sup.mkdir()
    sup_file = sup / "df_confine_stub.py"
    sup_file.write_text("# support\n")
    p = cr / "config.json"
    cfg = json.loads(p.read_text())
    cfg["assurance"] = "hardened"
    for k in ("autonomy", "checkpoint"):
        cfg.pop(k, None)
    cfg["intervention_mode"] = "H3"
    cfg.setdefault("roles", {}).setdefault("builder", {})
    cfg["roles"]["builder"]["support_files"] = [str(sup_file)]
    p.write_text(json.dumps(cfg))

    H._patch_hardened_probes(monkeypatch, os_ok=True, dk_ok=True)
    captured = {}
    real_build_argv = df_container.build_argv

    def capturing_build_argv(image, workspace, ro_mounts, **kw):
        captured["ro_mounts"] = list(ro_mounts)
        return real_build_argv(image, workspace, ro_mounts, **kw)

    monkeypatch.setattr(supervisor.df_container, "build_argv", capturing_build_argv)

    def fake_invoke(adapter, role, workdir, prompt_file, timeout_s,
                    exec_prefix=None, env_extra=None, **kw):
        with open(os.path.join(workdir, "greet.py"), "w", encoding="utf-8") as f:
            f.write(H.GREET_PY)
        return {"adapter_protocol": "0.1", "status": "ok"}, None

    monkeypatch.setattr(supervisor, "invoke_adapter", fake_invoke)
    supervisor.run(str(cr), None)
    assert os.path.realpath(str(sup_file)) in captured.get("ro_mounts", [])


def test_support_files_inside_control_root_rejected(tmp_path):
    from test_config import write_config
    adp = tmp_path / "adp"
    adp.mkdir()
    adapter = adp / "adapter"
    adapter.write_text("#!/bin/sh\n")
    cr = tmp_path / "control"
    cr.mkdir()
    inside = cr / "sneaky.py"
    inside.write_text("# would breach the barrier\n")
    write_config(
        cr, assurance="hardened",
        roles={"builder": {"adapter": str(adapter), "support_files": [str(inside)]}},
        hardened={"image": "python:3.12-alpine"})
    with pytest.raises(df_config.ConfigError, match="disjoint|support_files"):
        df_config.load_config(str(cr))
