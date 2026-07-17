"""M36a Task 5: df-migrate-config -- rewrite a legacy autonomy/checkpoint
config to the equivalent intervention_mode. Idempotent, atomic, validated,
dual-field-refusing, leaves a .bak. Also proves the mapped mode's OBSERVABLE
pause behavior is unchanged (compat fixture)."""
import json
import os

import df_config
import supervisor
from test_supervisor import FAKE, setup_control, read_journal


def _cfg(cr):
    return json.loads((cr / "config.json").read_text())


def test_migrate_legacy_pause_to_h2(tmp_path):
    cr = setup_control(tmp_path, FAKE)  # autonomy 4, checkpoint default (pause)
    assert supervisor.migrate_config_cmd(str(cr)) == 0
    cfg = _cfg(cr)
    assert cfg["intervention_mode"] == "H2"
    assert "autonomy" not in cfg and "checkpoint" not in cfg
    assert (cr / "config.json.bak").exists()
    # Still loads, and resolves to the same mode.
    assert df_config.load_config(str(cr))["_intervention_mode"] == "H2"


def test_migrate_legacy_auto_to_h3(tmp_path):
    cr = setup_control(tmp_path, FAKE, checkpoint="auto")
    assert supervisor.migrate_config_cmd(str(cr)) == 0
    assert _cfg(cr)["intervention_mode"] == "H3"


def test_migrate_is_idempotent(tmp_path):
    cr = setup_control(tmp_path, FAKE, checkpoint="auto")
    assert supervisor.migrate_config_cmd(str(cr)) == 0
    before = (cr / "config.json").read_text()
    assert supervisor.migrate_config_cmd(str(cr)) == 0     # no-op
    assert (cr / "config.json").read_text() == before


def test_migrate_refuses_dual_fields(tmp_path):
    cr = setup_control(tmp_path, FAKE)
    p = cr / "config.json"
    cfg = json.loads(p.read_text())
    cfg["intervention_mode"] = "H2"      # now has BOTH mode and legacy autonomy
    p.write_text(json.dumps(cfg))
    assert supervisor.migrate_config_cmd(str(cr)) == 2    # hand-edit to resolve
    # unchanged on refusal
    assert json.loads(p.read_text())["intervention_mode"] == "H2"


def test_migrated_config_pause_behavior_unchanged(tmp_path):
    """Compat fixture: an old {autonomy:4, checkpoint:pause} config and its
    migrated {intervention_mode:H2} equivalent PAUSE at the same point with the
    same holdout-free checkpoint artifacts -- observable behavior unchanged."""
    # legacy config: pauses after verify 1
    cr_legacy = setup_control(tmp_path / "legacy", FAKE)
    assert supervisor.run(str(cr_legacy), None) == 10
    legacy_states = [e["state"] for e in read_journal(cr_legacy)[0]]

    # migrated config on an identical control root
    cr_mig = setup_control(tmp_path / "mig", FAKE)
    assert supervisor.migrate_config_cmd(str(cr_mig)) == 0
    assert supervisor.run(str(cr_mig), None) == 10
    mig_states = [e["state"] for e in read_journal(cr_mig)[0]]

    # same transition sequence up to (and including) the CHECKPOINT pause
    assert legacy_states == mig_states
    assert mig_states[-1] == "CHECKPOINT"
