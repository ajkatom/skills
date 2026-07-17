"""M36a Task 1: df_modes -- the four intervention modes as pause-point sets,
the legacy (autonomy, checkpoint) -> mode mapping, dual-field rejection, the H4
tier gate, and alias canonicalization. Pure unit tests (no supervisor)."""
import json
import os

import pytest

import df_config
import df_modes
from test_supervisor import setup_control


def test_canonical_mode_h_codes_and_aliases():
    assert df_modes.canonical_mode("H1") == "H1"
    assert df_modes.canonical_mode("h2") == "H2"
    assert df_modes.canonical_mode("directed") == "H1"
    assert df_modes.canonical_mode("Supervised") == "H2"
    assert df_modes.canonical_mode("guarded") == "H3"
    assert df_modes.canonical_mode("guarded-autonomous") == "H3"
    assert df_modes.canonical_mode("lights_out") == "H4"
    assert df_modes.canonical_mode(" Lights-Out ") == "H4"


def test_canonical_mode_rejects_unknown():
    for bad in ("H5", "", "auto", "pause", "h0", None, 4):
        with pytest.raises(df_modes.ModeError):
            df_modes.canonical_mode(bad)


def test_pause_point_sets_are_the_authoritative_table():
    # H1 gates before-build (i>=2) + after-verify (+ budget). H2 == legacy
    # pause == after-verify only. H3 == legacy auto == budget guard only.
    # H4 == lights-out == nothing. before_ship is DEFERRED in every mode.
    assert df_modes.pauses_before_build("H1", 2) is True
    assert df_modes.pauses_before_build("H1", 1) is False  # never before the first build
    assert df_modes.pauses_before_build("H2", 2) is False
    assert df_modes.pauses_before_build("H3", 2) is False
    assert df_modes.pauses_before_build("H4", 2) is False

    assert df_modes.pauses_after_verify("H1") is True
    assert df_modes.pauses_after_verify("H2") is True
    assert df_modes.pauses_after_verify("H3") is False
    assert df_modes.pauses_after_verify("H4") is False

    # M36b: before_ship pauses on H1 + H2 (both supervised/directed modes gate
    # the ship on convergence); H3 (guarded) + H4 (lights-out) never do.
    assert df_modes.pauses_before_ship("H1") is True
    assert df_modes.pauses_before_ship("H2") is True
    assert df_modes.pauses_before_ship("H3") is False
    assert df_modes.pauses_before_ship("H4") is False

    assert df_modes.pauses_on_budget_guard("H1") is True
    assert df_modes.pauses_on_budget_guard("H2") is True
    assert df_modes.pauses_on_budget_guard("H3") is True
    assert df_modes.pauses_on_budget_guard("H4") is False  # lights-out halts, never pauses

    assert df_modes.is_lights_out("H4") is True
    assert not any(df_modes.is_lights_out(m) for m in ("H1", "H2", "H3"))
    assert df_modes.requires_hardened("H4") is True
    assert not any(df_modes.requires_hardened(m) for m in ("H1", "H2", "H3"))


def test_legacy_mode_mapping_full_table():
    assert df_modes.legacy_mode(4, "pause") == "H2"
    assert df_modes.legacy_mode(4, "auto") == "H3"
    assert df_modes.legacy_mode(5, "auto") == "H4"
    # (5, "pause") is contradictory (lights-out that pauses) -> rejected.
    with pytest.raises(df_modes.ModeError):
        df_modes.legacy_mode(5, "pause")


def test_legacy_fields_round_trip_back_compat():
    # The (autonomy, checkpoint) a mode is back-compat-equivalent to, so
    # cfg["_checkpoint"]/cfg["autonomy"] keep working for every reader.
    assert df_modes.legacy_fields_for("H1") == (4, "pause")
    assert df_modes.legacy_fields_for("H2") == (4, "pause")
    assert df_modes.legacy_fields_for("H3") == (4, "auto")
    assert df_modes.legacy_fields_for("H4") == (5, "auto")


# --- df_config integration: the mode knob, dual-field rejection, tier gate ---

_LOAD_SEQ = [0]


def _load(tmp_path, **over):
    _LOAD_SEQ[0] += 1
    sub = tmp_path / f"cr{_LOAD_SEQ[0]}"
    sub.mkdir()
    cr = setup_control(sub, "/bin/echo")
    p = cr / "config.json"
    cfg = json.loads(p.read_text())
    for k in ("autonomy", "checkpoint"):
        cfg.pop(k, None)
    cfg.update(over)
    p.write_text(json.dumps(cfg))
    return df_config.load_config(str(cr))


def test_config_default_is_h2(tmp_path):
    cfg = _load(tmp_path)  # nothing set
    assert cfg["_intervention_mode"] == "H2"
    assert cfg["_intervention_source"] == "default"
    assert cfg["_checkpoint"] == "pause"  # back-compat derivation preserved


def test_config_legacy_pairs_map(tmp_path):
    assert _load(tmp_path, autonomy=4, checkpoint="pause")["_intervention_mode"] == "H2"
    assert _load(tmp_path, autonomy=4, checkpoint="auto")["_intervention_mode"] == "H3"
    c = _load(tmp_path, autonomy=4, checkpoint="auto")
    assert c["_intervention_source"] == "legacy"
    assert c["_checkpoint"] == "auto"


def test_config_explicit_mode(tmp_path):
    c = _load(tmp_path, intervention_mode="directed")
    assert c["_intervention_mode"] == "H1"
    assert c["_intervention_source"] == "explicit"
    # H1 shares the pause family's legacy checkpoint so existing readers work.
    assert c["_checkpoint"] == "pause"
    assert c["autonomy"] == 4


def test_config_dual_field_rejected(tmp_path):
    with pytest.raises(df_config.ConfigError) as e:
        _load(tmp_path, intervention_mode="H2", checkpoint="auto")
    assert "df-migrate-config" in str(e.value)
    with pytest.raises(df_config.ConfigError):
        _load(tmp_path, intervention_mode="H2", autonomy=4)


def test_config_bad_mode_rejected(tmp_path):
    with pytest.raises(df_config.ConfigError):
        _load(tmp_path, intervention_mode="H9")


def test_config_h4_requires_hardened_tier(tmp_path):
    # cooperative can't run lights-out (reuses the autonomy-5 tier gate).
    with pytest.raises(df_config.ConfigError) as e:
        _load(tmp_path, intervention_mode="H4")
    assert "hardened" in str(e.value)


def test_config_legacy_autonomy5_pause_still_rejected(tmp_path):
    # The contradictory legacy pair maps through legacy_mode -> ModeError ->
    # ConfigError (autonomy 5 also requires hardened, caught first here at
    # cooperative; the mapping rejection is unit-tested above).
    with pytest.raises(df_config.ConfigError):
        _load(tmp_path, autonomy=5, checkpoint="pause")
