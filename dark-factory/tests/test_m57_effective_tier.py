"""M57 (Codex R5): DF-R5-04 — the sealed manifest records BOTH the requested and
the EFFECTIVE assurance tier, and every post-seal decision consumes the effective
tier, so a permitted --allow-downgrade can't create a requested-vs-effective
mismatch (the enterprise-downgrade-to-unshippable-dead-end).
"""
import json
import os

import supervisor
from test_supervisor import FAKE, setup_control, read_journal


def test_effective_tier_of_prefers_effective_then_falls_back():
    assert supervisor._effective_tier_of(
        {"tier": "enterprise", "effective_tier": "hardened"}) == "hardened"
    # pre-M57 manifest (no effective_tier) falls back to the configured tier.
    assert supervisor._effective_tier_of({"tier": "standard"}) == "standard"


def _h3(cr):
    # H3 (guarded) has no per-iteration pause, so a non-converging FAKE builder
    # runs to CAP_REACHED and seals a terminal manifest (which carries the tier
    # fields) — exactly what we assert here.
    p = cr / "config.json"
    cfg = json.loads(p.read_text())
    for k in ("autonomy", "checkpoint"):
        cfg.pop(k, None)
    cfg["intervention_mode"] = "H3"
    p.write_text(json.dumps(cfg))
    return cfg


def test_manifest_seals_requested_and_effective_tier(tmp_path):
    cr = setup_control(tmp_path, FAKE)
    _h3(cr)
    supervisor.run(str(cr), None)  # non-converging FAKE -> CAP_REACHED, manifest sealed
    run_dir = cr / "runs" / os.listdir(cr / "runs")[0]
    m = json.loads((run_dir / "manifest.json").read_text())
    # A non-downgraded run: all three agree (cooperative here).
    assert m["tier"] == "cooperative"
    assert m["requested_tier"] == "cooperative"
    assert m["effective_tier"] == "cooperative"


def test_downgraded_run_seals_distinct_effective_tier_consumed_downstream(tmp_path, monkeypatch):
    # Configure hardened, but force resolve_isolation to DOWNGRADE the effective
    # tier to standard (the --allow-downgrade path, deterministic).
    cr = setup_control(tmp_path, FAKE)
    p = cr / "config.json"
    cfg = json.loads(p.read_text())
    cfg["assurance"] = "hardened"
    p.write_text(json.dumps(cfg))
    _h3(cr)
    monkeypatch.setattr(supervisor, "resolve_isolation",
                        lambda *a, **k: ("standard", [], "fake-standard-backend", True))

    supervisor.run(str(cr), None, allow_downgrade=True)
    run_dir = cr / "runs" / os.listdir(cr / "runs")[0]
    m = json.loads((run_dir / "manifest.json").read_text())
    # The downgrade is EXPLICIT in the sealed evidence:
    assert m["requested_tier"] == "hardened"
    assert m["effective_tier"] == "standard"
    # And every post-seal decision consumes the EFFECTIVE tier — so this run is
    # treated as a standard run downstream, never as its configured hardened.
    assert supervisor._effective_tier_of(m) == "standard"
