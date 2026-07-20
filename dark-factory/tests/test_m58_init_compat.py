"""M58 (Codex R5): DF-R5-05/06/09/10.

  * R5-05: the candidate_network "deny" vs http-scenario rule is ONE shared
    function (run_scenarios.deny_network_incompatible_ids) consumed by BOTH the
    supervisor's pre-build gate and df_init.validate_scaffold — init can no
    longer bless a control root that `run` then rejects GATE_FAILED.
  * R5-06: the canonical init on-ramp passes through hardened / credentials /
    brownfield blocks and a fully-shaped roles.builder (timeout_s /
    adapter_sha256 / model_identity / support_files); a partial-legacy
    answers.autonomy:4 defaults the omitted checkpoint to "pause" (H2) exactly
    like the runtime config default, not silently "auto" (H3).
  * R5-09: one logical run pins ONE container image identity across process
    resume — first segment journals IMAGE_RESOLVED, later segments reuse it
    verbatim instead of re-resolving a possibly-moved mutable tag.
  * R5-10: df_ship.toolchain_identity resolves a bare command with every
    relative/empty PATH entry absolutized against the ACTION cwd (execvpe-
    after-chdir semantics), so PATH="." evidence matches what actually ran.
"""
import hashlib
import json
import os

import pytest

import df_config
import df_init
import df_ship
import run_scenarios
import supervisor
from test_init import _kv_answers


# ---------------------------------------------------------------------------
# R5-05 — the shared deny-vs-http rule
# ---------------------------------------------------------------------------

_HTTP_SC = {
    "ir_version": "0.3", "id": "BHV-GET-H1", "behavior_id": "BHV-GET",
    "cohort": "dev", "title": "http poll", "given": "svc",
    "when": {
        "http": {
            "start": ["python3", "svc.py"], "port_env": "PORT",
            "ready_path": "/health", "request": {"method": "GET", "path": "/kv/a"},
        },
        "timeout_s": 10,
    },
    "then": {"http_status": 200, "body_contains": "indigo"},
}


def test_deny_rule_flags_http_and_property_http_only():
    plain = {"id": "A", "when": {"run": ["true"]}}
    http = {"id": "B", "when": {"http": {}}}
    prop_http = {"id": "C", "when": {"property": {"steps": [{"http": {}}]}}}
    prop_plain = {"id": "D", "when": {"property": {"steps": [{"run": ["true"]}]}}}
    ids = run_scenarios.deny_network_incompatible_ids(
        [plain, http, prop_http, prop_plain])
    assert ids == ["B", "C"]


def _scaffolded_deny_root(tmp_path, candidate_network):
    answers = _kv_answers(
        tmp_path, assurance="standard",
        options={"candidate_network": candidate_network})
    cr = answers["control_root"]
    df_init.scaffold(cr, answers)
    # An http scenario for a DECLARED behavior (so the ONLY possible failure
    # is the network-compat rule, never orphan/coverage noise).
    with open(os.path.join(cr, "scenarios", "BHV-GET-H1.json"), "w",
              encoding="utf-8") as f:
        json.dump(_HTTP_SC, f)
    return cr


def test_validate_scaffold_refuses_deny_plus_http_scenario(tmp_path):
    cr = _scaffolded_deny_root(tmp_path, "deny")
    ok, report = df_init.validate_scaffold(cr)
    assert report["network_incompatible"] == ["BHV-GET-H1"]
    assert ok is False, "init must not bless a root run would reject GATE_FAILED"
    # ...and the operator-facing failure lines NAME the rule + offending ids.
    lines = "\n".join(supervisor._init_report_lines(report))
    assert "BHV-GET-H1" in lines and "candidate_network" in lines


def test_validate_scaffold_loopback_plus_http_scenario_is_blessed(tmp_path):
    # Same tree, candidate_network "loopback" -> 127.0.0.1 stays reachable ->
    # the SAME rule passes (no false refusal of a legitimate http root).
    cr = _scaffolded_deny_root(tmp_path, "loopback")
    ok, report = df_init.validate_scaffold(cr)
    assert report["network_incompatible"] == []
    assert ok is True


def test_validate_scaffold_enforces_the_adequacy_gate_like_run(tmp_path):
    # Opus-review finding (R5-05 general class): `run` also gates on scenario-
    # class ADEQUACY pre-build; a stricter scenario_adequacy block (hand-edited
    # into a blessed root — exactly what validate_scaffold exists to re-check)
    # must fail validation HERE, not first at run's ADEQUACY_GATE_FAILED.
    answers = _kv_answers(tmp_path)
    cr = answers["control_root"]
    df_init.scaffold(cr, answers)
    cfg_path = os.path.join(cr, "config.json")
    cfg = json.loads(open(cfg_path, encoding="utf-8").read())
    cfg["scenario_adequacy"] = {"required_classes": ["happy", "failure"]}
    with open(cfg_path, "w", encoding="utf-8") as f:
        json.dump(cfg, f)

    ok, report = df_init.validate_scaffold(cr)
    assert report["adequacy_under_covered"], "kv scenarios are all happy-class"
    assert ok is False
    lines = "\n".join(supervisor._init_report_lines(report))
    assert "adequacy" in lines


# ---------------------------------------------------------------------------
# R5-06 — init passthrough + legacy default parity
# ---------------------------------------------------------------------------

def test_build_config_forwards_hardened_block_and_load_config_accepts(tmp_path):
    answers = _kv_answers(
        tmp_path, assurance="hardened",
        # hardened path hygiene needs an EXISTING absolute adapter file.
        builder_adapter=os.path.realpath("/usr/bin/true"),
        options={"hardened": {"network": "bridge", "memory": "1g"}})
    cfg = df_init.build_config(answers)
    assert cfg["hardened"] == {"network": "bridge", "memory": "1g"}
    df_init.scaffold(answers["control_root"], answers)
    loaded = df_config.load_config(answers["control_root"])
    assert loaded["_container"]["network"] == "bridge"
    assert loaded["_container"]["memory"] == "1g"


def test_build_config_forwards_brownfield_and_load_config_accepts(tmp_path):
    answers = _kv_answers(
        tmp_path, options={"brownfield": {"mode": "greenfield"}})
    cfg = df_init.build_config(answers)
    assert cfg["brownfield"] == {"mode": "greenfield"}
    df_init.scaffold(answers["control_root"], answers)
    df_config.load_config(answers["control_root"])  # accepted, single validator


def test_build_config_forwards_credentials_and_df_config_stays_the_validator(tmp_path):
    # Forwarded VERBATIM — and a malformed block is refused by load_config
    # (proving it reached the one validator instead of being dropped).
    answers = _kv_answers(tmp_path, options={"credentials": ["not-an-object"]})
    cfg = df_init.build_config(answers)
    assert cfg["credentials"] == ["not-an-object"]
    df_init.scaffold(answers["control_root"], answers)
    with pytest.raises(df_config.ConfigError, match="credentials"):
        df_config.load_config(answers["control_root"])


def test_build_config_shaped_builder_role_passes_through(tmp_path):
    support = tmp_path / "helper.py"
    support.write_text("x = 1\n")
    digest = hashlib.sha256(b"whatever").hexdigest()
    answers = _kv_answers(tmp_path)
    answers["roles"] = {"builder": {
        "timeout_s": 44,
        "adapter_sha256": digest,
        "model_identity": "anthropic/claude-fable-5",
        "support_files": [str(support)],
    }}
    cfg = df_init.build_config(answers)
    b = cfg["roles"]["builder"]
    assert b["adapter"] == "/bin/true"
    assert b["timeout_s"] == 44
    assert b["adapter_sha256"] == digest
    assert b["model_identity"] == "anthropic/claude-fable-5"
    assert b["support_files"] == [str(support)]
    df_init.scaffold(answers["control_root"], answers)
    loaded = df_config.load_config(answers["control_root"])
    assert loaded["_support_files"] == [os.path.realpath(str(support))]


def test_build_config_shaped_builder_adapter_conflict_is_init_error(tmp_path):
    answers = _kv_answers(tmp_path)
    answers["roles"] = {"builder": {"adapter": "/bin/false"}}
    with pytest.raises(df_init.InitError, match="conflicts"):
        df_init.build_config(answers)


def test_build_config_shaped_builder_unknown_key_fails_closed(tmp_path):
    # Opus-review finding (R5-06 general class): df_config never rejects
    # unknown builder keys, so a typo'd `adaptersha256` would be forwarded and
    # silently DROPPED — the operator believes the adapter is content-pinned
    # while it runs unauthenticated. Same DF-R3-01 discipline as options.
    answers = _kv_answers(tmp_path)
    answers["roles"] = {"builder": {"adaptersha256": "a" * 64}}
    with pytest.raises(df_init.InitError, match="adaptersha256"):
        df_init.build_config(answers)


def test_partial_legacy_autonomy_4_defaults_to_pause_like_runtime(tmp_path):
    # answers supplies ONLY autonomy:4 — init must scaffold the SAME default
    # the runtime would resolve for the same partial config: checkpoint
    # "pause" -> H2 (supervised), never the silent "auto" -> H3 of pre-M58.
    answers = _kv_answers(tmp_path, autonomy=4)
    cfg = df_init.build_config(answers)
    assert cfg["autonomy"] == 4
    assert cfg["checkpoint"] == "pause"
    df_init.scaffold(answers["control_root"], answers)
    loaded = df_config.load_config(answers["control_root"])
    assert loaded["_intervention_mode"] == "H2"


# ---------------------------------------------------------------------------
# R5-09 — one image identity per logical run, across resume
# ---------------------------------------------------------------------------

def _journal(run_dir):
    return supervisor.Journal(os.path.join(run_dir, "journal.jsonl"))


def test_pin_effective_image_first_segment_resolves_and_journals(tmp_path, monkeypatch):
    run_dir = str(tmp_path / "run")
    os.makedirs(run_dir)
    monkeypatch.setattr(supervisor.df_container, "resolve_image_digest",
                        lambda image: "repo@sha256:" + "a" * 64)
    cfg = {"_container": {"image": "python:3.12-slim"}}
    supervisor._pin_effective_image(cfg, run_dir, _journal(run_dir))
    assert cfg["_container"]["_effective_image"] == "repo@sha256:" + "a" * 64
    pinned = supervisor._image_resolved_from_journal(run_dir)
    assert pinned["effective_image"] == "repo@sha256:" + "a" * 64
    assert pinned["resolved_image_digest"] == "repo@sha256:" + "a" * 64


def test_pin_effective_image_resume_reuses_journaled_pin_never_reresolves(tmp_path, monkeypatch):
    run_dir = str(tmp_path / "run")
    os.makedirs(run_dir)
    monkeypatch.setattr(supervisor.df_container, "resolve_image_digest",
                        lambda image: "repo@sha256:" + "a" * 64)
    supervisor._pin_effective_image(
        {"_container": {"image": "python:3.12-slim"}}, run_dir, _journal(run_dir))

    # The tag MOVED between segments (digest B) — and the resolver must not
    # even be consulted on resume: the journaled pin is authoritative.
    def _moved(image):
        raise AssertionError("resume must NOT re-resolve the image")

    monkeypatch.setattr(supervisor.df_container, "resolve_image_digest", _moved)
    cfg2 = {"_container": {"image": "python:3.12-slim"}}  # reloaded config, no cache
    supervisor._pin_effective_image(cfg2, run_dir, _journal(run_dir))
    assert cfg2["_container"]["_effective_image"] == "repo@sha256:" + "a" * 64
    assert supervisor._effective_image(cfg2) == "repo@sha256:" + "a" * 64


def test_pin_wins_over_config_image_edited_across_pause_and_is_journaled(tmp_path, monkeypatch):
    run_dir = str(tmp_path / "run")
    os.makedirs(run_dir)
    monkeypatch.setattr(supervisor.df_container, "resolve_image_digest",
                        lambda image: "repo@sha256:" + "a" * 64)
    supervisor._pin_effective_image(
        {"_container": {"image": "python:3.12-slim"}}, run_dir, _journal(run_dir))

    # Operator edits hardened.image across the pause: the run's pin WINS (one
    # logical run = one image) but the override is journaled, never silent.
    cfg2 = {"_container": {"image": "python:3.13-slim"}}
    supervisor._pin_effective_image(cfg2, run_dir, _journal(run_dir))
    assert cfg2["_container"]["_effective_image"] == "repo@sha256:" + "a" * 64
    events = [json.loads(l) for l in
              open(os.path.join(run_dir, "journal.jsonl"), encoding="utf-8")]
    kept = [e for e in events if e["state"] == "IMAGE_PIN_KEPT"]
    assert len(kept) == 1
    assert kept[0]["data"]["edited_config_image"] == "python:3.13-slim"
    assert kept[0]["data"]["original_config_image"] == "python:3.12-slim"


def test_pin_effective_image_no_container_is_a_noop(tmp_path):
    run_dir = str(tmp_path / "run")
    os.makedirs(run_dir)
    supervisor._pin_effective_image({}, run_dir, _journal(run_dir))
    assert supervisor._image_resolved_from_journal(run_dir) is None
    assert not os.path.exists(os.path.join(run_dir, "journal.jsonl"))


# ---------------------------------------------------------------------------
# R5-10 — bare-command toolchain identity mirrors the child's PATH/cwd
# ---------------------------------------------------------------------------

def _make_tool(dirpath, name):
    os.makedirs(dirpath, exist_ok=True)
    p = os.path.join(dirpath, name)
    with open(p, "w", encoding="utf-8") as f:
        f.write("#!/bin/sh\nexit 0\n")
    os.chmod(p, 0o755)
    return p


def test_bare_command_dot_path_entry_resolves_against_action_cwd(tmp_path, monkeypatch):
    action_cwd = str(tmp_path / "shipws")
    tool = _make_tool(action_cwd, "deploytool")
    monkeypatch.setenv("PATH", ".")
    entry = df_ship.toolchain_identity("deploy", "deploytool", action_cwd)
    assert entry["resolved_path"] == os.path.realpath(tool)
    assert entry["sha256"] is not None
    assert entry["note"] is None


def test_bare_command_relative_path_entry_resolves_under_action_cwd(tmp_path, monkeypatch):
    action_cwd = str(tmp_path / "shipws")
    tool = _make_tool(os.path.join(action_cwd, "bin"), "deploytool")
    monkeypatch.setenv("PATH", "bin")
    entry = df_ship.toolchain_identity("deploy", "deploytool", action_cwd)
    assert entry["resolved_path"] == os.path.realpath(tool)
    assert entry["sha256"] is not None


def test_bare_command_supervisor_cwd_is_not_falsely_matched(tmp_path, monkeypatch):
    # The pre-M58 bug inverted: a tool that exists ONLY in the SUPERVISOR cwd
    # (where which() used to run) but not under the action cwd must NOT
    # resolve — the child, after chdir to the action cwd, would not find it.
    sup_cwd = str(tmp_path / "supervisor_cwd")
    _make_tool(sup_cwd, "deploytool")
    monkeypatch.chdir(sup_cwd)
    monkeypatch.setenv("PATH", ".")
    action_cwd = str(tmp_path / "shipws")
    os.makedirs(action_cwd)
    entry = df_ship.toolchain_identity("deploy", "deploytool", action_cwd)
    assert entry["resolved_path"] is None
    assert entry["sha256"] is None
    assert entry["note"] is not None


def test_bare_command_child_env_path_overrides_supervisor_path(tmp_path, monkeypatch):
    # Opus-review finding (R5-10): the child runs under _child_env(base_env,
    # cred_values) — a resolved credential named PATH shadows the supervisor's.
    # The evidence mirror must search the CHILD's PATH, not os.environ's.
    cred_dir = str(tmp_path / "cred_path")
    tool = _make_tool(cred_dir, "deploytool")
    monkeypatch.setenv("PATH", "/nonexistent-supervisor-path")
    entry = df_ship.toolchain_identity(
        "deploy", "deploytool", str(tmp_path / "shipws-nonexistent"),
        child_env={"PATH": cred_dir})
    assert entry["resolved_path"] == os.path.realpath(tool)
    assert entry["sha256"] is not None


def test_bare_command_absolute_path_entries_still_resolve(tmp_path, monkeypatch):
    tooldir = str(tmp_path / "tools")
    tool = _make_tool(tooldir, "deploytool")
    monkeypatch.setenv("PATH", tooldir)
    entry = df_ship.toolchain_identity(
        "deploy", "deploytool", str(tmp_path / "shipws-nonexistent"))
    assert entry["resolved_path"] == os.path.realpath(tool)
    assert entry["sha256"] is not None
