"""M42 Task 4 unit tests for df_critic (the decorrelated critic role) + the
config-level model-distinctness enforcement.

Covers:
  - compose_critic_prompt embeds the spec, behaviors, the AUTHORED scenarios,
    and the strict verdict contract;
  - parse_critic_output fail-closed on missing/garbage/wrong-shape;
  - validate_critic_verdict drops malformed/undeclared/unknown-kind findings
    fail-SAFE, keeps well-formed ones;
  - render_scenario_review surfaces advisories (never auto-applied);
  - df_config: critic==builder (collusion) and critic==author (decorrelation)
    are refused fail-closed, an ack overrides + seals same_model_ack, and a
    critic without an author is refused.
"""
import json

import pytest

import df_config
import df_critic


SPEC = "# Greet\nBuild greet.py that greets a name.\n"
BEHAVIORS = [{"id": "BHV-001", "description": "greets a name"}]
SCENARIOS = [
    {"id": "BHV-001-S1", "behavior_id": "BHV-001", "class": "happy", "cohort": "dev",
     "when": {"run": ["python3", "greet.py", "World"]},
     "then": {"exit_code": 0, "stdout_equals": "Hello, World!"}},
]


# --- compose_critic_prompt -------------------------------------------------

def test_prompt_embeds_spec_behaviors_scenarios_and_contract():
    p = df_critic.compose_critic_prompt(SPEC, BEHAVIORS, SCENARIOS,
                                        policy={"required_classes": ["happy", "boundary", "failure"]})
    assert "Build greet.py" in p                 # the spec
    assert "BHV-001" in p                          # behaviors + scenarios
    assert "BHV-001-S1" in p                       # the authored scenario id
    assert "critic.json" in p                      # the output contract
    assert "blocking" in p and "advisories" in p   # the verdict schema
    assert "boundary" in p                         # the adequacy policy in force


# --- parse_critic_output ---------------------------------------------------

def test_parse_missing_file_fails_closed(tmp_path):
    with pytest.raises(df_critic.CriticError, match="did not write"):
        df_critic.parse_critic_output(str(tmp_path))


def test_parse_garbage_fails_closed(tmp_path):
    (tmp_path / "critic.json").write_text("{not json", encoding="utf-8")
    with pytest.raises(df_critic.CriticError, match="could not be read/parsed"):
        df_critic.parse_critic_output(str(tmp_path))


def test_parse_non_object_fails_closed(tmp_path):
    (tmp_path / "critic.json").write_text("[]", encoding="utf-8")
    with pytest.raises(df_critic.CriticError, match="must be a JSON object"):
        df_critic.parse_critic_output(str(tmp_path))


def test_parse_good_returns_verdict(tmp_path):
    (tmp_path / "critic.json").write_text(
        json.dumps({"blocking": [], "advisories": []}), encoding="utf-8")
    assert df_critic.parse_critic_output(str(tmp_path)) == {"blocking": [], "advisories": []}


# --- validate_critic_verdict ----------------------------------------------

def test_validate_keeps_well_formed_and_drops_malformed():
    declared = {"BHV-001"}
    verdict = {
        "blocking": [
            {"behavior_id": "BHV-001", "kind": "weak_assertion", "detail": "d"},  # keep
            {"behavior_id": "BHV-999", "kind": "weak_assertion", "detail": "x"},  # undeclared -> drop
            {"behavior_id": "BHV-001", "kind": "bogus", "detail": "y"},           # bad kind -> drop
            "not-an-object",                                                       # drop
        ],
        "advisories": [
            {"topic": "auth", "detail": "confirm"},
            "nope",  # drop
        ],
    }
    blocking, advisories = df_critic.validate_critic_verdict(verdict, declared)
    assert blocking == [{"behavior_id": "BHV-001", "kind": "weak_assertion", "detail": "d"}]
    assert advisories == [{"topic": "auth", "detail": "confirm"}]


def test_validate_rejects_non_list_blocking():
    with pytest.raises(df_critic.CriticError, match="'blocking' must be a list"):
        df_critic.validate_critic_verdict({"blocking": {}}, {"BHV-001"})


def test_validate_absent_fields_default_empty():
    assert df_critic.validate_critic_verdict({}, {"BHV-001"}) == ([], [])


# --- render_scenario_review ------------------------------------------------

def test_render_scenario_review_lists_advisories():
    md = df_critic.render_scenario_review(
        [{"topic": "pagination", "detail": "list endpoints usually paginate"}],
        rounds=1, blocking_resolved=2)
    assert "pagination" in md
    assert "NOT auto-applied" in md
    assert "rounds: 1" in md and "resolved: 2" in md


def test_render_scenario_review_no_advisories():
    md = df_critic.render_scenario_review([], rounds=0, blocking_resolved=0)
    assert "_None._" in md


# --- config: model-distinctness (the two inequalities) ---------------------

def _cfg(tmp_path, roles):
    cr = tmp_path / "cr"
    cr.mkdir(parents=True)
    ws = tmp_path / "ws"
    (cr / "config.json").write_text(json.dumps({
        "config_version": "0.1", "autonomy": 4, "assurance": "cooperative",
        "feedback": "ids", "max_iterations": 5, "workspace_root": str(ws),
        "roles": roles, "budget": {"billing": "subscription"}}), encoding="utf-8")
    return str(cr)


def test_critic_equal_builder_refused(tmp_path):
    with pytest.raises(df_config.ConfigError, match="DIFFERENT path than roles.builder"):
        df_config.load_config(_cfg(tmp_path, {
            "builder": {"adapter": "/bin/echo"},
            "author": {"adapter": "/bin/cat"},
            "critic": {"adapter": "/bin/echo"}}))


def test_critic_equal_author_refused(tmp_path):
    with pytest.raises(df_config.ConfigError, match="DIFFERENT path than roles.author"):
        df_config.load_config(_cfg(tmp_path, {
            "builder": {"adapter": "/bin/echo"},
            "author": {"adapter": "/bin/cat"},
            "critic": {"adapter": "/bin/cat"}}))


def test_critic_without_author_refused(tmp_path):
    with pytest.raises(df_config.ConfigError, match="requires roles.author"):
        df_config.load_config(_cfg(tmp_path, {
            "builder": {"adapter": "/bin/echo"},
            "critic": {"adapter": "/bin/ls"}}))


def test_critic_ack_overrides_and_seals(tmp_path):
    cfg = df_config.load_config(_cfg(tmp_path, {
        "builder": {"adapter": "/bin/echo"},
        "author": {"adapter": "/bin/cat"},
        "critic": {"adapter": "/bin/echo", "allow_same_model_ack": True}}))
    assert cfg["_critic"]["same_model_ack"] is True
    assert cfg["_critic"]["adapter"] == "/bin/echo"


def test_three_distinct_models_load(tmp_path):
    cfg = df_config.load_config(_cfg(tmp_path, {
        "builder": {"adapter": "/bin/echo"},
        "author": {"adapter": "/bin/cat"},
        "critic": {"adapter": "/bin/ls"}}))
    assert cfg["_critic"]["adapter"] == "/bin/ls"
    assert cfg["_critic"]["same_model_ack"] is False


# ---------- DF-R3-04 (M50): critic content-digest + asserted model_identity ----------

_DA = "a" * 64
_DB = "b" * 64
_DC = "c" * 64


def test_critic_same_digest_as_builder_refused(tmp_path):
    with pytest.raises(df_config.ConfigError, match="IDENTICAL to roles.builder.adapter_sha256"):
        df_config.load_config(_cfg(tmp_path, {
            "builder": {"adapter": "/bin/echo", "adapter_sha256": _DA},
            "author": {"adapter": "/bin/cat", "adapter_sha256": _DB},
            "critic": {"adapter": "/bin/ls", "adapter_sha256": _DA}}))


def test_critic_same_digest_as_author_refused(tmp_path):
    with pytest.raises(df_config.ConfigError, match="IDENTICAL to roles.author.adapter_sha256"):
        df_config.load_config(_cfg(tmp_path, {
            "builder": {"adapter": "/bin/echo", "adapter_sha256": _DA},
            "author": {"adapter": "/bin/cat", "adapter_sha256": _DB},
            "critic": {"adapter": "/bin/ls", "adapter_sha256": _DB}}))


def test_critic_same_digest_waived_by_ack(tmp_path):
    cfg = df_config.load_config(_cfg(tmp_path, {
        "builder": {"adapter": "/bin/echo", "adapter_sha256": _DA},
        "author": {"adapter": "/bin/cat", "adapter_sha256": _DB},
        "critic": {"adapter": "/bin/ls", "adapter_sha256": _DA,
                   "allow_same_model_ack": True}}))
    assert cfg["_critic"]["same_model_ack"] is True


def test_critic_distinct_digests_load(tmp_path):
    cfg = df_config.load_config(_cfg(tmp_path, {
        "builder": {"adapter": "/bin/echo", "adapter_sha256": _DA},
        "author": {"adapter": "/bin/cat", "adapter_sha256": _DB},
        "critic": {"adapter": "/bin/ls", "adapter_sha256": _DC}}))
    assert cfg["_critic"]["expected_sha256"] == _DC


def test_critic_same_model_identity_as_author_refused(tmp_path):
    with pytest.raises(df_config.ConfigError, match="model_identity is IDENTICAL"):
        df_config.load_config(_cfg(tmp_path, {
            "builder": {"adapter": "/bin/echo"},
            "author": {"adapter": "/bin/cat", "model_identity": "gemini/2.5-pro"},
            "critic": {"adapter": "/bin/ls", "model_identity": "gemini/2.5-pro"}}))


def test_critic_distinct_model_identities_sealed(tmp_path):
    cfg = df_config.load_config(_cfg(tmp_path, {
        "builder": {"adapter": "/bin/echo", "model_identity": "anthropic/claude"},
        "author": {"adapter": "/bin/cat", "model_identity": "openai/gpt-5"},
        "critic": {"adapter": "/bin/ls", "model_identity": "gemini/2.5-pro"}}))
    assert cfg["_critic"]["model_identity"] == "gemini/2.5-pro"
    assert cfg["_author"]["model_identity"] == "openai/gpt-5"
