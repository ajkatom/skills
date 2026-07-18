"""M40 unit tests for df_author (the agent-`author` role) + df_init's
scenarios-pending-author scaffolding.

Covers:
  - compose_author_prompt: embeds the spec, every behavior id, the output
    contract, and (when given) impoverished retry feedback.
  - parse_author_output: fail-closed on missing / unparseable / wrong-shape /
    empty scenarios.json; a good file returns the raw list.
  - validate_authored: a good set passes; catches non-discriminating,
    uncovered-behavior, orphan-behavior, spec-leak, and shape violations, and
    reports them barrier-safely (titles / behavior-ids / leak values only).
  - df_init pending scaffold: an author + zero scenarios scaffolds an EMPTY
    scenarios/ + a marker; validate_scaffold passes it as pending; a control
    root with human scenarios is unchanged (no marker).
"""
import json
import os

import pytest

import df_author
import df_init


SPEC = (
    "# Greet\n"
    "Build greet.py that prints a friendly greeting to a name argument, "
    "or exits 2 with an error when given no arguments.\n"
)
BEHAVIORS = [
    {"id": "BHV-001", "description": "greets a name"},
    {"id": "BHV-002", "description": "errors on no args"},
]


def _good_raw():
    return [
        {"behavior_id": "BHV-001", "cohort": "dev",
         "run": ["python3", "greet.py", "World"],
         "then": {"exit_code": 0, "stdout_equals": "Hello, World!"},
         "title": "greets world"},
        {"behavior_id": "BHV-001", "cohort": "final",
         "run": ["python3", "greet.py", "Alon"],
         "then": {"exit_code": 0, "stdout_equals": "Hello, Alon!"},
         "title": "greets alon"},
        {"behavior_id": "BHV-002", "cohort": "dev",
         "run": ["python3", "greet.py"],
         "then": {"exit_code": 2, "stderr_contains": "greet.py <name>"},
         "title": "missing arg error"},
    ]


# --- compose_author_prompt -------------------------------------------------

def test_prompt_embeds_spec_behaviors_and_contract():
    p = df_author.compose_author_prompt(SPEC, BEHAVIORS)
    assert "Build greet.py" in p           # the spec
    assert "BHV-001" in p and "BHV-002" in p  # every behavior id
    assert "scenarios.json" in p           # the output contract
    assert "DISCRIMINATING" in p           # the authoring rules
    # No prior-attempt feedback section on the first invocation.
    assert "FAILED validation" not in p


def test_prompt_appends_impoverished_feedback():
    report = {
        "schema_errors": [],
        "non_discriminating_titles": ["inert one"],
        "uncovered_behaviors": ["BHV-002"],
        "orphan_titles": [],
        "spec_leak_values": ["Hello, World!"],
        "counts": {"scenarios": 1, "dev": 1, "final": 0},
    }
    p = df_author.compose_author_prompt(SPEC, BEHAVIORS, attempt_feedback=report)
    assert "FAILED validation" in p
    assert "BHV-002" in p            # uncovered behavior id crosses back
    assert "inert one" in p          # non-discriminating title crosses back
    assert "Hello, World!" in p      # leak value crosses back (spec content)


# --- parse_author_output ---------------------------------------------------

def test_parse_missing_file_fails_closed(tmp_path):
    with pytest.raises(df_author.AuthorError, match="did not write"):
        df_author.parse_author_output(str(tmp_path))


def test_parse_unparseable_fails_closed(tmp_path):
    (tmp_path / "scenarios.json").write_text("{not json", encoding="utf-8")
    with pytest.raises(df_author.AuthorError, match="could not be read/parsed"):
        df_author.parse_author_output(str(tmp_path))


@pytest.mark.parametrize("payload", [
    "[]",                                   # top-level list, not object
    '{"scenarios": {}}',                    # scenarios not a list
    '{"nope": []}',                         # no scenarios key
    '{"scenarios": []}',                    # empty list
    '{"scenarios": ["not-an-object"]}',     # non-dict entry
])
def test_parse_wrong_shape_fails_closed(tmp_path, payload):
    (tmp_path / "scenarios.json").write_text(payload, encoding="utf-8")
    with pytest.raises(df_author.AuthorError):
        df_author.parse_author_output(str(tmp_path))


def test_parse_good_returns_list(tmp_path):
    (tmp_path / "scenarios.json").write_text(
        json.dumps({"scenarios": _good_raw()}), encoding="utf-8")
    got = df_author.parse_author_output(str(tmp_path))
    assert isinstance(got, list) and len(got) == 3


# --- validate_authored -----------------------------------------------------

def test_validate_good_set_passes_and_normalizes_ids():
    ok, report, normalized = df_author.validate_authored(_good_raw(), SPEC, BEHAVIORS)
    assert ok, report
    # Same {bid}-S{n}/{bid}-F{n} id scheme df_init.build_scenarios uses.
    ids = {s["id"] for s in normalized}
    assert ids == {"BHV-001-S1", "BHV-001-F1", "BHV-002-S1"}
    assert report["counts"] == {"scenarios": 3, "dev": 2, "final": 1}
    # Normalized shape is oracle-IR (loadable by run_scenarios).
    for s in normalized:
        assert s["ir_version"] == "0.1"
        assert "when" in s and "run" in s["when"]


def test_validate_catches_non_discriminating():
    raw = [
        {"behavior_id": "BHV-001", "cohort": "dev", "run": ["python3", "greet.py", "X"],
         "then": {"stdout_contains": ""}, "title": "inert"},   # tautological
        {"behavior_id": "BHV-002", "cohort": "dev", "run": ["python3", "greet.py"],
         "then": {"exit_code": 2}, "title": "ok2"},
    ]
    ok, report, _ = df_author.validate_authored(raw, SPEC, BEHAVIORS)
    assert not ok
    assert "inert" in report["non_discriminating_titles"]


def test_validate_catches_uncovered_behavior():
    raw = [
        {"behavior_id": "BHV-001", "cohort": "dev", "run": ["python3", "greet.py", "X"],
         "then": {"exit_code": 0, "stdout_equals": "Hello, X!"}, "title": "only one"},
    ]
    ok, report, _ = df_author.validate_authored(raw, SPEC, BEHAVIORS)
    assert not ok
    assert report["uncovered_behaviors"] == ["BHV-002"]


def test_validate_catches_orphan_behavior():
    raw = _good_raw() + [
        {"behavior_id": "BHV-999", "cohort": "dev", "run": ["x"],
         "then": {"exit_code": 5}, "title": "orphan sc"},
    ]
    ok, report, _ = df_author.validate_authored(raw, SPEC, BEHAVIORS)
    assert not ok
    assert "orphan sc" in report["orphan_titles"]


def test_validate_catches_spec_leak():
    # "friendly greeting" appears verbatim in SPEC -> leaks the answer.
    raw = [
        {"behavior_id": "BHV-001", "cohort": "dev", "run": ["python3", "greet.py", "X"],
         "then": {"stdout_equals": "a friendly greeting"}, "title": "leaky"},
        {"behavior_id": "BHV-002", "cohort": "dev", "run": ["python3", "greet.py"],
         "then": {"exit_code": 2}, "title": "ok2"},
    ]
    ok, report, _ = df_author.validate_authored(raw, SPEC, BEHAVIORS)
    assert not ok
    assert "a friendly greeting" in report["spec_leak_values"]


def test_validate_rejects_unknown_then_key_before_install():
    # An unknown `then` assertion key (`output_is`) sits alongside a VALID one
    # (`exit_code`), so df_gates.is_discriminating passes -- but the strict
    # run_scenarios._validate keyset check (which the INSTALLED set faces at
    # run time) must reject it. Otherwise it would install, clear the marker,
    # then deadlock `run` with an OracleError. Caught here => driven back into
    # a retry, never installed.
    raw = [
        {"behavior_id": "BHV-001", "cohort": "dev",
         "run": ["python3", "greet.py", "World"],
         "then": {"exit_code": 0, "output_is": "Hello, World!"}, "title": "sneaky key"},
        {"behavior_id": "BHV-002", "cohort": "dev", "run": ["python3", "greet.py"],
         "then": {"exit_code": 2}, "title": "ok2"},
    ]
    ok, report, normalized = df_author.validate_authored(raw, SPEC, BEHAVIORS)
    assert not ok
    assert any("known assertion key" in e for e in report["schema_errors"])
    # The offending scenario is NOT in the installable set.
    assert "BHV-001-S1" not in {s["id"] for s in normalized}
    # The complaint reaches the author as retry feedback.
    assert any("known assertion key" in line for line in df_author._feedback_lines(report))


def test_validate_rejects_mismatched_http_then_key():
    # An http assertion key on a CLI (when.run) scenario is a mismatched
    # then/when that _validate rejects -- another class df_gates alone misses.
    raw = [
        {"behavior_id": "BHV-001", "cohort": "dev", "run": ["python3", "greet.py", "X"],
         "then": {"http_status": 200}, "title": "http on cli"},
        {"behavior_id": "BHV-002", "cohort": "dev", "run": ["python3", "greet.py"],
         "then": {"exit_code": 2}, "title": "ok2"},
    ]
    ok, report, normalized = df_author.validate_authored(raw, SPEC, BEHAVIORS)
    assert not ok
    assert report["schema_errors"]
    assert "BHV-001-S1" not in {s["id"] for s in normalized}


def test_validate_catches_shape_errors():
    raw = [
        {"cohort": "dev", "run": ["x"], "then": {"exit_code": 0}},        # no behavior_id
        {"behavior_id": "BHV-001", "cohort": "weird", "run": ["x"],
         "then": {"exit_code": 0}, "title": "bad cohort"},
        {"behavior_id": "BHV-001", "cohort": "dev", "run": [],
         "then": {"exit_code": 0}, "title": "empty run"},
        {"behavior_id": "BHV-002", "cohort": "dev", "run": ["x"],
         "then": {}, "title": "empty then"},
    ]
    ok, report, normalized = df_author.validate_authored(raw, SPEC, BEHAVIORS)
    assert not ok
    assert len(report["schema_errors"]) == 4
    assert normalized == []   # nothing well-formed to normalize


# --- df_init pending scaffold ----------------------------------------------

def _pending_answers(tmp_path):
    return {
        "app_name": "greet",
        "spec_text": SPEC,
        "assurance": "cooperative",
        "workspace_root": str(tmp_path / "ws"),
        "control_root": str(tmp_path / "control"),
        "builder_adapter": "/bin/true",
        "author_adapter": "/bin/cat",   # != builder -> different-model OK
        "behaviors": [{"id": "BHV-001", "description": "greets"}],
        # no scenarios -> pending
    }


def test_pending_scaffold_writes_marker_and_empty_scenarios(tmp_path):
    cr = str(tmp_path / "control")
    df_init.scaffold(cr, _pending_answers(tmp_path))
    assert df_init.is_scenarios_pending(cr)
    assert os.path.isdir(os.path.join(cr, "scenarios"))
    assert os.listdir(os.path.join(cr, "scenarios")) == []
    # config carries roles.author.
    cfg = json.loads((tmp_path / "control" / "config.json").read_text())
    assert cfg["roles"]["author"]["adapter"] == "/bin/cat"
    # validate_scaffold passes structurally, flagged pending.
    ok, report = df_init.validate_scaffold(cr)
    assert ok and report["scenarios_pending"]


def test_author_with_scenarios_is_not_pending(tmp_path):
    # An author configured but scenarios ALSO supplied -> ordinary human
    # scaffold, no marker (can't have BOTH pending and human scenarios).
    answers = _pending_answers(tmp_path)
    answers["behaviors"] = [{
        "id": "BHV-001", "description": "greets",
        "scenarios": [{"cohort": "dev", "run": ["python3", "greet.py", "X"],
                       "then": {"exit_code": 0, "stdout_equals": "Hello, X!"},
                       "title": "greets X"}],
    }]
    cr = str(tmp_path / "control")
    df_init.scaffold(cr, answers)
    assert not df_init.is_scenarios_pending(cr)
    assert os.listdir(os.path.join(cr, "scenarios"))   # a real scenario file


def test_no_author_no_marker(tmp_path):
    # Absent author role -> today's behavior exactly (no marker, needs scenarios).
    answers = {
        "app_name": "greet", "spec_text": SPEC, "assurance": "cooperative",
        "workspace_root": str(tmp_path / "ws"), "control_root": str(tmp_path / "control"),
        "builder_adapter": "/bin/true",
        "behaviors": [{
            "id": "BHV-001",
            "scenarios": [{"cohort": "dev", "run": ["python3", "greet.py", "X"],
                           "then": {"exit_code": 0, "stdout_equals": "Hello, X!"}}],
        }],
    }
    cr = str(tmp_path / "control")
    df_init.scaffold(cr, answers)
    assert not df_init.is_scenarios_pending(cr)
