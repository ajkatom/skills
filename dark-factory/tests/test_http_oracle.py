import os
import subprocess
import time

import pytest

import df_gates
import run_scenarios
from test_twin_evidence_oracle import _LiveTwin

HERE = os.path.dirname(os.path.abspath(__file__))
SERVER = os.path.join(HERE, "fixtures", "http_oracle_fixture_server")
TWIN_SERVER = os.path.join(HERE, "fixtures", "http_oracle_twin_fixture_server")

# `import time; time.sleep(30)` fixture that never binds a port -- proves
# fail-closed behavior (no vacuous pass) for a service that never becomes
# ready. Carries a distinctive marker so pgrep -f can confirm reaping.
NEVER_READY = [
    "python3", "-c",
    "import time; time.sleep(30)  # df-http-never-ready-fixture-b7e2",
]
# Exits immediately without ever binding a port -- proves fail-closed
# behavior for a process that dies before readiness.
DIES_IMMEDIATELY = ["python3", "-c", "import sys; sys.exit(1)"]


def _no_orphans(marker):
    out = subprocess.run(["pgrep", "-f", marker], capture_output=True, text=True)
    return out.stdout.strip() == ""


# ---------------------------------------------------------------------------
# evaluate_http unit matrix
# ---------------------------------------------------------------------------

BASE_OBSERVED = {"http_status": 200, "body": "ok", "json": None}


@pytest.mark.parametrize(
    "then, observed, expected",
    [
        # no response at all -> crash, regardless of `then`
        (
            {"http_status": 200},
            {"http_status": None, "body": "", "json": None},
            "crash",
        ),
        # status hit, no other assertions -> pass
        (
            {"http_status": 200},
            {"http_status": 200, "body": "ok", "json": None},
            None,
        ),
        # status miss -> wrong_exit_code
        (
            {"http_status": 200},
            {"http_status": 500, "body": "ok", "json": None},
            "wrong_exit_code",
        ),
        # body_contains hit -> pass
        (
            {"http_status": 200, "body_contains": "ok"},
            {"http_status": 200, "body": "it is ok really", "json": None},
            None,
        ),
        # body_contains miss -> wrong_output
        (
            {"http_status": 200, "body_contains": "ok"},
            {"http_status": 200, "body": "nope", "json": None},
            "wrong_output",
        ),
        # json_equals hit -> pass
        (
            {"json_equals": {"a": 1}},
            {"http_status": 200, "body": "{}", "json": {"a": 1}},
            None,
        ),
        # json_equals miss -> wrong_output
        (
            {"json_equals": {"a": 1}},
            {"http_status": 200, "body": "{}", "json": {"a": 2}},
            "wrong_output",
        ),
        # json_contains subset hit (extra keys in observed are fine) -> pass
        (
            {"json_contains": {"status": "ok"}},
            {"http_status": 200, "body": "{}", "json": {"status": "ok", "extra": 1}},
            None,
        ),
        # json_contains subset miss -> wrong_output
        (
            {"json_contains": {"status": "ok"}},
            {"http_status": 200, "body": "{}", "json": {"status": "bad"}},
            "wrong_output",
        ),
        # json_path dotted+indexed hit -> pass
        (
            {"json_path": {"nested.x[1]": 20}},
            {
                "http_status": 200,
                "body": "{}",
                "json": {"nested": {"x": [10, 20, 30]}},
            },
            None,
        ),
        # json_path dotted+indexed miss (wrong value) -> wrong_output
        (
            {"json_path": {"nested.x[1]": 999}},
            {
                "http_status": 200,
                "body": "{}",
                "json": {"nested": {"x": [10, 20, 30]}},
            },
            "wrong_output",
        ),
        # json_path missing path -> wrong_output
        (
            {"json_path": {"nested.y[0]": 1}},
            {
                "http_status": 200,
                "body": "{}",
                "json": {"nested": {"x": [10, 20, 30]}},
            },
            "wrong_output",
        ),
        # json_* keys with observed json None -> mismatch (wrong_output)
        (
            {"json_equals": {"a": 1}},
            {"http_status": 200, "body": "not json", "json": None},
            "wrong_output",
        ),
        (
            {"json_contains": {"a": 1}},
            {"http_status": 200, "body": "not json", "json": None},
            "wrong_output",
        ),
        (
            {"json_path": {"a": 1}},
            {"http_status": 200, "body": "not json", "json": None},
            "wrong_output",
        ),
        # priority: status miss wins over a simultaneous body miss
        (
            {"http_status": 200, "body_contains": "ok"},
            {"http_status": 500, "body": "nope", "json": None},
            "wrong_exit_code",
        ),
        # priority: no-response wins over everything
        (
            {"http_status": 200, "body_contains": "ok", "json_equals": {"a": 1}},
            {"http_status": None, "body": "", "json": None},
            "crash",
        ),
    ],
)
def test_evaluate_http_table(then, observed, expected):
    assert run_scenarios.evaluate_http(then, observed) == expected


def test_evaluate_http_no_assertions_pass():
    assert run_scenarios.evaluate_http({}, BASE_OBSERVED) is None


# ---------------------------------------------------------------------------
# _run_http_scenario -- LIVE against the stdlib fixture server
# ---------------------------------------------------------------------------


def _http_scenario(request, ready_path="/health", port_env="PORT"):
    return {
        "id": "BHV-100-S1",
        "behavior_id": "BHV-100",
        "when": {
            "http": {
                "start": ["python3", SERVER],
                "port_env": port_env,
                "ready_path": ready_path,
                "request": request,
            }
        },
    }


def test_run_http_scenario_captures_status_body_json(tmp_path):
    sc = _http_scenario({"method": "GET", "path": "/data"})
    observed = run_scenarios._run_http_scenario(sc, str(tmp_path), None, None, 10)
    assert observed["http_status"] == 200
    assert observed["json"]["status"] == "ok"
    assert observed["json"]["nested"]["x"] == [1, 2, 3]
    assert "ok" in observed["body"]


def test_run_http_scenario_health_endpoint_plain_text(tmp_path):
    sc = _http_scenario({"method": "GET", "path": "/health"})
    observed = run_scenarios._run_http_scenario(sc, str(tmp_path), None, None, 10)
    assert observed["http_status"] == 200
    assert observed["body"] == "ok"
    assert observed["json"] is None  # not JSON, so no parse


def test_run_http_scenario_post_echo_json(tmp_path):
    sc = _http_scenario({
        "method": "POST", "path": "/echo",
        "headers": {"Content-Type": "application/json"},
        "body": '{"hello": "world"}',
    })
    observed = run_scenarios._run_http_scenario(sc, str(tmp_path), None, None, 10)
    assert observed["http_status"] == 200
    assert observed["json"] == {"received": {"hello": "world"}}


def test_run_http_scenario_reaps_service_process(tmp_path):
    marker = "http_oracle_fixture_server"
    sc = _http_scenario({"method": "GET", "path": "/health"})
    run_scenarios._run_http_scenario(sc, str(tmp_path), None, None, 10)
    # give the OS a moment to finish tearing down before checking
    for _ in range(20):
        if _no_orphans(marker):
            break
        time.sleep(0.1)
    assert _no_orphans(marker)


def test_run_http_scenario_never_ready_returns_none_status_and_reaps(tmp_path):
    sc = {
        "id": "BHV-101-S1",
        "behavior_id": "BHV-101",
        "when": {
            "http": {
                "start": NEVER_READY,
                "port_env": "PORT",
                "ready_path": "/health",
                "request": {"method": "GET", "path": "/health"},
            }
        },
    }
    observed = run_scenarios._run_http_scenario(sc, str(tmp_path), None, None, 1)
    # fail-closed: never-ready service -> no response captured, never a
    # vacuous pass
    assert observed["http_status"] is None
    for _ in range(20):
        if _no_orphans("df-http-never-ready-fixture-b7e2"):
            break
        time.sleep(0.1)
    assert _no_orphans("df-http-never-ready-fixture-b7e2")


def test_run_http_scenario_process_dies_before_ready(tmp_path):
    sc = {
        "id": "BHV-102-S1",
        "behavior_id": "BHV-102",
        "when": {
            "http": {
                "start": DIES_IMMEDIATELY,
                "port_env": "PORT",
                "ready_path": "/health",
                "request": {"method": "GET", "path": "/health"},
            }
        },
    }
    observed = run_scenarios._run_http_scenario(sc, str(tmp_path), None, None, 5)
    assert observed["http_status"] is None


def test_evaluate_http_maps_never_ready_to_crash_taxonomy():
    # a never-ready/crashing service's observed dict must fail-closed
    # through the SAME oracle used for real assertions -- never a special
    # vacuous-pass path.
    observed = {"http_status": None, "body": "", "json": None}
    assert run_scenarios.evaluate_http({"http_status": 200}, observed) == "crash"


# ---------------------------------------------------------------------------
# run_all dispatch (bypassing load_scenarios/_validate, which is Task 2 scope)
# ---------------------------------------------------------------------------


def test_run_all_dispatches_http_scenario(tmp_path, monkeypatch):
    sc = _http_scenario({"method": "GET", "path": "/data"})
    sc["then"] = {"http_status": 200, "json_contains": {"status": "ok"}}
    sc["cohort"] = "dev"
    monkeypatch.setattr(run_scenarios, "load_scenarios", lambda *a, **k: [sc])
    report = run_scenarios.run_all(str(tmp_path), str(tmp_path))
    assert report["count"] == 1
    assert report["all_pass"] is True
    assert report["results"][0]["taxonomy"] is None
    assert report["results"][0]["observed"]["http_status"] == 200


def test_run_all_dispatch_http_scenario_wrong_status_fails(tmp_path, monkeypatch):
    sc = _http_scenario({"method": "GET", "path": "/data"})
    sc["then"] = {"http_status": 999}
    sc["cohort"] = "dev"
    monkeypatch.setattr(run_scenarios, "load_scenarios", lambda *a, **k: [sc])
    report = run_scenarios.run_all(str(tmp_path), str(tmp_path))
    assert report["all_pass"] is False
    assert report["results"][0]["taxonomy"] == "wrong_exit_code"


def test_run_all_still_dispatches_when_run_scenarios_unchanged(tmp_path, monkeypatch):
    # existing CLI (when.run) scenarios must be byte-identical through the
    # SAME run_all/run_scenario path.
    sc = {
        "id": "BHV-200-S1", "behavior_id": "BHV-200", "cohort": "dev",
        "when": {"run": ["python3", "-c", "print('ok')"], "timeout_s": 10},
        "then": {"exit_code": 0, "stdout_equals": "ok"},
    }
    monkeypatch.setattr(run_scenarios, "load_scenarios", lambda *a, **k: [sc])
    report = run_scenarios.run_all(str(tmp_path), str(tmp_path))
    assert report["all_pass"] is True
    assert report["results"][0]["observed"]["exit_code"] == 0


# ---------------------------------------------------------------------------
# is_discriminating over http then-keys
# ---------------------------------------------------------------------------


def test_is_discriminating_true_for_real_http_status_assertion():
    assert df_gates.is_discriminating({"http_status": 200}) is True


def test_is_discriminating_false_for_inert_body_contains():
    assert df_gates.is_discriminating({"body_contains": ""}) is False


def test_is_discriminating_false_for_inert_json_contains():
    assert df_gates.is_discriminating({"json_contains": {}}) is False


def test_is_discriminating_true_for_json_equals_assertion():
    assert df_gates.is_discriminating({"json_equals": {"status": "ok"}}) is True


def test_is_discriminating_true_for_json_path_assertion():
    assert df_gates.is_discriminating({"json_path": {"a.b[0]": 1}}) is True


def test_is_discriminating_true_for_body_contains_real_assertion():
    assert df_gates.is_discriminating({"body_contains": "success"}) is True


# ---------------------------------------------------------------------------
# M20 Task 2 review coverage minor #1: an http scenario composes with a TWIN
# -- observer_files set -> twin_observed works on an http scenario exactly
# like it does on a CLI one (the service itself calls the twin; the delta
# is attributed to this scenario's http request/response window).
# ---------------------------------------------------------------------------


def test_http_scenario_composes_with_twin_observed(tmp_path, monkeypatch):
    with _LiveTwin(tmp_path) as twin:
        sc = {
            "id": "BHV-300-S1",
            "behavior_id": "BHV-300",
            "when": {
                "http": {
                    "start": ["python3", TWIN_SERVER],
                    "port_env": "PORT",
                    "ready_path": "/health",
                    "request": {"method": "GET", "path": "/call-twin/Harriet"},
                },
                "timeout_s": 10,
            },
            "then": {
                "http_status": 200,
                "json_contains": {"status": "ok"},
                "twin_observed": {"twin": "greeter", "contains": "/greet/Harriet"},
            },
            "cohort": "dev",
        }
        monkeypatch.setattr(run_scenarios, "load_scenarios", lambda *a, **k: [sc])
        report = run_scenarios.run_all(
            str(tmp_path), str(tmp_path),
            env_extra=twin.env, observer_files=twin.ts.observer_files,
        )
        assert report["all_pass"] is True, report
        result = report["results"][0]
        assert result["taxonomy"] is None
        assert result["observed"]["http_status"] == 200
        assert any(
            "/greet/Harriet" in line
            for line in result["observed"]["twin_observations"]["greeter"]
        ), "http scenario's twin_observed delta never saw the real twin call"


def test_http_scenario_with_twin_observed_fails_closed_without_evidence(tmp_path, monkeypatch):
    # The twin is live but this scenario's request never calls it -- the
    # twin_observed assertion must still fail closed (no vacuous pass just
    # because SOME http assertion passed).
    with _LiveTwin(tmp_path) as twin:
        sc = {
            "id": "BHV-301-S1",
            "behavior_id": "BHV-301",
            "when": {
                "http": {
                    "start": ["python3", SERVER],  # plain fixture -- never calls the twin
                    "port_env": "PORT",
                    "ready_path": "/health",
                    "request": {"method": "GET", "path": "/health"},
                },
                "timeout_s": 10,
            },
            "then": {
                "http_status": 200,
                "twin_observed": {"twin": "greeter", "contains": "/greet/Nobody"},
            },
            "cohort": "dev",
        }
        monkeypatch.setattr(run_scenarios, "load_scenarios", lambda *a, **k: [sc])
        report = run_scenarios.run_all(
            str(tmp_path), str(tmp_path),
            env_extra=twin.env, observer_files=twin.ts.observer_files,
        )
        assert report["all_pass"] is False
        assert report["results"][0]["taxonomy"] == "no_twin_evidence"


# ---------------------------------------------------------------------------
# M20 Task 2 review coverage minor #2: a MALFORMED json_path never raises --
# evaluate_http always returns "wrong_output" for it, fail-closed.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "bad_path",
    [
        "a..b",       # empty segment in the middle
        "x[9]",       # index out of range
        "",           # empty path entirely
        "a.b[",       # unterminated index bracket
        "a[abc]",     # non-numeric index
    ],
)
def test_evaluate_http_malformed_json_path_never_raises(bad_path):
    observed = {
        "http_status": 200,
        "body": '{"a": {"b": 1}, "x": [1, 2, 3]}',
        "json": {"a": {"b": 1}, "x": [1, 2, 3]},
    }
    then = {"json_path": {bad_path: "anything"}}
    # must not raise -- always resolves to the "wrong_output" taxonomy
    assert run_scenarios.evaluate_http(then, observed) == "wrong_output"
