"""M40 e2e acceptance for the agent-`author` role, driven as real subprocesses
against the supervisor CLI (matches test_e2e_init.py / test_e2e_gates.py). A
STUB author adapter (fixtures/fake_author*) emits a fixed scenarios.json -- NO
paid API calls, fully deterministic, mirroring how the suite stubs the builder.

Covers:
  (a) init scaffolds a scenarios-pending control root (author configured, zero
      scenarios) -> a `run` BEFORE authoring refuses fail-closed; then
      `author-scenarios` installs the agent set, and a normal fake-builder
      `run` converges against the agent-authored holdout with the barrier
      intact (builder workspace never contains scenarios/). The manifest
      records authored_by (the independent author adapter).
  (b) a fake author that emits a non-discriminating set -> author-scenarios
      exits 2 after bounded retries, and NO scenarios are installed (the
      control root stays pending).
"""
import json
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
SUP = os.path.join(HERE, "..", "scripts", "supervisor.py")
FAKE_BUILDER = os.path.join(HERE, "fixtures", "fake_builder")
FAKE_AUTHOR = os.path.join(HERE, "fixtures", "fake_author")
FAKE_AUTHOR_INERT = os.path.join(HERE, "fixtures", "fake_author_inert")
FAKE_AUTHOR_RETRY = os.path.join(HERE, "fixtures", "fake_author_retry")

# The greet spec the fake_author/fake_builder fixtures agree on. Deliberately
# free of any string a fixture `then` asserts verbatim (no spec leak).
SPEC = (
    "# Greet\n"
    "Build greet.py that prints a friendly greeting to a name argument, "
    "or exits 2 with an error when run with no arguments.\n"
)


def _answers(tmp_path, author_adapter):
    return {
        "app_name": "greet",
        "spec_text": SPEC,
        "assurance": "cooperative",
        "workspace_root": str(tmp_path / "ws"),
        "control_root": str(tmp_path / "control"),
        "builder_adapter": FAKE_BUILDER,
        "author_adapter": author_adapter,
        "behaviors": [
            {"id": "BHV-001", "description": "greets a name"},
            {"id": "BHV-002", "description": "errors on no args"},
        ],
        # M42: these tests exercise the M40 AUTHOR flow (barrier/retry/install),
        # which predates M42's stricter agent-authored default (happy+boundary+
        # failure). Pin the back-compat happy-only policy so they keep testing
        # exactly the author flow; class-typed adequacy + the critic loop are
        # covered by test_adequacy.py / test_e2e_critic.py.
        "scenario_adequacy": {"required_classes": ["happy"]},
        # no scenarios -> scenarios-pending-author
    }


def _init(tmp_path, author_adapter):
    cr = tmp_path / "control"
    answers = tmp_path / "answers.json"
    answers.write_text(json.dumps(_answers(tmp_path, author_adapter)), encoding="utf-8")
    p = subprocess.run(
        [sys.executable, SUP, "init", "--control-root", str(cr), "--answers", str(answers)],
        capture_output=True, text=True, timeout=120,
    )
    return cr, p


def _cli(*args):
    return subprocess.run([sys.executable, SUP, *args], capture_output=True, text=True, timeout=180)


def _run_dir(cr):
    run_id = os.listdir(cr / "runs")[0]
    return cr / "runs" / run_id


def test_author_flow_converges_barrier_intact(tmp_path):
    cr, p = _init(tmp_path, FAKE_AUTHOR)
    assert p.returncode == 0, p.stderr
    assert "PENDING" in p.stdout
    # marker present, scenarios/ empty.
    assert (cr / "scenarios_pending_author").exists()
    assert os.listdir(cr / "scenarios") == []

    # (a) run BEFORE authoring refuses fail-closed.
    r = _cli("run", "--control-root", str(cr))
    assert r.returncode == 2
    assert "author-scenarios first" in r.stderr
    assert not (cr / "runs").exists()   # no run was ever started

    # author-scenarios installs the agent set + clears the marker.
    a = _cli("author-scenarios", "--control-root", str(cr))
    assert a.returncode == 0, a.stderr
    installed = sorted(os.listdir(cr / "scenarios"))
    assert installed == ["BHV-001-F1.json", "BHV-001-S1.json", "BHV-002-S1.json"]
    assert not (cr / "scenarios_pending_author").exists()

    # AUTHORED_SCENARIOS journal event records adapter + counts, NEVER content.
    events = [json.loads(l) for l in (cr / "authored.jsonl").read_text().splitlines()]
    sealed = [e for e in events if e["state"] == "AUTHORED_SCENARIOS"]
    assert sealed and sealed[0]["data"]["adapter"] == FAKE_AUTHOR
    assert sealed[0]["data"]["counts"] == {"scenarios": 3, "dev": 2, "final": 1}
    dumped = (cr / "authored.jsonl").read_text()
    assert "Hello, World!" not in dumped   # no scenario `then` content leaked

    # a normal fake-builder run converges against the agent-authored holdout.
    r = _cli("run", "--control-root", str(cr))
    assert r.returncode == 0, r.stderr
    assert "CONVERGED" in r.stdout

    # manifest records authored_by (the independent author adapter).
    rd = _run_dir(cr)
    manifest = json.loads((rd / "manifest.json").read_text())
    assert manifest["authored_by"]["adapter"] == FAKE_AUTHOR
    assert manifest["authored_by"]["same_model_ack"] is False

    # BARRIER: the builder's workspace never contained any scenario file.
    ws_root = tmp_path / "ws"
    workspaces = [ws_root / d for d in os.listdir(ws_root)]
    for w in workspaces:
        present = os.listdir(w)
        assert "scenarios" not in present
        # the only json a builder ever sees is its own ID/taxonomy feedback.
        for name in present:
            assert name in ("greet.py", "feedback.json", "spec.md",
                            "DARK_FACTORY_PROMPT.md"), name


def test_non_discriminating_author_fails_closed_no_install(tmp_path):
    cr, p = _init(tmp_path, FAKE_AUTHOR_INERT)
    assert p.returncode == 0, p.stderr

    # bounded retries all fail (the stub emits the same inert set every time).
    a = _cli("author-scenarios", "--control-root", str(cr), "--attempts", "2")
    assert a.returncode == 2
    assert "exhausted" in a.stderr
    # fail-closed: NO scenarios installed, marker still present.
    assert os.listdir(cr / "scenarios") == []
    assert (cr / "scenarios_pending_author").exists()

    # and a subsequent run still refuses.
    r = _cli("run", "--control-root", str(cr))
    assert r.returncode == 2
    assert "author-scenarios first" in r.stderr


def test_unknown_then_key_rejected_pre_install_then_retry_converges(tmp_path):
    # An author whose FIRST attempt carries an unknown `then` assertion key
    # (is_discriminating passes, but the strict oracle-IR keyset check -- the
    # one the INSTALLED set faces at run time -- rejects). This must be caught
    # PRE-install (no marker removal, no install-then-`run`-deadlock), fed back,
    # and fixed on the retry.
    cr, p = _init(tmp_path, FAKE_AUTHOR_RETRY)
    assert p.returncode == 0, p.stderr

    a = _cli("author-scenarios", "--control-root", str(cr), "--attempts", "2")
    # Attempt 1 failed on the unknown key (surfaced), attempt 2 converged.
    assert a.returncode == 0, a.stderr + a.stdout
    assert "known assertion key" in a.stderr        # the fed-back complaint
    installed = sorted(os.listdir(cr / "scenarios"))
    assert installed == ["BHV-001-S1.json", "BHV-002-S1.json"]
    assert not (cr / "scenarios_pending_author").exists()

    # CRITICAL: the installed set actually RUNS (no OracleError deadlock) --
    # i.e. what validate_authored accepted is exactly what `run` accepts.
    r = _cli("run", "--control-root", str(cr))
    assert r.returncode == 0, r.stderr
    assert "CONVERGED" in r.stdout

    # And two attempt events prove the retry consumed the feedback.
    events = [json.loads(l) for l in (cr / "authored.jsonl").read_text().splitlines()]
    attempts = [e for e in events if e["state"] == "AUTHORED_SCENARIOS_ATTEMPT"]
    assert [e["data"]["ok"] for e in attempts] == [False, True]


def test_unknown_key_single_attempt_leaves_pending_no_install(tmp_path):
    # With only ONE attempt, the unknown-key set never gets fixed -> exit 2,
    # NOTHING installed, marker RETAINED (no install-then-deadlock).
    cr, p = _init(tmp_path, FAKE_AUTHOR_RETRY)
    assert p.returncode == 0
    a = _cli("author-scenarios", "--control-root", str(cr), "--attempts", "1")
    assert a.returncode == 2
    assert "known assertion key" in a.stderr
    assert os.listdir(cr / "scenarios") == []
    assert (cr / "scenarios_pending_author").exists()


def test_author_scenarios_without_author_role_refuses(tmp_path):
    # A control root with human scenarios (no roles.author) -> author-scenarios
    # refuses (nothing to do), and the control root is untouched.
    cr = tmp_path / "control"
    (cr / "scenarios").mkdir(parents=True)
    (cr / "config.json").write_text(json.dumps({
        "config_version": "0.1", "autonomy": 4, "assurance": "cooperative",
        "feedback": "ids", "max_iterations": 5,
        "workspace_root": str(tmp_path / "ws"),
        "roles": {"builder": {"adapter": "/bin/true"}},
        "budget": {"billing": "subscription"},
    }), encoding="utf-8")
    (cr / "spec.md").write_text(SPEC, encoding="utf-8")
    (cr / "behaviors.json").write_text(json.dumps({"behaviors": [{"id": "BHV-001"}]}), encoding="utf-8")
    a = _cli("author-scenarios", "--control-root", str(cr))
    assert a.returncode == 2
    assert "no roles.author configured" in a.stderr


def test_author_scenarios_refuses_existing_scenarios(tmp_path):
    # If scenarios already exist, author-scenarios refuses to overwrite.
    cr, p = _init(tmp_path, FAKE_AUTHOR)
    assert p.returncode == 0
    a = _cli("author-scenarios", "--control-root", str(cr))
    assert a.returncode == 0   # first author installs
    # second author-scenarios call now sees existing scenarios -> refuse.
    a2 = _cli("author-scenarios", "--control-root", str(cr))
    assert a2.returncode == 2
    assert "already has" in a2.stderr


def test_author_model_identity_sealed_verbatim_into_manifest(tmp_path):
    # DF-R3-04 (M50): an operator-ASSERTED roles.author.model_identity is sealed
    # VERBATIM into the terminal manifest's authored_by. init doesn't surface
    # this optional field, so we patch config.json directly (author-scenarios +
    # run both re-load config fresh) before authoring.
    cr, p = _init(tmp_path, FAKE_AUTHOR)
    assert p.returncode == 0, p.stderr

    cfg_path = cr / "config.json"
    cfg = json.loads(cfg_path.read_text())
    cfg["roles"]["author"]["model_identity"] = "openai/gpt-5-codex"
    cfg_path.write_text(json.dumps(cfg), encoding="utf-8")

    a = _cli("author-scenarios", "--control-root", str(cr))
    assert a.returncode == 0, a.stderr
    r = _cli("run", "--control-root", str(cr))
    assert r.returncode == 0, r.stderr

    manifest = json.loads((_run_dir(cr) / "manifest.json").read_text())
    # Verbatim, operator-asserted (not verified) identity on the sealed manifest.
    assert manifest["authored_by"]["model_identity"] == "openai/gpt-5-codex"
