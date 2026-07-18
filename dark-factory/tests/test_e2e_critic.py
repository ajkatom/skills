"""M42 Task 4 e2e acceptance for the decorrelated `critic` role, driven as real
subprocesses against the supervisor CLI. STUB author/critic adapters
(fixtures/fake_author*, fixtures/fake_critic*) emit fixed JSON -- NO paid API
calls, fully deterministic, mirroring how the suite stubs the builder.

Covers:
  (a) a critic emitting a BLOCKING finding drives ONE author revision that then
      passes; the set installs; scenario_review.md + CRITIC_REVIEW/CRITIC_ADVISORY
      journal events appear; a subsequent build converges with the barrier
      intact (the builder workspace never contains scenarios/, scenario_review.md,
      or any critic output).
  (b) a CLEAN critic with an advisory: the advisory surfaces to scenario_review.md
      (never auto-applied into the scenarios), 0 revision rounds.
  (c) a critic that never clears its blocking finding -> author-scenarios exits 2
      after the bounded rounds, NOTHING installed (control root stays pending).
"""
import json
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
SUP = os.path.join(HERE, "..", "scripts", "supervisor.py")
FAKE_BUILDER = os.path.join(HERE, "fixtures", "fake_builder")
FAKE_AUTHOR = os.path.join(HERE, "fixtures", "fake_author")
FAKE_AUTHOR_REVISE = os.path.join(HERE, "fixtures", "fake_author_revise")
FAKE_CRITIC_CLEAN = os.path.join(HERE, "fixtures", "fake_critic_clean")
FAKE_CRITIC_GAP = os.path.join(HERE, "fixtures", "fake_critic_gap")

SPEC = (
    "# Greet\n"
    "Build greet.py that prints a friendly greeting to a name argument, "
    "or exits 2 with an error when run with no arguments.\n"
)


def _answers(tmp_path, author_adapter, critic_adapter):
    return {
        "app_name": "greet",
        "spec_text": SPEC,
        "assurance": "cooperative",
        "workspace_root": str(tmp_path / "ws"),
        "control_root": str(tmp_path / "control"),
        "builder_adapter": FAKE_BUILDER,
        "author_adapter": author_adapter,
        "critic_adapter": critic_adapter,
        "behaviors": [
            {"id": "BHV-001", "description": "greets a name"},
            {"id": "BHV-002", "description": "errors on no args"},
        ],
        # Pin happy-only so the happy stub sets satisfy adequacy while the
        # critic loop still runs (critic stays enabled by default). This test
        # exercises the CRITIC mechanism, not class coverage (test_adequacy).
        "scenario_adequacy": {"required_classes": ["happy"]},
    }


def _init(tmp_path, author_adapter, critic_adapter):
    cr = tmp_path / "control"
    answers = tmp_path / "answers.json"
    answers.write_text(json.dumps(_answers(tmp_path, author_adapter, critic_adapter)),
                       encoding="utf-8")
    p = subprocess.run(
        [sys.executable, SUP, "init", "--control-root", str(cr), "--answers", str(answers)],
        capture_output=True, text=True, timeout=120)
    return cr, p


def _cli(*args):
    return subprocess.run([sys.executable, SUP, *args], capture_output=True, text=True, timeout=180)


def _events(cr):
    return [json.loads(l) for l in (cr / "authored.jsonl").read_text().splitlines()]


def test_critic_blocking_loop_converges_installs_and_barrier_holds(tmp_path):
    cr, p = _init(tmp_path, FAKE_AUTHOR_REVISE, FAKE_CRITIC_GAP)
    assert p.returncode == 0, p.stderr

    a = _cli("author-scenarios", "--control-root", str(cr))
    assert a.returncode == 0, a.stderr + a.stdout

    # The author revised once (base -> base + "revised extra"), so all 3 install.
    installed = sorted(os.listdir(cr / "scenarios"))
    assert installed == ["BHV-001-S1.json", "BHV-001-S2.json", "BHV-002-S1.json"], installed
    assert not (cr / "scenarios_pending_author").exists()

    # scenario_review.md is CONTROL-PLANE (records the loop + advisories).
    review = (cr / "scenario_review.md").read_text()
    assert "revision rounds: 1" in review
    assert "idempotency" in review           # the CLEAN critic's advisory

    # journal: exactly one revision round, CRITIC_REVIEW + CRITIC_ADVISORY, and
    # NO scenario `then` content ever leaked into the journal.
    ev = _events(cr)
    reviews = [e for e in ev if e["state"] == "CRITIC_REVIEW"]
    assert reviews and reviews[0]["data"]["rounds"] == 1
    assert reviews[0]["data"]["blocking_resolved"] == 1
    assert any(e["state"] == "CRITIC_ADVISORY" for e in ev)
    assert any(e["state"] == "CRITIC_ATTEMPT" for e in ev)
    assert "Hello, World!" not in (cr / "authored.jsonl").read_text()

    # manifest-visible: a subsequent build converges.
    r = _cli("run", "--control-root", str(cr))
    assert r.returncode == 0, r.stderr
    assert "CONVERGED" in r.stdout

    # BARRIER: the builder workspace never contained scenarios/, the critic
    # output, or scenario_review.md.
    ws_root = tmp_path / "ws"
    for d in os.listdir(ws_root):
        present = os.listdir(ws_root / d)
        assert "scenarios" not in present
        assert "scenario_review.md" not in present
        assert "critic.json" not in present
        for name in present:
            assert name in ("greet.py", "feedback.json", "spec.md",
                            "DARK_FACTORY_PROMPT.md"), name

    # manifest records the critic (top-level) + the adequacy.critic record.
    run_id = os.listdir(cr / "runs")[0]
    mf = json.loads((cr / "runs" / run_id / "manifest.json").read_text())
    assert mf["critic"]["adapter"] == FAKE_CRITIC_GAP
    assert mf["critic"]["same_model_ack"] is False
    assert mf["adequacy"]["critic"]["enabled"] is True
    assert mf["adequacy"]["critic"]["review"]["rounds"] == 1


def test_clean_critic_advisory_surfaces_never_auto_applied(tmp_path):
    cr, p = _init(tmp_path, FAKE_AUTHOR, FAKE_CRITIC_CLEAN)
    assert p.returncode == 0, p.stderr

    a = _cli("author-scenarios", "--control-root", str(cr))
    assert a.returncode == 0, a.stderr + a.stdout

    # No blocking -> 0 revision rounds; the advisory is in scenario_review.md.
    review = (cr / "scenario_review.md").read_text()
    assert "revision rounds: 0" in review
    assert "input validation" in review      # the advisory topic

    # The advisory is NOT auto-applied: no scenario file mentions it.
    for name in os.listdir(cr / "scenarios"):
        body = (cr / "scenarios" / name).read_text()
        assert "input validation" not in body

    ev = _events(cr)
    reviews = [e for e in ev if e["state"] == "CRITIC_REVIEW"]
    assert reviews and reviews[0]["data"]["rounds"] == 0
    assert reviews[0]["data"]["advisories"] == 1


def test_critic_never_clears_blocking_fails_closed_no_install(tmp_path):
    # A non-revising author (plain fake_author) + a critic that keeps blocking
    # (fake_critic_gap never sees "revised extra") -> exhaust the rounds, exit 2,
    # NOTHING installed, marker retained, and no scenario_review.md written.
    cr, p = _init(tmp_path, FAKE_AUTHOR, FAKE_CRITIC_GAP)
    assert p.returncode == 0, p.stderr

    a = _cli("author-scenarios", "--control-root", str(cr))
    assert a.returncode == 2
    assert "blocking" in a.stderr.lower()
    assert os.listdir(cr / "scenarios") == []
    assert (cr / "scenarios_pending_author").exists()
    assert not (cr / "scenario_review.md").exists()

    ev = _events(cr)
    assert any(e["state"] == "CRITIC_UNRESOLVED" for e in ev)

    # and a subsequent run still refuses (no scenarios).
    r = _cli("run", "--control-root", str(cr))
    assert r.returncode == 2
    assert "author-scenarios first" in r.stderr
