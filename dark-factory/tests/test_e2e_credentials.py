"""M11-3 e2e: the credential broker end to end — allowlist-only delivery,
gitignore/permission fail-closed refusal, and artifact scrubbing. Driven as
real supervisor CLI subprocess calls, mirroring test_e2e_hardened.py's
(DOCKER_LIVE guard, session pre-pull fixture, _make_hardened-style config
mutation, set-diff run selection) and test_e2e_security.py's (planted-value
grep discipline across every file under run_dir) conventions.

  (a) hardened brokered env (live docker, skipif): an env-file credential
      source resolves DF_TEST_CRED, allowlisted into the hardened container.
      `env_seen.txt` (written by fake_builder_envdump from its own
      `os.environ`) proves DF_TEST_CRED and HOME reached the builder but a
      control var planted in the SUPERVISOR's env before the run
      (DF_LEAKME_API_KEY) did not — allowlist-only, not merely
      cred-present. The builder also smuggles DF_TEST_CRED's VALUE into
      greet.py's usage-error stderr message (see the fixture's docstring);
      the dev-cohort verify pass captures that stderr into
      verifier_report_iter_1.json through the run's Redactor. The e2e
      asserts the value is NOWHERE under run_dir or in CLI stdout/stderr,
      AND `***REDACTED***` IS somewhere under run_dir — the second
      assertion is what makes the first non-vacuous (it proves the smuggle
      reached a written artifact and the redactor fired, not that the
      channel was simply never exercised). Manifest `credentials` is
      names-only.
  (b) standard/cooperative launcher-scoping (no docker needed): the same
      env-file source under `assurance: standard`, with the supervisor's
      OWN process launched with DF_LEAKME_API_KEY set — env_seen.txt has
      DF_TEST_CRED and PATH, not DF_LEAKME_API_KEY.
  (c) gitignore refusal: an env-file living inside a fresh `git init` tmp
      repo, not yet ignored -> exit 2, stderr mentions gitignore; add the
      ignore rule -> the run proceeds past credential resolution (whatever
      it does next is fine — the credentials refusal specifically is gone).
  (d) unresolvable -> refusal: the allowlist names a var missing from the
      env-file -> exit 2 before any builder call (no run_dir at all, since
      credentials are resolved before run_dir is created — see
      supervisor._run_locked).
"""
import json
import os
import subprocess
import sys
import uuid

import pytest

import df_container
from test_e2e_hardened import _make_hardened, _prepull_image  # noqa: F401 (fixture)
from test_supervisor import FAKE, external_reachable, needs_network, setup_control

HERE = os.path.dirname(os.path.abspath(__file__))
FAKE_ENVDUMP = os.path.join(HERE, "fixtures", "fake_builder_envdump")
SUP = os.path.join(HERE, "..", "scripts", "supervisor.py")

DOCKER_LIVE = df_container.docker_available()


def _run(cr, *args, env=None, timeout=180):
    return subprocess.run(
        [sys.executable, SUP, *args, "--control-root", str(cr)],
        capture_output=True, text=True, timeout=timeout, env=env,
    )


def _write_env_file(path, pairs):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "\n".join(f"{k}={v}" for k, v in pairs.items()) + "\n", encoding="utf-8"
    )
    path.chmod(0o600)


def _set_credentials(cr, credentials):
    cfg_path = cr / "config.json"
    cfg = json.loads(cfg_path.read_text(encoding="utf-8"))
    cfg["credentials"] = credentials
    cfg_path.write_text(json.dumps(cfg), encoding="utf-8")


def _walk_all_files(root):
    for dirpath, _, filenames in os.walk(root):
        for name in filenames:
            yield os.path.join(dirpath, name)


def _assert_value_absent_and_redacted_present(run_dir, proc, secret):
    """The non-vacuousness pair: the raw secret must appear NOWHERE under
    run_dir or in CLI stdout/stderr, AND the placeholder must appear
    SOMEWHERE under run_dir — proving the redactor actually fired on a
    real smuggle rather than the channel simply never being exercised."""
    checked_any = False
    redacted_seen = False
    for path in _walk_all_files(str(run_dir)):
        checked_any = True
        with open(path, "rb") as f:
            data = f.read()
        assert secret.encode() not in data, f"secret leaked into {path}"
        if b"***REDACTED***" in data:
            redacted_seen = True
    assert checked_any, "run_dir is empty — scan would be vacuous"
    assert redacted_seen, "no ***REDACTED*** marker found anywhere under run_dir " \
        "— the smuggle never reached a written, redacted artifact (vacuous proof)"
    assert secret not in proc.stdout
    assert secret not in proc.stderr


# ---------------------------------------------------------------------------
# (a) hardened brokered env — live docker, allowlist-only + smuggle proof
# ---------------------------------------------------------------------------

@needs_network
@pytest.mark.skipif(not DOCKER_LIVE, reason="docker daemon unavailable")
def test_live_hardened_brokered_env_allowlist_only_and_redacted(tmp_path):
    if not external_reachable():
        pytest.skip("no external reachability for the candidate egress-denial probe")
    cr = setup_control(tmp_path, FAKE_ENVDUMP, checkpoint="auto")
    # M47 RA-08(a): confine candidate egress so the hardened run QUALIFIES.
    _make_hardened(cr, tmp_path, candidate_network="deny")

    secret = "supersecret-" + uuid.uuid4().hex
    env_file = tmp_path / "creds" / ".env"  # 3rd tmp dir, disjoint from cr and ws
    _write_env_file(env_file, {"DF_TEST_CRED": secret})
    _set_credentials(cr, {
        "source": "env-file", "env_file": str(env_file),
        "allowlist": ["DF_TEST_CRED"],
    })

    env = dict(os.environ)
    env["DF_LEAKME_API_KEY"] = "leaked-value-should-never-reach-the-builder"

    proc = _run(cr, "run", env=env, timeout=240)
    assert proc.returncode == 0, proc.stderr

    run_id = os.listdir(cr / "runs")[0]
    run_dir = cr / "runs" / run_id
    workspace = tmp_path / "ws" / run_id

    env_seen = (workspace / "env_seen.txt").read_text(encoding="utf-8")
    names = set(env_seen.splitlines())
    assert "DF_TEST_CRED" in names
    assert "HOME" in names
    assert "DF_LEAKME_API_KEY" not in names  # allowlist-only, not merely cred-present

    _assert_value_absent_and_redacted_present(run_dir, proc, secret)

    manifest = json.loads((run_dir / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["credentials"] == {"source": "env-file", "allowlist": ["DF_TEST_CRED"]}
    assert manifest["outcome"] == "COMPLETE_QUALIFIED"


# ---------------------------------------------------------------------------
# (b) standard/cooperative launcher-scoping — no docker needed
# ---------------------------------------------------------------------------

def test_standard_launcher_scoping_strips_leaked_var(tmp_path):
    b_backend_available = True
    try:
        import df_sandbox
        b = df_sandbox.current_backend()
        b_backend_available = bool(b and b.available())
    except Exception:
        b_backend_available = False

    cr = setup_control(tmp_path, FAKE_ENVDUMP, checkpoint="auto")
    if b_backend_available:
        cfg = json.loads((cr / "config.json").read_text())
        cfg["assurance"] = "standard"
        (cr / "config.json").write_text(json.dumps(cfg), encoding="utf-8")

    secret = "supersecret-" + uuid.uuid4().hex
    env_file = tmp_path / "creds" / ".env"
    _write_env_file(env_file, {"DF_TEST_CRED": secret})
    _set_credentials(cr, {
        "source": "env-file", "env_file": str(env_file),
        "allowlist": ["DF_TEST_CRED"],
    })

    env = dict(os.environ)
    env["DF_LEAKME_API_KEY"] = "leaked-value-should-never-reach-the-builder"

    proc = _run(cr, "run", env=env, timeout=120)
    assert proc.returncode == 0, proc.stderr

    run_id = os.listdir(cr / "runs")[0]
    workspace = tmp_path / "ws" / run_id
    run_dir = cr / "runs" / run_id

    env_seen = (workspace / "env_seen.txt").read_text(encoding="utf-8")
    names = set(env_seen.splitlines())
    assert "DF_TEST_CRED" in names
    assert "PATH" in names
    assert "DF_LEAKME_API_KEY" not in names

    _assert_value_absent_and_redacted_present(run_dir, proc, secret)

    manifest = json.loads((run_dir / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["credentials"] == {"source": "env-file", "allowlist": ["DF_TEST_CRED"]}


# ---------------------------------------------------------------------------
# (c) gitignore refusal -> exit 2, then ignored -> proceeds past credentials
# ---------------------------------------------------------------------------

def test_gitignore_refusal_then_ignored_proceeds(tmp_path):
    cr = setup_control(tmp_path, FAKE, checkpoint="auto")

    repo = tmp_path / "creds_repo"
    repo.mkdir()
    subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
    env_file = repo / "secrets.env"
    _write_env_file(env_file, {"DF_TEST_CRED": "whatever-value-1234567890"})
    _set_credentials(cr, {
        "source": "env-file", "env_file": str(env_file),
        "allowlist": ["DF_TEST_CRED"],
    })

    proc = _run(cr, "run")
    assert proc.returncode == 2
    assert "gitignore" in proc.stderr.lower()
    assert not (cr / "runs").exists()

    (repo / ".gitignore").write_text("secrets.env\n", encoding="utf-8")

    proc2 = _run(cr, "run")
    # Any later outcome is fine (build/converge/whatever) — the credentials
    # refusal specifically must be gone.
    assert "credentials:" not in proc2.stderr


# ---------------------------------------------------------------------------
# (d) unresolvable allowlist name -> refusal before any builder call
# ---------------------------------------------------------------------------

def test_unresolvable_allowlist_name_refuses_before_any_builder_call(tmp_path):
    cr = setup_control(tmp_path, FAKE, checkpoint="auto")

    env_file = tmp_path / "creds" / ".env"
    _write_env_file(env_file, {"DF_TEST_CRED": "some-value-1234567890"})
    _set_credentials(cr, {
        "source": "env-file", "env_file": str(env_file),
        "allowlist": ["DF_MISSING_CRED"],  # not in the env-file
    })

    proc = _run(cr, "run")
    assert proc.returncode == 2
    assert "credentials:" in proc.stderr
    # fail-closed at run start: no run_dir was ever created, no builder call.
    assert not (cr / "runs").exists()
