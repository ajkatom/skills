"""M24 Task 2: LIVE proof that api_anthropic runs a real model INSIDE the
minimal hardened-tier container (python:3.12-alpine -- no claude/codex/gemini
CLI installed), against a local stub Messages endpoint -- deterministic, no
paid calls.

This is the mechanism M10 documented as missing ("real-model-in-container
needs a builder image with the CLI"): api_anthropic needs nothing but
python3 stdlib (urllib), so it is the FIRST builder adapter that can actually
run to completion inside that plain image -- claude/codex/gemini would all
fail with "CLI not found on PATH" in the same container, because their
adapters shell out to a binary this image never has.

Only the model's BRAIN is stubbed here (a canned Messages response). Every
other layer is the real thing and runs live: the Docker container (built
fresh, `--network bridge`, all capabilities dropped, read-only rootfs --
same `df_container.build_argv` the hardened tier's `_run_loop` uses for
every builder call), the network hop from inside the container out to the
stub HTTP server on the host (reached via `host.docker.internal`, the exact
pattern M17's enterprise egress-proxy tests already prove live on this Docker
install -- see test_enterprise_config.py's `host.docker.internal:{proxy_port}`
usage), the real HTTP POST + response parse, and the path-safe write into the
bind-mounted workspace.

The stub binds 127.0.0.1 on the HOST (tests/fixtures/stub_messages_api, also
used by test_api_adapter.py); `network: bridge` (not hardened's default
`network: none`) is required here because, unlike a CLI builder that needs no
network at all, api_anthropic's entire job is one outbound HTTP call.

The container invocation below is built the same way supervisor._run_loop
builds it for a real hardened run (`df_container.build_argv` for the docker
argv, then `argv + [adapter_path]` as the command -- see
`supervisor.invoke_adapter`) -- driven directly here (not via the full
supervisor CLI/config path) for a lean, single-purpose e2e that isolates the
one thing this milestone adds: a builder adapter that can run in this
container at all.

Honest scope: only the model's brain is stubbed. A live PAID in-container run
needs just an ANTHROPIC_API_KEY and this exact ANTHROPIC_BASE_URL/network
wiring pointed at the real Anthropic API -- see references/hardened.md.
"""
import json
import os
import subprocess

import pytest

import df_container
from test_api_adapter import TEST_KEY, _start_stub, _stop_stub

HERE = os.path.dirname(os.path.abspath(__file__))
ADAPTER = os.path.realpath(os.path.join(HERE, "..", "scripts", "adapters", "api_anthropic"))
IMAGE = "python:3.12-alpine"

DOCKER_LIVE = df_container.docker_available()


@pytest.fixture(scope="module", autouse=True)
def _prepull_image():
    """Mirrors test_e2e_hardened.py's session pre-pull: the live test below
    must not absorb a cold image download inside its own tighter subprocess
    timeout. No-op when docker is absent."""
    if DOCKER_LIVE:
        subprocess.run(["docker", "pull", "-q", IMAGE], capture_output=True, timeout=600)
    yield


def _run_adapter_in_container(workdir, prompt_file, container_base_url, timeout_s=60):
    """Build the exact docker argv supervisor._run_loop builds for a real
    hardened builder call (df_container.build_argv: workspace rw-mounted,
    the adapter's OWN directory ro-mounted, network bridge, the credential
    env baked in as docker `-e` flags) and invoke the adapter INSIDE it,
    exactly the way supervisor.invoke_adapter does (`exec_prefix + [adapter]`,
    protocol-0.1 request JSON piped on stdin). Returns the raw
    subprocess.CompletedProcess so the caller can inspect/grep stdout+stderr
    directly (rather than only the parsed response) for the no-key-leak
    assertion below."""
    adapter_ro_dir = os.path.dirname(ADAPTER)
    docker_argv = df_container.build_argv(
        IMAGE, workdir, ro_mounts=[adapter_ro_dir], network="bridge",
        env={"ANTHROPIC_BASE_URL": container_base_url, "ANTHROPIC_API_KEY": TEST_KEY},
    )
    req = {
        "adapter_protocol": "0.1",
        "role": "builder",
        "workdir": workdir,
        "prompt_file": prompt_file,
        "timeout_s": timeout_s,
        "confine": False,
    }
    argv = docker_argv + [ADAPTER]
    return subprocess.run(
        argv, input=json.dumps(req), capture_output=True, text=True,
        timeout=timeout_s + 60,
    )


@pytest.mark.skipif(not DOCKER_LIVE, reason="docker daemon unavailable")
def test_api_anthropic_builds_inside_container_against_stub(tmp_path):
    stub_proc, base_on_host = _start_stub(tmp_path, "greet")
    try:
        workspace = tmp_path / "ws"
        workspace.mkdir()
        ws_real = os.path.realpath(str(workspace))

        prompt_file = workspace / "DARK_FACTORY_PROMPT.md"
        prompt_file.write_text("Build greet.py per SPEC.", encoding="utf-8")

        # The stub is bound to 127.0.0.1 on the HOST; from INSIDE the
        # container it is reached at host.docker.internal:<same port> --
        # the identical pattern test_enterprise_config.py's live egress-
        # proxy probe already proves works on this Docker install.
        stub_port = base_on_host.rsplit(":", 1)[-1]
        container_base_url = f"http://host.docker.internal:{stub_port}"

        proc = _run_adapter_in_container(ws_real, str(prompt_file), container_base_url)

        assert proc.returncode == 0, proc.stderr
        resp = json.loads(proc.stdout)
        assert resp["adapter_protocol"] == "0.1"
        assert resp["status"] == "ok", resp.get("detail")

        # The model's file output landed in the bind-mounted workspace --
        # proof the adapter ran to completion INSIDE the container, not on
        # the host.
        greet = workspace / "greet.py"
        assert greet.exists(), (
            "greet.py missing from the mounted workspace -- the in-container "
            "adapter never actually wrote it"
        )
        assert "Hello" in greet.read_text(encoding="utf-8")

        # No key leak: neither the container's stdout/stderr nor any file it
        # wrote into the workspace ever contains the literal key value.
        assert TEST_KEY not in proc.stdout
        assert TEST_KEY not in proc.stderr
        for root, _dirs, files in os.walk(ws_real):
            for fn in files:
                content = open(
                    os.path.join(root, fn), encoding="utf-8", errors="replace"
                ).read()
                assert TEST_KEY not in content
    finally:
        _stop_stub(stub_proc)


@pytest.mark.skipif(not DOCKER_LIVE, reason="docker daemon unavailable")
def test_api_anthropic_container_run_key_absent_even_on_adapter_error(tmp_path):
    """Same in-container mechanism, but the stub replies with an unsafe path
    (mode="unsafe") so the adapter reports status:"error" -- the no-key-leak
    guarantee must hold on the failure path too, and the all-or-nothing
    write discipline (Task 1) must hold inside the container exactly as it
    does on the host."""
    stub_proc, base_on_host = _start_stub(tmp_path, "unsafe")
    try:
        workspace = tmp_path / "ws"
        workspace.mkdir()
        ws_real = os.path.realpath(str(workspace))

        prompt_file = workspace / "DARK_FACTORY_PROMPT.md"
        prompt_file.write_text("Build greet.py per SPEC.", encoding="utf-8")

        stub_port = base_on_host.rsplit(":", 1)[-1]
        container_base_url = f"http://host.docker.internal:{stub_port}"

        proc = _run_adapter_in_container(ws_real, str(prompt_file), container_base_url)

        assert proc.returncode == 0, proc.stderr
        resp = json.loads(proc.stdout)
        assert resp["status"] == "error"
        assert os.listdir(ws_real) == ["DARK_FACTORY_PROMPT.md"]  # no escape write

        assert TEST_KEY not in proc.stdout
        assert TEST_KEY not in proc.stderr
    finally:
        _stop_stub(stub_proc)
