"""Config loading + validation for dark-factory. Stdlib only."""
import json
import os
import re
import urllib.parse

import df_container
import df_modes
import df_proxy
from df_common import canonical_json, sha256_str

SCRIPTS_DIR = os.path.dirname(os.path.abspath(__file__))
TAXONOMY = ("wrong_exit_code", "wrong_output", "timeout", "crash")
# M27 Task 2 (spec §7.4): candidate-network authority modes. Mirrors
# df_sandbox._NETWORK_MODES exactly -- kept as its own constant here (rather
# than importing df_sandbox) because config validation must never depend on
# platform-specific sandbox backends being importable/available.
_CANDIDATE_NETWORK_MODES = ("unrestricted", "deny", "loopback")
_CANDIDATE_HOST_READ_MODES = ("default_deny", "allow_host_read")
_MEMORY_RE = re.compile(r"^[0-9]+[bkmg]$")
_CRED_NAME_RE = re.compile(r"^[A-Z][A-Z0-9_]*$")
_PROBE_ID_RE = re.compile(r"^[a-z0-9-]{1,32}$")
_HEX64_RE = re.compile(r"^[0-9a-fA-F]{64}$")
# M41: a ship-action name is a slug (it names an action in the release claim's
# `action_names`, in the ship journal, and in the sealed ship record — so it
# must be stable, greppable, and free of anything that could be confused with a
# path or shell token). Deliberately narrower than a free string.
_SHIP_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")

# M33a (DF-06): at these tiers the security gates are MANDATORY — a run cannot
# reach COMPLETE_QUALIFIED with them off (supervisor folds app_security into
# `qualified`). secret_scan + dangerous_scan are the immutable minimum set: an
# operator may STRENGTHEN the policy (add gates, add fail_on entries, keep
# strict_unavailable) but never disable the minimum at standard+. cooperative
# is unaffected — gates stay fully optional there, byte-identical to pre-M33a.
MANDATORY_TIERS = ("standard", "hardened", "enterprise")
MANDATORY_GATES = ("secret_scan", "dangerous_scan")


class ConfigError(ValueError):
    pass


def load_supported_tiers() -> dict:
    with open(os.path.join(SCRIPTS_DIR, "supported_tiers.json"), encoding="utf-8") as f:
        return json.load(f)


def _validate_seccomp_profile(path, label="enterprise.seccomp_profile"):
    """Fail-closed offline shape-check (M22 Task 1) for a Docker seccomp
    profile: the file exists, parses as JSON, and is a dict with a string
    `defaultAction` and a list `syscalls`. This is a SHAPE check only -- it
    proves nothing about what the profile actually denies on a real kernel
    (that is df_container.probe_seccomp, a live probe run at enterprise
    resolve time, not at config load). Raises ConfigError naming the exact
    problem; never silently accepts a malformed/missing profile."""
    if not os.path.isfile(path):
        raise ConfigError(f"{label} does not exist: {path}")
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except OSError as e:
        raise ConfigError(f"{label} could not be read ({path}): {e}") from e
    except json.JSONDecodeError as e:
        raise ConfigError(f"{label} is not valid JSON ({path}): {e}") from e
    if not isinstance(data, dict):
        raise ConfigError(
            f"{label} must be a JSON object, got {type(data).__name__} ({path})"
        )
    if not isinstance(data.get("defaultAction"), str):
        raise ConfigError(f"{label} must have a string 'defaultAction' ({path})")
    if not isinstance(data.get("syscalls"), list):
        raise ConfigError(f"{label} must have a list 'syscalls' ({path})")


def _disjoint(a: str, b: str) -> bool:
    a = os.path.realpath(a)
    b = os.path.realpath(b)
    return not (a == b or a.startswith(b + os.sep) or b.startswith(a + os.sep))


# M42 Task 1/5: the scenario `class` taxonomy the adequacy policy draws from.
# Canonical value space lives in run_scenarios.SCENARIO_CLASSES; df_config
# avoids importing it (no import cycle, and load_config stays stdlib-shaped),
# so the tuple is restated here and cross-checked by tests.
_SCENARIO_CLASSES = ("happy", "boundary", "failure")


def _resolve_adequacy(raw_adq, cfg_author, cfg_critic) -> dict:
    """Resolve cfg["_adequacy"] from an optional `scenario_adequacy` block plus
    the author/critic presence. Returns
    {"required_classes": [...], "min_per_class": int,
     "critic": {"enabled": bool, "max_rounds": int}}.

    Defaults are back-compat-first (see the call site): happy-only + critic off
    for a human-authored root; happy+boundary+failure + critic-on-if-configured
    for an agent-authored one. An explicit block overrides per key, fail-closed
    on any malformed value (a silently-wrong adequacy policy would weaken the
    gate)."""
    agent_authored = cfg_author is not None
    default_classes = (
        ["happy", "boundary", "failure"] if agent_authored else ["happy"]
    )
    required = list(default_classes)
    min_per = 1
    critic_enabled = agent_authored and cfg_critic is not None
    max_rounds = 2

    if raw_adq is not None:
        if not isinstance(raw_adq, dict):
            raise ConfigError("scenario_adequacy must be a JSON object")
        if "required_classes" in raw_adq:
            rc = raw_adq["required_classes"]
            if (not isinstance(rc, list) or not rc
                    or not all(isinstance(c, str) for c in rc)):
                raise ConfigError(
                    "scenario_adequacy.required_classes must be a non-empty list of strings")
            bad = [c for c in rc if c not in _SCENARIO_CLASSES]
            if bad:
                raise ConfigError(
                    f"scenario_adequacy.required_classes has unknown class(es) {bad!r}; "
                    f"allowed: {list(_SCENARIO_CLASSES)}")
            # De-dup while preserving order (a repeated class is a no-op, not
            # an error, but the resolved policy is canonicalized).
            seen = set()
            required = [c for c in rc if not (c in seen or seen.add(c))]
        if "min_per_class" in raw_adq:
            mp = raw_adq["min_per_class"]
            if not isinstance(mp, int) or isinstance(mp, bool) or mp < 1:
                raise ConfigError("scenario_adequacy.min_per_class must be a positive int")
            min_per = mp
        if "critic" in raw_adq:
            crit = raw_adq["critic"]
            if not isinstance(crit, dict):
                raise ConfigError("scenario_adequacy.critic must be a JSON object")
            if "enabled" in crit:
                if not isinstance(crit["enabled"], bool):
                    raise ConfigError("scenario_adequacy.critic.enabled must be a bool")
                critic_enabled = crit["enabled"]
            if "max_rounds" in crit:
                mr = crit["max_rounds"]
                if not isinstance(mr, int) or isinstance(mr, bool) or mr < 1:
                    raise ConfigError("scenario_adequacy.critic.max_rounds must be a positive int")
                max_rounds = mr

    # Fail-closed coherence: the critic loop cannot run without a critic
    # adapter. Enabling it (explicitly or by agent-authored default) with no
    # roles.critic is an operator error, not a silent no-op.
    if critic_enabled and cfg_critic is None:
        raise ConfigError(
            "scenario_adequacy.critic.enabled is true but no roles.critic adapter "
            "is configured -- add roles.critic or disable the critic")

    return {
        "required_classes": required,
        "min_per_class": min_per,
        "critic": {"enabled": critic_enabled, "max_rounds": max_rounds},
    }


# M30 (DF-03) Part C: the shipped API adapters each expect ONE specific
# (injection header, provider host) pairing -- see scripts/adapters/
# api_anthropic and api_openai. A credential_proxy configured with the WRONG
# header for the adapter in use (or an allowlist that never names that
# provider's host) cannot possibly work: the proxy would inject the token
# under a header the adapter/provider never looks at, or refuse the request
# outright as off-allowlist. This is exactly the class of enterprise-real-
# model-path breakage DF-03 found -- catching the wrong PAIRING at config
# LOAD time (a ConfigError naming the mismatch) is strictly better than
# discovering it only when a real enterprise run's API call inexplicably
# fails at request time.
_PROXY_PROVIDER_RULES = {
    "anthropic": {"header": "x-api-key", "host": "api.anthropic.com"},
    "openai": {"header": "authorization", "host": "api.openai.com"},
}


def _adapter_provider(adapter_path):
    """basename-based provider inference for the two shipped API adapters
    (api_anthropic/api_openai) -- None for any other adapter (the CLI
    adapters don't read DF_PROXY_DESCRIPTOR at all, so the credential_proxy
    coherence check below doesn't apply to them)."""
    name = os.path.basename(adapter_path)
    if name == "api_anthropic":
        return "anthropic"
    if name == "api_openai":
        return "openai"
    return None


def _validate_adapter_sha256(role_raw, role_label):
    """M47 condition #7: an OPTIONAL `adapter_sha256` on a role pins the EXACT
    adapter file content (not just its path/basename). Validate the hex SHAPE
    at load (a 64-char hex sha256); the supervisor computes the file's real
    sha256 at run start and REFUSES on mismatch (fail-closed). Returns the
    lowercased expected digest or None. Absent -> None -> today's behavior is
    byte-identical (no pin, no check)."""
    if "adapter_sha256" not in role_raw:
        return None
    expected = role_raw["adapter_sha256"]
    if not isinstance(expected, str) or not _HEX64_RE.match(expected):
        raise ConfigError(
            f"roles.{role_label}.adapter_sha256 must be a 64-character hex "
            "sha256 digest (pins the exact adapter file content)")
    return expected.lower()


def _allowlist_entry_host(entry):
    """Read the HOST component back out of one credential_proxy.allowlist
    entry, using df_proxy's own canonical-origin parser (parse_allowlist_entry)
    so config-load-time validation agrees exactly with what df_proxy will
    actually match at request time -- one parser, not two definitions of
    "the same" allowlist shape that could quietly drift apart. Raises
    ConfigError (not AllowlistError) so the caller doesn't need to know
    df_proxy's exception type."""
    try:
        origins = df_proxy.parse_allowlist_entry(entry)
    except df_proxy.AllowlistError as e:
        raise ConfigError(f"credential_proxy.allowlist entry invalid: {e}") from e
    # Every origin df_proxy.parse_allowlist_entry derives from ONE entry
    # shares the same host (only scheme/port vary) -- any element's host is
    # the entry's host.
    return next(iter(origins))[1]


def load_config(control_root: str) -> dict:
    path = os.path.join(control_root, "config.json")
    if not os.path.exists(path):
        raise ConfigError(f"missing config: {path}")
    with open(path, encoding="utf-8") as f:
        try:
            raw = json.load(f)
        except json.JSONDecodeError as e:
            raise ConfigError(f"invalid JSON in {path}: {e}") from e

    if not isinstance(raw, dict):
        raise ConfigError(
            f"config must be a JSON object, got {type(raw).__name__}"
        )

    tiers = load_supported_tiers()["tiers"]
    tier = raw.get("assurance")
    if tier not in tiers:
        raise ConfigError(
            f"assurance tier {tier!r} has no conforming backend in this build; "
            f"supported: {sorted(tiers)} (spec section 2.3)"
        )

    if raw.get("feedback") != "ids":
        raise ConfigError("M1 supports only feedback: 'ids' (spec section 6.1)")

    mi = raw.get("max_iterations")
    if not isinstance(mi, int) or isinstance(mi, bool) or not (1 <= mi <= 20):
        raise ConfigError("max_iterations must be an int in 1..20")

    ws = raw.get("workspace_root")
    if not ws:
        raise ConfigError("workspace_root is required")
    if not _disjoint(ws, control_root):
        raise ConfigError("workspace_root must be disjoint from the control root")

    roles = raw.get("roles", {})
    if not isinstance(roles, dict):
        raise ConfigError("roles must be a JSON object")
    builder = roles.get("builder", {})
    if not isinstance(builder, dict):
        raise ConfigError("roles.builder must be a JSON object")
    adapter = builder.get("adapter")
    if not adapter:
        raise ConfigError("roles.builder.adapter is required")
    if tier in ("hardened", "enterprise"):
        # The adapter's DIRECTORY is bind-mounted ro into the builder container
        # at both hardened AND enterprise (enterprise's container path IS the
        # hardened container path, plus the egress lock + seccomp), so it must
        # be pinned down at config time: a bare command name (e.g. "claude")
        # would realpath against the process CWD (mounting whatever directory
        # the operator happens to run from), and an adapter inside the control
        # root would mount holdout content into the "isolated" builder. Both
        # are mount-escape paths — reject at load.
        adapter_path = os.path.expanduser(adapter)
        if not os.path.isabs(adapter_path) or not os.path.isfile(adapter_path):
            raise ConfigError(
                f"{tier} requires roles.builder.adapter to be an absolute path "
                "to an existing file (its directory is mounted into the container)"
            )
        adapter_dir = os.path.dirname(os.path.realpath(adapter_path))
        if not _disjoint(adapter_dir, control_root):
            raise ConfigError(
                f"{tier} requires the roles.builder.adapter directory to be "
                "disjoint from the control root (it would be mounted into the "
                "builder container)"
            )
    builder_expected_sha256 = _validate_adapter_sha256(builder, "builder")

    # M40: optional `roles.author` -- an AGENT (a different model than the
    # builder) writes the hidden scenarios instead of a human, with the SAME
    # barrier preserved. Absent -> cfg["_author"] = None and today's behavior is
    # byte-identical (human-authored, no author role). The author adapter is NOT
    # mounted into any container (authoring is a discarded pre-run step, never
    # concurrent with the builder), but it gets the SAME path hygiene as the
    # builder at hardened+ so a bare command name can't silently resolve against
    # CWD. The load-bearing gate is DIFFERENT-MODEL enforcement, fail-closed.
    author_raw = roles.get("author")
    if author_raw is not None:
        if not isinstance(author_raw, dict):
            raise ConfigError("roles.author must be a JSON object")
        author_adapter = author_raw.get("adapter")
        if not author_adapter:
            raise ConfigError("roles.author.adapter is required when roles.author is present")
        if tier in ("hardened", "enterprise"):
            a_path = os.path.expanduser(author_adapter)
            if not os.path.isabs(a_path) or not os.path.isfile(a_path):
                raise ConfigError(
                    f"{tier} requires roles.author.adapter to be an absolute path "
                    "to an existing file"
                )
            a_dir = os.path.dirname(os.path.realpath(a_path))
            if not _disjoint(a_dir, control_root):
                raise ConfigError(
                    f"{tier} requires the roles.author.adapter directory to be "
                    "disjoint from the control root"
                )
        author_timeout = author_raw.get("timeout_s", 600)
        if not isinstance(author_timeout, int) or isinstance(author_timeout, bool) or author_timeout < 1:
            raise ConfigError("roles.author.timeout_s must be a positive int")
        allow_same_model_ack = author_raw.get("allow_same_model_ack", False)
        if not isinstance(allow_same_model_ack, bool):
            raise ConfigError("roles.author.allow_same_model_ack must be a bool")
        # Different-model enforcement (owner's strongest-anti-snooping choice),
        # fail-closed: realpath(author.adapter) must differ from
        # realpath(builder.adapter). For the shipped adapters a distinct path
        # ⇒ a distinct model; the SAME adapter (even with a different
        # DF_API_MODEL) is a same-model case -> refuse UNLESS
        # allow_same_model_ack explicitly records the weaker guarantee, which
        # is then sealed into the manifest's `authored_by.same_model_ack` for
        # an auditor to see.
        if (os.path.realpath(os.path.expanduser(author_adapter))
                == os.path.realpath(os.path.expanduser(adapter))):
            if not allow_same_model_ack:
                raise ConfigError(
                    "roles.author.adapter must resolve to a DIFFERENT path than "
                    "roles.builder.adapter (an agent grading its own model's "
                    "build is not an independent check) -- set "
                    "roles.author.allow_same_model_ack: true to accept the "
                    "weaker guarantee (recorded in the manifest's authored_by)"
                )
        cfg_author = {
            "adapter": author_adapter,
            "timeout_s": author_timeout,
            "same_model_ack": allow_same_model_ack,
            "expected_sha256": _validate_adapter_sha256(author_raw, "author"),
        }
    else:
        cfg_author = None

    # M42 Task 4/5: optional `roles.critic` -- a SECOND, independent
    # (different-model) agent that adversarially reviews the AUTHORED scenarios
    # before they seal. Absent -> cfg["_critic"] = None (byte-identical to pre-
    # M42; no critic loop). Same path hygiene as author at hardened+. The
    # load-bearing gate is TWO fail-closed model-distinctness inequalities:
    #   realpath(critic) != realpath(builder)  -- COLLUSION (a critic must not
    #       bless scenarios its own model will build against), AND
    #   realpath(critic) != realpath(author)   -- DECORRELATION (the whole
    #       point is a second, independent mind).
    # A single `allow_same_model_ack` waives BOTH (recording the weaker
    # guarantee in the manifest's critic.same_model_ack), mirroring M40's
    # author check exactly.
    critic_raw = roles.get("critic")
    if critic_raw is not None:
        if not isinstance(critic_raw, dict):
            raise ConfigError("roles.critic must be a JSON object")
        critic_adapter = critic_raw.get("adapter")
        if not critic_adapter:
            raise ConfigError("roles.critic.adapter is required when roles.critic is present")
        if cfg_author is None:
            # A critic reviews an AGENT-authored set; without roles.author there
            # is nothing for it to review (human-authored scenarios go through
            # the human review path, not this loop). Fail-closed rather than
            # silently ignore a configured critic.
            raise ConfigError(
                "roles.critic requires roles.author (the critic reviews the "
                "agent-authored scenarios)")
        if tier in ("hardened", "enterprise"):
            c_path = os.path.expanduser(critic_adapter)
            if not os.path.isabs(c_path) or not os.path.isfile(c_path):
                raise ConfigError(
                    f"{tier} requires roles.critic.adapter to be an absolute path "
                    "to an existing file")
            c_dir = os.path.dirname(os.path.realpath(c_path))
            if not _disjoint(c_dir, control_root):
                raise ConfigError(
                    f"{tier} requires the roles.critic.adapter directory to be "
                    "disjoint from the control root")
        critic_timeout = critic_raw.get("timeout_s", 600)
        if not isinstance(critic_timeout, int) or isinstance(critic_timeout, bool) or critic_timeout < 1:
            raise ConfigError("roles.critic.timeout_s must be a positive int")
        critic_ack = critic_raw.get("allow_same_model_ack", False)
        if not isinstance(critic_ack, bool):
            raise ConfigError("roles.critic.allow_same_model_ack must be a bool")
        critic_real = os.path.realpath(os.path.expanduser(critic_adapter))
        builder_real = os.path.realpath(os.path.expanduser(adapter))
        author_real = os.path.realpath(os.path.expanduser(cfg_author["adapter"]))
        if critic_real == builder_real and not critic_ack:
            raise ConfigError(
                "roles.critic.adapter must resolve to a DIFFERENT path than "
                "roles.builder.adapter (a critic blessing scenarios its own "
                "model will build against is collusion, not an independent "
                "check) -- set roles.critic.allow_same_model_ack: true to accept "
                "the weaker guarantee (recorded in the manifest's critic field)")
        if critic_real == author_real and not critic_ack:
            raise ConfigError(
                "roles.critic.adapter must resolve to a DIFFERENT path than "
                "roles.author.adapter (the critic exists to be a DECORRELATED "
                "second mind; the same model can't decorrelate from itself) -- "
                "set roles.critic.allow_same_model_ack: true to accept the "
                "weaker guarantee (recorded in the manifest's critic field)")
        cfg_critic = {
            "adapter": critic_adapter,
            "timeout_s": critic_timeout,
            "same_model_ack": critic_ack,
            "expected_sha256": _validate_adapter_sha256(critic_raw, "critic"),
        }
    else:
        cfg_critic = None

    # M42 Task 1/5: the scenario-adequacy policy (class-typed coverage + the
    # critic loop toggle) -> cfg["_adequacy"]. DEFAULTS are back-compat-first:
    #   - absent `scenario_adequacy` + NO agent author  -> happy-only, critic
    #     off (today's behavior exactly; every pre-M42 scenario satisfies it).
    #   - absent `scenario_adequacy` + an agent author   -> the stricter
    #     happy+boundary+failure, and the critic loop ON iff roles.critic is
    #     set (an agent writing the tests gets the strongest machine floor).
    # An explicit `scenario_adequacy` block overrides these per key.
    cfg_adequacy = _resolve_adequacy(raw.get("scenario_adequacy"), cfg_author, cfg_critic)

    # L5 gate (spec 2.2): autonomy must be int 4 or 5 (absent -> 4). autonomy 5
    # (lights-off) is available only with a conforming hardened (or, being
    # strictly stronger, enterprise) backend.
    # M36a: intervention_mode (H1..H4) is the NEW, single knob. It is mutually
    # exclusive with the legacy (autonomy, checkpoint) pair -- specifying both
    # is a hard error (name the migration command; a machine can't know which
    # the operator meant). When only the legacy fields are present they map to
    # a mode via df_modes.legacy_mode, and cfg["_checkpoint"]/cfg["autonomy"]
    # keep being derived so every existing reader (the pause gate, the status
    # print) is byte-unchanged. Default when NOTHING is set: H2 (faithful to
    # today's autonomy 4 -> checkpoint pause).
    intervention_raw = raw.get("intervention_mode")
    autonomy_raw = raw.get("autonomy")
    checkpoint_raw = raw.get("checkpoint")
    if intervention_raw is not None:
        if autonomy_raw is not None or checkpoint_raw is not None:
            raise ConfigError(
                "intervention_mode cannot be combined with legacy autonomy/checkpoint "
                "(specify one scheme); migrate an old config with "
                "`supervisor.py df-migrate-config <control_root>`")
        try:
            intervention_mode = df_modes.canonical_mode(intervention_raw)
        except df_modes.ModeError as e:
            raise ConfigError(str(e))
        # Back-compat derivations so the rest of the codebase (which still reads
        # cfg["_checkpoint"] and cfg["autonomy"]) is unaffected by the new knob.
        autonomy, checkpoint = df_modes.legacy_fields_for(intervention_mode)
        intervention_source = "explicit"
    else:
        autonomy = 4 if autonomy_raw is None else autonomy_raw
        if not isinstance(autonomy, int) or isinstance(autonomy, bool) or autonomy not in (4, 5):
            raise ConfigError("autonomy must be an int, 4 or 5")
        if autonomy == 5 and tier not in ("hardened", "enterprise"):
            raise ConfigError(
                "autonomy 5 (lights-off) requires assurance: hardened or enterprise (spec 2.2)"
            )
        checkpoint = checkpoint_raw
        if checkpoint is None:
            checkpoint = "pause" if autonomy == 4 else "auto"
        elif checkpoint not in ("pause", "auto"):
            raise ConfigError("checkpoint must be 'pause' or 'auto'")
        try:
            intervention_mode = df_modes.legacy_mode(autonomy, checkpoint)
        except df_modes.ModeError as e:
            raise ConfigError(str(e))
        intervention_source = (
            "default" if (autonomy_raw is None and checkpoint_raw is None) else "legacy"
        )

    # H4 (lights-out) reuses legacy autonomy-5's tier gate: a run that never
    # pauses and fail-closes any human-needed condition is only safe on a
    # denial-by-construction backend. (The legacy path already enforced this
    # via the autonomy-5 check above; this catches an explicit H4 too.)
    if df_modes.requires_hardened(intervention_mode) and tier not in ("hardened", "enterprise"):
        raise ConfigError(
            "intervention_mode H4 (lights-out) requires assurance: hardened or enterprise")

    # hardened tier: optional `hardened` block -> cfg["_container"]. The block
    # is meaningless (and rejected) outside assurance: hardened|enterprise
    # (enterprise's container path IS the hardened container path, so the
    # SAME block configures image/network/memory/pids there too); injected
    # with defaults regardless of tier so downstream code can read
    # cfg["_container"] unconditionally (mirrors _security/_budget/_twins).
    hardened_raw = raw.get("hardened")
    if hardened_raw is not None and tier not in ("hardened", "enterprise"):
        raise ConfigError("hardened block requires assurance: hardened (or enterprise)")
    if hardened_raw is None:
        hardened_raw = {}
    if not isinstance(hardened_raw, dict):
        raise ConfigError("hardened must be a JSON object")

    c_image = hardened_raw.get("image", df_container.DEFAULT_IMAGE)
    if not isinstance(c_image, str) or not c_image or c_image.startswith("-"):
        # Leading "-" could be parsed as a docker flag; df_container.build_argv
        # rejects it too, but surfacing it lazily as a probe failure is a much
        # worse operator experience than a load-time ConfigError.
        raise ConfigError(
            "hardened.image must be a non-empty string not starting with '-'"
        )
    c_network = hardened_raw.get("network", "none")
    if c_network not in ("none", "bridge"):
        raise ConfigError("hardened.network must be 'none' or 'bridge'")
    c_memory = hardened_raw.get("memory", "2g")
    if not isinstance(c_memory, str) or not _MEMORY_RE.match(c_memory):
        raise ConfigError(
            "hardened.memory must match ^[0-9]+[bkmg]$ (lowercase, e.g. '2g', '512m')"
        )
    c_pids = hardened_raw.get("pids", 256)
    if not isinstance(c_pids, int) or isinstance(c_pids, bool) or c_pids < 16:
        raise ConfigError("hardened.pids must be an int >= 16")
    c_dep_cache_dir = hardened_raw.get("dep_cache_dir")
    if c_dep_cache_dir is not None:
        if not isinstance(c_dep_cache_dir, str) or not c_dep_cache_dir:
            raise ConfigError("hardened.dep_cache_dir must be a non-empty string")
        if not os.path.isdir(c_dep_cache_dir):
            raise ConfigError(
                f"hardened.dep_cache_dir does not exist or is not a directory: "
                f"{c_dep_cache_dir!r}"
            )
        c_dep_cache_dir = os.path.realpath(c_dep_cache_dir)

    kb_raw = raw.get("knowledge_base", {})
    if not isinstance(kb_raw, dict):
        raise ConfigError("knowledge_base must be an object")
    kb_kind = kb_raw.get("kind", "none")
    if kb_kind not in ("none", "wiki", "open-brain"):
        raise ConfigError(
            f"knowledge_base.kind must be none|wiki|open-brain, got {kb_kind!r}"
        )
    kb_write_back = kb_raw.get("write_back", False)
    if not isinstance(kb_write_back, bool):
        raise ConfigError("knowledge_base.write_back must be a bool")
    kb_path = kb_raw.get("path", "")
    if kb_kind == "wiki":
        if not kb_path or not os.path.isdir(kb_path):
            raise ConfigError(
                f"knowledge_base kind 'wiki' requires 'path' to be an existing directory: {kb_path!r}"
            )

    tw_raw = raw.get("twins", {})
    if not isinstance(tw_raw, dict):
        raise ConfigError("twins must be an object")
    tw_enabled = tw_raw.get("enabled", bool(tw_raw))  # present-but-no-enabled → True
    if not isinstance(tw_enabled, bool):
        raise ConfigError("twins.enabled must be a bool")
    tw_timeout = tw_raw.get("startup_timeout_s", 20)
    if not isinstance(tw_timeout, int) or isinstance(tw_timeout, bool) or not (1 <= tw_timeout <= 120):
        raise ConfigError("twins.startup_timeout_s must be an int in 1..120")
    if tw_enabled:
        tdir = os.path.join(control_root, "twins")
        if not os.path.isdir(tdir) or not [n for n in os.listdir(tdir) if n.endswith(".json")]:
            raise ConfigError("twins.enabled is true but no twins/*.json definitions found")

    # M27 Task 2 (spec §7.4): candidate_network -- the OPTIONAL candidate-ONLY
    # network-restriction mode. Config load never reads scenarios (that check
    # -- deny + an http scenario -- belongs to the supervisor's pre-build
    # gate, where scenarios are already loaded); this is a pure shape +
    # cross-field check, same posture as every other top-level field here.
    candidate_network = raw.get("candidate_network", "unrestricted")
    if candidate_network not in _CANDIDATE_NETWORK_MODES:
        # Membership on a tuple of strings already rejects a bool (True/False
        # never equal any of these strings) as well as any other type/value,
        # so no separate isinstance check is needed.
        raise ConfigError(
            f"candidate_network must be one of {_CANDIDATE_NETWORK_MODES!r}, "
            f"got {candidate_network!r}"
        )
    if candidate_network != "unrestricted" and tier not in ("standard", "hardened", "enterprise"):
        raise ConfigError(
            "candidate_network requires assurance: standard or above "
            "(cooperative has no sandbox to enforce it)"
        )
    if candidate_network == "deny" and tw_enabled:
        raise ConfigError(
            "candidate_network 'deny' would make configured twins unreachable; "
            "use 'loopback' (macOS) or remove twins"
        )

    # M29b (DF-02 host-read half): candidate_host_read -- whether the
    # CANDIDATE (the built artifact under test) runs under the default-deny
    # host-read profile. The default at standard+ is the REMEDIATION itself
    # ("default_deny"): existing configs get the stronger behavior
    # automatically. "allow_host_read" is the explicit, honest opt-out for
    # candidates that genuinely need host reads -- allowed, but the manifest
    # marks host_isolation unqualified for it. At cooperative there is no
    # candidate sandbox at all, so requesting "default_deny" there is a
    # cooperative rejection (same tier rule as candidate_network); an
    # explicit "allow_host_read" at cooperative merely states the tier's
    # reality and is accepted.
    candidate_host_read = raw.get("candidate_host_read")
    if candidate_host_read is None:
        candidate_host_read = ("default_deny"
                               if tier in ("standard", "hardened", "enterprise")
                               else "allow_host_read")
    elif candidate_host_read not in _CANDIDATE_HOST_READ_MODES:
        raise ConfigError(
            f"candidate_host_read must be one of {_CANDIDATE_HOST_READ_MODES!r}, "
            f"got {candidate_host_read!r}"
        )
    elif (candidate_host_read == "default_deny"
          and tier not in ("standard", "hardened", "enterprise")):
        raise ConfigError(
            "candidate_host_read 'default_deny' requires assurance: standard or "
            "above (cooperative has no sandbox to enforce it)"
        )

    audit_raw = raw.get("audit", {})
    if not isinstance(audit_raw, dict):
        raise ConfigError("audit must be a JSON object")
    # hardened|enterprise => signed audit (spec 7): default signing to True at
    # hardened or enterprise (absent means "on"); an explicit false is a hard
    # rejection, not a quiet downgrade — a hardened/enterprise run whose
    # manifest isn't signed is not hardened/enterprise.
    audit_signing = audit_raw.get("signing", tier in ("hardened", "enterprise"))
    if not isinstance(audit_signing, bool):
        raise ConfigError("audit.signing must be a bool")
    if tier in ("hardened", "enterprise") and not audit_signing:
        raise ConfigError(
            f"{tier} requires signed audit manifests (audit.signing: true)"
        )
    audit_key_path = audit_raw.get("key_path", "")
    if audit_signing:
        if not audit_key_path:
            audit_key_path = os.path.expanduser("~/.dark-factory/audit.key")
        key_dir = os.path.dirname(os.path.abspath(audit_key_path))
        if not _disjoint(key_dir, control_root) or not _disjoint(key_dir, ws):
            raise ConfigError(
                "audit.key_path must live outside both the control root and "
                "workspace_root (the signing key must never be reachable by a run)"
            )

    # Optional `audit.sink` block -> cfg["_audit"]["sink"] (M13): an
    # off-box append-only push target for each finalized chain entry.
    # Absent -> {"kind": "none", "required": False}, byte-identical to
    # today's behavior (no sink is ever pushed to).
    sink_raw = audit_raw.get("sink", {})
    if not isinstance(sink_raw, dict):
        raise ConfigError("audit.sink must be a JSON object")

    # Only env-var NAMES may travel through config.json -- a literal secret
    # value inline would sit in a control-root file read by every run,
    # get hashed into _config_sha256, and be trivially greppable. Reject
    # eagerly rather than accept-and-leak; push() resolves actual values
    # from os.environ at call time (df_audit_sink.py), never from config.
    for _forbidden in ("secret_key", "access_key"):
        if _forbidden in sink_raw:
            raise ConfigError(
                f"audit.sink.{_forbidden} is a raw secret value and is not "
                f"allowed inline; use audit.sink.{_forbidden}_env to name an "
                f"environment variable instead (must match "
                f"{_CRED_NAME_RE.pattern!r})"
            )

    sink_kind = sink_raw.get("kind", "none")
    if sink_kind not in ("none", "http-append", "s3-objectlock"):
        raise ConfigError(
            "audit.sink.kind must be none|http-append|s3-objectlock, "
            f"got {sink_kind!r}"
        )

    sink_required = sink_raw.get("required", False)
    if not isinstance(sink_required, bool):
        raise ConfigError("audit.sink.required must be a bool")

    cfg_sink = {"kind": sink_kind, "required": sink_required}

    if sink_kind == "http-append":
        sink_url = sink_raw.get("url")
        if not isinstance(sink_url, str) or not re.match(r"^https?://\S+$", sink_url):
            raise ConfigError(
                "audit.sink.url is required for kind 'http-append' and must "
                "be a http(s):// URL"
            )
        cfg_sink["url"] = sink_url
    elif sink_kind == "s3-objectlock":
        for _field in ("endpoint", "bucket", "region"):
            _val = sink_raw.get(_field)
            if not isinstance(_val, str) or not _val:
                raise ConfigError(
                    f"audit.sink.{_field} is required for kind 's3-objectlock'"
                )
            cfg_sink[_field] = _val

        sink_prefix = sink_raw.get("prefix", "")
        if not isinstance(sink_prefix, str):
            raise ConfigError("audit.sink.prefix must be a str")
        cfg_sink["prefix"] = sink_prefix

        for _env_field, _default in (
            ("access_key_env", "DF_AUDIT_S3_ACCESS_KEY"),
            ("secret_key_env", "DF_AUDIT_S3_SECRET_KEY"),
        ):
            _env_name = sink_raw.get(_env_field, _default)
            if not isinstance(_env_name, str) or not _CRED_NAME_RE.match(_env_name):
                raise ConfigError(
                    f"audit.sink.{_env_field} must be an environment variable "
                    f"NAME matching {_CRED_NAME_RE.pattern!r} (never a raw secret)"
                )
            cfg_sink[_env_field] = _env_name

    budget_raw = raw.get("budget", {})
    if not isinstance(budget_raw, dict):
        raise ConfigError("budget must be a JSON object")
    billing = budget_raw.get("billing", "subscription")
    if billing not in ("api", "subscription"):
        raise ConfigError("budget.billing must be 'api' or 'subscription'")

    def _positive_number(name):
        val = budget_raw.get(name)
        if val is None:
            return None
        if isinstance(val, bool) or not isinstance(val, (int, float)):
            raise ConfigError(f"budget.{name} must be a number > 0")
        if not val > 0:
            raise ConfigError(f"budget.{name} must be a number > 0")
        return float(val)

    max_usd = _positive_number("max_usd")
    per_call_usd = _positive_number("per_call_usd")

    max_calls = budget_raw.get("max_calls")
    if max_calls is not None:
        if isinstance(max_calls, bool) or not isinstance(max_calls, int) or max_calls < 1:
            raise ConfigError("budget.max_calls must be an int >= 1")

    alert_at = budget_raw.get("alert_at", 0.85)
    if isinstance(alert_at, bool) or not isinstance(alert_at, (int, float)) or not (0 < alert_at <= 1):
        raise ConfigError("budget.alert_at must be a number in (0, 1]")
    alert_at = float(alert_at)

    notification_sink = budget_raw.get("notification_sink", "")
    if not isinstance(notification_sink, str):
        raise ConfigError("budget.notification_sink must be a str")
    if notification_sink:
        _ns = urllib.parse.urlsplit(notification_sink)
        if _ns.scheme in ("http", "https"):
            pass
        elif _ns.scheme == "file":
            if _ns.netloc or not _ns.path or not os.path.isabs(_ns.path):
                raise ConfigError(
                    "budget.notification_sink file:// URLs must carry an "
                    "absolute path with no host component (file:///abs/path)"
                )
        else:
            raise ConfigError(
                "budget.notification_sink must be http://, https://, or "
                f"file://<abs path> (got {notification_sink!r})"
            )

    # M22 Task 2: opt-in AT-LEAST-ONCE notification delivery -- a local disk
    # spool + bounded retry, not a real message queue (see df_notify /
    # references/budget.md for the honest scope). Absent -> False/3, the
    # exact defaults that make the M18 best-effort path byte-identical.
    notification_durable = budget_raw.get("notification_durable", False)
    if not isinstance(notification_durable, bool):
        raise ConfigError("budget.notification_durable must be a bool")

    notification_attempts = budget_raw.get("notification_attempts", 3)
    if (isinstance(notification_attempts, bool)
            or not isinstance(notification_attempts, int)
            or notification_attempts < 1):
        raise ConfigError("budget.notification_attempts must be an int >= 1")

    # M25 Task 2: optional operator-supplied pricing, dollars per MILLION
    # tokens, keyed by "<model>" or "default". Purely additive/optional --
    # absent -> {} (no pricing, no actual_usd computed; see
    # references/budget.md). dark-factory never embeds or fetches prices
    # itself (prices change, fetching is network egress) -- the operator is
    # the sole source of truth here, same posture as credentials.
    token_pricing_raw = budget_raw.get("token_pricing")
    token_pricing = {}
    if token_pricing_raw is not None:
        if not isinstance(token_pricing_raw, dict):
            raise ConfigError("budget.token_pricing must be a JSON object")
        for _key, _entry in token_pricing_raw.items():
            if not isinstance(_entry, dict):
                raise ConfigError(
                    f"budget.token_pricing.{_key} must be a JSON object with "
                    "input_per_mtok/output_per_mtok"
                )
            _parsed = {}
            for _field in ("input_per_mtok", "output_per_mtok"):
                _val = _entry.get(_field)
                if isinstance(_val, bool) or not isinstance(_val, (int, float)) or _val < 0:
                    raise ConfigError(
                        f"budget.token_pricing.{_key}.{_field} must be a number >= 0"
                    )
                _parsed[_field] = float(_val)
            token_pricing[_key] = _parsed

    sg_raw = raw.get("security_gates", {})
    if not isinstance(sg_raw, dict):
        raise ConfigError("security_gates must be a JSON object")
    sg_enabled = sg_raw.get("enabled", False)
    if not isinstance(sg_enabled, bool):
        raise ConfigError("security_gates.enabled must be a bool")

    if sg_enabled:

        def _bool_default(key, default):
            val = sg_raw.get(key, default)
            if not isinstance(val, bool):
                raise ConfigError(f"security_gates.{key} must be a bool")
            return val

        sg_secret_scan = _bool_default("secret_scan", True)
        sg_dangerous_scan = _bool_default("dangerous_scan", True)
        sg_sbom = _bool_default("sbom", True)
        sg_strict_unavailable = _bool_default("strict_unavailable", True)

        # Optional `license` sub-block (M18 Task 2) -> cfg["_security"]
        # ["license"]. Unlike secret_scan/dangerous_scan/sbom (plain bool
        # flags), license carries its own allowlist + require_license, so
        # it is a nested object. Absent -> {"enabled": False, "allowlist":
        # [], "require_license": False}, byte-identical to pre-M18 (no
        # license gate runs; run_gates reads sec.get("license") defensively
        # for sec dicts built before this block existed at all).
        sg_license_raw = sg_raw.get("license", {})
        if not isinstance(sg_license_raw, dict):
            raise ConfigError("security_gates.license must be a JSON object")
        sg_license_enabled = sg_license_raw.get("enabled", False)
        if not isinstance(sg_license_enabled, bool):
            raise ConfigError("security_gates.license.enabled must be a bool")
        sg_license_allowlist_raw = sg_license_raw.get("allowlist", [])
        if not isinstance(sg_license_allowlist_raw, list) or not all(
            isinstance(x, str) and x.strip() for x in sg_license_allowlist_raw
        ):
            raise ConfigError(
                "security_gates.license.allowlist must be a list of non-empty strings"
            )
        sg_license_require = sg_license_raw.get("require_license", False)
        if not isinstance(sg_license_require, bool):
            raise ConfigError("security_gates.license.require_license must be a bool")
        cfg_license = {
            "enabled": sg_license_enabled,
            "allowlist": list(sg_license_allowlist_raw),
            "require_license": sg_license_require,
        }

        # Optional `dependency_audit` sub-block (M23 Task 2) -> cfg["_security"]
        # ["dependency_audit"]: an opt-in OSV CVE check over the artifact's
        # PINNED dependencies (df_depaudit.parse_installed + query_osv_api/
        # query_osv_snapshot). Absent block (or enabled: false) is
        # byte-identical to pre-M23 -- no dependency_audit gate ever runs,
        # zero network calls, ever.
        #
        # TIER POLICY (the point of M23): `source: "osv-api"` makes a LIVE
        # network call to api.osv.dev, egressing dependency names+versions
        # -- forbidden by ConfigError at hardened/enterprise, whose whole
        # guarantee is no/controlled egress. `source: "osv-snapshot"`
        # queries a pre-provisioned local snapshot with ZERO run-time
        # network egress -- allowed at every tier, including
        # hardened/enterprise. Net effect: every tier can get a CVE check,
        # and no tier's egress promise is broken.
        sg_depaudit_raw = sg_raw.get("dependency_audit", {})
        if not isinstance(sg_depaudit_raw, dict):
            raise ConfigError("security_gates.dependency_audit must be a JSON object")
        sg_depaudit_enabled = sg_depaudit_raw.get("enabled", False)
        if not isinstance(sg_depaudit_enabled, bool):
            raise ConfigError("security_gates.dependency_audit.enabled must be a bool")

        sg_depaudit_ecosystems_raw = sg_depaudit_raw.get("ecosystems", [])
        if not isinstance(sg_depaudit_ecosystems_raw, list) or not all(
            isinstance(x, str) and x.strip() for x in sg_depaudit_ecosystems_raw
        ):
            raise ConfigError(
                "security_gates.dependency_audit.ecosystems must be a list of "
                "non-empty strings"
            )

        sg_depaudit_timeout_s = sg_depaudit_raw.get("timeout_s", 20)
        if (
            not isinstance(sg_depaudit_timeout_s, int)
            or isinstance(sg_depaudit_timeout_s, bool)
            or not (1 <= sg_depaudit_timeout_s <= 300)
        ):
            raise ConfigError(
                "security_gates.dependency_audit.timeout_s must be an int in 1..300"
            )

        sg_depaudit_source = None
        sg_depaudit_snapshot_path = None
        if sg_depaudit_enabled:
            sg_depaudit_source = sg_depaudit_raw.get("source")
            if sg_depaudit_source not in ("osv-api", "osv-snapshot"):
                raise ConfigError(
                    "security_gates.dependency_audit.source is required when "
                    "enabled and must be 'osv-api' or 'osv-snapshot'"
                )
            if sg_depaudit_source == "osv-api" and tier in ("hardened", "enterprise"):
                raise ConfigError(
                    f"{tier} forbids uncontrolled network egress; use source: "
                    "osv-snapshot for security_gates.dependency_audit"
                )
            if sg_depaudit_source == "osv-snapshot":
                sg_depaudit_snapshot_path = sg_depaudit_raw.get("snapshot_path")
                if (
                    not isinstance(sg_depaudit_snapshot_path, str)
                    or not sg_depaudit_snapshot_path
                    or not os.path.isdir(sg_depaudit_snapshot_path)
                ):
                    raise ConfigError(
                        "security_gates.dependency_audit.snapshot_path must be "
                        "an existing directory when source is 'osv-snapshot'"
                    )

        cfg_depaudit = {
            "enabled": sg_depaudit_enabled,
            "source": sg_depaudit_source,
            "snapshot_path": sg_depaudit_snapshot_path,
            "ecosystems": list(sg_depaudit_ecosystems_raw),
            "timeout_s": sg_depaudit_timeout_s,
        }

        sg_external_raw = sg_raw.get("external", [])
        if not isinstance(sg_external_raw, list):
            raise ConfigError("security_gates.external must be a list")
        sg_external = []
        external_names = set()
        _reserved = {"secret_scan", "dangerous_scan", "sbom", "license", "dependency_audit"}
        for entry in sg_external_raw:
            if not isinstance(entry, dict):
                raise ConfigError("security_gates.external entries must be objects")
            name = entry.get("name")
            if not isinstance(name, str) or not name:
                raise ConfigError(
                    "security_gates.external entries require a non-empty 'name'"
                )
            if name in _reserved:
                raise ConfigError(
                    f"security_gates.external name {name!r} collides with a reserved "
                    f"built-in gate name (reserved: {sorted(_reserved)})"
                )
            if name in external_names:
                raise ConfigError(
                    f"security_gates.external has a duplicate gate name {name!r}"
                )
            cmd = entry.get("cmd")
            if (
                not isinstance(cmd, list)
                or not cmd
                or not all(isinstance(c, str) for c in cmd)
            ):
                raise ConfigError(
                    f"security_gates.external {name!r} 'cmd' must be a non-empty list of str"
                )
            sg_external.append({"name": name, "cmd": list(cmd)})
            external_names.add(name)

        sg_fail_on_raw = sg_raw.get("fail_on", ["secret_scan", "dangerous_scan"])
        if not isinstance(sg_fail_on_raw, list) or not all(
            isinstance(n, str) for n in sg_fail_on_raw
        ):
            raise ConfigError("security_gates.fail_on must be a list of str")
        known_gates = {
            "secret_scan", "dangerous_scan", "sbom", "license", "dependency_audit",
        } | external_names
        for name in sg_fail_on_raw:
            if name not in known_gates:
                raise ConfigError(
                    f"security_gates.fail_on references unknown gate {name!r} "
                    f"(known: {sorted(known_gates)})"
                )

        # M33a (DF-06): mandatory-gate forcing at standard+. The operator may
        # STRENGTHEN the policy (more gates, more fail_on entries, stricter
        # unavailable handling) but never weaken the immutable minimum. An
        # EXPLICIT attempt to disable a mandatory gate is a loud ConfigError
        # (not a silent override) so the operator learns the policy rather
        # than believing a disabled gate took effect.
        sg_fail_on = list(sg_fail_on_raw)
        if tier in MANDATORY_TIERS:
            for gate in MANDATORY_GATES:
                if sg_raw.get(gate) is False:
                    raise ConfigError(
                        f"{tier} may strengthen security gates, never disable "
                        f"{gate} (mandatory at {'/'.join(MANDATORY_TIERS)})"
                    )
            sg_secret_scan = True
            sg_dangerous_scan = True
            # Force each mandatory gate INTO fail_on (union, dedup, sorted for
            # a deterministic sealed policy) and force strict_unavailable: a
            # mandatory gate that cannot run must FAIL the run, never pass by
            # omission.
            sg_fail_on = sorted(set(sg_fail_on) | set(MANDATORY_GATES))
            sg_strict_unavailable = True

        cfg_security = {
            "enabled": True,
            "secret_scan": sg_secret_scan,
            "dangerous_scan": sg_dangerous_scan,
            "sbom": sg_sbom,
            "external": sg_external,
            "fail_on": sg_fail_on,
            "strict_unavailable": sg_strict_unavailable,
            "license": cfg_license,
            "dependency_audit": cfg_depaudit,
        }
    elif tier in MANDATORY_TIERS:
        # No security_gates block (or enabled:false) at a mandatory tier:
        # SYNTHESIZE the mandatory minimum rather than leave gates off. This is
        # the intended M33a behavior change — a standard/hardened/enterprise
        # run with no gate config still gets secret_scan + dangerous_scan,
        # enabled, in fail_on, strict_unavailable. Omission is NOT an error;
        # only an EXPLICIT enabled:true + mandatory-gate:false is (handled
        # above). The sub-blocks mirror the enabled-branch disabled defaults
        # byte-for-byte so run_gates reads them uniformly.
        cfg_security = {
            "enabled": True,
            "secret_scan": True,
            "dangerous_scan": True,
            "sbom": False,
            "external": [],
            "fail_on": list(MANDATORY_GATES),
            "strict_unavailable": True,
            "license": {"enabled": False, "allowlist": [], "require_license": False},
            "dependency_audit": {
                "enabled": False,
                "source": None,
                "snapshot_path": None,
                "ecosystems": [],
                "timeout_s": 20,
            },
        }
    else:
        cfg_security = {"enabled": False}

    # M33a (DF-06): the OPTIONAL waiver policy — TIER-INDEPENDENT (a standard
    # run may carry one), validated even when the gate flags above were
    # synthesized, and ALWAYS present on cfg["_security"] so downstream code
    # reads it unconditionally. Absent -> {"signers": [], "threshold": 0}: the
    # fail-closed default, since threshold 0 is NEVER satisfiable in
    # df_waiver.verify_waiver_set (a run with no waiver policy can never be
    # waived). `signers` are ed25519 PUBLIC keys as raw-32-byte hex (64 chars),
    # lowercased + deduped, validated with the SAME stdlib _HEX64_RE shape
    # check `custody.approvers` uses — this module stays stdlib-only and never
    # imports `cryptography`; df_custody.verify_one rejects a malformed/
    # off-curve key at verify time, exactly as for custody approvers.
    sg_waivers_raw = sg_raw.get("waivers", {})
    if not isinstance(sg_waivers_raw, dict):
        raise ConfigError("security_gates.waivers must be a JSON object")
    w_signers_raw = sg_waivers_raw.get("signers", [])
    if not isinstance(w_signers_raw, list):
        raise ConfigError(
            "security_gates.waivers.signers must be a list of 64-hex-char "
            "ed25519 public keys"
        )
    w_signers = []
    w_seen = set()
    for entry in w_signers_raw:
        if not isinstance(entry, str) or not _HEX64_RE.match(entry):
            raise ConfigError(
                "security_gates.waivers.signers entries must be 64-hex-char "
                f"ed25519 public keys: {entry!r}"
            )
        canonical = entry.lower()
        if canonical in w_seen:
            raise ConfigError(
                "security_gates.waivers.signers has a duplicate entry "
                f"(signers must be unique): {entry!r}"
            )
        w_seen.add(canonical)
        w_signers.append(canonical)
    w_threshold = sg_waivers_raw.get("threshold", 0)
    if w_signers:
        if (
            not isinstance(w_threshold, int)
            or isinstance(w_threshold, bool)
            or not (1 <= w_threshold <= len(w_signers))
        ):
            raise ConfigError(
                "security_gates.waivers.threshold must be an int in 1.."
                f"{len(w_signers)} (the number of signers)"
            )
    else:
        # No signers => no waivers acceptable. A truthy threshold with no
        # signers is a broken policy — reject it loudly rather than silently
        # pin to 0; the absent/0 default is fine.
        if w_threshold:
            raise ConfigError(
                "security_gates.waivers.threshold requires a non-empty signers list"
            )
        w_threshold = 0
    cfg_security["waivers"] = {"signers": w_signers, "threshold": w_threshold}

    # M33a (DF-06) SECURITY: a NON-EMPTY waiver policy REQUIRES a SIGNED audit
    # manifest. The signer allowlist + threshold that govern a run are sealed
    # into `security.waiver_policy`, but that seal is only tamper-PROOF when the
    # manifest is HMAC-signed. With `audit.signing` off (its default at
    # cooperative/standard), an attacker with control-root write could append
    # their OWN pubkey to the sealed allowlist, recompute `manifest.sha256`,
    # self-sign a waiver, and get WAIVED_QUALIFIED — defeating "sealed so no
    # post-run edit can widen who may waive." (Split-custody sidesteps this by
    # being enterprise-only, where signing is always on; waivers are offered at
    # standard, where it is not.) So: require signing whenever signers are
    # configured, MIRRORING the hardened/enterprise audit.signing rule above —
    # an EXPLICIT `false` is a hard rejection, an absent/defaulted-false is
    # forced ON (with the same key_path defaulting + disjointness guard the
    # audit block applies), so the strong sealing claim holds by construction.
    if w_signers:
        if audit_raw.get("signing") is False:
            raise ConfigError(
                "security_gates.waivers requires audit.signing: true so the sealed "
                "waiver allowlist is HMAC-protected — an unsigned manifest's "
                "waiver_policy can be widened by anyone with control-root write"
            )
        if not audit_signing:
            audit_signing = True
            if not audit_key_path:
                audit_key_path = os.path.expanduser("~/.dark-factory/audit.key")
            key_dir = os.path.dirname(os.path.abspath(audit_key_path))
            if not _disjoint(key_dir, control_root) or not _disjoint(key_dir, ws):
                raise ConfigError(
                    "audit.key_path must live outside both the control root and "
                    "workspace_root (the signing key must never be reachable by a run)"
                )

    # M36b (Part A): optional `resume_overrides` block -> cfg["_resume_overrides"].
    # The allowlist + threshold that govern a SIGNED resume budget-ceiling
    # override (df_override). Shape mirrors `security_gates.waivers` exactly:
    # `approvers` are ed25519 PUBLIC keys as 64-hex (lowercased + deduped, same
    # stdlib _HEX64_RE shape check — this module never imports `cryptography`),
    # `threshold` an int in 1..len(approvers). ABSENT -> {"approvers": [],
    # "threshold": 0}, the fail-closed default: threshold 0 is NEVER satisfiable
    # in df_override.verify_override, so no override is accepted unless a policy
    # is explicitly configured. Tier-independent (overrides are a governance
    # feature, not a tier gate).
    ro_raw = raw.get("resume_overrides", {})
    if not isinstance(ro_raw, dict):
        raise ConfigError("resume_overrides must be a JSON object")
    ro_approvers_raw = ro_raw.get("approvers", [])
    if not isinstance(ro_approvers_raw, list):
        raise ConfigError(
            "resume_overrides.approvers must be a list of 64-hex-char ed25519 public keys")
    ro_approvers = []
    ro_seen = set()
    for entry in ro_approvers_raw:
        if not isinstance(entry, str) or not _HEX64_RE.match(entry):
            raise ConfigError(
                "resume_overrides.approvers entries must be 64-hex-char ed25519 "
                f"public keys: {entry!r}")
        canonical = entry.lower()
        if canonical in ro_seen:
            raise ConfigError(
                "resume_overrides.approvers has a duplicate entry "
                f"(approvers must be unique): {entry!r}")
        ro_seen.add(canonical)
        ro_approvers.append(canonical)
    ro_threshold = ro_raw.get("threshold", 0)
    if ro_approvers:
        if (not isinstance(ro_threshold, int) or isinstance(ro_threshold, bool)
                or not (1 <= ro_threshold <= len(ro_approvers))):
            raise ConfigError(
                "resume_overrides.threshold must be an int in 1.."
                f"{len(ro_approvers)} (the number of approvers)")
    else:
        # No approvers => no override acceptable. A truthy threshold with no
        # approvers is a broken policy — reject it loudly rather than pin to 0.
        if ro_threshold:
            raise ConfigError(
                "resume_overrides.threshold requires a non-empty approvers list")
        ro_threshold = 0
    cfg_resume_overrides = {"approvers": ro_approvers, "threshold": ro_threshold}

    # M36b SECURITY (mirrors the M33a waiver rule above): a NON-EMPTY resume-
    # override policy REQUIRES a SIGNED audit manifest. The approver allowlist
    # governing who may raise a spend cap lives in config.json, and every
    # terminal manifest seals `config_sha256`; that seal is only tamper-PROOF
    # when the manifest is HMAC-signed. With `audit.signing` off (its default at
    # cooperative/standard), an actor with control-root write could append their
    # OWN pubkey to `resume_overrides.approvers`, self-sign, and lift the cap
    # undetectably. So: require signing whenever approvers are configured — an
    # EXPLICIT `false` is a hard rejection; an absent/defaulted-false is forced
    # ON (with the same key_path defaulting + disjointness guard the audit block
    # applies) so the sealing claim holds by construction.
    if ro_approvers:
        if audit_raw.get("signing") is False:
            raise ConfigError(
                "resume_overrides requires audit.signing: true so the sealed config "
                "(hence the approver allowlist) is HMAC-protected — an unsigned "
                "manifest's config_sha256 can be forged by anyone with control-root write")
        if not audit_signing:
            audit_signing = True
            if not audit_key_path:
                audit_key_path = os.path.expanduser("~/.dark-factory/audit.key")
            key_dir = os.path.dirname(os.path.abspath(audit_key_path))
            if not _disjoint(key_dir, control_root) or not _disjoint(key_dir, ws):
                raise ConfigError(
                    "audit.key_path must live outside both the control root and "
                    "workspace_root (the signing key must never be reachable by a run)")

    # M41: optional `ship` block -> cfg["_ship"]: the governed post-seal action
    # runner (references/ship.md). Absent -> None, and the workflow ends at the
    # sealed artifact EXACTLY as today (byte-identical). Each action is plain
    # operator argv (git/kubectl/deploy scripts) — this module validates SHAPE
    # only; df_ship executes them, gated by qualification (invariant #1),
    # ordering, the signature gate (df_release), brokered creds, audit, and
    # rollback. SECURITY posture mirrors the M33a waiver / M36b resume-override
    # rules exactly: an irreversible action forces a SIGNED release approval
    # policy AND assurance: hardened|enterprise AND audit.signing.
    ship_raw = raw.get("ship")
    if ship_raw is not None:
        if not isinstance(ship_raw, dict):
            raise ConfigError("ship must be a JSON object")

        actions_raw = ship_raw.get("actions")
        if not isinstance(actions_raw, list) or not actions_raw:
            raise ConfigError("ship.actions must be a non-empty list")

        cfg_ship_actions = []
        seen_action_names = set()
        any_irreversible = False
        for action in actions_raw:
            if not isinstance(action, dict):
                raise ConfigError(f"ship.actions entries must be objects: {action!r}")

            a_name = action.get("name")
            if not isinstance(a_name, str) or not _SHIP_NAME_RE.match(a_name):
                raise ConfigError(
                    f"ship.actions[].name must match {_SHIP_NAME_RE.pattern!r}: {a_name!r}")
            if a_name in seen_action_names:
                raise ConfigError(
                    f"ship.actions has a duplicate name (names must be unique): {a_name!r}")
            seen_action_names.add(a_name)

            a_run = action.get("run")
            if (not isinstance(a_run, list) or not a_run
                    or not all(isinstance(x, str) for x in a_run)):
                raise ConfigError(
                    f"ship.actions[{a_name!r}].run must be a non-empty list of strings")

            # `reversible` is REQUIRED and must be a real bool — no default, so
            # nothing is ever ACCIDENTALLY treated as reversible (an operator
            # must consciously declare an action's blast radius). `bool` is an
            # `int` subclass, so isinstance(x, bool) accepts True/False only.
            a_reversible = action.get("reversible")
            if not isinstance(a_reversible, bool):
                raise ConfigError(
                    f"ship.actions[{a_name!r}].reversible is REQUIRED and must be a bool "
                    "(true|false) — declare an action's reversibility explicitly; there is "
                    "no default so nothing is silently treated as reversible")

            a_rollback = action.get("rollback")
            if a_rollback is not None:
                if (not isinstance(a_rollback, list) or not a_rollback
                        or not all(isinstance(x, str) for x in a_rollback)):
                    raise ConfigError(
                        f"ship.actions[{a_name!r}].rollback must be a non-empty list of strings "
                        "when present")

            # creds: env-var NAMES only (resolved host-side by df_creds at action
            # time), NEVER an inline value — same posture as credential_proxy
            # .token_env and credentials.allowlist. A key that looks like it
            # carries a literal secret is refused loudly.
            a_creds_env = []
            a_creds = action.get("creds")
            if a_creds is not None:
                if not isinstance(a_creds, dict):
                    raise ConfigError(f"ship.actions[{a_name!r}].creds must be a JSON object")
                for banned in ("value", "values", "token", "secret", "password"):
                    if banned in a_creds:
                        raise ConfigError(
                            f"ship.actions[{a_name!r}].creds.{banned} is a raw secret value and "
                            "is not allowed inline; list env-var NAMES in creds.env instead "
                            f"(each matching {_CRED_NAME_RE.pattern!r}), resolved host-side")
                env_raw = a_creds.get("env")
                if env_raw is not None:
                    if (not isinstance(env_raw, list) or not env_raw
                            or not all(isinstance(x, str) for x in env_raw)):
                        raise ConfigError(
                            f"ship.actions[{a_name!r}].creds.env must be a non-empty list of "
                            "env-var name strings")
                    seen_env = set()
                    for env_name in env_raw:
                        if not _CRED_NAME_RE.match(env_name):
                            raise ConfigError(
                                f"ship.actions[{a_name!r}].creds.env entries must be env-var "
                                f"NAMES matching {_CRED_NAME_RE.pattern!r} (a literal secret is "
                                f"refused): {env_name!r}")
                        if env_name in seen_env:
                            raise ConfigError(
                                f"ship.actions[{a_name!r}].creds.env has a duplicate: {env_name!r}")
                        seen_env.add(env_name)
                        a_creds_env.append(env_name)

            a_timeout = action.get("timeout_s")
            if (not isinstance(a_timeout, int) or isinstance(a_timeout, bool)
                    or not (1 <= a_timeout <= 3600)):
                raise ConfigError(
                    f"ship.actions[{a_name!r}].timeout_s must be an int in 1..3600")

            # Optional cwd, RELATIVE to the materialized ship workspace and
            # path-safe: no absolute path, no `..` traversal, no `~`. df_ship
            # re-checks containment before use (belt-and-suspenders).
            a_cwd = action.get("cwd")
            if a_cwd is not None:
                if not isinstance(a_cwd, str) or not a_cwd:
                    raise ConfigError(
                        f"ship.actions[{a_name!r}].cwd must be a non-empty relative path string")
                if (os.path.isabs(a_cwd) or a_cwd.startswith("~")
                        or ".." in a_cwd.replace("\\", "/").split("/")):
                    raise ConfigError(
                        f"ship.actions[{a_name!r}].cwd must be a RELATIVE, path-safe subpath of "
                        f"the ship workspace (no absolute path, no '..', no '~'): {a_cwd!r}")

            if not a_reversible:
                any_irreversible = True
            cfg_ship_actions.append({
                "name": a_name,
                "run": list(a_run),
                "reversible": a_reversible,
                "rollback": list(a_rollback) if a_rollback is not None else None,
                "creds": {"env": a_creds_env},
                "timeout_s": a_timeout,
                "cwd": a_cwd,
            })

        # ship.approval — the K-of-N release-approval policy that gates every
        # irreversible action (df_release). Shape mirrors `custody` /
        # `resume_overrides` exactly (64-hex ed25519 pubkeys, unique, threshold
        # 1..len). Absent -> empty (threshold 0), the fail-closed default:
        # threshold 0 is NEVER satisfiable in df_release.verify_release, so no
        # approval is ever accepted unless a policy is explicitly configured.
        approval_raw = ship_raw.get("approval")
        ship_approvers = []
        ship_threshold = 0
        if approval_raw is not None:
            if not isinstance(approval_raw, dict):
                raise ConfigError("ship.approval must be a JSON object")
            approvers_raw = approval_raw.get("approvers", [])
            if not isinstance(approvers_raw, list):
                raise ConfigError(
                    "ship.approval.approvers must be a list of 64-hex-char ed25519 public keys")
            ship_seen = set()
            for entry in approvers_raw:
                if not isinstance(entry, str) or not _HEX64_RE.match(entry):
                    raise ConfigError(
                        "ship.approval.approvers entries must be 64-hex-char ed25519 public "
                        f"keys: {entry!r}")
                canonical = entry.lower()
                if canonical in ship_seen:
                    raise ConfigError(
                        "ship.approval.approvers has a duplicate entry (approvers must be "
                        f"unique): {entry!r}")
                ship_seen.add(canonical)
                ship_approvers.append(canonical)
            ship_threshold = approval_raw.get("threshold", 0)
            if ship_approvers:
                if (not isinstance(ship_threshold, int) or isinstance(ship_threshold, bool)
                        or not (1 <= ship_threshold <= len(ship_approvers))):
                    raise ConfigError(
                        "ship.approval.threshold must be an int in 1.."
                        f"{len(ship_approvers)} (the number of approvers)")
            else:
                if ship_threshold:
                    raise ConfigError(
                        "ship.approval.threshold requires a non-empty approvers list")
                ship_threshold = 0

        # An irreversible action with NO one able to approve it is an
        # unshippable dead end — refuse at load, never at ship time. And an
        # irreversible prod push off an unqualified-isolation tier is refused:
        # a reversible:false action requires assurance: hardened|enterprise.
        if any_irreversible:
            if not ship_approvers or ship_threshold < 1:
                raise ConfigError(
                    "a ship action with reversible:false requires a ship.approval policy with "
                    "threshold>=1 and approver public keys (you cannot have an irreversible "
                    "action that no one is able to sign off on)")
            if tier not in ("hardened", "enterprise"):
                raise ConfigError(
                    "a ship action with reversible:false requires assurance: hardened or "
                    "enterprise (an irreversible prod action off an unqualified-isolation tier "
                    "is refused)")

        # SECURITY (mirrors M33a waivers / M36b resume-overrides): a NON-EMPTY
        # release-approval policy REQUIRES a SIGNED audit manifest. The approver
        # allowlist + threshold that decide who may authorize an irreversible
        # ship live in config.json, and every terminal manifest seals
        # config_sha256; that seal is only tamper-PROOF when the manifest is
        # HMAC-signed. Without signing, an actor with control-root write could
        # append their OWN pubkey to ship.approval.approvers, self-sign a
        # release, and ship an irreversible prod action. So: force signing
        # whenever approvers are configured — an EXPLICIT false is rejected, an
        # absent/defaulted-false is forced ON (same key_path defaulting +
        # disjointness guard as the audit/waiver blocks).
        if ship_approvers:
            if audit_raw.get("signing") is False:
                raise ConfigError(
                    "ship.approval requires audit.signing: true so the sealed config (hence the "
                    "release-approver allowlist) is HMAC-protected — an unsigned manifest's "
                    "config_sha256 can be forged by anyone with control-root write")
            if not audit_signing:
                audit_signing = True
                if not audit_key_path:
                    audit_key_path = os.path.expanduser("~/.dark-factory/audit.key")
                key_dir = os.path.dirname(os.path.abspath(audit_key_path))
                if not _disjoint(key_dir, control_root) or not _disjoint(key_dir, ws):
                    raise ConfigError(
                        "audit.key_path must live outside both the control root and "
                        "workspace_root (the signing key must never be reachable by a run)")

        cfg_ship = {
            "actions": cfg_ship_actions,
            "approval": {"approvers": ship_approvers, "threshold": ship_threshold},
        }
    else:
        cfg_ship = None

    # Optional `credentials` block -> cfg["_credentials"] (M11): a brokered
    # allowlist of provider credentials the builder is permitted to receive.
    # Absent -> None (exactly today's behavior at every tier). Validated here
    # (control-plane, load time); df_creds.load_credentials resolves the
    # actual values at run start, never at config-load time (config load must
    # never touch a keychain or read a secret file).
    creds_raw = raw.get("credentials")
    if creds_raw is not None:
        if not isinstance(creds_raw, dict):
            raise ConfigError("credentials must be a JSON object")

        cred_source = creds_raw.get("source")
        if cred_source not in ("env-file", "keychain", "env"):
            raise ConfigError(
                f"credentials.source must be env-file|keychain|env, got {cred_source!r}"
            )

        cred_allowlist = creds_raw.get("allowlist")
        if not isinstance(cred_allowlist, list) or not cred_allowlist:
            raise ConfigError("credentials.allowlist must be a non-empty list")
        seen_names = set()
        for name in cred_allowlist:
            if not isinstance(name, str) or not _CRED_NAME_RE.match(name):
                raise ConfigError(
                    "credentials.allowlist entries must match ^[A-Z][A-Z0-9_]*$, "
                    f"got {name!r}"
                )
            if name in seen_names:
                raise ConfigError(
                    f"credentials.allowlist has a duplicate entry {name!r}"
                )
            seen_names.add(name)

        cred_env_file = None
        if cred_source == "env-file":
            cred_env_file = creds_raw.get("env_file")
            if not isinstance(cred_env_file, str) or not cred_env_file:
                raise ConfigError(
                    "credentials.env_file is required when source is 'env-file'"
                )
            cred_env_file = os.path.expanduser(cred_env_file)
            if not os.path.isabs(cred_env_file):
                raise ConfigError(
                    "credentials.env_file must be an absolute path (after expanduser)"
                )
            if not _disjoint(cred_env_file, control_root):
                raise ConfigError(
                    "credentials.env_file must be disjoint from the control root "
                    "(it would be readable by a run that is supposed to be barrier-safe)"
                )
            if not _disjoint(cred_env_file, ws):
                raise ConfigError(
                    "credentials.env_file must be disjoint from workspace_root"
                )
        elif "env_file" in creds_raw:
            raise ConfigError("credentials.env_file is only valid when source is 'env-file'")

        if cred_source != "keychain" and "service_prefix" in creds_raw:
            raise ConfigError(
                "credentials.service_prefix is only valid when source is 'keychain'"
            )
        cred_service_prefix = creds_raw.get("service_prefix", "dark-factory/")
        if not isinstance(cred_service_prefix, str) or not cred_service_prefix:
            raise ConfigError("credentials.service_prefix must be a non-empty str")

        cfg_credentials = {
            "source": cred_source,
            "env_file": cred_env_file,
            "service_prefix": cred_service_prefix,
            "allowlist": list(cred_allowlist),
        }
    else:
        cfg_credentials = None

    # Optional `brownfield` block -> cfg["_brownfield"] (M15): mode + the
    # human-curated probe set the supervisor characterizes BEFORE the
    # builder touches anything. Absent -> {"mode": "auto", "probes": []},
    # byte-identical to today's greenfield-only behavior (df_brownfield
    # .detect_mode("auto", None, None) == "greenfield").
    bf_raw = raw.get("brownfield", {})
    if not isinstance(bf_raw, dict):
        raise ConfigError("brownfield must be a JSON object")

    bf_mode = bf_raw.get("mode", "auto")
    if bf_mode not in ("auto", "greenfield", "brownfield"):
        raise ConfigError(
            f"brownfield.mode must be one of 'auto', 'greenfield', 'brownfield', got {bf_mode!r}"
        )

    # Per-probe shape validation below is intentionally kept in lockstep with
    # df_brownfield._validate_probes (slug id regex, unique id, non-empty
    # list[str] `run`, int timeout_s 1..120) — the two MUST stay in sync. We do
    # NOT delegate to _validate_probes here because it also requires a NON-EMPTY
    # probe list, whereas an empty `probes` is the valid config-time default for
    # mode auto/greenfield (only mode: "brownfield" requires >=1, enforced
    # separately below); it also raises BrownfieldError, not ConfigError.
    bf_probes_raw = bf_raw.get("probes", [])
    if not isinstance(bf_probes_raw, list):
        raise ConfigError("brownfield.probes must be a list")

    bf_probes = []
    seen_probe_ids = set()
    for probe in bf_probes_raw:
        if not isinstance(probe, dict):
            raise ConfigError(f"brownfield.probes entries must be objects: {probe!r}")

        pid = probe.get("id")
        if not isinstance(pid, str) or not _PROBE_ID_RE.match(pid):
            raise ConfigError(
                f"brownfield.probes id must match {_PROBE_ID_RE.pattern!r}: {pid!r}"
            )
        if pid in seen_probe_ids:
            raise ConfigError(f"brownfield.probes has a duplicate id: {pid}")
        seen_probe_ids.add(pid)

        run = probe.get("run")
        if not isinstance(run, list) or not run or not all(isinstance(x, str) for x in run):
            raise ConfigError(f"brownfield.probes {pid!r}: run must be a non-empty list of strings")

        timeout_s = probe.get("timeout_s")
        if (
            not isinstance(timeout_s, int)
            or isinstance(timeout_s, bool)
            or not (1 <= timeout_s <= 120)
        ):
            raise ConfigError(f"brownfield.probes {pid!r}: timeout_s must be an int in 1..120")

        bf_probes.append({"id": pid, "run": list(run), "timeout_s": timeout_s})

    # Brownfield with nothing to characterize is a no-op that would falsely
    # claim regression coverage; greenfield with probes configured is
    # contradictory (the human is both overriding detection AND asking for
    # characterization) -- both are load-time refusals, not silent no-ops.
    if bf_mode == "brownfield" and not bf_probes:
        raise ConfigError(
            "brownfield.mode 'brownfield' requires >=1 probe (nothing to characterize)"
        )
    if bf_mode == "greenfield" and bf_probes:
        raise ConfigError(
            "brownfield.probes is not allowed when brownfield.mode is 'greenfield' "
            "(contradictory: greenfield explicitly skips characterization)"
        )

    cfg_brownfield = {"mode": bf_mode, "probes": bf_probes}

    # Optional `builder_confinement` block -> cfg["_confine"] (M14): confines
    # the BUILDER subprocess (the agentic CLI dark-factory spawns to write
    # the workspace) to an explicit tool allowlist -- no MCP servers, no
    # sub-agents, no web tools. Absent -> {"enabled": False, "required":
    # False, "profile": "standard"}, byte-identical to today's behavior
    # (confine=False on every builder invoke_adapter call; adapters unaware
    # this block ever existed).
    bc_raw = raw.get("builder_confinement", {})
    if not isinstance(bc_raw, dict):
        raise ConfigError("builder_confinement must be a JSON object")

    bc_enabled = bc_raw.get("enabled", False)
    if not isinstance(bc_enabled, bool):
        raise ConfigError("builder_confinement.enabled must be a bool")

    # `required` defaults to `enabled`: turning confinement ON defaults to
    # REQUIRING it (fail-closed by default) -- an operator opts INTO the
    # softer "warn and fall back unconfined" behavior explicitly, rather
    # than opting out of a safety net by omission.
    bc_required = bc_raw.get("required", bc_enabled)
    if not isinstance(bc_required, bool):
        raise ConfigError("builder_confinement.required must be a bool")

    # RA-04 coherence (ANY tier): `required: true` with `enabled: false` is
    # a contradiction -- you cannot REQUIRE a mechanism you have turned OFF.
    # Because `required` defaults to `enabled` (above), this only bites an
    # EXPLICIT {enabled:false, required:true}, exactly the audited case: an
    # enterprise (or any) config that CLAIMS mandatory confinement while the
    # runtime path (confine=enabled) is disabled, so the builder runs
    # unconfined despite the "required" flag. Refuse at LOAD, fail-closed,
    # before the enterprise gate below even runs.
    if bc_required and not bc_enabled:
        raise ConfigError(
            "builder_confinement.required: true is incoherent with "
            "enabled: false — you cannot require confinement that is "
            "disabled; set enabled: true (or drop required)"
        )

    bc_profile = bc_raw.get("profile", "standard")
    if bc_profile != "standard":
        raise ConfigError(
            f"builder_confinement.profile must be 'standard' (the only "
            f"supported profile), got {bc_profile!r}"
        )

    cfg_confine = {"enabled": bc_enabled, "required": bc_required, "profile": bc_profile}

    # Optional `custody` block -> cfg["_custody"] (M17 Task 1): the K-of-N
    # split-custody approver allowlist + threshold. Absent -> None (byte-
    # identical to pre-M17 behavior at every tier). Only the BLOCK SHAPE is
    # validated here -- approvers are ed25519 public keys as raw-32-byte hex
    # (64 hex chars), unique; threshold an int in 1..len(approvers). This
    # module never imports `cryptography` (df_custody.py is the sole,
    # guarded import site) and never checks whether a hex string is a valid
    # *curve point* -- verify_custody rejects a bad key at verify time,
    # returning False rather than crashing. Enforcing custody as REQUIRED at
    # assurance: "enterprise" is Task 3 (the enterprise tier doesn't exist
    # in supported_tiers.json until then); here an absent block at ANY tier,
    # including a future enterprise, is still None.
    custody_raw = raw.get("custody")
    if custody_raw is not None:
        if not isinstance(custody_raw, dict):
            raise ConfigError("custody must be a JSON object")

        custody_approvers = custody_raw.get("approvers")
        if not isinstance(custody_approvers, list) or not custody_approvers:
            raise ConfigError("custody.approvers must be a non-empty list")
        seen_approvers = set()
        canonical_approvers = []
        for entry in custody_approvers:
            if not isinstance(entry, str) or not _HEX64_RE.match(entry):
                raise ConfigError(
                    "custody.approvers entries must be 64-hex-char ed25519 "
                    f"public keys, got {entry!r}"
                )
            # Canonicalize to lowercase BEFORE the uniqueness check: two
            # entries that differ only in hex case are the SAME public key,
            # so they must collide as a duplicate here — never silently kept
            # as two "distinct" approvers that verify_custody would then also
            # canonicalize into one, quietly shrinking N below what the
            # operator configured.
            canonical = entry.lower()
            if canonical in seen_approvers:
                raise ConfigError(
                    f"custody.approvers has a duplicate entry (approvers must be unique): {entry!r}"
                )
            seen_approvers.add(canonical)
            canonical_approvers.append(canonical)

        custody_threshold = custody_raw.get("threshold")
        if (
            not isinstance(custody_threshold, int)
            or isinstance(custody_threshold, bool)
            or not (1 <= custody_threshold <= len(custody_approvers))
        ):
            raise ConfigError(
                "custody.threshold must be an int in 1.."
                f"{len(custody_approvers)} (the number of approvers)"
            )

        cfg_custody = {
            "approvers": canonical_approvers,
            "threshold": custody_threshold,
        }
    else:
        cfg_custody = None

    # Optional `credential_proxy` block -> cfg["_proxy"] (M17 Task 2): a
    # host-side allowlist credential proxy (see scripts/df_proxy.py). The
    # provider token is NEVER accepted inline here -- only the NAME of an
    # env var the proxy reads host-side at request time, mirroring the
    # M11/M13 inline-secret rejection (credentials.*, audit.sink.*). Absent
    # -> {"enabled": False}, byte-identical to pre-M17 behavior at every
    # tier (the enterprise tier's REQUIRED credential_proxy.enabled:true
    # gate is Task 3 -- this module validates only the block's shape).
    proxy_raw = raw.get("credential_proxy", {})
    if not isinstance(proxy_raw, dict):
        raise ConfigError("credential_proxy must be a JSON object")

    if "token" in proxy_raw:
        raise ConfigError(
            "credential_proxy.token is a raw secret value and is not "
            "allowed inline; use credential_proxy.token_env to name an "
            f"environment variable instead (must match {_CRED_NAME_RE.pattern!r})"
        )

    proxy_header = proxy_raw.get("header", "authorization")
    if proxy_header not in ("authorization", "x-api-key"):
        raise ConfigError(
            "credential_proxy.header must be 'authorization' or "
            f"'x-api-key', got {proxy_header!r}"
        )

    proxy_enabled = proxy_raw.get("enabled", False)
    if not isinstance(proxy_enabled, bool):
        raise ConfigError("credential_proxy.enabled must be a bool")

    if proxy_enabled:
        proxy_allowlist = proxy_raw.get("allowlist")
        if not isinstance(proxy_allowlist, list) or not proxy_allowlist:
            raise ConfigError(
                "credential_proxy.allowlist must be a non-empty list of "
                "hostnames when credential_proxy.enabled is true"
            )
        for entry in proxy_allowlist:
            if not isinstance(entry, str) or not entry:
                raise ConfigError(
                    "credential_proxy.allowlist entries must be non-empty "
                    f"hostname strings, got {entry!r}"
                )

        proxy_token_env = proxy_raw.get("token_env")
        if not isinstance(proxy_token_env, str) or not _CRED_NAME_RE.match(proxy_token_env):
            raise ConfigError(
                "credential_proxy.token_env must be an environment "
                f"variable NAME matching {_CRED_NAME_RE.pattern!r}, got "
                f"{proxy_token_env!r}"
            )

        cfg_proxy = {
            "enabled": True,
            "allowlist": list(proxy_allowlist),
            "token_env": proxy_token_env,
            "header": proxy_header,
        }

        # M30 (DF-03) Part C: adapter <-> provider host <-> allowlist <->
        # injection header coherence -- only meaningful when the configured
        # builder is one of the two API adapters (a CLI adapter never reads
        # DF_PROXY_DESCRIPTOR, so credential_proxy's shape is irrelevant to
        # it). `adapter` was already read above (roles.builder.adapter);
        # basename inference doesn't require it to be an absolute/existing
        # path, so this fires at every tier, not only hardened/enterprise.
        cp_provider = _adapter_provider(adapter)
        if cp_provider is not None:
            rules = _PROXY_PROVIDER_RULES[cp_provider]
            if proxy_header != rules["header"]:
                raise ConfigError(
                    f"credential_proxy.header is {proxy_header!r}, but "
                    f"roles.builder.adapter ({adapter!r}) is the {cp_provider} "
                    f"API adapter, which expects the {rules['header']!r} header "
                    "-- a mismatched header means df_proxy would inject the "
                    "credential under a header this adapter/provider never "
                    "looks at"
                )
            allow_hosts = {_allowlist_entry_host(h) for h in proxy_allowlist}
            if rules["host"] not in allow_hosts:
                raise ConfigError(
                    f"credential_proxy.allowlist does not include "
                    f"{rules['host']!r}, required for roles.builder.adapter "
                    f"({adapter!r}), the {cp_provider} API adapter -- a proxy "
                    "that never allowlists the provider it's meant to reach "
                    "would refuse every real request"
                )
    else:
        cfg_proxy = {"enabled": False}

    # Enterprise composition (M17 Task 3): assurance:"enterprise" REQUIRES
    # every enterprise-only guarantee to be explicitly present and
    # unweakened — split custody (Task 1), the credential proxy actually
    # ENABLED (Task 2), a REQUIRED off-box audit sink (M13), REQUIRED
    # builder confinement (M14), and signed audit (already defaulted+
    # enforced above via the `tier in ("hardened", "enterprise")` checks,
    # re-asserted here so every enterprise-required guarantee is named in
    # ONE place). Any missing/weakened piece is a ConfigError NAMING the
    # missing guarantee — fail-closed at LOAD time, before any run starts.
    # cfg["_enterprise"] carries only the seccomp profile PATH (never a
    # secret) for the supervisor to pass to df_container.build_enterprise_argv.
    if tier == "enterprise":
        if cfg_custody is None:
            raise ConfigError(
                "enterprise requires a `custody` block (split-custody K-of-N "
                "sign-off; spec 2.2/7.3) — none was configured"
            )
        if not cfg_proxy["enabled"]:
            raise ConfigError(
                "enterprise requires `credential_proxy.enabled: true` (the "
                "host-side allowlist credential proxy; spec 7.3) — the raw "
                "provider token must never enter the sandbox"
            )
        if not sink_required:
            raise ConfigError(
                "enterprise requires `audit.sink.required: true` (a REQUIRED "
                "off-box audit sink; spec 7.5) — sink.kind='none' or "
                "sink.required=false is a weakened enterprise config"
            )
        if not bc_required:
            raise ConfigError(
                "enterprise requires `builder_confinement.required: true` "
                "(spec 7.4) — confinement.enabled without required, or "
                "confinement absent, is a weakened enterprise config"
            )
        # RA-04 belt-and-suspenders: `required: true` alone is not enough —
        # the RUNTIME confine flag is `enabled`, and confine=enabled is what
        # actually sandboxes the builder. The coherence check above already
        # forbids required-without-enabled, so this is redundant TODAY, but
        # it names `enabled` explicitly at the enterprise gate so a future
        # refactor of the default/coherence logic cannot silently let an
        # enterprise run through with confinement OFF.
        if not bc_enabled:
            raise ConfigError(
                "enterprise requires `builder_confinement.enabled: true` "
                "(spec 7.4) — confinement that is 'required' but not "
                "'enabled' does not actually confine the builder at runtime"
            )
        if not audit_signing:
            raise ConfigError(
                "enterprise requires signed audit manifests (audit.signing: true)"
            )
        # Token-collision guard (M17 Task 3 review): the whole point of the
        # credential proxy is that the raw provider token NEVER enters the
        # sandbox — the proxy injects it host-side. If the operator ALSO lists
        # the proxy's token_env in `credentials.allowlist` (M11), df_creds
        # would resolve that env var and bake its VALUE into the enterprise
        # container as a `-e` var, silently putting the token right back into
        # the sandbox and defeating the guarantee. Refuse at load. (Belt-and-
        # suspenders: the supervisor also passes NO credential env into the
        # enterprise container at all — the proxy is the sole credential
        # path — but a config that even expresses this contradiction is
        # fail-closed here rather than quietly ignored.)
        if cfg_credentials is not None:
            proxy_token_env_name = cfg_proxy["token_env"]
            if proxy_token_env_name in cfg_credentials["allowlist"]:
                raise ConfigError(
                    f"enterprise: credential_proxy.token_env ({proxy_token_env_name!r}) must "
                    "NOT also appear in credentials.allowlist — that would bake the provider "
                    "token into the container as a -e var, defeating the proxy's "
                    "token-never-in-sandbox guarantee"
                )
        # M22 Task 1: enterprise.seccomp_profile is an OPTIONAL operator
        # knob -- absent means the shipped M17 default (byte-identical
        # behavior to before this task). When given, it must be a real,
        # parseable, well-shaped Docker seccomp profile (see
        # _validate_seccomp_profile) or ConfigError at LOAD time, before any
        # run starts. This is a SHAPE check only; the supervisor's
        # enterprise resolve additionally LIVE-PROBES the resolved path
        # (df_container.probe_seccomp) to prove it actually denies what it
        # claims to -- a parseable-but-toothless profile is caught there,
        # fail-closed, not here.
        enterprise_raw = raw.get("enterprise", {})
        if not isinstance(enterprise_raw, dict):
            raise ConfigError("enterprise must be a JSON object")
        seccomp_profile_raw = enterprise_raw.get("seccomp_profile")
        if seccomp_profile_raw is None:
            seccomp_path = df_container.DEFAULT_SECCOMP_PATH
        else:
            if not isinstance(seccomp_profile_raw, str) or not seccomp_profile_raw:
                raise ConfigError(
                    "enterprise.seccomp_profile must be a non-empty path string"
                )
            seccomp_path = os.path.abspath(seccomp_profile_raw)
        _validate_seccomp_profile(seccomp_path)
        cfg_enterprise = {"seccomp": seccomp_path}
    else:
        cfg_enterprise = None

    cfg = dict(raw)
    cfg["_qualified"] = bool(tiers[tier]["qualified"])
    cfg["_config_sha256"] = sha256_str(canonical_json(raw))
    cfg["_checkpoint"] = checkpoint
    # M36a: resolved intervention mode + how we got it (explicit /
    # legacy-mapped / default) for the run-start MODE journal event.
    cfg["_intervention_mode"] = intervention_mode
    cfg["_intervention_source"] = intervention_source
    # Keep the legacy fields present on cfg so readers (status print, any
    # `cfg['autonomy']`) work even for an intervention_mode-only config that
    # never wrote autonomy/checkpoint to disk.
    cfg["autonomy"] = autonomy
    cfg["checkpoint"] = checkpoint
    cfg["_kb"] = {"kind": kb_kind, "path": kb_path, "write_back": kb_write_back}
    cfg["_twins"] = {"enabled": tw_enabled, "startup_timeout_s": tw_timeout}
    cfg["candidate_network"] = candidate_network
    cfg["candidate_host_read"] = candidate_host_read
    cfg["_audit"] = {
        "signing": audit_signing,
        "key_path": audit_key_path if audit_signing else "",
        "sink": cfg_sink,
    }
    cfg["_security"] = cfg_security
    cfg["_container"] = {
        "image": c_image, "network": c_network, "memory": c_memory, "pids": c_pids,
        "dep_cache_dir": c_dep_cache_dir,
    }
    cfg["_budget"] = {
        "billing": billing,
        "max_usd": max_usd,
        "per_call_usd": per_call_usd,
        "max_calls": max_calls,
        "alert_at": alert_at,
        "notification_sink": notification_sink,
        "notification_durable": notification_durable,
        "notification_attempts": notification_attempts,
        "token_pricing": token_pricing,
    }
    cfg["_credentials"] = cfg_credentials
    cfg["_resume_overrides"] = cfg_resume_overrides
    cfg["_brownfield"] = cfg_brownfield
    cfg["_confine"] = cfg_confine
    cfg["_custody"] = cfg_custody
    cfg["_proxy"] = cfg_proxy
    cfg["_enterprise"] = cfg_enterprise
    # M41: the governed ship-action runner policy (or None). df_ship executes
    # it after a run qualifies; the supervisor wires the phase + df_release
    # gate. Absent -> None -> workflow ends at the sealed artifact (byte-identical).
    cfg["_ship"] = cfg_ship
    # M40: resolved author role (or None) -- the supervisor's `author-scenarios`
    # subcommand reads it, and `_run_locked` seals it into the manifest's
    # `authored_by` field so an audit shows the scenarios were agent-written and
    # by which independent model.
    cfg["_author"] = cfg_author
    # M42: the decorrelated critic role (or None) + the resolved scenario-
    # adequacy policy. author-scenarios reads _critic + _adequacy["critic"] to
    # drive the review loop; the M7 pre-build gate reads _adequacy's
    # required_classes/min_per_class for BOTH human- and agent-authored roots.
    cfg["_critic"] = cfg_critic
    cfg["_adequacy"] = cfg_adequacy
    # M47 condition #7: expected adapter content digests (or None) per role. The
    # supervisor computes each configured adapter file's real sha256 at run start
    # and REFUSES (exit 2, journal ADAPTER_DIGEST_MISMATCH) on mismatch, so an
    # operator pins the exact bytes rather than trusting a path. All None (the
    # default) -> no pin -> byte-identical to pre-M47.
    cfg["_adapter_digests"] = {
        "builder": builder_expected_sha256,
        "author": cfg_author["expected_sha256"] if cfg_author else None,
        "critic": cfg_critic["expected_sha256"] if cfg_critic else None,
    }
    return cfg
