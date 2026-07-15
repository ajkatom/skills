"""Config loading + validation for dark-factory. Stdlib only."""
import json
import os
import re

import df_container
from df_common import canonical_json, sha256_str

SCRIPTS_DIR = os.path.dirname(os.path.abspath(__file__))
TAXONOMY = ("wrong_exit_code", "wrong_output", "timeout", "crash")
_MEMORY_RE = re.compile(r"^[0-9]+[bkmg]$")


class ConfigError(ValueError):
    pass


def load_supported_tiers() -> dict:
    with open(os.path.join(SCRIPTS_DIR, "supported_tiers.json"), encoding="utf-8") as f:
        return json.load(f)


def _disjoint(a: str, b: str) -> bool:
    a = os.path.realpath(a)
    b = os.path.realpath(b)
    return not (a == b or a.startswith(b + os.sep) or b.startswith(a + os.sep))


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
    if tier == "hardened":
        # The adapter's DIRECTORY is bind-mounted ro into the builder container,
        # so it must be pinned down at config time: a bare command name (e.g.
        # "claude") would realpath against the process CWD (mounting whatever
        # directory the operator happens to run from), and an adapter inside
        # the control root would mount holdout content into the "isolated"
        # builder. Both are mount-escape paths — reject at load.
        adapter_path = os.path.expanduser(adapter)
        if not os.path.isabs(adapter_path) or not os.path.isfile(adapter_path):
            raise ConfigError(
                "hardened requires roles.builder.adapter to be an absolute path "
                "to an existing file (its directory is mounted into the container)"
            )
        adapter_dir = os.path.dirname(os.path.realpath(adapter_path))
        if not _disjoint(adapter_dir, control_root):
            raise ConfigError(
                "hardened requires the roles.builder.adapter directory to be "
                "disjoint from the control root (it would be mounted into the "
                "builder container)"
            )

    # L5 gate (spec 2.2): autonomy must be int 4 or 5 (absent -> 4). autonomy 5
    # (lights-off) is available only with a conforming hardened backend.
    autonomy = raw.get("autonomy", 4)
    if not isinstance(autonomy, int) or isinstance(autonomy, bool) or autonomy not in (4, 5):
        raise ConfigError("autonomy must be an int, 4 or 5")
    if autonomy == 5 and tier != "hardened":
        raise ConfigError(
            "autonomy 5 (lights-off) requires assurance: hardened (spec 2.2)"
        )

    checkpoint = raw.get("checkpoint")
    if checkpoint is None:
        checkpoint = "pause" if autonomy == 4 else "auto"
    elif checkpoint not in ("pause", "auto"):
        raise ConfigError("checkpoint must be 'pause' or 'auto'")

    # hardened tier: optional `hardened` block -> cfg["_container"]. The block
    # is meaningless (and rejected) outside assurance: hardened; injected with
    # defaults regardless of tier so downstream code can read cfg["_container"]
    # unconditionally (mirrors _security/_budget/_twins).
    hardened_raw = raw.get("hardened")
    if hardened_raw is not None and tier != "hardened":
        raise ConfigError("hardened block requires assurance: hardened")
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

    audit_raw = raw.get("audit", {})
    if not isinstance(audit_raw, dict):
        raise ConfigError("audit must be a JSON object")
    # hardened => signed audit (spec 7): default signing to True at hardened
    # (absent means "on"); an explicit false is a hard rejection, not a quiet
    # downgrade — a hardened run whose manifest isn't signed is not hardened.
    audit_signing = audit_raw.get("signing", tier == "hardened")
    if not isinstance(audit_signing, bool):
        raise ConfigError("audit.signing must be a bool")
    if tier == "hardened" and not audit_signing:
        raise ConfigError(
            "hardened requires signed audit manifests (audit.signing: true)"
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

        sg_external_raw = sg_raw.get("external", [])
        if not isinstance(sg_external_raw, list):
            raise ConfigError("security_gates.external must be a list")
        sg_external = []
        external_names = set()
        _reserved = {"secret_scan", "dangerous_scan", "sbom"}
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
        known_gates = {"secret_scan", "dangerous_scan", "sbom"} | external_names
        for name in sg_fail_on_raw:
            if name not in known_gates:
                raise ConfigError(
                    f"security_gates.fail_on references unknown gate {name!r} "
                    f"(known: {sorted(known_gates)})"
                )

        cfg_security = {
            "enabled": True,
            "secret_scan": sg_secret_scan,
            "dangerous_scan": sg_dangerous_scan,
            "sbom": sg_sbom,
            "external": sg_external,
            "fail_on": list(sg_fail_on_raw),
            "strict_unavailable": sg_strict_unavailable,
        }
    else:
        cfg_security = {"enabled": False}

    cfg = dict(raw)
    cfg["_qualified"] = bool(tiers[tier]["qualified"])
    cfg["_config_sha256"] = sha256_str(canonical_json(raw))
    cfg["_checkpoint"] = checkpoint
    cfg["_kb"] = {"kind": kb_kind, "path": kb_path, "write_back": kb_write_back}
    cfg["_twins"] = {"enabled": tw_enabled, "startup_timeout_s": tw_timeout}
    cfg["_audit"] = {"signing": audit_signing, "key_path": audit_key_path if audit_signing else ""}
    cfg["_security"] = cfg_security
    cfg["_container"] = {
        "image": c_image, "network": c_network, "memory": c_memory, "pids": c_pids,
    }
    cfg["_budget"] = {
        "billing": billing,
        "max_usd": max_usd,
        "per_call_usd": per_call_usd,
        "max_calls": max_calls,
        "alert_at": alert_at,
        "notification_sink": notification_sink,
    }
    return cfg
