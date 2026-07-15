"""Config loading + validation for dark-factory. Stdlib only."""
import json
import os

from df_common import canonical_json, sha256_str

SCRIPTS_DIR = os.path.dirname(os.path.abspath(__file__))
TAXONOMY = ("wrong_exit_code", "wrong_output", "timeout", "crash")


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

    checkpoint = raw.get("checkpoint")
    if checkpoint is None:
        checkpoint = "pause" if raw.get("autonomy") == 4 else "auto"
    elif checkpoint not in ("pause", "auto"):
        raise ConfigError("checkpoint must be 'pause' or 'auto'")

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
    audit_signing = audit_raw.get("signing", False)
    if not isinstance(audit_signing, bool):
        raise ConfigError("audit.signing must be a bool")
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

    cfg = dict(raw)
    cfg["_qualified"] = bool(tiers[tier]["qualified"])
    cfg["_config_sha256"] = sha256_str(canonical_json(raw))
    cfg["_checkpoint"] = checkpoint
    cfg["_kb"] = {"kind": kb_kind, "path": kb_path, "write_back": kb_write_back}
    cfg["_twins"] = {"enabled": tw_enabled, "startup_timeout_s": tw_timeout}
    cfg["_audit"] = {"signing": audit_signing, "key_path": audit_key_path if audit_signing else ""}
    cfg["_budget"] = {
        "billing": billing,
        "max_usd": max_usd,
        "per_call_usd": per_call_usd,
        "max_calls": max_calls,
        "alert_at": alert_at,
        "notification_sink": notification_sink,
    }
    return cfg
