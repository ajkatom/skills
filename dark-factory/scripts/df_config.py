"""Config loading + validation for dark-factory. Stdlib only."""
import json
import os
import re
import urllib.parse

import df_container
import df_proxy
from df_common import canonical_json, sha256_str

SCRIPTS_DIR = os.path.dirname(os.path.abspath(__file__))
TAXONOMY = ("wrong_exit_code", "wrong_output", "timeout", "crash")
# M27 Task 2 (spec §7.4): candidate-network authority modes. Mirrors
# df_sandbox._NETWORK_MODES exactly -- kept as its own constant here (rather
# than importing df_sandbox) because config validation must never depend on
# platform-specific sandbox backends being importable/available.
_CANDIDATE_NETWORK_MODES = ("unrestricted", "deny", "loopback")
_MEMORY_RE = re.compile(r"^[0-9]+[bkmg]$")
_CRED_NAME_RE = re.compile(r"^[A-Z][A-Z0-9_]*$")
_PROBE_ID_RE = re.compile(r"^[a-z0-9-]{1,32}$")
_HEX64_RE = re.compile(r"^[0-9a-fA-F]{64}$")


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

    # L5 gate (spec 2.2): autonomy must be int 4 or 5 (absent -> 4). autonomy 5
    # (lights-off) is available only with a conforming hardened (or, being
    # strictly stronger, enterprise) backend.
    autonomy = raw.get("autonomy", 4)
    if not isinstance(autonomy, int) or isinstance(autonomy, bool) or autonomy not in (4, 5):
        raise ConfigError("autonomy must be an int, 4 or 5")
    if autonomy == 5 and tier not in ("hardened", "enterprise"):
        raise ConfigError(
            "autonomy 5 (lights-off) requires assurance: hardened or enterprise (spec 2.2)"
        )

    checkpoint = raw.get("checkpoint")
    if checkpoint is None:
        checkpoint = "pause" if autonomy == 4 else "auto"
    elif checkpoint not in ("pause", "auto"):
        raise ConfigError("checkpoint must be 'pause' or 'auto'")

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

        cfg_security = {
            "enabled": True,
            "secret_scan": sg_secret_scan,
            "dangerous_scan": sg_dangerous_scan,
            "sbom": sg_sbom,
            "external": sg_external,
            "fail_on": list(sg_fail_on_raw),
            "strict_unavailable": sg_strict_unavailable,
            "license": cfg_license,
            "dependency_audit": cfg_depaudit,
        }
    else:
        cfg_security = {"enabled": False}

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
    cfg["_kb"] = {"kind": kb_kind, "path": kb_path, "write_back": kb_write_back}
    cfg["_twins"] = {"enabled": tw_enabled, "startup_timeout_s": tw_timeout}
    cfg["candidate_network"] = candidate_network
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
    cfg["_brownfield"] = cfg_brownfield
    cfg["_confine"] = cfg_confine
    cfg["_custody"] = cfg_custody
    cfg["_proxy"] = cfg_proxy
    cfg["_enterprise"] = cfg_enterprise
    return cfg
