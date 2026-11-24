import yaml
import sys
import copy
from pathlib import Path

RISK_DEFS_PATH = Path(__file__).resolve().parent.parent / "libraries" / "09-custom-risks-lib.yml"

# Threagile's severity enum, low to high (see `threagile -explain-types`).
SEVERITY_ORDER = ["low", "medium", "elevated", "high", "critical"]

# Threagile's likelihood and impact enums, low to high. Every custom finding gets its own
# Likelihood, Impact, and Severity for the asset it lands on (see compute_likelihood(),
# compute_impact(), and compute_severity()).
LIKELIHOOD_ORDER = ["unlikely", "possible", "likely", "very-likely"]
IMPACT_ORDER = ["low", "medium", "high", "very-high"]

# Model-level mission criticality: four values, separate from the five-value integrity and
# availability scale. It gates the incident-response readiness checks and changes no score.
# mission_criticality is the key, while business_criticality, its older name, is still read,
# and its five values map onto the four.
MISSION_CRITICALITY_VALUES = ("administrative", "mission-support", "mission-essential", "mission-critical")
LEGACY_MISSION_CRITICALITY = {
    "archive": "administrative", "operational": "administrative", "important": "mission-support",
    "critical": "mission-essential", "mission-critical": "mission-critical",
}
# The incident-response readiness checks apply to systems the mission cannot do without.
MISSION_ESSENTIAL_OR_ABOVE = {"mission-essential", "mission-critical"}


def is_internet_side_caller(asset: dict) -> bool:
    """An asset on the internet side of the system: internet-facing, and either an external
    entity or out of scope. Mirrors the fork's unguarded-access-from-internet gate, where an
    in-scope internet-facing component (an application gateway, a firewall) calling inward is the
    guarded path rather than internet access."""
    return bool(asset.get('internet')) and (
        bool(asset.get('out_of_scope')) or str(asset.get('type', '')).strip() == 'external-entity')


def mission_criticality(model: dict) -> str:
    """The model's mission criticality on the four-value scale ('' when unset or unknown)."""
    value = str(model.get('mission_criticality') or model.get('business_criticality') or '').strip().lower()
    if value in MISSION_CRITICALITY_VALUES:
        return value
    return LEGACY_MISSION_CRITICALITY.get(value, '')

# Ordinal rank (0-4, low to high) for Threagile's Confidentiality enum
# (public/internal/restricted/confidential/strictly-confidential) and its
# Integrity/Availability enum (archive/operational/important/critical/
# mission-critical) -- differently worded, same 5-level low-to-high shape
# (00-threagile-field-reference.yml), so one table keyed by value string
# covers all three fields on a technical asset.
CIA_RANK = {
    "public": 0, "internal": 1, "restricted": 2, "confidential": 3, "strictly-confidential": 4,
    "archive": 0, "operational": 1, "important": 2, "critical": 3, "mission-critical": 4,
}

# CIA rank (0-4) to the Impact step: the bottom two tiers step down, the middle tier leaves the
# baseline alone, and the top two step up. The step is one level, since the baseline is meant
# to carry most of the signal.
CIA_RANK_TO_DELTA = {0: -1, 1: -1, 2: 0, 3: 1, 4: 1}

# The CIA dimension each STRIDE category threatens, so that a denial-of-service finding steps on
# Availability alone. Elevation of privilege, and anything unmapped, uses the highest of the
# three. Spoofing maps to Integrity, since a spoofing finding breaks the authentication
# decision itself (see docs/risk-methodology.md, "Impact", for this choice and its accepted
# exception for infrastructure impersonation).
STRIDE_TO_CIA_DIMENSION = {
    "information-disclosure": "confidentiality",
    "spoofing": "integrity",
    "tampering": "integrity",
    "repudiation": "integrity",
    "denial-of-service": "availability",
}

# Technology sets for the checks that read the native technology field rather than a tag.
# Canonical names only: Threagile resolves a technology by exact key, so an alias never
# reaches this script.
RAG_PIPELINE_TECHNOLOGIES = {"ai-rag-pipeline"}
AGENT_ORCHESTRATOR_TECHNOLOGIES = {"ai-agent-orchestrator"}
MULTI_AGENT_GATEWAY_TECHNOLOGIES = {"ai-multi-agent-gateway"}
DATASET_STORE_TECHNOLOGIES = {"ai-dataset-store"}
# Search engines and indexes: the asset a search-index finding belongs to.
SEARCH_TECHNOLOGIES = {"search-engine", "search-index"}
# Network edge devices, preferred as the holder of findings about a whole self-managed network.
NETWORK_EDGE_TECHNOLOGIES = {"gateway", "load-balancer", "reverse-proxy", "waf", "network-encryptor", "ids", "ips"}
# Assets whose content reaches an agent's model as context: retrieved documents, tool results,
# other agents' messages. A link to one of these is what makes an agent an indirect-injection target.
CONTENT_SOURCE_TECHNOLOGIES = {"ai-vector-store", "ai-rag-pipeline", "ai-feature-store",
                               "ai-tool-server", "ai-multi-agent-gateway"}
# Technologies the fork marks frontend_related (pkg/types/technologies.yaml): web front ends,
# proxies, gateways and client devices. Used to decide whether a caller brings outside requests in.
FRONTEND_TECHNOLOGIES = {
    "air-vehicle", "browser", "client-system", "cms", "desktop", "devops-client", "gateway",
    "iot-device", "load-balancer", "mobile-app", "reverse-proxy", "waf", "web-application",
}


def asset_technologies(asset_data: dict) -> set:
    """Every technology an asset declares: the single `technology` field and the fork's
    `technologies` list."""
    technologies = set()
    if asset_data.get("technology"):
        technologies.add(str(asset_data["technology"]).strip())
    for technology in asset_data.get("technologies") or []:
        technologies.add(str(technology).strip())
    return technologies

# Severity is the product of Fibonacci-spaced weights for Likelihood and Impact, bucketed by
# threshold: 1 Low, 2-3 Medium, 4-6 Elevated, 9-15 High, and 25 Critical. This matches the fork's
# CalculateSeverity() (pkg/types/model.go), and docs/risk-methodology.md, "Severity", gives the
# reasons for the weights and their validation.
WEIGHT = [1, 2, 3, 5]

SEVERITY_THRESHOLDS = [
    (1, "low"),
    (3, "medium"),
    (6, "elevated"),
    (15, "high"),
]  # anything above the last threshold is "critical"


def _asset_cia_ranks(asset_data: dict) -> tuple:
    """(confidentiality_rank, integrity_rank, availability_rank), each 0-4
    per CIA_RANK, for one technical asset."""
    return (
        CIA_RANK.get(str(asset_data.get("confidentiality", "")).strip(), 0),
        CIA_RANK.get(str(asset_data.get("integrity", "")).strip(), 0),
        CIA_RANK.get(str(asset_data.get("availability", "")).strip(), 0),
    )


def _clamp(idx: int) -> int:
    return max(0, min(idx, 3))


# Threagile's RAA (Relative Attacker Attractiveness) formula, replicated from the fork's
# pkg/model/raa.go. Threagile computes RAA only after its own analysis, which is too late for
# this script, so the formula runs here independently on the same model data.
CONF_ASSET = [8, 13, 21, 34, 55]
CONF_PROCESSED_OR_STORED = [5, 8, 13, 21, 34]
CONF_TRANSFERRED = [2, 3, 5, 8, 13]
CRIT_ASSET = [5, 8, 13, 21, 34]
CRIT_PROCESSED_OR_STORED = [3, 5, 8, 13, 21]
CRIT_TRANSFERRED = [2, 3, 5, 8, 13]
QTY_FACTOR = {"very-few": 1, "few": 2, "many": 3, "very-many": 5}

# RAA's technology multiplier: a reverse proxy or load balancer is a conduit and scales down,
# while an identity provider, vault, or container platform scales up regardless of its rating.
RAA_TECHNOLOGY_MULTIPLIER = {
    "reverse-proxy": 1 / 5.5, "load-balancer": 1 / 5.5,
    "monitoring": 1 / 5,
    "container-platform": 5,
    "vault": 2,
    "build-pipeline": 2, "sourcecode-repository": 2, "artifact-registry": 2,
    "identity-provider": 2.5, "identity-store-ldap": 2.5, "identity-store-database": 2.5,
    "database": 2,
}

# RAA at or above this raises Likelihood one level. It matches the fork's
# RAALikelihoodThreshold (pkg/types/risk_scoring.go). RAA is normalized within each model, so
# the threshold is relative to the model (see docs/risk-methodology.md, "Relative Attacker
# Attractiveness (RAA)").
RAA_LIKELIHOOD_THRESHOLD = 40.0

# RAA below this lowers Likelihood one level. It sits well below the upper threshold, so only a
# clearly low-value asset steps down. It matches the fork's RAALikelihoodLowThreshold.
RAA_LIKELIHOOD_LOW_THRESHOLD = 15.0


def _raa_data_asset_ranks(data_asset: dict) -> tuple:
    return (
        CIA_RANK.get(str(data_asset.get("confidentiality", "")).strip(), 0),
        CIA_RANK.get(str(data_asset.get("integrity", "")).strip(), 0),
        CIA_RANK.get(str(data_asset.get("availability", "")).strip(), 0),
    )


def _raa_raw_attractiveness(asset_data: dict, data_assets_by_id: dict) -> float:
    """An asset's raw attractiveness: its own CIA weights plus a weight for every data asset it
    processes, stores, or transfers (Confidentiality and Integrity scaled by quantity, while
    Availability is not, as in Threagile), scaled by its technology and multi-tenancy."""
    c, i, a = _asset_cia_ranks(asset_data)
    score = CONF_ASSET[c] + CRIT_ASSET[i] + CRIT_ASSET[a]

    for field in ("data_assets_processed", "data_assets_stored"):
        for da_id in (asset_data.get(field) or []):
            da = data_assets_by_id.get(da_id)
            if not da:
                continue
            dc, di, da_a = _raa_data_asset_ranks(da)
            qf = QTY_FACTOR.get(str(da.get("quantity", "")).strip(), 1)
            score += CONF_PROCESSED_OR_STORED[dc] * qf + CRIT_PROCESSED_OR_STORED[di] * qf + CRIT_PROCESSED_OR_STORED[da_a]

    for link in (asset_data.get("communication_links") or {}).values():
        for field in ("data_assets_sent", "data_assets_received"):
            for da_id in (link.get(field) or []):
                da = data_assets_by_id.get(da_id)
                if not da:
                    continue
                dc, di, da_a = _raa_data_asset_ranks(da)
                qf = QTY_FACTOR.get(str(da.get("quantity", "")).strip(), 1)
                score += CONF_TRANSFERRED[dc] * qf + CRIT_TRANSFERRED[di] * qf + CRIT_TRANSFERRED[da_a]

    technology = str(asset_data.get("technology", "")).strip()
    if technology in RAA_TECHNOLOGY_MULTIPLIER:
        score *= RAA_TECHNOLOGY_MULTIPLIER[technology]
    elif asset_data.get("type") == "datastore":
        score *= 2

    if asset_data.get("multi_tenant"):
        score *= 1.5

    return score


def _raa_normalize(raw_by_id: dict) -> dict:
    """Each raw score as a percent of the range across this model, floored at 1%, since 0%
    would suggest that an asset cannot be attacked at all."""
    if not raw_by_id:
        return {}
    values = list(raw_by_id.values())
    lo, hi = min(values), max(values)
    spread = (hi - lo) or 1
    return {aid: max((v - lo) / spread * 100, 1) for aid, v in raw_by_id.items()}


def compute_raa_by_id(model: dict) -> dict:
    """{technical_asset_id: RAA percent}, as Threagile computes it: raw attractiveness, normalized
    once, then a pivoting pass that adds up to a third of the gap to the most attractive asset
    each one can reach, then normalized again."""
    tech_assets = model.get("technical_assets", {})
    data_assets_by_id = {da["id"]: da for da in (model.get("data_assets") or {}).values() if da.get("id")}
    id_to_asset = {a["id"]: a for a in tech_assets.values() if a.get("id")}

    raw = {aid: _raa_raw_attractiveness(a, data_assets_by_id) for aid, a in id_to_asset.items()}
    relative = _raa_normalize(raw)

    adjusted_raw = {}
    for aid, asset_data in id_to_asset.items():
        adjustment = 0.0
        for link in (asset_data.get("communication_links") or {}).values():
            target_id = link.get("target")
            if target_id not in relative:
                continue
            delta = relative[target_id] - relative[aid]
            if delta > 0:
                adjustment = max(adjustment, delta / 3)
        adjusted_raw[aid] = raw[aid] + adjustment

    return _raa_normalize(adjusted_raw)


def compute_likelihood(definition: dict, asset_raa: float, internet_reachable: bool, adjust: int = 0) -> str:
    """The category's baseline_likelihood, plus an RAA step (+1 at or above
    RAA_LIKELIHOOD_THRESHOLD, -1 below RAA_LIKELIHOOD_LOW_THRESHOLD), plus +1 if the asset carries
    net:internet-reachable, plus `adjust`, clamped.

    The internet step never goes negative, since an unreachable asset is the ordinary case that
    the baseline already assumes. `adjust` is an optional one-level step from a model fact that
    a branch reads, such as a guardrail on a prompt-injection asset's request path."""
    baseline = LIKELIHOOD_ORDER.index(definition["baseline_likelihood"])
    if asset_raa >= RAA_LIKELIHOOD_THRESHOLD:
        raa_delta = 1
    elif asset_raa < RAA_LIKELIHOOD_LOW_THRESHOLD:
        raa_delta = -1
    else:
        raa_delta = 0
    exposed_delta = 1 if internet_reachable else 0
    return LIKELIHOOD_ORDER[_clamp(baseline + raa_delta + exposed_delta + adjust)]


def compute_impact(definition: dict, asset_data: dict) -> str:
    """The category's baseline_impact, plus the CIA step for the asset's rank on the dimension
    that the finding's STRIDE category threatens (see STRIDE_TO_CIA_DIMENSION), clamped. Mission
    criticality does not enter it."""
    baseline = IMPACT_ORDER.index(definition["baseline_impact"])
    c, i, a = _asset_cia_ranks(asset_data)
    dimension = STRIDE_TO_CIA_DIMENSION.get(definition.get("stride", ""))
    rank = {"confidentiality": c, "integrity": i, "availability": a}.get(dimension, max(c, i, a))
    cia_delta = CIA_RANK_TO_DELTA[rank]
    return IMPACT_ORDER[_clamp(baseline + cia_delta)]


def compute_severity(likelihood: str, impact: str) -> str:
    product = WEIGHT[LIKELIHOOD_ORDER.index(likelihood)] * WEIGHT[IMPACT_ORDER.index(impact)]
    for threshold, severity in SEVERITY_THRESHOLDS:
        if product <= threshold:
            return severity
    return "critical"


def inject_risks(yaml_file_path, output_path='threagile_injected.yml'):
    # 1. Load the developer's Threagile YAML
    with open(yaml_file_path, 'r', encoding='utf-8') as file:
        model = yaml.safe_load(file)

    if not model:
        print("Error: Could not load YAML model.")
        sys.exit(1)

    # 2. Ensure individual_risk_categories exists
    if 'individual_risk_categories' not in model or model['individual_risk_categories'] is None:
        model['individual_risk_categories'] = {}

    # 3. Load the Baseline IL5 Risk Categories from the central risk library
    with open(RISK_DEFS_PATH, 'r', encoding='utf-8') as file:
        risk_defs = yaml.safe_load(file)['custom_risk_definitions']

    for key, definition in risk_defs.items():
        if 'risks_identified' not in definition:
            print(f"FATAL: Risk definition '{key}' is missing the required 'risks_identified' key.")
            sys.exit(1)
        if 'baseline_likelihood' not in definition or 'baseline_impact' not in definition:
            print(f"FATAL: Risk definition '{key}' is missing 'baseline_likelihood'/'baseline_impact' -- "
                  f"required by compute_likelihood()/compute_impact() to score every finding in this category.")
            sys.exit(1)

    # 4. Scan Technical Assets for trigger tags
    model_is_mission_essential = mission_criticality(model) in MISSION_ESSENTIAL_OR_ABOVE
    raa_by_id = compute_raa_by_id(model)

    tech_assets = model.get('technical_assets', {})

    # Graph indexes for the few branches that read links or trust boundaries: each asset's
    # technology, its directly containing trust boundary, and incoming links by target id.
    technologies_by_id = {a.get('id'): asset_technologies(a) for a in tech_assets.values()}
    assets_by_id = {a.get('id'): a for a in tech_assets.values()}
    boundaries = {b.get('id'): b for b in (model.get('trust_boundaries') or {}).values()}
    boundary_by_id = {}
    parent_by_boundary = {}
    for boundary in boundaries.values():
        for inside in boundary.get('technical_assets_inside') or []:
            boundary_by_id[inside] = boundary.get('id')
        for nested in boundary.get('trust_boundaries_nested') or []:
            parent_by_boundary[nested] = boundary.get('id')

    def network_boundary(asset_id):
        # Network-only semantics, as in the fork's rules and Threagile's built-ins: look through
        # execution-environment boundaries to the nearest enclosing network boundary.
        boundary = boundary_by_id.get(asset_id)
        for _ in range(4):
            if boundary is None or (boundaries.get(boundary) or {}).get('type') != 'execution-environment':
                return boundary
            boundary = parent_by_boundary.get(boundary)
        return boundary

    def reads_content(asset_data):
        # True when the asset has an outgoing link to a content source: a retrieval store or
        # pipeline, a tool server, another agent's gateway, or anything external or out of scope.
        for link in (asset_data.get('communication_links') or {}).values():
            target_id = link.get('target')
            target = assets_by_id.get(target_id) or {}
            if technologies_by_id.get(target_id, set()) & CONTENT_SOURCE_TECHNOLOGIES:
                return True
            if target.get('out_of_scope') or target.get('type', 'external-entity') == 'external-entity':
                return True
        return False

    def is_outside_caller(caller_id, own_network_boundary):
        # External (an external entity, out of scope, or internet-facing), or a frontend in a
        # different network boundary, the same test the fork's rules use.
        caller = assets_by_id.get(caller_id) or {}
        if caller.get('internet') or caller.get('out_of_scope') or caller.get('type', 'external-entity') == 'external-entity':
            return True
        return bool(technologies_by_id.get(caller_id, set()) & FRONTEND_TECHNOLOGIES) and \
            network_boundary(caller_id) != own_network_boundary
    incoming_by_target = {}
    for source in tech_assets.values():
        for link in (source.get('communication_links') or {}).values():
            incoming_by_target.setdefault(link.get('target'), []).append((source.get('id'), link))

    # Rogue access points and missing route origin validation are properties of a self-managed
    # network, not of each workload on it. Thus, they are raised once per network trust boundary
    # that holds unhardened self-managed assets, on its edge asset where one is modeled.
    def self_managed_unhardened(asset):
        tags = set(asset.get('tags') or [])
        return (not asset.get('out_of_scope') and 'mgmt:self-managed-network' in tags
                and 'mgmt:self-managed-network-hardened' not in tags)

    network_edge_holder = {}
    for asset in sorted(tech_assets.values(),
                        key=lambda a: (not (asset_technologies(a) & NETWORK_EDGE_TECHNOLOGIES), a.get('id') or '')):
        if self_managed_unhardened(asset):
            network_edge_holder.setdefault(network_boundary(asset.get('id')), asset.get('id'))

    for asset_name, asset_data in tech_assets.items():
        # Every custom category asks whether this organization documented or hardened something,
        # which does not apply to an out-of-scope asset that it neither owns nor controls.
        if asset_data.get('out_of_scope'): continue
        tags = asset_data.get('tags', [])
        asset_techs = technologies_by_id.get(asset_data.get('id'), set())
        asset_id = asset_data.get('id')
        asset_is_internet_reachable = 'net:internet-reachable' in tags
        asset_raa = raa_by_id.get(asset_id, 1.0)
        incoming = incoming_by_target.get(asset_id, [])
        outgoing_targets = [link.get('target') for link in (asset_data.get('communication_links') or {}).values()]
        # A guardrail on the request path lowers prompt-injection likelihood one level. There are
        # two shapes:
        #   - sidecar: this asset calls an ai-guardrails asset to screen its traffic. The model
        #     cannot show a bypass here, so the link is trusted.
        #   - inline: ai-guardrails assets call this asset. It counts only when every caller other
        #     than monitoring is a guardrail, since any other caller reaches the asset unscreened.
        callers = [source for source, _ in incoming
                   if not technologies_by_id.get(source, set()) & {'monitoring', 'ai-observability-stack'}]
        inline_guarded = bool(callers) and all('ai-guardrails' in technologies_by_id.get(source, set()) for source in callers)
        sidecar_guarded = any('ai-guardrails' in technologies_by_id.get(target, set()) for target in outgoing_targets)
        guarded = inline_guarded or sidecar_guarded
        injection_delta = -1 if guarded else 0
        # Written from outside: an outside caller (see is_outside_caller) writes into this asset
        # through an incoming link that is not readonly.
        own_network_boundary = network_boundary(asset_id)
        written_from_outside = any(
            not link.get('readonly', False) and is_outside_caller(source, own_network_boundary)
            for source, link in incoming)

        # Adds one finding of category cid on this asset, scored for the asset.
        def inject(cid, title, likelihood_delta=0):
            definition = risk_defs[cid]
            likelihood = compute_likelihood(definition, asset_raa, asset_is_internet_reachable, likelihood_delta)
            impact = compute_impact(definition, asset_data)
            severity = compute_severity(likelihood, impact)
            if cid not in model['individual_risk_categories']:
                model['individual_risk_categories'][cid] = copy.deepcopy(definition)
            risks_dict = model['individual_risk_categories'][cid].setdefault('risks_identified', {})
            risks_dict[f"{title} at {asset_name}"] = {
                "severity": severity,
                "exploitation_likelihood": likelihood,
                "exploitation_impact": impact,
                "data_breach_probability": "possible",
                "most_relevant_technical_asset": asset_id
            }

        # --- 1. SOFTWARE BEHAVIORAL FEATURES ---
        if 'feature:third-party-plugins' in tags: inject("Unauthorized Marketplace Plugin", "Plugin Risk")
        if 'feature:vdi-path' in tags: inject("VDI Clipboard Data Exfiltration", "VDI Risk")
        if 'feature:file-upload-processing' in tags: inject("Malicious Archive Processing (Zip Slip and Decompression Bombs)", "Archive Processing Risk")
        if 'feature:public-api-endpoint' in tags:
            inject("Public API Abuse and Asymmetric DoS", "API Abuse Risk")
            inject("Improper API Inventory Management", "API Inventory Risk")
            if 'ops:api-abuse-logging-enabled' not in tags:
                inject("API Abuse and Enumeration Logging Gap", "API Abuse Logging Gap Risk")
        # OWASP API6:2023: automated abuse of a legitimate business flow (bulk account creation,
        # scalping), as distinct from raw request volume.
        if 'feature:sensitive-business-flow' in tags:
            inject("Unrestricted Access to Sensitive Business Flows", "Business Flow Abuse Risk")
        # OWASP API10:2023: the asset trusts a legitimate external API's response without
        # validating it, the inverse of SSRF.
        if 'net:external-api-consumer' in tags:
            inject("Unsafe Consumption of APIs", "Unsafe API Consumption Risk")
        if 'feature:dynamic-code-execution' in tags: inject("Server-Side Template Injection and RCE", "RCE Risk")
        # Search index abuse belongs to the search engine itself, or to an app tagged
        # feature:search-index whose search is built in, rather than to every app that calls a
        # modeled search engine.
        calls_search_engine = any(technologies_by_id.get(t, set()) & SEARCH_TECHNOLOGIES for t in outgoing_targets)
        if asset_techs & SEARCH_TECHNOLOGIES or ('feature:search-index' in tags and not calls_search_engine):
            inject("Search Index Abuse and Data Exposure", "Search Index Risk")
        if 'feature:oauth-oidc-provider' in tags:
            inject("OAuth 2.0 and OIDC Implementation Vulnerabilities", "OAuth/OIDC Risk")
            if 'ops:token-binding-enforced' not in tags:
                inject("Missing Token Binding on Session and Refresh Tokens", "Token Binding Gap Risk")
            if 'ops:oauth-consent-governed' not in tags:
                inject("OAuth Illicit Consent Grant via Malicious Application Registration", "OAuth Consent Grant Risk")
        if 'mgmt:self-managed-identity' in tags and 'mgmt:self-managed-identity-hardened' not in tags:
            inject("Self-Managed Directory Tier-0 Infrastructure Compromise", "Directory Tier-0 Compromise Risk")
            inject("Self-Managed Certificate Authority Template Privilege Escalation", "CA Template Escalation Risk")
            inject("Self-Managed Hybrid Identity Synchronization Server Compromise", "Hybrid Sync Compromise Risk")
        if 'feature:webhook-receiver' in tags: inject("Webhook Signature Verification Bypass", "Webhook Signature Risk")
        if 'feature:import-export' in tags: inject("Bulk Import/Export Data Abuse", "Import/Export Abuse Risk")
        if 'feature:pdf-generation' in tags: inject("Server-Side PDF Generation Injection", "PDF Generation Injection Risk")
        if 'feature:email-sending' in tags: inject("Email Header Injection and Sending Abuse", "Email Header Injection Risk")
        if 'feature:graphql-endpoint' in tags: inject("GraphQL Introspection, Query Depth, and Authorization Gaps", "GraphQL Security Risk")
        # WebSocket: an incoming ws or wss link, or the feature:websocket tag where the protocol is
        # not modeled. Browser-facing: a caller whose technology is a browser, since CORS and
        # framing policies are browser mechanisms.
        accepts_websocket = any(link.get('protocol') in ('ws', 'wss') for _, link in incoming)
        if accepts_websocket or 'feature:websocket' in tags:
            inject("WebSocket Origin Validation and Authentication Gaps", "WebSocket Security Risk")
        browser_facing = any('browser' in technologies_by_id.get(source, set()) for source, _ in incoming)
        if browser_facing and 'ops:cors-csp-hardened' not in tags:
            inject("Permissive CORS and Missing Browser Framing/Content Policy", "CORS/Framing Policy Gap Risk")
        if 'feature:saml-sp' in tags: inject("SAML Assertion Vulnerabilities", "SAML Security Risk")
        if 'feature:password-reset' in tags: inject("Insecure Password Reset and Credential Recovery", "Password Reset Risk")
        if 'feature:admin-panel' in tags: inject("Exposed Administrative Interface Without Hardened Access Controls", "Admin Panel Exposure Risk")
        if 'feature:background-jobs' in tags: inject("Background Job Parameter Injection and Authorization Bypass", "Background Job Security Risk")
        if 'feature:caching-layer' in tags: inject("Application Cache Poisoning and Sensitive Data Persistence", "Cache Poisoning Risk")
        if 'feature:vendor-remote-support' in tags and 'ops:vendor-access-case-bound' not in tags:
            inject("Third-Party Vendor Remote Support Access Lifecycle Gap", "Vendor Remote Support Risk")
        if 'mgmt:self-managed-pam' in tags and 'mgmt:self-managed-pam-hardened' not in tags:
            inject("Standing Privileged Access with No Administrative Tiering", "Standing Privilege Risk")
            inject("Privileged Session Credential Disclosure Without Vaulting or Brokering", "Credential Disclosure Risk")
            inject("Break-Glass Emergency Access Circular Dependency or Untested Procedure", "Break-Glass Gap Risk")

        # Not gated on mgmt:self-managed-*: the app team owns its workload role assignments even
        # when the landing zone is inherited.
        if 'mgmt:workload-identity-assigned' in tags and 'mgmt:workload-identity-least-privilege' not in tags:
            inject("Over-Privileged Workload Identity and Cloud Control-Plane Pivot", "Workload Identity Overprivilege Risk")

        # --- 2. AI THREAT VECTORS ---

        # Prompt input surface (direct injection, jailbreak, system prompt extraction)
        if 'ai:user-prompt-input' in tags:
            inject("Direct Prompt Injection and Jailbreak", "Direct Prompt Injection Risk", injection_delta)

        # Indirect injection surface (emails, docs, web content fed to LLM)
        if 'ai:indirect-prompt-input' in tags:
            inject("Indirect Prompt Injection and Goal Hijack", "Indirect Prompt Injection Risk", injection_delta)

        if asset_techs & RAG_PIPELINE_TECHNOLOGIES:
            # RAG retrieval is inherently an indirect prompt injection surface -- unless the asset
            # is already tagged ai:indirect-prompt-input, which injected the same category above.
            if 'ai:indirect-prompt-input' not in tags:
                inject("Indirect Prompt Injection and Goal Hijack", "RAG Indirect Injection Risk", injection_delta)

        if asset_techs & AGENT_ORCHESTRATOR_TECHNOLOGIES:
            # An orchestrator that reads content inherits indirect injection, since retrieved
            # documents, tool results, and other agents' messages reach the model as context. An
            # agent that talks only to its LLM and its own stores has no such path.
            if 'ai:indirect-prompt-input' not in tags and reads_content(asset_data):
                inject("Indirect Prompt Injection and Goal Hijack", "Agent Indirect Injection Risk", injection_delta)

        # Agent persistent memory (memory/thread poisoning, chat history manipulation); one level
        # more likely when the memory is written from outside its trust boundary.
        if 'ai:agent-memory' in tags:
            # The net:internet-reachable tag already adds +1 in compute_likelihood, so the
            # outside-writer step applies only when that tag is absent.
            memory_step = 1 if written_from_outside and not asset_is_internet_reachable else 0
            inject("Agent Memory and Context Poisoning", "Agent Memory Poisoning Risk", memory_step)

        # Code the agent or tool runs itself (ASI05, AST06). It is one level more likely on an
        # explicitly physical machine, with no VM, container, or serverless boundary, while a
        # missing machine field takes no step.
        if 'ai:code-execution' in tags:
            unisolated = asset_data.get('machine') == 'physical'
            inject("Unexpected Code Execution and Weak Sandbox", "Code Execution Risk", 1 if unisolated else 0)

        # Agent skills loaded into the agent (AST01/04/05/08/10), unless vetted.
        if 'ai:skills-enabled' in tags and 'ai:skills-vetted' not in tags:
            inject("Unvetted Agent Skills and Instructions", "Agent Skills Risk")

        # Human labelers / reviewers seeing the data (DSGAI19).
        if 'ai:human-labeling' in tags:
            inject("Labeler and Human-in-the-Loop Overexposure", "Labeler Overexposure Risk")

        # AI assistants on user endpoints and browsers (DSGAI16).
        if 'ai:endpoint-assistant' in tags:
            inject("Endpoint and Browser AI Overreach", "Endpoint AI Overreach Risk")

        if asset_techs & MULTI_AGENT_GATEWAY_TECHNOLOGIES:
            # A multi-agent gateway inherits indirect prompt injection, since agents treat other
            # agents' messages as instructions. The tag check avoids injecting the same category
            # twice under two titles.
            if 'ai:indirect-prompt-input' not in tags:
                inject("Indirect Prompt Injection and Goal Hijack", "Cross-Agent Injection Risk", injection_delta)

        # --- 2b. AI OPERATIONAL AND DEPLOYMENT GAPS ---

        if 'ai:ot-adjacent-output' in tags:
            inject("AI Output Path to OT or Safety-Critical Actuation Without Human Gate", "OT Actuation Boundary Risk")

        # An air-gapped enclave has no native field to read, so this check stays on its tag.
        if 'ai:air-gapped-model-delivery' in tags and 'ai:model-package-signed' not in tags:
            inject("Offline or Air-Gapped Model Package Integrity Gap", "Air-Gapped Model Integrity Risk")

        if 'ai:third-party-model-api' in tags and 'ai:vendor-model-governed' not in tags:
            inject("Ungoverned Third-Party Foundation Model API Dependency", "Third-Party Model API Risk")

        if 'ai:decision-support-output' in tags and 'ai:output-confidence-disclosed' not in tags:
            inject("Overreliance and Human-Agent Trust Exploitation", "AI Overreliance Risk")

        # --- 2c. CROSS-DOMAIN SOLUTION INTERFACE ---

        # Low-side interface
        if 'cds:low-side-submitter' in tags:
            inject("CDS: Classification Marking Validation Bypass", "CDS Marking Validation Risk")
            inject("CDS: Misclassification and Insufficient Transfer Audit Trail", "CDS Audit Trail Risk")

        if 'cds:low-side-receiver' in tags:
            inject("CDS: Unsafe Processing of CDS-Sourced Inbound Content", "CDS Inbound Content Risk")

        if 'cds:low-side-broker' in tags:
            inject("CDS: Transfer Broker Unauthorized Write and Queue Injection", "CDS Broker Injection Risk")

        # High-side interface (in-scope when both sides modeled in single ATO package)
        if 'cds:high-side-submitter' in tags:
            inject("CDS: Inadvertent Above-Releasable Content Inclusion in Downward Release", "CDS Above-Releasable Content Risk")
            inject("CDS: Release Authority Bypass on High-Side Downward Transfer", "CDS Release Authority Bypass Risk")
            inject("CDS: Misclassification and Insufficient Transfer Audit Trail", "CDS High-Side Audit Trail Risk")
            # An authorized releaser deliberately misusing access that no technical control can
            # revoke, as distinct from accidental inclusion or a workflow bypass.
            inject("CDS: Malicious Insider Abuse of Authorized Release Privileges", "CDS Insider Release Abuse Risk")

        if 'cds:high-side-receiver' in tags:
            inject("CDS: Low-to-High Content Integrity and Influence Risk", "CDS Inbound Integrity Risk")

        if 'cds:high-side-broker' in tags:
            inject("CDS: High-Side Transfer Broker Unauthorized Access and Queue Tampering", "CDS High-Side Broker Risk")

        # Covert channel exposure, assessed on each CDS submitter and receiver interface.
        if 'cds:low-side-submitter' in tags or 'cds:low-side-receiver' in tags \
                or 'cds:high-side-submitter' in tags or 'cds:high-side-receiver' in tags:
            inject("CDS: Transfer Interface Covert Channel Exposure", "Covert Channel Exposure Risk")

        # --- 3. POLICY EXCEPTIONS (Explicit Bad) ---
        if 'exception:runs-as-root' in tags: inject("Container Runs as Root (Policy Exception)", "Root Waiver")
        if 'exception:eol-component' in tags: inject("EOL Component in ATO Boundary", "EOL Component Waiver")
        # Direct admin access waiver. Where the built-in unguarded-access-from-internet already
        # raises the exposure (a non-VPN link from an internet-side caller to an asset rated
        # confidential or critical, its gate mirrored here), the waiver is recorded as accepted on
        # that finding instead. Thus, this fires only where the built-in stays silent: a
        # lower-value VM, or an admin path the model does not draw as a link.
        if 'exception:direct-admin-access' in tags:
            built_in_covers = (
                (CIA_RANK.get(str(asset_data.get('confidentiality', '')).strip(), 0) >= 3
                 or CIA_RANK.get(str(asset_data.get('integrity', '')).strip(), 0) >= 3)
                and any(is_internet_side_caller(assets_by_id.get(source) or {}) and not link.get('vpn')
                        for source, link in incoming))
            if not built_in_covers:
                inject("Policy Exception: Direct Admin Access", "Admin Access Waiver")
        if 'exception:local-auth-fallback' in tags: inject("Policy Exception: Local Authentication", "Local Auth Waiver")

        # --- 4. INFRASTRUCTURE BASELINE (Absence of Good) ---

        # TLS termination: FIPS compliance check, unless the asset is tagged compliant.
        if 'net:tls-terminator' in tags and 'compliance:fips-validated' not in tags:
            inject("FIPS Non-Compliant Cryptography", "FIPS Compliance Check")

        # TLS termination: deprecated protocol and weak cipher check, on every TLS terminator.
        if 'net:tls-terminator' in tags:
            inject("Deprecated TLS Versions and Weak Cipher Suites", "Weak TLS Configuration Risk")

        # Backup integrity, on every asset that requires backup.
        if 'ops:requires-backup' in tags:
            inject("Backup Integrity and Recovery Assurance Gap", "Backup Integrity Risk")

            # Narrower backup and recovery risks, each suppressed by its own tag (see
            # 03-tags-lib.yml, "Backup and Recovery Hardening").
            if 'ops:backup-admin-segregated' not in tags:
                inject("Backup Administrative Privilege Separation Gap", "Backup Admin Separation Risk")
            if 'ops:backup-immutable' not in tags:
                inject("Backup Immutability Not Enforced", "Backup Immutability Risk")
            if 'ops:backup-key-rotation-aligned' not in tags:
                inject("Backup Encryption Key Rotation and Retention Mismatch", "Backup Key Rotation Risk")
            if 'ops:recovery-objectives-defined' not in tags:
                inject("Recovery Objective Definition Gap", "RTO/RPO Gap Risk")
            if 'ops:backup-recovery-tested' not in tags:
                inject("Untested Restoration Procedure", "Untested Restore Risk")

        # SaaS and vendor-hosted assets that the enterprise backup platform cannot enroll.
        if 'ops:vendor-hosted-service' in tags and 'ops:saas-export-configured' not in tags:
            inject("Unsupported or SaaS Service Backup Gap", "SaaS Backup Gap Risk")

        # Public endpoint: internet-facing, and called by an out-of-scope or external-entity asset.
        # A public DNS name belongs to such an asset, not to one behind it, nor to a device that
        # carries only outbound traffic.
        public_endpoint = bool(asset_data.get('internet')) and any(
            (assets_by_id.get(source) or {}).get('out_of_scope')
            or (assets_by_id.get(source) or {}).get('type', 'external-entity') == 'external-entity'
            for source, _ in incoming)
        if public_endpoint and 'ops:dns-record-reconciled' not in tags:
            inject("Dangling DNS Record and Subdomain Takeover", "Dangling DNS Risk")

        # Network detection gap, on the public endpoint or an asset marked net:internet-reachable,
        # since a sensor at the edge does not cover traffic to the application a few hops behind.
        if (public_endpoint or asset_is_internet_reachable) and 'net:ids-monitored' not in tags:
            inject("Network Intrusion Detection and Traffic Anomaly Blind Spot", "Network IDS Blind Spot Risk")

        # Physical host hardening applies only to self-managed bare metal, since a cloud provider
        # owns the hypervisor host under a VM.
        if asset_data.get('machine') == 'physical' \
                and 'mgmt:self-managed-hardware' in tags and 'mgmt:self-managed-hardware-hardened' not in tags:
            inject("Self-Managed Out-of-Band Management Controller Compromise", "BMC Compromise Risk")
            inject("Self-Managed Below-OS Firmware Persistence Gap", "Firmware Persistence Risk")
            inject("Self-Managed Boot Integrity Bypass", "Boot Integrity Risk")

        # --- 5. DATA GOVERNANCE AND LIFECYCLE ---
        # Each check fires when its confirming tag is absent (see 03-tags-lib.yml, "DATA GOVERNANCE
        # AND LIFECYCLE TAGS"). A PIA (E-Gov Act Sec. 208) applies to processing PII at all, not only
        # to storing it.
        if 'data:pii' in tags and 'data:pia-documented' not in tags:
            inject("Missing Privacy Impact Assessment", "Missing PIA Risk")

        if ('data:external-feed-ingest' in tags or asset_techs & DATASET_STORE_TECHNOLOGIES) and 'data:provenance-tracked' not in tags:
            inject("Missing Data Provenance and Lineage Chain-of-Custody", "Data Provenance Gap Risk")

        if 'feature:import-export' in tags and 'ops:dlp-egress-inspected' not in tags:
            inject("Data Loss Prevention Egress Path Blind Spot", "DLP Egress Gap Risk")

        if ('cds:high-side-submitter' in tags or 'cds:high-side-broker' in tags) \
                and 'data:downgrade-procedure-documented' not in tags:
            inject("Media Downgrading Procedure Gap", "Media Downgrade Gap Risk")

        if 'data:release-candidate' in tags:
            if 'data:reidentification-tested' not in tags:
                inject("Released Dataset Re-Identification Risk", "Re-Identification Risk")
            if 'data:rights-managed' not in tags:
                inject("Missing Data Rights Management on Released Files", "Missing DRM Risk")

        # --- 6. INCIDENT-RESPONSE READINESS ---

        # Containment disposition, on internet-reachable, exception-bearing, and CDS-interface
        # assets, and on every asset in a mission-essential model. It reads net:internet-reachable
        # rather than zone:dmz, since the likely compromise target is usually the application behind
        # the edge.
        if 'ir:containment-disposition-documented' not in tags and (
                model_is_mission_essential
                or asset_is_internet_reachable
                or any(tag.startswith('exception:') for tag in tags)
                or any(tag.startswith('cds:') for tag in tags)):
            inject("Undocumented Incident Containment Disposition", "Containment Disposition Gap Risk")

        # Credential blast radius, on secrets brokers and any asset that holds credentials.
        if ('sec:secrets-broker' in tags or 'data:credential' in tags) \
                and 'ir:credential-inventory-documented' not in tags:
            inject("Undocumented Credential Blast Radius for Incident-Driven Rotation", "Credential Blast Radius Risk")

        # IR plan testing, breach notification, and chain of custody are program-level facts, but
        # they are raised per asset, since risk_tracking signs off each finding per asset and one
        # finding covering many assets cannot be partly accepted.
        if model_is_mission_essential:
            if 'ir:plan-tested' not in tags:
                inject("Untested Incident Response Plan", "Untested IR Plan Risk")
            if 'ir:breach-notification-procedure-documented' not in tags:
                inject("DFARS 252.204-7012 72-Hour Cyber Incident Reporting Gap", "Breach Notification Gap Risk")
            if 'ir:evidence-handling-documented' not in tags:
                inject("Forensic Evidence Chain-of-Custody Gap", "Chain-of-Custody Gap Risk")

        # --- 7. NETWORK SEGMENTATION AND PERIMETER (SELF-MANAGED) ---
        if 'mgmt:self-managed-network' in tags and 'mgmt:self-managed-network-hardened' not in tags:
            # Containers are left to the fork's missing-network-micro-segmentation, which also
            # honors a modeled namespace-isolation boundary.
            if asset_data.get('machine') != 'container':
                inject("No Macro or Micro-Segmentation of Self-Managed Network", "Self-Managed Segmentation Gap Risk")
            if network_edge_holder.get(network_boundary(asset_data.get('id'))) == asset_data.get('id'):
                inject("Rogue Access Point and Evil-Twin Credential Harvesting on Self-Managed Wireless", "Rogue AP Risk")
                inject("Missing Route Origin Validation on Self-Managed External Routing", "Missing RPKI Validation Risk")

    # 5. Convert to custom_risk_categories, a list of categories with a 'title' field. The
    # title-keyed dict above only makes inject()'s lookups convenient. Threagile silently drops an
    # unrecognized top-level key, so writing the dict under its old name would produce no custom
    # findings at all.
    custom_categories_by_title = model.pop('individual_risk_categories')
    model['custom_risk_categories'] = []
    for title, category in custom_categories_by_title.items():
        category = dict(category)
        category['title'] = title
        model['custom_risk_categories'].append(category)

    # 6. Save the enriched YAML
    with open(output_path, 'w', encoding='utf-8') as file:
        yaml.dump(model, file, sort_keys=False, allow_unicode=True)

    print(f"Successfully generated {output_path}")

if __name__ == "__main__":
    inject_risks(sys.argv[1], sys.argv[2] if len(sys.argv) > 2 else 'threagile_injected.yml')