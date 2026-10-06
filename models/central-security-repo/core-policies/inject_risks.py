import yaml
import sys
import copy
from pathlib import Path

RISK_DEFS_PATH = Path(__file__).resolve().parent.parent / "libraries" / "09-custom-risks-lib.yml"

# Threagile's severity enum, low to high (see `threagile -explain-types`).
SEVERITY_ORDER = ["low", "medium", "elevated", "high", "critical"]

# Threagile's own exploitation_likelihood/exploitation_impact enums, also
# low to high -- used below to compute a real, per-asset Severity for every
# custom finding instead of a flat literal repeated on every finding in a
# category regardless of which asset it landed on. See compute_likelihood(),
# compute_impact(), and compute_severity() for the full methodology; this
# mirrors what the report's Methodology section (report.html.jinja)
# describes Threagile's own built-in rules as doing, applied here to our
# custom categories with our own documented scoring logic -- not an attempt
# to replicate Threagile's own (undisclosed, compiled-into-the-binary)
# matrix.
LIKELIHOOD_ORDER = ["unlikely", "likely", "very-likely", "frequent"]
IMPACT_ORDER = ["low", "medium", "high", "very-high"]

# Business criticality values (see 00-threagile-field-reference.yml) that
# bump Impact (see compute_impact()) as a system-level consequence signal,
# distinct from any single asset's own CIA rating, and separately gate a
# handful of incident-response-readiness triggers further below (unrelated
# to severity) that already existed before this variable took on its
# Impact role.
CRITICAL_BUSINESS_VALUES = {"critical", "mission-critical"}

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

# CIA_RANK (0-4) -> a -1/0/+1 delta applied on top of a category's own
# baseline_likelihood/baseline_impact (see 09-custom-risks-lib.yml): the
# bottom two CIA tiers pull the baseline down a notch, the middle tier
# leaves it alone, and the top two tiers push it up a notch. A flat +1/-1
# rather than a wider swing, since the category's own baseline is meant to
# carry most of the signal -- context should nudge it, not override it.
CIA_RANK_TO_DELTA = {0: -1, 1: -1, 2: 0, 3: 1, 4: 1}

# Which CIA dimension a finding's STRIDE category most directly threatens,
# for compute_impact() below -- so a denial-of-service finding is nudged by
# the asset's Availability rating rather than the same flat max(C, I, A) an
# information-disclosure finding on that same asset would also use.
# elevation-of-privilege (and any STRIDE value not listed here -- none as of
# this writing, see 09-custom-risks-lib.yml) falls back to the max of all
# three, since a privileged attacker can read, alter, or deny at will
# regardless of which single dimension the category happens to be filed
# under.
#
# spoofing maps to integrity, not confidentiality: Microsoft's original
# STRIDE mnemonic pairs spoofing with Authentication, which isn't one of
# the three CIA fields a Threagile technical asset actually carries, so
# this has to approximate onto one of the three regardless. The direct
# consequence of a successful spoofing finding (an attacker impersonates
# another identity, forges a token, bypasses an authentication check) is
# that the integrity of the authentication decision itself is what broke
# -- what the attacker does with that impersonated identity afterward can
# certainly become a confidentiality (or availability) event too, but
# that's a downstream consequence of the identity forgery, not the finding
# itself. This matters in practice for most of Domain 1 (Identity), where
# nearly every category is tagged spoofing: an identity broker or CA whose
# real value is its Integrity rating (not necessarily its Confidentiality
# rating) is now scored off the axis that actually reflects what it is.
#
# Known, accepted exception: spoofing also covers infrastructure
# impersonation (e.g. Rogue Access Point and Evil-Twin Credential
# Harvesting), where the actual consequence -- credentials intercepted
# over the air -- is a confidentiality event, not an authentication-
# integrity one. This mapping is a single global table, not something an
# individual category can override, so this trades a worse fit for that
# minority case for a better fit across the majority (identity
# impersonation) case it was changed for -- a net improvement, not a
# universally correct one. Reclassifying that entry's own `stride` value
# just to route around this table would misrepresent its actual STRIDE
# category (it genuinely is spoofing), so it's left as-is and documented
# here instead.
STRIDE_TO_CIA_DIMENSION = {
    "information-disclosure": "confidentiality",
    "spoofing": "integrity",
    "tampering": "integrity",
    "repudiation": "integrity",
    "denial-of-service": "availability",
}

# Likelihood (row) x Impact (column) -> Severity, as an explicit,
# hand-authored lookup table rather than an arithmetic formula -- the way a
# standard qualitative risk matrix is actually built. The rule behind it is a
# plain diagonal band: rank each axis 0-3, sum the two ranks (0-6), and
# bucket the sum into the five Severity levels (0-1 -> Low, 2 -> Medium,
# 3 -> Elevated, 4 -> High, 5-6 -> Critical). This gives a genuinely balanced
# spread across all five levels rather than concentrating in the top two --
# an earlier version instead bumped Severity a level whenever Likelihood
# *and* Impact were both at least moderately elevated at once, which read
# right for any one cell in isolation but meant 10 of 16 cells landed on
# High/Critical, and on a real CUI-heavy app (most of whose assets are
# legitimately rated Confidential/Critical-or-higher, and whose findings are
# mostly Likely-or-worse) that pushed 85-98% of all custom findings to
# High/Critical and left the label unable to discriminate anything.
#
# One cell deliberately breaks the pure sum-6 rule: (Frequent, High) sits at
# High, not Critical. Left at Critical (its literal sum-band position), it
# alone made Critical read as ~20-25% of all custom findings on a real
# CUI-heavy app -- far above what Critical means in ordinary vulnerability-
# management practice (a small, urgent minority, typically well under 15%).
# Critical is now reachable only where both axes are genuinely maxed
# together (Very-likely/Frequent paired with Very-High, or Frequent paired
# with High is no longer enough on its own), which brought Critical down to
# 10-11% -- High absorbs the difference and becomes the largest single
# tier, but that's the normal, expected shape for the second-most-severe
# level in a right-skewed severity distribution, not a discrimination
# problem the way an over-large Critical tier was.
SEVERITY_MATRIX = [
    # Low         Medium        High          Very-High
    ["low",       "low",        "medium",     "elevated"],   # Unlikely
    ["low",       "medium",     "elevated",   "high"],       # Likely
    ["medium",    "elevated",   "high",       "critical"],   # Very-likely
    ["elevated",  "high",       "high",       "critical"],   # Frequent
]


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


# Tags marking a technical asset as a real application/service tier, as
# opposed to pure network/infrastructure plumbing (a firewall, a load
# balancer). Used by the Baseline Security Event Logging check below.
APP_TIER_TAGS = {"app:frontend-ui", "app:backend-api", "app:async-worker"}

# net:internet-reachable was previously a computed signal (a multi-hop walk
# from every zone:dmz asset, following outbound communication_links,
# stopping at the first real application tier reached -- see this file's
# git history for compute_internet_reachable_ids()) rather than an explicit
# tag. Removed after that walk was confirmed producing false positives in
# real use: a shared infrastructure hop with multiple independent inbound
# paths (e.g. one Ingress Controller serving both a DMZ-rooted login flow
# and an entirely separate, never-internet-facing East-West integration)
# has no way in a plain graph walk to distinguish which of its own outbound
# edges continue the DMZ-originated flow versus which belong to an
# unrelated caller -- once any inbound edge marked the shared hop reachable,
# the walk indiscriminately marked every one of its outbound targets
# reachable too, regardless of whether they had anything to do with the
# original DMZ path. Fixing that properly would mean tracking path
# provenance through shared nodes (per-edge tagging), which reintroduces a
# comparable maintenance burden to what an explicit tag already requires,
# without the walk's own upside of being cheap to audit. An explicit tag,
# applied to whichever specific assets are actually known to be reachable
# (typically the real application behind an already-modeled app
# gateway/ALB/WAF, not the gateway itself, which already carries its own
# internet: true field), is now the only signal compute_likelihood() and
# the two trigger sites below use -- author-maintained ground truth rather
# than a derived approximation that can't reason about shared plumbing.


# Threagile's own RAA (Relative Attacker Attractiveness) formula, replicated
# faithfully from pkg/model/raa.go and pkg/types/confidentiality.go/
# criticality.go/quantity.go in the pinned threagile/threagile:0.9.1 source
# -- not an approximation. Threagile only computes RAA itself *after* its
# own analysis runs (technical-assets.json, which generate_report.py's
# load_raa_by_id() reads), which is after inject_risks.py already needs a
# Likelihood value -- so this is our own independent computation of the
# same formula against the same model data, not a read of Threagile's
# actual output.
CONF_ASSET = [8, 13, 21, 34, 55]
CONF_PROCESSED_OR_STORED = [5, 8, 13, 21, 34]
CONF_TRANSFERRED = [2, 3, 5, 8, 13]
CRIT_ASSET = [5, 8, 13, 21, 34]
CRIT_PROCESSED_OR_STORED = [3, 5, 8, 13, 21]
CRIT_TRANSFERRED = [2, 3, 5, 8, 13]
QTY_FACTOR = {"very-few": 1, "few": 2, "many": 3, "very-many": 5}

# Technology-type multiplier Threagile's own RAA formula applies on top of
# the CIA/data-driven base score -- a reverse proxy or load balancer is
# structurally a conduit (it holds nothing itself, even if sensitive data
# flows through it), while an identity provider, vault, or container
# platform is disproportionately attractive regardless of its own stated
# CIA rating.
RAA_TECHNOLOGY_MULTIPLIER = {
    "reverse-proxy": 1 / 5.5, "load-balancer": 1 / 5.5,
    "monitoring": 1 / 5,
    "container-platform": 5,
    "vault": 2,
    "build-pipeline": 2, "sourcecode-repository": 2, "artifact-registry": 2,
    "identity-provider": 2.5, "identity-store-ldap": 2.5, "identity-store-database": 2.5,
    "database": 2,
}

# The threshold Threagile's own built-in engine uses in two of the four
# built-in rules that consult RAA at all (unguarded-access-from-internet,
# unguarded-direct-datastore-access) to decide whether an asset's RAA is
# high enough to matter -- the other two (missing-hardening, missing-
# network-segmentation) use a two-tier raaLimit/raaLimitReduced pair
# instead, but a single flat cutoff is the majority real-world pattern and
# simpler to reason about; validated against confluence and exposed-ai-chat
# before adopting. Deliberately left matching Threagile's own real value
# rather than tuned independently, even though RAA is normalized relative
# to *this specific model's own* asset population (see _raa_normalize()) --
# so "at or above 40%" means a different absolute attack-worthiness in a
# 3-asset model than a 50-asset one. That instability is inherited
# directly from Threagile's own real RAA design (which this codebase
# faithfully replicates, see compute_raa_by_id()'s docstring), not
# introduced here, and correcting it would mean deviating from that
# faithful replication -- judged not worth doing without first confirming
# Threagile's own built-in rules are actually less exposed to it in
# practice, which hasn't been checked.
RAA_LIKELIHOOD_THRESHOLD = 40.0

# The mirror-image cutoff for the negative branch compute_likelihood()
# below applies -- see that function's docstring for why this needed to
# exist at all. Set well below RAA_LIKELIHOOD_THRESHOLD rather than as its
# exact reflection (e.g. 60.0), since RAA_LIKELIHOOD_THRESHOLD's own value
# is anchored to Threagile's real built-in rules and isn't ours to move --
# an asset has to be genuinely low-value relative to this model, not
# merely below-average, to earn the downward nudge.
#
# This is a second absolute cutoff on the same self-relative, per-model
# min-max-normalized RAA scale RAA_LIKELIHOOD_THRESHOLD's own comment
# already flags as unstable across model sizes -- it doesn't fix that
# instability, it's exposed to it the same way. Accepted for the same
# reason as that comment: correcting the underlying normalization would
# mean deviating from faithfully replicating Threagile's own real RAA
# formula, not a decision to make lightly just to smooth over one
# secondary threshold.
RAA_LIKELIHOOD_LOW_THRESHOLD = 15.0


def _raa_data_asset_ranks(data_asset: dict) -> tuple:
    return (
        CIA_RANK.get(str(data_asset.get("confidentiality", "")).strip(), 0),
        CIA_RANK.get(str(data_asset.get("integrity", "")).strip(), 0),
        CIA_RANK.get(str(data_asset.get("availability", "")).strip(), 0),
    )


def _raa_raw_attractiveness(asset_data: dict, data_assets_by_id: dict) -> float:
    """The sum of an asset's own CIA attractiveness plus every data asset it
    processes/stores/transfers (each weighted by that data asset's own CIA
    and quantity -- Confidentiality/Integrity only, not Availability, per
    Threagile's own formula), scaled by RAA_TECHNOLOGY_MULTIPLIER."""
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
    """Percent value of each raw score relative to the min/max across every
    asset in this model -- floored at 1% rather than 0%, since 0 would
    suggest an asset can't be attacked at all."""
    if not raw_by_id:
        return {}
    values = list(raw_by_id.values())
    lo, hi = min(values), max(values)
    spread = (hi - lo) or 1
    return {aid: max((v - lo) / spread * 100, 1) for aid, v in raw_by_id.items()}


def compute_raa_by_id(model: dict) -> dict:
    """{technical_asset_id: RAA percent}, matching Threagile's own real
    computation: raw attractiveness, normalized once, then a "pivoting"
    pass adds up to a third of the positive gap to the most attractive
    asset each one can reach (value propagates backward from a high-value
    target onto whatever can reach it), before a final normalization."""
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


def compute_likelihood(definition: dict, asset_raa: float, internet_reachable: bool) -> str:
    """Likelihood = the category's own baseline_likelihood (see
    09-custom-risks-lib.yml -- an author judgment of how exploitable this
    vulnerability class inherently is, informed by CWE/OWASP data where a
    real mapping exists), adjusted by this specific asset's own context:
    a -1/0/+1 delta from the asset's own RAA (see compute_raa_by_id()) --
    +1 at or above RAA_LIKELIHOOD_THRESHOLD, -1 below
    RAA_LIKELIHOOD_LOW_THRESHOLD, 0 in between -- plus +1 (never negative)
    if the asset carries net:internet-reachable (an explicit, author-
    maintained tag, not the direct zone:dmz tag itself -- broader than
    that, since most vulnerability classes pass straight through a WAF
    untouched, so the real application behind a DMZ gateway is still a
    realistic target even though it isn't the edge component itself; see
    03-tags-lib.yml for this tag's own definition and the reasoning for
    why it's explicit rather than derived). The RAA delta used to be 0/+1 only, with no negative branch --
    that made every category's baseline_likelihood a hard floor
    regardless of how obscure or low-value the specific asset actually
    was, biasing Likelihood to only ever escalate as a model grows. The
    internet-reachability delta stays one-directional deliberately: NOT
    being reachable is simply the ordinary case the baseline already
    assumes, not a fact that should push likelihood below it the way a
    genuinely low-RAA asset does. RAA replaces what was previously a
    cruder max-CIA-rank delta here -- RAA already includes the asset's own
    CIA as its first term, plus the data it actually
    processes/stores/transfers, its technology role, and the pivoting
    effect, so it's a strictly richer version of the same signal, not an
    additional one stacked on top."""
    baseline = LIKELIHOOD_ORDER.index(definition["baseline_likelihood"])
    if asset_raa >= RAA_LIKELIHOOD_THRESHOLD:
        raa_delta = 1
    elif asset_raa < RAA_LIKELIHOOD_LOW_THRESHOLD:
        raa_delta = -1
    else:
        raa_delta = 0
    exposed_delta = 1 if internet_reachable else 0
    return LIKELIHOOD_ORDER[_clamp(baseline + raa_delta + exposed_delta)]


def compute_impact(definition: dict, asset_data: dict, mission_critical_system: bool) -> str:
    """Impact = the category's own baseline_impact, adjusted by -1/0/+1 from
    the asset's CIA rank on whichever single dimension this finding's
    STRIDE category actually threatens (see STRIDE_TO_CIA_DIMENSION), plus
    +1 if the model's overall Business Criticality is Critical/
    Mission-Critical -- but only when this asset's own CIA rank hasn't
    already earned that +1 on its own. A system rated Critical/Mission-
    Critical is, almost by definition, built mostly from components that
    themselves carry top-tier CIA ratings, so applying both bumps
    unconditionally mostly double-counts the same underlying fact for the
    same finding. Gating the system-level bump to only fill the gap for an
    otherwise-unremarkable asset preserves its real justification -- a
    low-value component still matters more inside an important system --
    without stacking on assets that already earned the bump themselves."""
    baseline = IMPACT_ORDER.index(definition["baseline_impact"])
    c, i, a = _asset_cia_ranks(asset_data)
    dimension = STRIDE_TO_CIA_DIMENSION.get(definition.get("stride", ""))
    rank = {"confidentiality": c, "integrity": i, "availability": a}.get(dimension, max(c, i, a))
    cia_delta = CIA_RANK_TO_DELTA[rank]
    criticality_delta = 1 if (mission_critical_system and cia_delta < 1) else 0
    return IMPACT_ORDER[_clamp(baseline + cia_delta + criticality_delta)]


def compute_severity(likelihood: str, impact: str) -> str:
    return SEVERITY_MATRIX[LIKELIHOOD_ORDER.index(likelihood)][IMPACT_ORDER.index(impact)]


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
    model_is_business_critical = model.get('business_criticality') in CRITICAL_BUSINESS_VALUES
    raa_by_id = compute_raa_by_id(model)

    tech_assets = model.get('technical_assets', {})
    for asset_name, asset_data in tech_assets.items():
        # Out-of-scope assets (external entities the app team doesn't
        # operate -- an end user's own device, a partner's own backend) are
        # explicitly excluded from the entire custom risk-injection engine,
        # not just implicitly via having no other tags to trigger on. Every
        # custom category here asks some version of "has this organization
        # documented/hardened X" -- a question that doesn't apply to
        # infrastructure this organization doesn't own or control, per that
        # asset's own justification_out_of_scope text. Without this check,
        # an out-of-scope asset that happens to carry ANY tag (even a purely
        # cosmetic icon: tag) silently starts firing these checks -- caught
        # for real when adding a diagram icon to two external-entity assets
        # newly triggered VM-hardening and model-criticality-readiness
        # findings on infrastructure explicitly marked as someone else's
        # responsibility.
        if asset_data.get('out_of_scope'): continue
        tags = asset_data.get('tags', [])
        if not tags: continue
        asset_id = asset_data.get('id')
        asset_is_internet_reachable = 'net:internet-reachable' in tags
        asset_raa = raa_by_id.get(asset_id, 1.0)

        # Generic function to safely inject a risk from our dictionary
        def inject(cid, title):
            definition = risk_defs[cid]
            likelihood = compute_likelihood(definition, asset_raa, asset_is_internet_reachable)
            impact = compute_impact(definition, asset_data, model_is_business_critical)
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
        if 'feature:file-upload-processing' in tags: inject("Malicious File Parsing and XXE", "File Parsing Risk")
        if 'feature:public-api-endpoint' in tags:
            inject("Public API Abuse and Asymmetric DoS", "API Abuse Risk")
            inject("Improper API Inventory Management", "API Inventory Risk")
            if 'ops:api-abuse-logging-enabled' not in tags:
                inject("API Abuse and Enumeration Logging Gap", "API Abuse Logging Gap Risk")
        if 'feature:dynamic-code-execution' in tags: inject("Server-Side Template Injection and RCE", "RCE Risk")
        if 'feature:search-index' in tags: inject("Search Index Abuse and Data Exposure", "Search Index Risk")
        if 'feature:deserialization' in tags: inject("Insecure Deserialization", "Insecure Deserialization Risk")
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
        if 'feature:websocket' in tags: inject("WebSocket Origin Validation and Authentication Gaps", "WebSocket Security Risk")
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

        # --- 2. MITRE ATLAS AI/ML THREAT VECTORS ---
        # One inject call per risk category, keyed to the new tag namespace.
        # Tags and the risk definitions they trigger:

        # Prompt input surface (direct injection, jailbreak, system prompt extraction)
        if 'ai:user-prompt-input' in tags:
            inject("ATLAS: LLM Prompt Injection (Direct) and Jailbreak", "Direct Prompt Injection Risk")

        # Indirect injection surface (emails, docs, web content fed to LLM)
        if 'ai:indirect-prompt-input' in tags:
            inject("ATLAS: Indirect Prompt Injection and Trusted Output Manipulation", "Indirect Prompt Injection Risk")

        # RAG pipeline (poisoning, credential harvesting, data exfil from retrieval)
        if 'ai:rag-pipeline' in tags:
            inject("ATLAS: RAG Pipeline Poisoning and Data Exfiltration", "RAG Poisoning Risk")
            # RAG retrieval is inherently an indirect prompt injection surface
            inject("ATLAS: Indirect Prompt Injection and Trusted Output Manipulation", "RAG Indirect Injection Risk")

        # RAG ingest pipeline (dataset / knowledge base integrity at write time)
        if 'ai:rag-ingest-pipeline' in tags:
            inject("ATLAS: Dataset and RAG Ingest Integrity Erosion", "RAG Ingest Poisoning Risk")

        # Agent orchestration (full agentic attack surface: context poisoning, config tamper, C2, escape)
        if 'ai:agent-orchestrator' in tags:
            inject("ATLAS: AI Agent Orchestration Hijack and Persistence", "Agent Orchestration Risk")
            # Orchestrators that process external content also inherit indirect injection
            if 'ai:indirect-prompt-input' not in tags:
                inject("ATLAS: Indirect Prompt Injection and Trusted Output Manipulation", "Agent Indirect Injection Risk")

        # Tool/plugin surface (tool poisoning, credential theft, exfil via tool calls)
        if 'ai:plugin-tool-use' in tags:
            inject("ATLAS: AI Agent Tool and Plugin Compromise", "Agent Tool Compromise Risk")

        # Agent persistent memory (memory/thread poisoning, chat history manipulation)
        if 'ai:agent-memory' in tags:
            inject("ATLAS: AI Agent Memory and Session State Poisoning", "Agent Memory Poisoning Risk")

        # LLM inference endpoint (API abuse, model extraction, DoAI, cost harvesting)
        if 'ai:llm-endpoint' in tags:
            inject("ATLAS: LLM Inference API Abuse, Cost Harvesting, and Model Extraction", "Inference API Abuse Risk")

        # Model serving host (supply chain compromise, weight manipulation, embedded malware)
        if 'ai:model-serving' in tags:
            inject("ATLAS: AI Model Supply Chain Compromise and Model Manipulation", "Model Supply Chain Risk")

        # Training / fine-tuning pipeline (data poisoning, backdoor insertion, CUI memorization)
        if 'ai:training-pipeline' in tags:
            inject("ATLAS: Training Data Poisoning and Model Backdoor Insertion", "Training Data Poisoning Risk")

        # Training dataset store (dataset exfiltration, integrity erosion, CUI at rest)
        if 'ai:dataset-store' in tags:
            inject("ATLAS: AI Training Dataset Exfiltration and Integrity Attack", "Dataset Store Attack Risk")

        # Model registry / artifact store (registry supply chain, rug pull, reputation inflation)
        if 'ai:model-registry' in tags:
            inject("ATLAS: AI Model Registry Supply Chain and Reputation Attack", "Model Registry Risk")

        # Model IP exfiltration boundary (model extraction, proxy creation, IP theft)
        if 'ai:model-exfil-risk' in tags:
            inject("ATLAS: AI Model Intellectual Property Theft and Proxy Model Creation", "Model IP Theft Risk")

        # --- 2b. MAESTRO GAP COVERAGE ---
        # Agent framework dependency supply chain (MAESTRO L3)
        if 'ai:agent-framework' in tags:
            inject("MAESTRO L3: Agent Framework and Dependency Supply Chain Compromise", "Framework Supply Chain Risk")

        # Evaluation pipeline integrity (MAESTRO L5)
        if 'ai:eval-pipeline' in tags:
            inject("MAESTRO L5: Evaluation Pipeline and Benchmark Poisoning", "Eval Pipeline Poisoning Risk")

        # Observability stack as adversarial target (MAESTRO L5)
        if 'ai:observability-stack' in tags:
            inject("MAESTRO L5: AI Observability Stack Compromise and Evidence Destruction", "Observability Compromise Risk")

        # AI-powered security tooling as target (MAESTRO L6)
        if 'ai:security-agent' in tags:
            inject("MAESTRO L6: AI-Powered Security Tooling Compromise", "Security AI Compromise Risk")

        # Multi-agent trust boundary — identity, impersonation, goal manipulation (MAESTRO L7)
        if 'ai:multi-agent-boundary' in tags:
            inject("MAESTRO L7: Agent Ecosystem Identity, Impersonation, and Goal Manipulation", "Agent Ecosystem Identity Risk")
            # Multi-agent boundaries also inherit indirect prompt injection since agents
            # interpret messages from other agents as instructions -- but only when
            # the asset isn't already directly tagged ai:indirect-prompt-input, the
            # same guard the ai:agent-orchestrator branch above already uses, to
            # avoid double-injecting the same category onto the same asset under two
            # different titles (e.g. every MCP server, which carries both tags at
            # once now that each one's own content-relay role is tagged explicitly).
            if 'ai:indirect-prompt-input' not in tags:
                inject("ATLAS: Indirect Prompt Injection and Trusted Output Manipulation", "Cross-Agent Injection Risk")

        # --- 2b(ii). AI OPERATIONAL AND DEPLOYMENT HARDENING GAPS ---
        # Beyond standard ATLAS/MAESTRO coverage -- see 03-tags-lib.yml's
        # "Operational and Deployment Hardening Surface" tags.

        if 'ai:ot-adjacent-output' in tags:
            inject("AI Output Path to OT or Safety-Critical Actuation Without Human Gate", "OT Actuation Boundary Risk")

        if any(t in tags for t in ('ai:user-prompt-input', 'ai:llm-endpoint', 'ai:agent-orchestrator')) \
                and 'ai:system-prompt-governed' not in tags:
            inject("Ungoverned Production System Prompt Change", "System Prompt Governance Risk")

        if 'ai:on-device-inference' in tags and 'ai:secure-enclave-protected' not in tags:
            inject("On-Device Model Extraction Resistance Gap", "On-Device Extraction Risk")

        if 'ai:air-gapped-model-delivery' in tags and 'ai:model-package-signed' not in tags:
            inject("Offline or Air-Gapped Model Package Integrity Gap", "Air-Gapped Model Integrity Risk")

        if 'ai:model-serving' in tags and 'ai:rollback-capable' not in tags:
            inject("Missing Model Rollback and Kill-Switch Mechanism", "Model Rollback Gap Risk")

        if 'ai:llm-endpoint' in tags and 'ai:canary-tested' not in tags:
            inject("No Canary Prompt Testing Against Production Inference Endpoint", "Canary Testing Gap Risk")

        if any(t in tags for t in ('ai:model-registry', 'ai:model-serving')) \
                and 'ai:registry-source-verified' not in tags:
            inject("Untrusted Model Registry Source", "Untrusted Registry Source Risk")

        if 'ai:training-pipeline' in tags:
            if 'ai:training-code-protected' not in tags:
                inject("Training Script and Feature-Engineering Pipeline IP Exfiltration", "Training Script Exfiltration Risk")
            if 'ai:hyperparameter-diffed' not in tags:
                inject("Hyperparameter Tampering Without Baseline Diffing", "Hyperparameter Tampering Risk")

        if 'ai:third-party-model-api' in tags and 'ai:vendor-model-governed' not in tags:
            inject("Ungoverned Third-Party Foundation Model API Dependency", "Third-Party Model API Risk")

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
            # Distinct from the above-releasable-content-inclusion (accidental)
            # and release-authority-bypass (technical/workflow circumvention)
            # risks -- this one is a legitimately authorized individual
            # deliberately misusing access no technical control can revoke.
            inject("CDS: Malicious Insider Abuse of Authorized Release Privileges", "CDS Insider Release Abuse Risk")

        if 'cds:high-side-receiver' in tags:
            inject("CDS: Low-to-High Content Integrity and Influence Risk", "CDS Inbound Integrity Risk")

        if 'cds:high-side-broker' in tags:
            inject("CDS: High-Side Transfer Broker Unauthorized Access and Queue Tampering", "CDS High-Side Broker Risk")

        # Covert channel — fires on any CDS transfer submitter/receiver interface
        # (timing/storage/feedback channel exposure, assessed per side)
        if 'cds:low-side-submitter' in tags or 'cds:low-side-receiver' in tags \
                or 'cds:high-side-submitter' in tags or 'cds:high-side-receiver' in tags:
            inject("CDS: Transfer Interface Covert Channel Exposure", "Covert Channel Exposure Risk")

        # --- 3. POLICY EXCEPTIONS (Explicit Bad) ---
        if 'exception:runs-as-root' in tags: inject("Container Runs as Root (Policy Exception)", "Root Waiver")
        if 'exception:eol-component' in tags: inject("EOL Component in ATO Boundary", "EOL Component Waiver")
        if 'exception:direct-admin-access' in tags: inject("Policy Exception: Direct Admin Access", "Admin Access Waiver")
        if 'exception:cleartext-internal' in tags: inject("Policy Exception: Cleartext Internal Transit", "Cleartext Waiver")
        if 'exception:local-auth-fallback' in tags: inject("Policy Exception: Local Authentication", "Local Auth Waiver")

        # --- 4. INFRASTRUCTURE BASELINE (Absence of Good) ---

        # TLS termination: FIPS compliance check (skip if already tagged compliant)
        if 'net:tls-terminator' in tags and 'compliance:fips-validated' not in tags:
            inject("FIPS Non-Compliant Cryptography", "FIPS Compliance Check")

        # TLS termination: deprecated protocol / weak cipher check (always fires on tls-terminator)
        if 'net:tls-terminator' in tags:
            inject("Deprecated TLS Versions and Weak Cipher Suites", "Weak TLS Configuration Risk")

        # Key management hardening -- fires on any secrets/key vault asset
        if 'storage:vault' in tags:
            if 'crypto:hsm-backed' not in tags or 'crypto:customer-managed-key' not in tags:
                inject("Key Storage and Ownership Hardening Gap", "Key Storage Hardening Risk")
            if 'crypto:key-rotation-tested' not in tags:
                inject("Key Rotation and Escrow Neglect", "Key Rotation Neglect Risk")
            if 'crypto:key-management-separated' not in tags:
                inject("Key Management Separation-of-Duties Violation", "Key Management SoD Risk")

        # Spillage check (all compute assets)
        if any(tag in tags for tag in ['app:frontend-ui', 'app:backend-api', 'app:async-worker']):
            inject("CUI Telemetry Spillage", "Log Spillage Risk")
            inject("Insufficient Audit Logging (AU-2 Compliance Gap)", "AU-2 Logging Gap Risk")
            inject("Mishandling of Exceptional Conditions", "Exceptional Conditions Risk")

        # Backend API authorization risks
        if 'app:backend-api' in tags:
            inject("Broken Object-Level Authorization (BOLA/IDOR)", "BOLA/IDOR Risk")
            inject("Broken Function-Level Authorization (BFLA)", "BFLA Risk")
            inject("Broken Object Property Level Authorization (Mass Assignment)", "Mass Assignment Risk")

        # Multi-tenancy amplifier: raises isolation risk when multi-tenancy is declared
        if 'feature:multi-tenancy' in tags:
            inject("Multi-Tenant Data Isolation Failure", "Multi-Tenant Isolation Risk")

        # Frontend session management
        if 'app:frontend-ui' in tags:
            inject("Insecure Session Management", "Session Management Risk")

        # Secrets sprawl — fires on any asset explicitly identified as a secrets broker
        # and on assets storing credentials (absence of a secrets broker tag is the risk signal)
        if 'sec:secrets-broker' not in tags and 'data:credential' in tags:
            inject("Hardcoded Credentials and Secrets Sprawl", "Secrets Sprawl Risk")

        # Backup integrity — fires on all assets requiring backup
        if 'ops:requires-backup' in tags:
            inject("Backup Integrity and Recovery Assurance Gap", "Backup Integrity Risk")

            # Sharper, independently-triggerable backup/DR risks alongside
            # the bundled one above -- see 03-tags-lib.yml's "Backup and
            # Recovery Hardening" tags for what each suppresses.
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

        # SaaS/vendor-hosted assets the enterprise backup platform can't enroll
        if 'ops:vendor-hosted-service' in tags and 'ops:saas-export-configured' not in tags:
            inject("Unsupported or SaaS Service Backup Gap", "SaaS Backup Gap Risk")

        # Internet-facing assets without confirmed WAF
        if 'zone:dmz' in tags and 'ops:waf-enabled' not in tags:
            inject("Missing Web Application Firewall on Internet-Facing Asset", "Missing WAF Risk")

        # Internet-facing assets without reconciled DNS records
        if 'zone:dmz' in tags and 'ops:dns-record-reconciled' not in tags:
            inject("Dangling DNS Record and Subdomain Takeover", "Dangling DNS Risk")

        # Network-based detection gap -- uses the broader net:internet-reachable
        # tag, not just a direct zone:dmz tag, since an NIDS/NDR sensor
        # placed at the actual edge component doesn't automatically cover
        # traffic to the real application a few hops behind it.
        if (asset_is_internet_reachable or 'zone:dmz' in tags) and 'net:ids-monitored' not in tags:
            inject("Network Intrusion Detection and Traffic Anomaly Blind Spot", "Network IDS Blind Spot Risk")

        # Baseline security-event logging -- fires on the general app tier,
        # distinct from the narrower feature:public-api-endpoint-gated API
        # abuse logging check above, so a generic frontend/backend/worker
        # asset with no public API surface still gets Detection coverage.
        if (set(tags) & APP_TIER_TAGS) and 'ops:security-event-logging-enabled' not in tags:
            inject("Baseline Security Event Logging and SIEM Forwarding Gap", "Baseline Security Logging Gap Risk")

        # Container Hardening Audits
        if asset_data.get('machine') == 'container':
            if 'ops:trusted-base-image' not in tags: inject("Untrusted Container Image Supply Chain", "Unverified Image Source")
            if 'ops:read-only-fs' not in tags: inject("Mutable Container Filesystem", "Writable Filesystem")
            if 'net:micro-segmented' not in tags: inject("Missing Network Micro-Segmentation", "Unrestricted East-West Traffic")
            if 'ops:container-capabilities-restricted' not in tags: inject("Dangerous Container Linux Capabilities", "Excessive Container Capabilities Risk")
            if 'ops:cluster-audit-logging-enabled' not in tags: inject("Container Orchestrator Control-Plane Audit Logging Gap", "Cluster Audit Logging Gap Risk")

        # Physical Host Hardening Audits (self-managed bare metal only --
        # BMC/firmware/boot-chain don't apply to a cloud-provisioned VM,
        # where the hypervisor host is the cloud provider's responsibility)
        if asset_data.get('machine') == 'physical' \
                and 'mgmt:self-managed-hardware' in tags and 'mgmt:self-managed-hardware-hardened' not in tags:
            inject("Self-Managed Out-of-Band Management Controller Compromise", "BMC Compromise Risk")
            inject("Self-Managed Below-OS Firmware Persistence Gap", "Firmware Persistence Risk")
            inject("Self-Managed Boot Integrity Bypass", "Boot Integrity Risk")

        # VM Hardening Audits
        if asset_data.get('machine') == 'virtual':
            if 'ops:host-agents-installed' not in tags: inject("Missing Endpoint Security Agents", "Unmonitored IaaS Endpoint")
            if 'ops:stig-baseline' not in tags: inject("Unhardened OS / Missing Patch Management", "Non-STIG OS / Unpatched VM")
            if 'ops:disk-encrypted' not in tags: inject("Unencrypted Virtual Disk", "Unencrypted VHD")
            if 'ops:media-sanitization-documented' not in tags: inject("Media Sanitization Procedure Gap", "Media Sanitization Gap")

        # --- 5. DATA GOVERNANCE AND LIFECYCLE ---
        # All absence-fires-risk, following the same pattern as the
        # Infrastructure Baseline checks above -- see 03-tags-lib.yml's
        # "DATA GOVERNANCE AND LIFECYCLE TAGS" section for what each
        # positive-confirmation tag means.

        if 'storage:persistent' in tags:
            if 'data:classification-scanned' not in tags:
                inject("Unclassified or Unscanned Data Store", "Unscanned Data Store Risk")
            if 'data:retention-scheduled' not in tags:
                inject("Missing Data Retention and Disposition Schedule", "Data Retention Schedule Risk")

        if ('storage:persistent' in tags or 'storage:vault' in tags) and 'data:data-plane-audit-enabled' not in tags:
            inject("Data Store Audit Logging and Anomalous Access Detection Gap", "Data Store Audit Gap Risk")

        # PIA requirement (E-Gov Act Sec. 208) attaches to processing PII at
        # all, not just persisting it -- deliberately not nested under
        # storage:persistent above.
        if 'data:pii' in tags and 'data:pia-documented' not in tags:
            inject("Missing Privacy Impact Assessment", "Missing PIA Risk")

        if ('data:external-feed-ingest' in tags or 'ai:dataset-store' in tags) and 'data:provenance-tracked' not in tags:
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

        # Containment disposition -- fires on internet-reachable, exception-
        # bearing, or CDS-interface assets, and on every tagged asset once
        # the model itself is business-critical/mission-critical (reuses
        # model_is_business_critical rather than a separate per-asset
        # criticality tag, since Threagile has no such field). Uses the
        # broader net:internet-reachable tag rather than a direct zone:dmz
        # check -- an incident responder needs a containment disposition
        # for whatever asset is a plausible compromise target, and that's
        # usually the application a few hops behind the DMZ edge, not the
        # edge component itself.
        if 'ir:containment-disposition-documented' not in tags and (
                model_is_business_critical
                or asset_is_internet_reachable
                or any(tag.startswith('exception:') for tag in tags)
                or any(tag.startswith('cds:') for tag in tags)):
            inject("Undocumented Incident Containment Disposition", "Containment Disposition Gap Risk")

        # Credential blast radius -- fires on secrets brokers and any asset
        # holding credential material.
        if ('sec:secrets-broker' in tags or 'data:credential' in tags) \
                and 'ir:credential-inventory-documented' not in tags:
            inject("Undocumented Credential Blast Radius for Incident-Driven Rotation", "Credential Blast Radius Risk")

        # IR plan testing, DFARS breach-notification ownership, and forensic
        # chain-of-custody are program-level facts about the whole system
        # rather than a per-asset property (unlike the credential-inventory
        # check above, which genuinely varies by asset) -- gated on
        # model_is_business_critical alone, deliberately without the
        # broader internet-reachable/exception/cds ORs the containment-
        # disposition check above uses, since none of those conditions make
        # "is our IR plan tested" true independent of the model's own
        # criticality.
        if model_is_business_critical:
            if 'ir:plan-tested' not in tags:
                inject("Untested Incident Response Plan", "Untested IR Plan Risk")
            if 'ir:breach-notification-procedure-documented' not in tags:
                inject("DFARS 252.204-7012 72-Hour Cyber Incident Reporting Gap", "Breach Notification Gap Risk")
            if 'ir:evidence-handling-documented' not in tags:
                inject("Forensic Evidence Chain-of-Custody Gap", "Chain-of-Custody Gap Risk")

        # --- 7. SOFTWARE SUPPLY CHAIN AND CI/CD PIPELINE INTEGRITY ---
        if 'ops:ci-pipeline' in tags:
            if 'ops:dependency-proxy-enforced' not in tags:
                inject("Dependency Confusion via Unclaimed Internal Package Namespace", "Dependency Confusion Risk")
            if 'ops:install-scripts-restricted' not in tags:
                inject("Malicious Package Install-Script Execution on CI Runner", "Malicious Install-Script Risk")
            if 'ops:pipeline-changes-reviewed' not in tags:
                inject("CI/CD Pipeline and Admission-Policy Tampering Outside Repository Trail", "Pipeline Tampering Risk")

        # --- 8. NETWORK SEGMENTATION AND PERIMETER (SELF-MANAGED) ---
        if 'mgmt:self-managed-network' in tags and 'mgmt:self-managed-network-hardened' not in tags:
            inject("No Macro or Micro-Segmentation of Self-Managed Network", "Self-Managed Segmentation Gap Risk")
            inject("Rogue Access Point and Evil-Twin Credential Harvesting on Self-Managed Wireless", "Rogue AP Risk")
            inject("Missing Route Origin Validation on Self-Managed External Routing", "Missing RPKI Validation Risk")

    # 5. Convert to this engine's custom_risk_categories schema: a list of
    # category objects with an explicit 'title' field, not a dict keyed by
    # title. Built up as a title-keyed dict above (model['individual_risk_
    # categories']) purely for the setdefault()/lookup convenience in
    # inject() -- that was also the literal field name and shape Threagile
    # itself expected before this engine's custom_risk_categories rename
    # (map -> list), but this engine now silently drops an unrecognized
    # top-level key instead of erroring, so a model carrying the old key
    # "works" end to end while generating zero custom findings. Convert
    # right before writing, so inject()'s own logic above needs no change.
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