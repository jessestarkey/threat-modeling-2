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
LIKELIHOOD_ORDER = ["unlikely", "possible", "likely", "very-likely"]
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

# Technology-name sets, canonical name only, for a handful of checks that
# still live in Python but whose trigger condition is better read off the
# asset's own native `technology:` field instead of a same-named ai:* tag
# -- a tag naming the same concept as a technology an app can already
# select is a second, unenforced source of truth for the same fact.
# Deliberately NOT the `aliases:` list from the matching entry in
# pkg/types/technologies.yaml in the jessestarkey/threagile fork: Threagile
# itself resolves a `technology:` value by exact canonical-key lookup only
# (TechnologyMap.Get() in pkg/types/technology-map.go is a plain map
# lookup) -- aliases are documentation-only and never accepted in a real
# model's `technology:` field, so a model that used one would already be
# rejected by Threagile before ever reaching this script in a complete
# pipeline run. See docs/risk-methodology.md.
RAG_PIPELINE_TECHNOLOGIES = {"ai-rag-pipeline"}
AGENT_ORCHESTRATOR_TECHNOLOGIES = {"ai-agent-orchestrator"}
MULTI_AGENT_GATEWAY_TECHNOLOGIES = {"ai-multi-agent-gateway"}
DATASET_STORE_TECHNOLOGIES = {"ai-dataset-store"}

# Likelihood x Impact -> Severity, via a weight-product-and-threshold
# formula rather than a hand-authored rank-sum lookup table (an earlier
# version of this file used the latter -- see git history). Switched to
# keep this in lockstep with the same change made to Threagile's own
# built-in CalculateSeverity() in the forked engine (pkg/types/model.go) --
# both now score (likelihood, impact) identically in shape, even though
# they remain two independent scoring paths by design (see
# docs/risk-methodology.md's "Could the custom engine just adopt
# Threagile's own formula?" section for why that independence itself is
# kept). WEIGHT is Fibonacci-spaced (1, 2, 3, 5) rather than linear
# (1, 2, 3, 4): the real-world jump in exploitability/consequence from
# Likely to Very-Likely (or High to Very-High) is bigger than the jump
# from Unlikely to Possible (or Low to Medium), so equal linear steps
# understate it -- the same non-linear-tier-gap reasoning this file's own
# RAA weight tables below already use for Confidentiality/Criticality
# ranks. Validated against a real ~186-finding custom-risk run before
# landing: this window produces one more distinct severity value across
# the 16 likelihood x impact cells than linear weights do (10 vs 9), and
# the one tie it breaks is a real one -- Likely x Likely (moderate on both
# axes) no longer scores identically to Unlikely x VeryHigh (rare but
# catastrophic), which linear weights conflated.
#
# Thresholds chosen to preserve the same shape the old hand-authored
# matrix had rather than an arbitrary rescale: Low and Critical both stay
# a single-cell minority (product 1, and product 25 -- Very-Likely x
# Very-High, the one cell at both axes' true maximum), with Medium/
# Elevated/High banding the 8 distinct values in between in the same
# relative order: 1->Low, {2,3}->Medium, {4,5,6}->Elevated,
# {9,10,15}->High, 25->Critical. No exception cell needed this time --
# unlike the old rank-sum rule, Fibonacci's own non-linear spacing already
# keeps Critical naturally rare (1 of 16 cells) without having to
# hand-override one.
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


# NOTE: APP_TIER_TAGS (app:frontend-ui, app:backend-api, app:async-worker) used to be defined
# here for the Baseline Security Event Logging check, which has since been ported into the
# jessestarkey/threagile fork as a native script rule triggered off the frontend_related/
# backend_related technology attributes instead. That was the constant's last use, so it and
# its 3 member tags are now fully unused and removed. See docs/risk-methodology.md.

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
        asset_technology = asset_data.get('technology')
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
        # OWASP API Security Top 10:2023 API6 -- distinct from the asymmetric-DoS/rate-limiting
        # framing above: this is about automated/bulk abuse of a legitimate multi-step business
        # process itself (bulk account creation, ticket/inventory scalping), not raw request
        # volume.
        if 'feature:sensitive-business-flow' in tags:
            inject("Unrestricted Access to Sensitive Business Flows", "Business Flow Abuse Risk")
        # OWASP API Security Top 10:2023 API10 -- the inverse of SSRF: this asset calls a
        # legitimate external API and trusts its response content/schema without validation,
        # rather than its own request being hijacked to hit an unintended target.
        if 'net:external-api-consumer' in tags:
            inject("Unsafe Consumption of APIs", "Unsafe API Consumption Risk")
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
        if 'feature:browser-facing' in tags and 'ops:cors-csp-hardened' not in tags:
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

        # Deliberately NOT nested under mgmt:self-managed-*: workload role assignments are
        # owned by the app team even when the landing zone itself is inherited, so this
        # applies to every ordinary app workload regardless of self-managed status -- unlike
        # Standing Privileged Access above, which is specifically about human admin
        # credentials on a self-managed PAM deployment.
        if 'mgmt:workload-identity-assigned' in tags and 'mgmt:workload-identity-least-privilege' not in tags:
            inject("Over-Privileged Workload Identity and Cloud Control-Plane Pivot", "Workload Identity Overprivilege Risk")

        # --- 2. MITRE ATLAS AI/ML THREAT VECTORS ---
        # One inject call per risk category, keyed to the new tag namespace.
        # Tags and the risk definitions they trigger:

        # Prompt input surface (direct injection, jailbreak, system prompt extraction)
        if 'ai:user-prompt-input' in tags:
            inject("ATLAS: LLM Prompt Injection (Direct) and Jailbreak", "Direct Prompt Injection Risk")

        # Indirect injection surface (emails, docs, web content fed to LLM)
        if 'ai:indirect-prompt-input' in tags:
            inject("ATLAS: Indirect Prompt Injection and Trusted Output Manipulation", "Indirect Prompt Injection Risk")

        # NOTE: "ATLAS: RAG Pipeline Poisoning and Data Exfiltration" has been ported into the
        # jessestarkey/threagile fork as a native script rule
        # (pkg/risks/scripts/atlas-rag-poisoning-exfil.yaml), triggered off the new native
        # rag-pipeline technology instead of the ai:rag-pipeline tag. Removed here rather than
        # left duplicated. The ai:rag-pipeline TAG is also now fully removed from
        # 03-tags-lib.yml -- the indirect-prompt-injection half just below reads the asset's
        # own native `technology:` field instead, since a tag naming the same concept as a
        # selectable technology was a second, unenforced source of truth for the same fact.
        # See docs/risk-methodology.md for the full rationale.
        if asset_technology in RAG_PIPELINE_TECHNOLOGIES:
            # RAG retrieval is inherently an indirect prompt injection surface
            inject("ATLAS: Indirect Prompt Injection and Trusted Output Manipulation", "RAG Indirect Injection Risk")

        # NOTE: "ATLAS: Dataset and RAG Ingest Integrity Erosion" has been ported into the
        # jessestarkey/threagile fork as a native script rule
        # (pkg/risks/scripts/atlas-dataset-ingest-integrity.yaml), triggered off the new native
        # rag-ingest-pipeline technology instead of the ai:rag-ingest-pipeline tag. This was its
        # only use, so the tag is now fully removed from 03-tags-lib.yml too. See
        # docs/risk-methodology.md for the full rationale.

        # NOTE: "ATLAS: AI Agent Orchestration Hijack and Persistence" has been ported into the
        # jessestarkey/threagile fork as a native script rule
        # (pkg/risks/scripts/atlas-agent-orchestration-hijack.yaml), triggered off the new
        # native agent-orchestrator technology instead of the ai:agent-orchestrator tag.
        # Removed here rather than left duplicated. The ai:agent-orchestrator TAG is also now
        # fully removed from 03-tags-lib.yml -- the indirect-prompt-injection half just below
        # reads the asset's own native `technology:` field instead, same reasoning as the
        # rag-pipeline case above. (The AI OT-actuation check below reads only
        # ai:ot-adjacent-output, standalone -- it never depended on this tag.) See
        # docs/risk-methodology.md for the full rationale.
        if asset_technology in AGENT_ORCHESTRATOR_TECHNOLOGIES:
            # Orchestrators that process external content also inherit indirect injection
            if 'ai:indirect-prompt-input' not in tags:
                inject("ATLAS: Indirect Prompt Injection and Trusted Output Manipulation", "Agent Indirect Injection Risk")

        # Tool/plugin surface (tool poisoning, credential theft, exfil via tool calls)
        if 'ai:plugin-tool-use' in tags:
            inject("ATLAS: AI Agent Tool and Plugin Compromise", "Agent Tool Compromise Risk")

        # Agent persistent memory (memory/thread poisoning, chat history manipulation)
        if 'ai:agent-memory' in tags:
            inject("ATLAS: AI Agent Memory and Session State Poisoning", "Agent Memory Poisoning Risk")

        # NOTE: "ATLAS: LLM Inference API Abuse, Cost Harvesting, and Model Extraction" and
        # "ATLAS: Unbounded AI Resource Consumption and Denial of Service" -- both triggered by
        # ai:llm-endpoint -- have been ported into the jessestarkey/threagile fork as native
        # script rules (pkg/risks/scripts/atlas-inference-api-abuse.yaml and
        # atlas-unbounded-ai-consumption.yaml), triggered off the new native llm-endpoint
        # technology instead. Removed here rather than left duplicated. ai:llm-endpoint stays
        # -- still read further below for the AI OT-actuation and canary-testing checks,
        # neither of which is ported yet. ai:resource-budget-enforced was only ever the
        # suppression tag for the now-removed unbounded-consumption check, so it's fully
        # unused now and removed from 03-tags-lib.yml too. See docs/risk-methodology.md for
        # the full rationale.

        # NOTE: "ATLAS: AI Model Supply Chain Compromise and Model Manipulation" has been
        # ported into the jessestarkey/threagile fork as a native script rule
        # (pkg/risks/scripts/atlas-model-supply-chain.yaml), triggered off the new native
        # model-serving technology instead of the ai:model-serving tag. Removed here rather
        # than left duplicated. The tag itself stays -- still read further below for the
        # model-rollback and registry-source checks, neither of which is ported yet.

        # NOTE: "ATLAS: Training Data Poisoning and Model Backdoor Insertion" has been ported
        # into the jessestarkey/threagile fork as a native script rule
        # (pkg/risks/scripts/atlas-training-data-poisoning.yaml), triggered off the new native
        # training-pipeline technology instead of the ai:training-pipeline tag. Removed here
        # rather than left duplicated. The tag itself stays -- still read further below for the
        # training-script-exfiltration and hyperparameter-tampering checks, which are also
        # being ported in this same pass (see below).

        # NOTE: "ATLAS: AI Training Dataset Exfiltration and Integrity Attack" has been ported
        # into the jessestarkey/threagile fork as a native script rule
        # (pkg/risks/scripts/atlas-dataset-store-attack.yaml), triggered off the new native
        # dataset-store technology instead of the ai:dataset-store tag. Removed here rather than
        # left duplicated. The ai:dataset-store TAG is also now fully removed from
        # 03-tags-lib.yml -- the Missing Data Provenance and Lineage Chain-of-Custody check
        # further below reads the asset's own native `technology:` field instead (ORed with
        # the unrelated data:external-feed-ingest tag, which stays as-is), same reasoning as
        # the rag-pipeline/agent-orchestrator cases above.

        # NOTE: "ATLAS: AI Model Registry Supply Chain and Reputation Attack" has been ported
        # into the jessestarkey/threagile fork as a native script rule
        # (pkg/risks/scripts/atlas-model-registry-supply-chain.yaml), triggered off the new
        # native model-registry technology instead of the ai:model-registry tag. Removed here
        # rather than left duplicated. The tag itself stays -- still read further below for the
        # registry-source check, not yet ported.

        # NOTE: "ATLAS: AI Model Intellectual Property Theft and Proxy Model Creation" has been
        # removed, not ported -- re-reading its own description ("sits at a boundary where
        # systematic inference queries can be used to reconstruct a functional proxy of the
        # model or recover details of its training data") against the already-native
        # atlas-inference-api-abuse.yaml ("systematically queried to extract a functional copy
        # of the model, infer training data membership") showed they were describing the same
        # attack, not two distinct ones. This was ai:model-exfil-risk's only use, so the tag is
        # now fully removed from 03-tags-lib.yml too. See docs/risk-methodology.md.

        # --- 2b. MAESTRO GAP COVERAGE ---
        # Agent framework dependency supply chain (MAESTRO L3)
        if 'ai:agent-framework' in tags:
            inject("MAESTRO L3: Agent Framework and Dependency Supply Chain Compromise", "Framework Supply Chain Risk")

        # NOTE: "MAESTRO L5: Evaluation Pipeline and Benchmark Poisoning," "MAESTRO L5: AI
        # Observability Stack Compromise and Evidence Destruction," and "MAESTRO L6: AI-Powered
        # Security Tooling Compromise" have all been ported into the jessestarkey/threagile
        # fork as native script rules (pkg/risks/scripts/*.yaml), triggered off the new native
        # eval-pipeline/ai-observability-stack/ai-security-agent technologies instead of the
        # ai:eval-pipeline/ai:observability-stack/ai:security-agent tags. Each was that tag's
        # only use, so all 3 tags are now fully removed from 03-tags-lib.yml too. See
        # docs/risk-methodology.md for the full rationale.

        # NOTE: "MAESTRO L7: Agent Ecosystem Identity, Impersonation, and Goal Manipulation" has
        # been ported into the jessestarkey/threagile fork as a native script rule
        # (pkg/risks/scripts/maestro-l7-agent-ecosystem-identity.yaml), triggered off the new
        # native multi-agent-gateway technology instead of the ai:multi-agent-boundary tag.
        # Removed here rather than left duplicated. The ai:multi-agent-boundary TAG is also
        # now fully removed from 03-tags-lib.yml -- the indirect-prompt-injection piggyback
        # just below reads the asset's own native `technology:` field instead, same reasoning
        # as the rag-pipeline/agent-orchestrator/dataset-store cases above.
        if asset_technology in MULTI_AGENT_GATEWAY_TECHNOLOGIES:
            # Multi-agent gateways also inherit indirect prompt injection since agents
            # interpret messages from other agents as instructions -- but only when
            # the asset isn't already directly tagged ai:indirect-prompt-input, the
            # same guard the agent-orchestrator branch above already uses, to
            # avoid double-injecting the same category onto the same asset under two
            # different titles (e.g. every MCP server, which also carries the
            # indirect-prompt-input tag once its own content-relay role is tagged
            # explicitly).
            if 'ai:indirect-prompt-input' not in tags:
                inject("ATLAS: Indirect Prompt Injection and Trusted Output Manipulation", "Cross-Agent Injection Risk")

        # --- 2b(ii). AI OPERATIONAL AND DEPLOYMENT HARDENING GAPS ---
        # Beyond standard ATLAS/MAESTRO coverage -- see 03-tags-lib.yml's
        # "Operational and Deployment Hardening Surface" tags.

        if 'ai:ot-adjacent-output' in tags:
            inject("AI Output Path to OT or Safety-Critical Actuation Without Human Gate", "OT Actuation Boundary Risk")

        # NOTE: "Ungoverned Production System Prompt Change," "No Canary Prompt Testing Against
        # Production Inference Endpoint," "Missing Model Rollback and Kill-Switch Mechanism,"
        # and "Untrusted Model Registry Source" have all been ported into the
        # jessestarkey/threagile fork as native script rules (pkg/risks/scripts/*.yaml),
        # triggered off the native llm-endpoint/rag-pipeline/agent-orchestrator/model-serving/
        # model-registry technology attributes instead of re-checking tags of the same name.
        # Removed here rather than left duplicated. This was the last use of ai:llm-endpoint,
        # ai:model-serving, and ai:model-registry in this file, so all 3 tags are now fully
        # removed from 03-tags-lib.yml too. ai:agent-orchestrator and ai:rag-pipeline stay --
        # each still has one other, unrelated use (the indirect-prompt-injection piggyback)
        # elsewhere in this file. See docs/risk-methodology.md for the full rationale.

        # NOTE: "On-Device Model Extraction Resistance Gap" has been ported into the
        # jessestarkey/threagile fork as a native script rule
        # (pkg/risks/scripts/on-device-model-extraction-gap.yaml), triggered off the native
        # `machine` field (physical, matched by excluding virtual/container/serverless rather
        # than equal-matching physical directly -- it's machine's zero value with yaml
        # omitempty, so it never survives the script engine's own internal re-serialization as
        # a literal string) combined with the ai-model-serving/ai-llm-endpoint technology
        # attributes, instead of the ai:on-device-inference tag. Removed here rather than left
        # duplicated. This was ai:on-device-inference's and ai:secure-enclave-protected's only
        # use, so both tags are now fully removed from 03-tags-lib.yml too. The sibling
        # "Offline or Air-Gapped Model Package Integrity Gap" stays below -- "air-gapped/
        # disconnected" has no native field to trigger off (internet: false is set on far too
        # many ordinary internal assets to serve as a proxy). See docs/risk-methodology.md.

        if 'ai:air-gapped-model-delivery' in tags and 'ai:model-package-signed' not in tags:
            inject("Offline or Air-Gapped Model Package Integrity Gap", "Air-Gapped Model Integrity Risk")

        # NOTE: "Training Script and Feature-Engineering Pipeline IP Exfiltration" and
        # "Hyperparameter Tampering Without Baseline Diffing" have both been ported into the
        # jessestarkey/threagile fork as native script rules (pkg/risks/scripts/*.yaml),
        # triggered off the native training-pipeline technology instead of the
        # ai:training-pipeline tag. This was the tag's last remaining use, so it and its 2
        # suppression tags (ai:training-code-protected, ai:hyperparameter-diffed) are now fully
        # removed from 03-tags-lib.yml too. See docs/risk-methodology.md for the full rationale.

        if 'ai:third-party-model-api' in tags and 'ai:vendor-model-governed' not in tags:
            inject("Ungoverned Third-Party Foundation Model API Dependency", "Third-Party Model API Risk")

        if 'ai:decision-support-output' in tags and 'ai:output-confidence-disclosed' not in tags:
            inject("AI-Generated Decision Support Without Verification Signal", "AI Overreliance Risk")

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

        # NOTE: the key management hardening cluster (Key Storage and Ownership Hardening Gap,
        # Key Rotation and Escrow Neglect, Key Management Separation-of-Duties Violation) that
        # used to live here has been ported into the jessestarkey/threagile fork as native
        # script rules (pkg/risks/scripts/*.yaml), triggered off the native vault technology
        # attribute instead of the storage:vault tag. Removed here rather than left duplicated.
        # storage:vault itself stays in 03-tags-lib.yml -- still used below by the Data Store
        # Audit Logging check. See docs/risk-methodology.md for the full rationale.

        # NOTE: the app-tier baseline cluster that used to live here (CUI Telemetry Spillage,
        # AU-2 Logging Gap, Mishandling of Exceptional Conditions, BOLA/BFLA/Mass Assignment,
        # Multi-Tenant Data Isolation Failure, Insecure Session Management, Hardcoded
        # Credentials and Secrets Sprawl) has been ported into the jessestarkey/threagile fork
        # as native script rules (pkg/risks/scripts/*.yaml) -- 8 of 9 fully native (frontend/
        # backend-related and request-serving-API technology attributes, the native MultiTenant
        # field), one (secrets sprawl) still reading the data:credential tag directly since
        # DataAsset has no native "this is credential-shaped data" concept. Removed here rather
        # than left duplicated, since the Go-native versions fire unconditionally (disposed via
        # risk_tracking) and would otherwise double up with this Python injection on every app
        # run through the custom image. See docs/risk-methodology.md for the full rationale.
        #
        # app:frontend-ui/app:backend-api/app:async-worker have since also been fully removed
        # (the Baseline Security Event Logging check that was their last use is now native too
        # -- see below). sec:secrets-broker/data:credential are still used below by the
        # Credential Blast Radius check and stay -- checked against confluence's real tag usage,
        # sec:secrets-broker spans identity-provider/reverse-proxy/local-file-system/database
        # assets, not just vault technology, so it isn't a faithful native substitute the way
        # storage:vault was for the key-management batch.

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

        # Internet-facing assets without confirmed WAF. Auto-suppressed when the asset's own
        # native `technology:` is already `waf` -- that's Threagile's own technology value for
        # "this asset IS a web application firewall," a stronger and less error-prone signal
        # than relying on a human to also remember the ops:waf-enabled tag on top of it (found
        # via real data: both of confluence's zone:dmz gateway assets already set
        # technology: waf and additionally carried ops:waf-enabled, which was pure duplication).
        # ops:waf-enabled stays as an explicit fallback for the case this native check can't
        # see -- a separate upstream WAF asset (e.g. an external CDN-level WAF) not modeled as
        # this asset's own technology.
        if 'zone:dmz' in tags and asset_technology != 'waf' and 'ops:waf-enabled' not in tags:
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

        # NOTE: "Baseline Security Event Logging and SIEM Forwarding Gap" has been ported into
        # the jessestarkey/threagile fork as a native script rule
        # (pkg/risks/scripts/baseline-security-event-logging-gap.yaml), triggered off the
        # frontend_related/backend_related technology attributes instead of APP_TIER_TAGS.
        # Removed here rather than left duplicated. This was the last use of APP_TIER_TAGS, so
        # the constant and its 3 member tags are now fully unused -- see the removal below and
        # in 03-tags-lib.yml. See docs/risk-methodology.md for the full rationale.

        # NOTE: the Container Hardening Audits and VM Hardening Audits blocks that used to live
        # here (5 container checks, 4 VM checks) have been ported into the jessestarkey/threagile
        # fork as native script rules (pkg/risks/scripts/*.yaml), triggered off the native
        # `machine` field instead of a tag, firing unconditionally and disposed via risk_tracking
        # instead of a suppression tag. Removed here rather than left duplicated. See
        # docs/risk-methodology.md for the full rationale.
        #
        # Physical Host Hardening Audits (self-managed bare metal only -- BMC/firmware/boot-chain
        # don't apply to a cloud-provisioned VM, where the hypervisor host is the cloud provider's
        # responsibility) stays here: zero of the real apps have ever fired it, so it's not yet
        # proven against a real self-managed app worth the Go port.
        if asset_data.get('machine') == 'physical' \
                and 'mgmt:self-managed-hardware' in tags and 'mgmt:self-managed-hardware-hardened' not in tags:
            inject("Self-Managed Out-of-Band Management Controller Compromise", "BMC Compromise Risk")
            inject("Self-Managed Below-OS Firmware Persistence Gap", "Firmware Persistence Risk")
            inject("Self-Managed Boot Integrity Bypass", "Boot Integrity Risk")

        # --- 5. DATA GOVERNANCE AND LIFECYCLE ---
        # All absence-fires-risk, following the same pattern as the
        # Infrastructure Baseline checks above -- see 03-tags-lib.yml's
        # "DATA GOVERNANCE AND LIFECYCLE TAGS" section for what each
        # positive-confirmation tag means.

        # NOTE: the datastore cluster that used to live here (Unclassified or Unscanned Data
        # Store, Missing Data Retention and Disposition Schedule, Data Store Audit Logging and
        # Anomalous Access Detection Gap) has been ported into the jessestarkey/threagile fork
        # as native script rules (pkg/risks/scripts/*.yaml), triggered off the native
        # TechnicalAsset.Type == datastore field instead of the storage:persistent/storage:vault
        # tags (every real asset tagged with either is already type: datastore, so the native
        # field subsumes both). Removed here rather than left duplicated. See
        # docs/risk-methodology.md for the full rationale.

        # PIA requirement (E-Gov Act Sec. 208) attaches to processing PII at
        # all, not just persisting it -- deliberately not nested under
        # storage:persistent above.
        if 'data:pii' in tags and 'data:pia-documented' not in tags:
            inject("Missing Privacy Impact Assessment", "Missing PIA Risk")

        if ('data:external-feed-ingest' in tags or asset_technology in DATASET_STORE_TECHNOLOGIES) and 'data:provenance-tracked' not in tags:
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
        # chain-of-custody are conceptually program-level facts about the
        # whole system, not per-asset ones -- a brief experiment collapsed
        # them into one model-level finding each (see git history) to stop
        # a single undocumented fact from showing up as 17 separate
        # findings on a real app. Reverted: risk acceptance/disposition is
        # tracked per finding via risk_tracking, and that sign-off has to
        # happen per asset regardless of whether the underlying fact is
        # org-wide -- a single finding covering 17 assets can't be
        # half-accepted. Per-asset injection, same as every other check in
        # this loop, is the right shape for that workflow even though it
        # means the same organizational gap is visible once per asset.
        if model_is_business_critical:
            if 'ir:plan-tested' not in tags:
                inject("Untested Incident Response Plan", "Untested IR Plan Risk")
            if 'ir:breach-notification-procedure-documented' not in tags:
                inject("DFARS 252.204-7012 72-Hour Cyber Incident Reporting Gap", "Breach Notification Gap Risk")
            if 'ir:evidence-handling-documented' not in tags:
                inject("Forensic Evidence Chain-of-Custody Gap", "Chain-of-Custody Gap Risk")

        # --- 7. SOFTWARE SUPPLY CHAIN AND CI/CD PIPELINE INTEGRITY ---
        # NOTE: this entire cluster (Dependency Confusion via Unclaimed Internal Package
        # Namespace, Malicious Package Install-Script Execution on CI Runner, CI/CD Pipeline and
        # Admission-Policy Tampering Outside Repository Trail) has been ported into the
        # jessestarkey/threagile fork as native script rules (pkg/risks/scripts/*.yaml),
        # triggered off the native build-pipeline technology attribute instead of the
        # ops:ci-pipeline tag. Removed here rather than left duplicated. See
        # docs/risk-methodology.md for the full rationale.

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