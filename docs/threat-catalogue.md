# Threat Catalogue

A complete reference of every vulnerability-class risk category this framework can identify, across all three layers of the engine:

| Layer | Count | Source |
|---|---|---|
| Built-in rules | 35 | `pkg/risks/builtin/*_rule.go` in the `jessestarkey/threagile` fork |
| Native script rules | 73 | `pkg/risks/scripts/*.yaml` in the `jessestarkey/threagile` fork |
| Custom categories | 87 | `models/central-security-repo/libraries/09-custom-risks-lib.yml`, injected by `inject_risks.py` |
| **Total** | **195** | |

Threagile's own ~7 model-authoring-consistency rules (incomplete model, unnecessary assets/links, wrong content, etc.) are excluded — they flag problems in how a model was *built*, not architecture risks, and have no meaningful baseline Likelihood/Impact to catalogue the way a real vulnerability class does.

## How to read each entry

Every entry follows the same five fields:

- **Applies to** — the exact technology, attribute, tag, or behavior that triggers this category, read directly from the rule's own match condition (not inferred from its description).
- **Why it applies there** — the justification for that match condition. Quoted from an existing comment where one exists; labeled **(Structural inference)** where it doesn't, rather than invented.
- **Baseline Likelihood / Baseline Impact** — the asset-independent starting value, *before* any per-asset adjustment. See [Methodology](#methodology) below for what happens next.

Every claim traces to something actually present in the source — a field, a comment, a citation already in that category's own `references`/`Mitigation` text. Where no written justification exists anywhere in the source, the entry says so plainly instead of fabricating one.

## Methodology

A baseline is not the final score. Every real finding gets two further adjustments before severity is computed, applied identically across all three layers as of this session's recalibration work:

- **Likelihood** gets a -1/0/+1 delta from the specific asset's own RAA (Relative Attacker Attractiveness) — elevated (≥40%) nudges up, low (<15%) nudges down, same threshold everywhere.
- **Impact** gets a -1/0/+1 delta from the asset's own rating on whichever single CIA dimension the finding's STRIDE category actually threatens (e.g. a denial-of-service finding is nudged by Availability alone, not a flat max of all three).

There is deliberately **no model-wide "business criticality" bump** on top of that — one used to exist, and was removed from both the custom-category engine and all 73 native script rules after review: in practice it mostly inflated assets whose own CIA rating was genuinely lower than the system around them, the same peripheral-asset-noise problem it should have been preventing. Every asset in this framework already carries an individually-justified CIA rating; an asset that's more important than its own rating suggests should have that rating corrected directly, not compensated for indirectly by a system-wide flag.

See `docs/risk-methodology.md` for the full mechanics and reasoning behind every threshold.

## A note on what this catalogue found

Building this catalogue surfaced a few pre-existing inconsistencies in the source it was extracting from, worth tracking separately from the catalogue itself:

- **`unencrypted-asset`** (built-in): the code requires `confidentiality ≥ Confidential` **AND** `integrity ≥ Critical` to fire, despite its own description saying "and/or" — an asset with very high confidentiality alone (e.g. strictly-confidential data) but only moderate integrity currently isn't flagged at all.
- A number of native script rules (listed in their own entries below) have no "Baseline is..." comment explaining their likelihood or impact value — the value itself is correct and was read directly from the code, but the *reasoning* behind it isn't written down anywhere.

Neither of these has been changed as part of writing this catalogue — they're flagged here for a future pass.

---


# Part 1: Built-in Threagile Rules


Covers the 35 vulnerability-class rules in `pkg/risks/builtin/*_rule.go` of the `jessestarkey/threagile` fork. That directory holds 42 rule files. The 7 model-consistency rules (`incomplete-model`, the four `unnecessary-*` rules and the two `wrong-*` rules) are left out.

**Scoring conventions used in every entry.** The baseline Likelihood a rule passes into `computeLikelihood()` (in `helpers.go`) is shifted per asset. It gets -1, 0 or +1 from the asset's RAA (+1 at 40% or above, -1 below 15%). It gets a further +1 if the asset has `Internet: true` or the `net:internet-reachable` tag. The result is clamped to the Unlikely..Frequent range. The baseline Impact is the rule's own value **before** its CIA-based escalation. Built-in rules escalate Impact with their own inline CIA checks. None of them calls the shared `computeImpact()` helper. Severity always comes from `types.CalculateSeverity(likelihood, impact)`.

---

## Identity

### Missing Authentication

**ID:** `missing-authentication`
**Location:** Built-in rule — `pkg/risks/builtin/missing_authentication_rule.go`

**Description:** Technical assets that process sensitive data, especially multi-tenant systems, should authenticate incoming requests. Otherwise attackers might be able to access or modify sensitive data without authenticating.

**Applies to:** In-scope assets that do not have the `NoAuthenticationRequired` technology attribute. The asset must process data rated Confidential or higher, or Critical or higher for integrity or availability, or be `MultiTenant`. The rule fires once for each incoming link that has `authentication: none` and a protocol that is not process-local. Callers with `IsUnprotectedCommunicationsTolerated` and callers of type Datastore are skipped.

**Why it applies there:** DetectionLogic says sensitive assets "should authenticate incoming requests". It adds that this is "especially the case for all multi-tenant assets (there even non-sensitive ones)". Monitoring callers and similar callers are exempt, per RiskAssessment.

**Baseline Likelihood:** `types.Likely`. There is no explicit rationale in the source for this value. The Mitigation field lists CWE-306, CWE-287, ATT&CK T1190, OWASP A07:2025 and API2:2023 as references for the class.

**Baseline Impact:** `types.MediumImpact` (the default return of `calculateImpact()`). It drops to Low when the link's data is Internal or lower and Operational. It rises to High when the link carries Strictly-Confidential or Mission-Critical data. A comment explains that the score is "scoped to the comm link's own ratings rather than the target asset's" and that this STRIDE category (EoP) already corresponds to max(C,I,A).

### Missing Two-Factor Authentication (2FA)

**ID:** `missing-authentication-second-factor`
**Location:** Built-in rule — `pkg/risks/builtin/missing_authentication_second_factor_rule.go`

**Description:** Assets that process highly sensitive data and are accessed by humans should require two-factor authentication. Otherwise attackers might be able to access or modify highly sensitive data without strong authentication.

**Applies to:** The same sensitivity and multi-tenant gate as Missing Authentication. Traffic-forwarding assets and assets with `IsUnprotectedCommunicationsTolerated` are excluded. The rule fires on incoming links whose caller has `UsedAsClientByHuman`. If the caller is a traffic-forwarding asset, the rule walks one hop further back to find a human client. The originating link must carry Confidential or higher, or Critical-integrity, data and must not use `two-factor` authentication.

**Why it applies there:** The concern is human-initiated sessions specifically. The one-hop walk through proxies and load balancers is there so that a human client behind a gateway is still detected (source comment: "find a caller's caller used by human").

**Baseline Likelihood:** `types.Likely`. There is no explicit rationale in the source. Mitigation cites CWE-308 and ATT&CK T1078, T1110 and T1621.

**Baseline Impact:** `types.MediumImpact`, a fixed value with no CIA escalation. RiskAssessment is the plain string `Medium`.

### Missing Identity Propagation

**ID:** `missing-identity-propagation`
**Location:** Built-in rule — `pkg/risks/builtin/missing_identity_propagation_rule.go`

**Description:** Assets that process end-user data should authorize every authenticated request against the end user's identity. If they do not, an attacker who compromises an upstream component might be able to access or modify other users' data, because resource-based authorization checks are missing.

**Applies to:** In-scope assets with `IsUsuallyProcessingEndUserRequests`. Multi-tenant assets must be rated at least Restricted or Important. Other assets must be rated at least Confidential or Critical. The rule fires on incoming links that meet all of these conditions:
- The caller has `IsUsuallyAbleToPropagateIdentityToOutgoingTargets` and is not a Datastore.
- The link is authenticated.
- The link's authorization is not `end-user-identity-propagation`.
- The link is not a DevOps link that already has some authorization.

**Why it applies there:** The rule only targets callers that are able to propagate identity. Unauthenticated links are a different rule's concern. DetectionLogic exempts DevOps links: "For DevOps usages at least a technical-user authorization is required."

**Baseline Likelihood:** `types.Unlikely`. There is no explicit rationale in the source. Exploiting this requires that "a component within the system" has already been compromised (Impact text).

**Baseline Impact:** `types.LowImpact`. It rises to Medium when the asset itself is Strictly-Confidential or Mission-Critical (RiskAssessment: "medium or high").

### Missing Identity Provider Isolation

**ID:** `missing-identity-provider-isolation`
**Location:** Built-in rule — `pkg/risks/builtin/missing_identity_provider_isolation_rule.go`

**Description:** Identity providers and their identity stores should sit in their own network-segmentation trust boundary. Execution-environment boundaries do not count. Without that separation, compromising a nearby asset gives an easy path to highly sensitive identity assets.

**Applies to:** In-scope assets with `IsIdentityRelated`. The rule fires when any other asset that is neither identity-related nor `IsCloseToHighValueTargetsTolerated` shares the same execution environment or the same network-only trust boundary.

**Why it applies there:** The DetectionLogic text describes the risk as "especially prevalent when other non-identity related assets are within the same execution environment (i.e. same database or same application server)". The code treats that case as the more likely one.

**Baseline Likelihood:** `types.Unlikely` when the other asset is in the same network segment. `types.Likely` when it is in the same execution environment. This split is the source's only stated reasoning for the value (DetectionLogic, quoted above).

**Baseline Impact:** `types.HighImpact`. It rises to VeryHigh when the asset is Strictly-Confidential or Mission-Critical, as stated verbatim in RiskAssessment.

### Missing Identity Store

**ID:** `missing-identity-store`
**Location:** Built-in rule — `pkg/risks/builtin/missing_identity_store_rule.go`

**Description:** This is a model-completeness risk (`ModelFailurePossibleReason: true`). The architecture has no identity store, so risks in the missing identity provider or store go unseen.

**Applies to:** Whole-model check. It produces one finding when no in-scope asset has `IsIdentityStore` and at least one communication link uses `authorization: end-user-identity-propagation`. The most sensitive link target is used as the example asset.

**Why it applies there:** End-user-identity authorization implies that an identity store exists somewhere. If the model does not contain one, part of the attack surface is missing from the model (DetectionLogic).

**Baseline Likelihood:** `types.Unlikely`, nudged against the example asset. There is no explicit rationale in the source. The finding reports a gap in the model rather than a directly exploitable flaw.

**Baseline Impact:** `types.LowImpact`. It rises to Medium when the example target asset, or the data it processes, is rated Confidential or higher, or Critical or higher for integrity or availability.

---

## Device and Infrastructure

### Container Base Image Backdooring

**ID:** `container-baseimage-backdooring`
**Location:** Built-in rule — `pkg/risks/builtin/container_baseimage_backdooring_rule.go`

**Description:** Container base images and layers can contain vulnerable components or deliberate backdoors. This can give attackers deep persistence through code running in the deployed containers.

**Applies to:** Every in-scope asset with `machine: container`.

**Why it applies there:** Every container inherits whatever is in its base image, so the machine type alone is enough to trigger the rule (DetectionLogic: "In-scope technical assets running as containers.").

**Baseline Likelihood:** `types.Unlikely`. There is no explicit rationale in the source. Mitigation cites CWE-506, CWE-1395, ATT&CK T1525 and T1195.002, and NIST SP 800-190.

**Baseline Impact:** `types.MediumImpact`. It rises to High on any Strictly-Confidential or Mission-Critical processed data. A comment says Impact covers all three CIA dimensions because code execution "can read, modify, or deny whatever that container handles".

### Missing Cloud Hardening

**ID:** `missing-cloud-hardening`
**Location:** Built-in rule — `pkg/risks/builtin/missing_cloud_hardening_rule.go`

**Description:** Cloud components should be hardened according to the vendor's best practices, covering configuration, auditing and related areas. Otherwise attackers might access cloud components in unintended ways.

**Applies to:** Trust boundaries of a cloud type, and trust boundaries, shared runtimes or assets tagged `aws`, `azure`, `gcp` or `ocp` (or a `provider:*` sub-tag). The rule produces:
- One finding per tagged shared runtime and per trust boundary.
- For each provider that has no runtime or boundary finding, a fallback finding on that provider's most sensitive asset.
- Extra asset-level findings for `aws:ec2` and `aws:s3`.

**Why it applies there:** Hardening applies per provider and per benchmark, for example "CIS Benchmark for Microsoft Azure". The rule is therefore keyed off cloud placement and provider tags, not technology type.

**Baseline Likelihood:** `types.Unlikely`. For shared-runtime and trust-boundary findings this value is fixed and not nudged. The source comment says: "No single technical asset to anchor an RAA/reachability delta on -- a trust boundary is an aggregate of many assets". Asset-level findings do use `computeLikelihood()`.

**Baseline Impact:** `types.MediumImpact`. It rises to High at Confidential or Critical and to VeryHigh at Strictly-Confidential or Mission-Critical. A comment says this is a broad misconfiguration risk that "can just as easily expose or disrupt a resource as corrupt it".

### Missing Hardening

**ID:** `missing-hardening`
**Location:** Built-in rule — `pkg/risks/builtin/missing_hardening_rule.go`

**Description:** High-attractiveness assets should be explicitly hardened according to best practices and vendor guides. Without that, attackers might find high-value targets easier to attack.

**Applies to:** In-scope assets with an RAA of 55% or more. The threshold drops to 40% for Datastore-type assets and for assets with `IsHighValueTarget`.

**Why it applies there:** RAA is a direct measure of how attractive an asset is to attackers. DetectionLogic lowers the threshold for "data stores, application servers, identity providers and ERP systems".

**Baseline Likelihood:** `types.Likely`. A source comment explains that both RAA gates (55 and 40) are at or above the 40% likelihood threshold. Every finding therefore earns the RAA delta: "Likely becomes VeryLikely here consistently -- the reachability delta can still vary per asset."

**Baseline Impact:** `types.LowImpact`. It rises to Medium on Strictly-Confidential or Mission-Critical processed data. A comment says the Impact text is "generically about attacking a high-value target, not a single dimension".

### Mixed Targets on Shared Runtime

**ID:** `mixed-targets-on-shared-runtime`
**Location:** Built-in rule — `pkg/risks/builtin/mixed_targets_on_shared_runtime_rule.go`

**Description:** Attacker targets of different kinds, such as frontend and backend or datastore components, should not share an underlying runtime. Sharing one gives attackers an easy path from a less valuable target to a more valuable one.

**Applies to:** Any shared runtime that runs assets from more than one trust boundary. It also applies to any shared runtime that runs both an `IsExclusivelyFrontendRelated` asset and an `IsExclusivelyBackendRelated` asset.

**Why it applies there:** Both conditions describe co-location that lets a breach or load problem in an attacker-facing asset spread to more critical neighbours (Mitigation text).

**Baseline Likelihood:** `types.Unlikely`, a fixed value that is not nudged. A comment says that "a shared runtime is an aggregate of many assets, so there's no single asset's RAA/reachability to anchor a delta on".

**Baseline Impact:** `types.LowImpact`. It rises to Medium if any asset running on the runtime is Strictly-Confidential or Mission-Critical.

### Container Platform Escape

**ID:** `container-platform-escape`
**Location:** Built-in rule — `pkg/risks/builtin/container_platform_escape_rule.go`

**Description:** Container platforms host large parts of a containerized runtime. An attacker who escapes from one container to the platform effectively owns every container on it.

**Applies to:** Every in-scope asset with the `ContainerPlatform` technology attribute. The data-breach set for each finding is every asset with `machine: container`.

**Why it applies there:** The platform is the shared privilege point. An escape from any one container compromises all of them ("owning the container platform ... equals to owning every container").

**Baseline Likelihood:** `types.Unlikely`. There is no explicit rationale in the source. The Impact text assumes the attacker has already compromised a container "via other vulnerabilities". Mitigation cites CWE-250, CWE-269, ATT&CK T1611 and T1610, and NIST SP 800-190.

**Baseline Impact:** `types.HighImpact`. It rises to VeryHigh on Strictly-Confidential or Mission-Critical processed data.

### Code Backdooring

**ID:** `code-backdooring`
**Location:** Built-in rule — `pkg/risks/builtin/code_backdooring_rule.go`

**Description:** Attackers who compromise the build pipeline can ship backdoored artifacts into production. This includes compromise of dependencies or compilers (the source gives XcodeGhost as an example). The result could be code execution on, and takeover of, production environments.

**Applies to:** In-scope assets with `IsDevelopmentRelevant` that either have `Internet: true` themselves or have an incoming non-VPN link from an asset with `Internet: true`.

**Why it applies there:** DetectionLogic targets development assets reachable from unmanaged or internet clients. FalsePositives says an internal, fully trusted pipeline can be dismissed after review.

**Baseline Likelihood:** `types.Unlikely`. There is no explicit rationale in the source. Mitigation cites CWE-506, CWE-494, CAPEC-444, ATT&CK T1195.002 and NIST SSDF PS.1 and PS.2.

**Baseline Impact:** `types.LowImpact` for `CodeInspectionPlatform` assets. For other assets it is Medium, rising to High on Confidential or Critical-integrity data. A comment says backdoored code "can just as easily exfiltrate data as corrupt it".

### Service Registry Poisoning

**ID:** `service-registry-poisoning`
**Location:** Built-in rule — `pkg/risks/builtin/service_registry_poisoning_rule.go`

**Description:** Service registries used to discover trusted endpoints can be poisoned with malicious endpoints, lookup data or configuration data. This can lead to a breach of sensitive data.

**Applies to:** Every in-scope asset with the `ServiceRegistry` technology attribute.

**Why it applies there:** Every caller that resolves endpoints through the registry trusts what the registry returns, so the registry's role alone is enough to trigger the rule.

**Baseline Likelihood:** `types.Unlikely`. There is no explicit rationale in the source. Mitigation cites CWE-923, CWE-345 and ATT&CK T1557.

**Baseline Impact:** `types.LowImpact`. It rises to Medium if the registry, any of its callers, or any incoming link carries Strictly-Confidential or Mission-Critical data. A comment says poisoned lookups can cause a "breach of sensitive data" further downstream.

---

## Network and Environment

### DoS-risky Access Across Trust-Boundary

**ID:** `dos-risky-access-across-trust-boundary`
**Location:** Built-in rule — `pkg/risks/builtin/dos_risky_access_across_trust_boundary_rule.go`

**Description:** Assets with Critical or Mission-Critical availability that are reached across trust boundaries are more exposed to denial of service. Attackers could disrupt important parts of the system.

**Applies to:** In-scope assets rated Critical or higher for availability. Assets with the `LoadBalancer` attribute are also evaluated regardless of rating. The rule fires on incoming links that cross a network trust boundary and are neither DevOps-usage nor process-local. Traffic-forwarding callers are walked back one hop.

**Why it applies there:** A boundary crossing means a less-trusted caller can send load to an asset whose availability matters. RiskAssessment treats VPN, IP filtering and redundancy as mitigating factors.

**Baseline Likelihood:** `types.Unlikely`. There is no explicit rationale in the source. Mitigation cites CWE-400, CWE-770, CAPEC-125, ATT&CK T1498 and T1499, and API4:2023.

**Baseline Impact:** `types.LowImpact`. It rises to Medium when the asset is Mission-Critical **and** the link has no VPN, no IP filter and no redundancy. A comment says this "folds in rule-specific mitigating factors ... the generic helper has no way to know about".

### Missing Network Segmentation

**ID:** `missing-network-segmentation`
**Location:** Built-in rule — `pkg/risks/builtin/missing_network_segmentation_rule.go`

**Description:** Highly sensitive assets and data stores that share a network segment with less sensitive assets should be protected by a segmentation boundary. Without one, attackers have an easy lateral path to the more valuable targets.

**Applies to:** In-scope assets with an RAA of 50% or more that are either Datastores or rated Confidential or Critical. The rule fires when an `IsLessProtectedType` asset shares the same network trust boundary with no direct link and is not `IsCloseToHighValueTargetsTolerated`.

> **Note:** As written, the code also skips any asset that does **not** carry `IsNoNetworkSegmentationRequired`. In `technologies.yaml` only `ids`, `ips`, `reverse-proxy`, `service-registry` and `waf` set that attribute. This looks inverted relative to DetectionLogic.

**Why it applies there:** A less-protected neighbour with no business reason to be adjacent ("no direct connection between these") is a lateral-movement stepping stone.

**Baseline Likelihood:** `types.Unlikely`. A comment says the 50% RAA gate already exceeds the 40% threshold, so "Unlikely becomes Possible here consistently -- the reachability delta can still vary per asset."

**Baseline Impact:** `types.LowImpact`. It rises to Medium when the asset is Strictly-Confidential or Mission-Critical, matching RiskAssessment.

### Missing Web Application Firewall (WAF)

**ID:** `missing-waf`
**Location:** Built-in rule — `pkg/risks/builtin/missing_waf_rule.go`

**Description:** Web applications and web services should have a WAF in front of them as a first filtering layer. Without one, attackers can run standard attack patterns "at great speed without any filtering".

**Applies to:** In-scope assets with `WebApplication` or `IsWebService` that have at least one incoming link that crosses a network trust boundary, uses a web-access protocol and does not come from an asset with the `WAF` attribute.

**Why it applies there:** Traffic crossing a boundary over web protocols is exactly what a WAF filters. Traffic from a WAF caller means the WAF is already in place.

**Baseline Likelihood:** `types.Unlikely`. There is no explicit rationale in the source. Description frames a WAF as defense in depth, "not a replacement for security". Mitigation cites CWE-693 and ATT&CK T1190 and T1595.002.

**Baseline Impact:** `types.LowImpact`. It rises to Medium on any Strictly-Confidential or Mission-Critical processed data. A comment says a WAF is "a general filtering layer ... not a dimension-specific one".

### Unguarded Access From Internet

**ID:** `unguarded-access-from-internet`
**Location:** Built-in rule — `pkg/risks/builtin/unguarded_access_from_internet_rule.go`

**Description:** Internet-exposed assets must be guarded by a protecting service, application or reverse proxy. Otherwise attackers can attack sensitive systems directly, with no hardening components in between.

**Applies to:** In-scope assets other than `LoadBalancer` assets, rated Confidential or higher, or Critical-integrity or higher, that have an incoming link from an asset with `Internet: true`. The following are exempt:
- VPN links.
- Callers with the `Monitoring` attribute.
- Non-custom-developed assets that have `IsHTTPInternetAccessOK` and are reached over HTTP(S).
- Non-custom-developed assets that have `IsFTPInternetAccessOK` and are reached over FTP, FTPS or SFTP.

**Why it applies there:** Off-the-shelf web servers and proxies are expected to face the internet over their native protocols. Anything else that is sensitive should not be reachable directly.

**Baseline Likelihood:** `types.VeryLikely`. A comment says RAA was moved from Impact to the Likelihood delta because "RAA affects how likely exploitation is, not how severe it is".

**Baseline Impact:** `types.LowImpact`. It rises to Medium when the asset is Strictly-Confidential or Mission-Critical. The comment says Impact is now "keyed off the asset's own CIA rating alone".

### Unguarded Direct Datastore Access

**ID:** `unguarded-direct-datastore-access`
**Location:** Built-in rule — `pkg/risks/builtin/unguarded_direct_datastore_access_rule.go`

**Description:** Datastores reached across trust boundaries must be guarded by a protecting service or application. Otherwise attackers can attack sensitive datastores directly.

**Applies to:** In-scope Datastore-type assets rated Confidential or higher, or Critical-integrity or higher, that have incoming non-DevOps links crossing a network trust boundary. The following are excluded:
- Identity stores accessed by an identity provider.
- File servers accessed over FTP, FTPS or SFTP.
- Callers that share a parent trust boundary with the datastore.

**Why it applies there:** A caller outside the boundary that holds a raw path to the datastore skips any application-tier authorization (Mitigation). DetectionLogic excludes DevOps config and deployment access.

**Baseline Likelihood:** `types.Likely`. A comment gives the same rationale as Unguarded Access From Internet: RAA now affects Likelihood instead of Impact.

**Baseline Impact:** `types.LowImpact`. It rises to Medium when the datastore is Strictly-Confidential or Mission-Critical.

---

## Application

### Cross-Site Request Forgery (CSRF)

**ID:** `cross-site-request-forgery`
**Location:** Built-in rule — `pkg/risks/builtin/cross_site_request_forgery_rule.go`

**Description:** Web applications reached over web protocols may be vulnerable to CSRF. Attackers could trick logged-in users into unwanted actions by luring them to an attacker-controlled site.

**Applies to:** In-scope assets with `WebApplication`. The rule fires once per incoming link that uses a web-access protocol.

**Why it applies there:** CSRF needs a browser-driven web request. FalsePositives says that non-browser access, or authentication passed in custom headers instead of cookies, can be dismissed.

**Baseline Likelihood:** `types.Likely`, or `types.Unlikely` for DevOps-usage links (from `likelihoodFromUsage()`). There is no explicit rationale in the source beyond that branch. Mitigation cites CWE-352, CAPEC-62 and A01:2025.

**Baseline Impact:** `types.LowImpact`. It rises to Medium when the link's data is Mission-Critical for integrity. A comment says this is "scoped to the comm link's own Integrity rating rather than the target asset's".

### Cross-Site Scripting (XSS)

**ID:** `cross-site-scripting`
**Location:** Built-in rule — `pkg/risks/builtin/cross_site_scripting_rule.go`

**Description:** Any web application may be vulnerable to XSS. Other applications on the same domain also affect the overall risk. Attackers could take over victim sessions and steal or modify user data.

**Applies to:** Every in-scope asset with `WebApplication`. A TODO in the source mentions extending this to mobile and rich clients that use web views.

**Why it applies there:** Any web application that renders dynamic content is a potential XSS sink. FalsePositives excludes assets that are not reached by a browser.

**Baseline Likelihood:** `types.VeryLikely`. There is no explicit rationale in the source. Mitigation cites CWE-79, CAPEC-63 and A05:2025.

**Baseline Impact:** `types.MediumImpact`. It rises to High on Strictly-Confidential or Mission-Critical processed data. A comment says XSS lets an attacker "steal or modify", which is both a confidentiality and an integrity consequence.

### LDAP-Injection

**ID:** `ldap-injection`
**Location:** Built-in rule — `pkg/risks/builtin/ldap_injection_rule.go`

**Description:** Clients that query LDAP servers may be vulnerable to LDAP injection. Attackers could modify the queries and read more directory data than they are allowed to.

**Applies to:** In-scope assets with incoming `ldap` or `ldaps` links from in-scope callers. The finding is attributed to the caller.

**Why it applies there:** The LDAP protocol on the link identifies the query path where injection is possible (DetectionLogic).

**Baseline Likelihood:** `types.Likely`, or `types.Unlikely` for DevOps-usage links. There is no explicit rationale in the source beyond that branch. Mitigation cites CWE-90, CAPEC-136 and A05:2025.

**Baseline Impact:** `types.MediumImpact`. It rises to High on Strictly-Confidential or Mission-Critical data at the LDAP server. A comment says this covers "both a tampering and an information-disclosure consequence".

### Missing Build Infrastructure

**ID:** `missing-build-infrastructure`
**Location:** Built-in rule — `pkg/risks/builtin/missing_build_infrastructure_rule.go`

**Description:** This is a model-completeness risk (`ModelFailurePossibleReason: true`). The model has custom-developed parts but no build infrastructure, so supply-chain risks go unseen.

**Applies to:** Whole-model check. It produces one finding when any in-scope asset has `custom_developed_parts: true` and the model is missing at least one of a `BuildPipeline`, a `SourcecodeRepository` and a `DevOpsClient` asset.

**Why it applies there:** Custom code has to come from somewhere. Mitigation notes that without these assets the supply-chain rules (code backdooring, unchecked deployment and others) cannot evaluate anything.

**Baseline Likelihood:** `types.Unlikely`, nudged against the most sensitive custom-developed asset. There is no explicit rationale in the source. Mitigation cites NIST SSDF PO.3 and PO.5 and SA-15.

**Baseline Impact:** `types.LowImpact`. It rises to Medium when any custom-developed asset, or the data it processes, is rated Confidential or higher, or Critical or higher for integrity or availability.

### Missing File Validation

**ID:** `missing-file-validation`
**Location:** Built-in rule — `pkg/risks/builtin/missing_file_validation_rule.go`

**Description:** Assets that accept files should strictly validate filename and type. Otherwise attackers could supply malicious files.

**Applies to:** In-scope assets with `custom_developed_parts: true` whose `data_formats_accepted` includes `file`.

**Why it applies there:** Only custom code is in scope for the validation logic that this finding asks for (DetectionLogic). Off-the-shelf products are not covered.

**Baseline Likelihood:** `types.Likely`. There is no explicit rationale in the source. Mitigation cites CWE-434, CWE-409, CAPEC-17 and A06:2025.

**Baseline Impact:** `types.MediumImpact`. It rises to High on Strictly-Confidential or Mission-Critical processed data. A comment says a malicious file can carry malware or "exfiltrate data via a processing vulnerability".

### Path-Traversal

**ID:** `path-traversal`
**Location:** Built-in rule — `pkg/risks/builtin/path_traversal_rule.go`

**Description:** Filesystem access may be vulnerable to path traversal or local file inclusion. Attackers could read sensitive files such as configuration data, credentials or business data.

**Applies to:** Assets with `IsFileStorage`, for each incoming link from an in-scope caller. The finding is attributed to the caller. The target asset's own scope is not checked.

**Why it applies there:** Any in-scope caller that builds file paths against a filesystem is a potential traversal vector (DetectionLogic).

**Baseline Likelihood:** `types.VeryLikely`, or `types.Likely` for DevOps-usage links. There is no explicit rationale in the source beyond that branch. Mitigation cites CWE-22, CWE-98, CAPEC-126 and ATT&CK T1083.

**Baseline Impact:** `types.MediumImpact`. It rises to High on Strictly-Confidential data only. A comment says the Impact text is "purely about reading sensitive files, not modifying them".

### Push instead of Pull Deployment

**ID:** `push-instead-of-pull-deployment`
**Location:** Built-in rule — `pkg/risks/builtin/push_instead_of_pull_deployment_rule.go`

**Description:** Push-based deployment requires every production target to expose an interface that accepts deployments. Pull-based deployment avoids this, so push-based deployment means a larger attack surface.

**Applies to:** Any asset with `BuildPipeline` that has a non-readonly DevOps-usage link to an in-scope target. The target must not be `IsDevelopmentRelevant` and must not have `usage: devops`.

**Why it applies there:** A writable deployment link into a production target is the inbound interface that pull-based deployment would remove (DetectionLogic).

**Baseline Likelihood:** `types.Unlikely`, nudged against the deployment target. There is no explicit rationale in the source. Mitigation cites CWE-668, ATT&CK T1072 and T1195.002, and NIST SP 800-204D.

**Baseline Impact:** `types.LowImpact`. It rises to Medium on a target with Confidential or higher, or Critical or higher, processed data. Because the `impact` variable is declared outside the loop, an escalation persists for every later finding in the same run.

### Search-Query Injection

**ID:** `search-query-injection`
**Location:** Built-in rule — `pkg/risks/builtin/search_query_injection_rule.go`

**Description:** Search engine servers may be vulnerable to query injection (Solr is the source's example). Attackers could read more of the index and possibly escalate to code execution.

**Applies to:** Assets with `IsSearchRelated`, for each incoming link from an in-scope caller over `http`, `https`, `binary` or `binary-encrypted`. The finding is attributed to the caller.

**Why it applies there:** These protocols carry the query API that injection exploits (DetectionLogic: "typical search access protocols").

**Baseline Likelihood:** `types.VeryLikely`, or `types.Likely` for DevOps-usage links. There is no explicit rationale in the source beyond that branch. Mitigation cites CWE-943, CWE-74, T1190, CVE-2017-12629 and CVE-2019-17558.

**Baseline Impact:** `types.MediumImpact`. It rises to High on Strictly-Confidential or Mission-Critical data. It drops to Low on Internal or lower, Operational data. A comment says the consequence is "a disclosure consequence first, a tampering one as it escalates".

### Server-Side Request Forgery (SSRF)

**ID:** `server-side-request-forgery`
**Location:** Built-in rule — `pkg/risks/builtin/server_side_request_forgery_rule.go`

**Description:** Server systems that call other servers over web protocols may be vulnerable to SSRF, LFI or RFI. Attackers could reach sensitive services or files of network-reachable components by manipulating outgoing calls.

**Applies to:** In-scope assets that have neither `IsClient` nor `LoadBalancer`. The rule fires once per outgoing link that uses a web-access protocol.

**Why it applies there:** An outgoing request built by a server is the thing an attacker steers in SSRF. Clients and load balancers are excluded because they do not originate requests on a server's behalf.

**Baseline Likelihood:** `types.Likely` (nudged), or a fixed `types.Unlikely` for DevOps-usage links. A comment says a DevOps link has "a fixed, operator-configured destination, not one a caller influences" and that this justifies skipping the RAA and reachability delta.

**Baseline Impact:** `types.LowImpact`. It rises to Medium if the target, or any asset in the same trust boundary that is reachable over the web, processes Strictly-Confidential data. It also rises to Medium if the asset is inside a cloud trust boundary (RiskAssessment: "cloud backend services can be attacked via SSRF").

### SQL/NoSQL-Injection

**ID:** `sql-nosql-injection`
**Location:** Built-in rule — `pkg/risks/builtin/sql_nosql_injection_rule.go`

**Description:** Databases accessed over database protocols may be vulnerable to SQL or NoSQL injection. Attackers could steal and modify data and possibly escalate to code execution.

**Applies to:** In-scope Datastore-type assets. The rule fires per incoming link in either of two cases. In the first, the protocol is a database-access protocol and the datastore has `IsVulnerableToQueryInjection`. In the second, the protocol is a "lax" database-access protocol. The finding is attributed to the caller.

**Why it applies there:** Injection needs a query interface on a store that is vulnerable to it (DetectionLogic). FalsePositives allows dismissal when queries contain no caller-controlled parts.

**Baseline Likelihood:** `types.VeryLikely` (nudged), or a fixed `types.Likely` for DevOps-usage links. A comment gives the same reasoning as for SSRF: DevOps usage answers "no" to "is this specific query built from caller-controlled input".

**Baseline Impact:** `types.MediumImpact`. It rises to High on Strictly-Confidential or Mission-Critical data. A comment says this is deliberately multi-dimensional ("steal and modify data") and cross-references `docs/risk-methodology.md`.

### Unchecked Deployment

**ID:** `unchecked-deployment`
**Location:** Built-in rule — `pkg/risks/builtin/unchecked_deployment_rule.go`

**Description:** Build pipelines that lack DevSecOps scanning (SAST, DAST, IAST, dependency scanning and container scanning) may let vulnerabilities in custom code or dependencies reach deployment undetected.

**Applies to:** Every asset with `IsDevelopmentRelevant`. The code has no out-of-scope check.

**Why it applies there:** Every development-relevant asset is part of the path that should enforce scanning gates (DetectionLogic: "All development-relevant technical assets.").

**Baseline Likelihood:** `types.Likely`. There is no explicit rationale in the source. Mitigation cites CWE-1395, CWE-1104, T1195.001, A03:2025 and NIST SSDF PW.7, PW.8 and RV.1.

**Baseline Impact:** `types.LowImpact`. It rises to Medium when a DevOps-link deployment target that receives Important-or-higher-integrity data processes Confidential or higher, or Critical or higher, data. A comment says unscanned vulnerabilities can threaten "any of its CIA dimensions".

### Untrusted Deserialization

**ID:** `untrusted-deserialization`
**Location:** Built-in rule — `pkg/risks/builtin/untrusted_deserialization_rule.go`

**Description:** Assets that accept native serialized formats (such as Java or .NET serialization) may deserialize untrusted data. Attackers could achieve code execution on the target.

**Applies to:** In-scope assets that meet any one of these conditions:
- They accept the `serialization` data format.
- They have the `EJB` attribute.
- They have an incoming `iiop`, `iiop-encrypted`, `jrmp` or `jrmp-encrypted` link.

**Why it applies there:** Each of these is a native-object deserialization entry point (DetectionLogic: "including EJB and RMI protocols").

**Baseline Likelihood:** `types.Likely`, or `types.VeryLikely` when an IIOP or JRMP link crosses a network trust boundary. There is no explicit rationale in the source beyond that branch. Mitigation cites CWE-502, CAPEC-586 and A08:2025.

**Baseline Impact:** `types.HighImpact`. It rises to VeryHigh on Strictly-Confidential or Mission-Critical processed data. A comment says "full remote code execution threatens any of the three dimensions".

### XML External Entity (XXE)

**ID:** `xml-external-entity`
**Location:** Built-in rule — `pkg/risks/builtin/xml_external_entity_rule.go`

**Description:** Assets that accept XML may be vulnerable to XXE. Attackers could read local files or reach services and files on other components.

**Applies to:** Every in-scope asset whose `data_formats_accepted` includes `xml`.

**Why it applies there:** Any XML parser that handles caller input is a potential XXE entry point (DetectionLogic).

**Baseline Likelihood:** `types.Likely`. There is no explicit rationale in the source. Mitigation cites CWE-611, CWE-776, CAPEC-221 and A02:2025.

**Baseline Impact:** `types.MediumImpact`. It rises to High on Strictly-Confidential processed data only. A comment says this was narrowed to Confidentiality because the Impact text is "purely about reading files or accessing services". RiskAssessment's cloud "at least medium" note is already met by the Medium baseline.

---

## Data

### Accidental Secret Leak

**ID:** `accidental-secret-leak`
**Location:** Built-in rule — `pkg/risks/builtin/accidental_secret_leak_rule.go`

**Description:** Source repositories, including their history, and artifact registries can accidentally contain checked-in secrets such as passwords, tokens, certificates and keys. Anyone with access to them might find those secrets.

**Applies to:** In-scope assets with the `MayContainSecrets` technology attribute. Assets tagged `git` get a "Git Leak Prevention" titled variant.

**Why it applies there:** Repositories and registries are where secrets most often get committed or packaged by accident (DetectionLogic). FalsePositives: "Usually no false positives."

**Baseline Likelihood:** `types.Likely`. There is no explicit rationale in the source. Mitigation cites CWE-798, CWE-540, ATT&CK T1552.001 and NIST IA-5(7).

**Baseline Impact:** `types.LowImpact`. It rises to Medium at Confidential or Critical and to High at Strictly-Confidential or Mission-Critical, across all three dimensions. A comment says a leaked secret's damage "is bounded by what an attacker could do with it -- read, modify, or deny".

### Missing Vault (Secret Storage)

**ID:** `missing-vault`
**Location:** Built-in rule — `pkg/risks/builtin/missing_vault_rule.go`

**Description:** This is a model-completeness risk (`ModelFailurePossibleReason: true`). Without a dedicated, hardened vault, config secrets live in files and are easier to steal through file-read vulnerabilities such as path traversal.

**Applies to:** Whole-model check. It produces one finding when no asset has the `Vault` attribute. The most sensitive asset is used as the example.

**Why it applies there:** DetectionLogic says "Models without a Vault (Secret Storage)". Any sensitive configuration then has no proper home.

**Baseline Likelihood:** `types.Unlikely`. It is nudged against the example asset, or left as the fixed value when the model has no assets (`no-components`). There is no explicit rationale in the source. Mitigation cites CWE-798, CWE-522, CWE-312 and T1552.001 and T1552.004.

**Baseline Impact:** `types.LowImpact`. It rises to Medium if any asset, or its processed data, is Confidential or higher, or Critical or higher. Note: because the loop `break`s on finding a vault, this escalation only counts assets sorted before the vault, but in that case no finding is produced anyway.

### Missing Vault Isolation

**ID:** `missing-vault-isolation`
**Location:** Built-in rule — `pkg/risks/builtin/missing_vault_isolation_rule.go`

**Description:** Vaults and their storage should sit in their own network-segmentation boundary. Execution-environment boundaries do not count. Without that separation, compromising a nearby asset gives an easy path to the secrets.

**Applies to:** In-scope assets with the `Vault` attribute. The rule fires when a non-vault asset shares the vault's execution environment or network-only trust boundary. Datastores directly connected to the vault are exempt, because they count as its storage.

**Why it applies there:** DetectionLogic says the risk is "especially prevalent when other non-vault related assets are within the same execution environment".

**Baseline Likelihood:** `types.Unlikely` when the other asset is in the same network segment. `types.Likely` when it is in the same execution environment. This matches the DetectionLogic emphasis quoted above.

**Baseline Impact:** `types.MediumImpact`. It rises to High when the vault is Strictly-Confidential or Mission-Critical, as stated verbatim in RiskAssessment.

### Unencrypted Technical Assets

**ID:** `unencrypted-asset`
**Location:** Built-in rule — `pkg/risks/builtin/unencrypted_asset_rule.go`

**Description:** Assets that store sufficiently sensitive data must be encrypted at rest. Attackers who compromise a sensitive component could otherwise read the unencrypted data.

**Applies to:** In-scope assets that store data assets. Assets with `IsNoStorageAtRest` or `IsEmbeddedComponent` are excluded. The code requires stored confidentiality of Confidential or higher **and** stored integrity of Critical or higher; the DetectionLogic text says "or". A finding is produced when either of these holds:
- Encryption is `none`.
- The data is very sensitive, the asset has `IsUsuallyStoringEndUserData`, and encryption is not `data-with-end-user-individual-key`.

**Why it applies there:** The source comment says routing assets such as reverse proxies "usually don't have their own storage and thus have no encryption requirement".

**Baseline Likelihood:** `types.Unlikely`. There is no explicit rationale in the source. Exploiting this assumes the attacker is already "successfully compromising sensitive components" (Impact text).

**Baseline Impact:** `types.MediumImpact`. It rises to High when the stored data is Strictly-Confidential or Mission-Critical and there is no encryption. A comment says this stays two-dimensional because the detection logic "deliberately considers both".

### Unencrypted Communication

**ID:** `unencrypted-communication`
**Location:** Built-in rule — `pkg/risks/builtin/unencrypted_communication_rule.go`

**Description:** Links that carry sensitive data must be encrypted. Otherwise network attackers could eavesdrop on the data in transit.

**Applies to:** Unencrypted, non-process-local links where at least one end is in scope and neither end has `IsUnprotectedCommunicationsTolerated`. The link qualifies if it carries Strictly-Confidential or Mission-Critical data, or carries authentication data. It also qualifies if it carries Confidential or Critical data without a VPN.

**Why it applies there:** Sensitivity of the data in transit drives the requirement (Description). A VPN only offsets medium sensitivity: per the finding title, even VPN links "need to encrypt" the highest tiers.

**Baseline Likelihood:** `types.Unlikely`, or `types.Likely` when the link crosses a network trust boundary. There is no explicit rationale in the source beyond that branch. Mitigation cites CWE-319, CAPEC-94 and T1040 and T1557.

**Baseline Impact:** `types.MediumImpact`. It rises to High on high-sensitivity data or on authentication data. A comment says the Description itself says "confidentiality and/or integrity".

---

## Uncategorized

No rules. All 35 rule IDs in scope map to one of the five domains above.

---

# Part 2: Native Script Rules


One entry per native script risk rule in the `jessestarkey/threagile` fork's `pkg/risks/scripts/*.yaml` (73 files). Every field below is drawn from that rule file's own `description`, `impact`, `risk_assessment`, `false_positives`, `risk: match:` block, and the comments/return values in its `get_likelihood`/`get_impact` utilities.

Shared conventions across nearly every rule (from the files' own comments and code):

- **Likelihood delta:** the baseline moves up one tier when the asset's RAA is `>= 40` and down one tier when RAA is `< 15`, clamped to the `unlikely`..`very-likely` range. A baseline at a tier edge can therefore only move one way.
- **Impact delta:** the baseline moves by the asset's own rank on the single CIA dimension its STRIDE category maps to (Elevation-of-Privilege falls back to the max of all three). The files note that a model-wide Business Criticality bump that used to apply was removed, because "it mostly inflated already-peripheral assets rather than protecting genuinely under-rated ones".
- **Out of scope:** every rule's match requires `tech_asset.out_of_scope` to be false.

Where a rule file has no comment that states its baseline or explains its match condition, the entry says so. The value given is then read from the rule's return values, and the reasoning is labelled **(Structural inference)**.

---

## Identity

### Certificate Validation Service Soft-Fail Revocation Checking

**ID:** `certificate-validation-soft-fail`
**Location:** Native script rule — `pkg/risks/scripts/certificate-validation-soft-fail.yaml`

**Description:** An OCSP responder or CRL distribution point that fails open treats an unreachable or slow revocation check as "not revoked". A revoked or compromised certificate then keeps authenticating, especially in degraded or disconnected (DDIL) conditions. The attacker succeeds exactly when the check can't complete, which is when an attacker who caused the outage most needs it.

**Applies to:** In-scope technical assets whose technologies carry the `.attributes.certificate-validation-service` attribute.

**Why it applies there:** The rule's `false_positives` says it fires unconditionally for every in-scope certificate-validation-service asset by design. A confirmed fail-closed configuration is recorded as mitigated through `risk_tracking`. **(Structural inference)** The revocation-check behavior lives in that service.

**Baseline Likelihood:** `likely` — The comment calls it "a mid tier, not an edge", so possible, likely and very-likely are all reachable through the RAA delta.

**Baseline Impact:** `very-high` — Spoofing maps to Integrity. This is the ceiling, so only the downward (low Integrity) delta can apply. The comment's reason: "a revocation check that fails open defeats the entire purpose of revocation regardless of this asset's own rating."

### Insecure Session Management

**ID:** `insecure-session-management`
**Location:** Native script rule — `pkg/risks/scripts/insecure-session-management.yaml`

**Description:** The frontend issues session tokens without secure handling. Examples are missing Secure/HttpOnly flags, excessive lifetimes, and no re-authentication before sensitive actions. A stolen or fixated token gives an attacker authenticated access for as long as it stays valid.

**Applies to:** In-scope technical assets whose technologies carry the `.attributes.frontend_related` attribute.

**Why it applies there:** The rule's `false_positives` says it fires unconditionally for every in-scope frontend asset by design. It also notes partial overlap with Threagile's built-in `session-id-using-shared-secret` rule: this entry adds STIG-aligned timeout and re-authentication coverage, so it isn't a duplicate.

**Baseline Likelihood:** `very-likely` — This is the ceiling, so only the downward delta (RAA < 15) can apply.

**Baseline Impact:** `medium` — Spoofing maps to Integrity. The file gives no further reason for this value.

---

## Device and Infrastructure

### Dangerous Container Linux Capabilities

**ID:** `dangerous-container-capabilities`
**Location:** Native script rule — `pkg/risks/scripts/dangerous-container-capabilities.yaml`

**Description:** The container holds Linux capabilities beyond what its function needs, such as CAP_SYS_ADMIN, CAP_NET_ADMIN or CAP_SYS_PTRACE. An attacker can use them to escape the container, manipulate network traffic, or pull credentials from other processes on the same node. `risk_assessment` notes that all of these are CAT II STIG findings.

**Applies to:** In-scope technical assets whose `machine` is `container`.

**Why it applies there:** The rule's `false_positives` says it fires unconditionally for every in-scope container asset by design. A confirmed drop-all/admission-enforced configuration is recorded as mitigated through `risk_tracking`.

**Baseline Likelihood:** `likely` — The file has no baseline comment. **(Structural inference)** The code returns very-likely at RAA >= 40, possible below 15 and likely otherwise, which makes `likely` the mid-tier baseline.

**Baseline Impact:** `high` — The file has no explicit "Baseline is" statement. The comment says Elevation-of-Privilege falls back to the max rank across all three CIA dimensions, because "a privileged attacker can read, alter, or deny at will regardless of which single dimension is highest-rated". **(Structural inference)** The code returns medium, high or very-high by that rank, so `high` is the mid-tier baseline.

### Endpoint Security Management Console Fleet-Wide Compromise Path

**ID:** `endpoint-security-manager-fleet-compromise`
**Location:** Native script rule — `pkg/risks/scripts/endpoint-security-manager-fleet-compromise.yaml`

**Description:** A central endpoint security/EDR console pushes policy, signatures and remediation code to every endpoint it manages. Compromising the console is therefore the same as getting code execution on the whole fleet at once. The organization's own defensive tooling becomes the fastest path to total fleet compromise.

**Applies to:** In-scope technical assets whose technologies carry the `.attributes.endpoint-security-manager` attribute.

**Why it applies there:** The rule's `false_positives` says it fires unconditionally for every in-scope endpoint-security-manager asset by design. **(Structural inference)** The fleet-wide push capability is specific to that console.

**Baseline Likelihood:** `unlikely` — This is the floor, so only the upward delta (RAA >= 40) can apply. The comment's reason: "this requires actual console-level compromise, a rarer event than a routine configuration gap."

**Baseline Impact:** `very-high` — Elevation-of-Privilege uses the max CIA rank. This is the ceiling, so the only change is a drop when every dimension is at or below rank 1.

### Mutable Container Filesystem

**ID:** `mutable-container-filesystem`
**Location:** Native script rule — `pkg/risks/scripts/mutable-container-filesystem.yaml`

**Description:** The container's root filesystem is writable. An attacker who gains code execution can modify binaries or persist inside the container, keeping a durable foothold instead of being reset on restart. `risk_assessment` calls it medium in isolation, but it compounds with any code-execution finding on the same container.

**Applies to:** In-scope technical assets whose `machine` is `container`.

**Why it applies there:** The rule's `false_positives` says it fires unconditionally for every in-scope container asset by design. It's recorded as mitigated once `readOnlyRootFilesystem` is set to true.

**Baseline Likelihood:** `likely` — "not a tier edge", so both the upward (RAA >= 40) and downward (RAA < 15) deltas can apply. The comment points to `untrusted-container-image.yaml` for the general pattern.

**Baseline Impact:** `medium` — Tampering maps to Integrity. It's "a middle tier", so low, medium and high are all reachable depending on the asset's Integrity rank.

### Missing Endpoint Security Agents

**ID:** `missing-endpoint-security-agents`
**Location:** Native script rule — `pkg/risks/scripts/missing-endpoint-security-agents.yaml`

**Description:** The virtual machine lacks mandatory endpoint security agents, such as EDR or a centralized log forwarder. An attacker can establish persistence and move laterally from the host without raising any host-level SOC alert.

**Applies to:** In-scope technical assets whose `machine` is `virtual`.

**Why it applies there:** The rule's `false_positives` says it fires unconditionally for every in-scope virtual-machine asset by design. It's recorded as mitigated once EDR and log forwarding are confirmed with an active heartbeat.

**Baseline Likelihood:** `likely` — The file has no baseline comment. **(Structural inference)** The code returns very-likely, possible or likely by the standard RAA thresholds, so `likely` is the mid-tier baseline.

**Baseline Impact:** `medium` — The file has no baseline comment beyond "Information-Disclosure -> Confidentiality". **(Structural inference)** The code returns low, medium or high by Confidentiality rank, so `medium` is the mid-tier baseline.

### Space Vehicle Onboard Command Authentication and Bus Segmentation Gap

**ID:** `space-vehicle-bus-segmentation-gap`
**Location:** Native script rule — `pkg/risks/scripts/space-vehicle-bus-segmentation-gap.yaml`

**Description:** The spacecraft's own command-and-data-handling subsystem is the last line of defense if ground-segment controls are bypassed. It is often assumed secure because the ground segment is, rather than authenticating commands itself. With no onboard bus segmentation, a command that arrives by any path can reach attitude control, payload or other critical subsystems.

**Applies to:** In-scope technical assets whose technologies carry the `.attributes.space-vehicle` attribute.

**Why it applies there:** The rule's `false_positives` says it fires unconditionally for every in-scope space-vehicle asset by design. It's confirmed during pre-launch integration and test.

**Baseline Likelihood:** `unlikely` — This is the floor, so only the upward delta (RAA >= 40) can apply. The comment's reason: "reaching the spacecraft's own command path requires defeating or bypassing the ground segment first."

**Baseline Impact:** `very-high` — Spoofing maps to Integrity. The comment's reason: "an accepted malicious command reaching unsegmented subsystems is a total loss-of-vehicle-level failure ... and the vehicle cannot be physically re-hardened after launch."

### Unhardened OS / Missing Patch Management

**ID:** `unhardened-os-missing-patch-management`
**Location:** Native script rule — `pkg/risks/scripts/unhardened-os-missing-patch-management.yaml`

**Description:** The virtual machine wasn't deployed from a STIG-compliant baseline image and has no automated patch management. The OS accumulates known, unpatched CVEs and configuration drift that make privilege escalation substantially easier.

**Applies to:** In-scope technical assets whose `machine` is `virtual`.

**Why it applies there:** The rule's `false_positives` says it fires unconditionally for every in-scope virtual-machine asset by design. It's recorded as mitigated once a STIG baseline image and automated patching are confirmed.

**Baseline Likelihood:** `very-likely` — This is the ceiling, so only the downward delta (RAA < 15) can apply. The comment points to `untrusted-container-image.yaml` for the general pattern.

**Baseline Impact:** `high` — The comment states only that Elevation-of-Privilege falls back to the max CIA rank and gives no baseline value. **(Structural inference)** The code returns medium, high or very-high by that rank, so `high` is the mid-tier baseline.

### Untrusted Container Image Supply Chain

**ID:** `untrusted-container-image`
**Location:** Native script rule — `pkg/risks/scripts/untrusted-container-image.yaml`

**Description:** Nothing explicitly verifies that the container image comes from a trusted, scanned registry. The image can bring known CVEs or supply-chain malware into the ATO boundary. The file rates this the same as a compromised CI/CD dependency, because in both cases an attacker-controlled artifact runs with the workload's own privilege.

**Applies to:** In-scope technical assets whose `machine` is `container`.

**Why it applies there:** The rule's `false_positives` says it fires unconditionally for every in-scope container asset by design. `risk_assessment` adds that even a DoD-approved registry doesn't fully close the risk without digest pinning and deploy-time signature verification.

**Baseline Likelihood:** `very-likely` — The comment says this mirrors `compute_likelihood()` in `inject_risks.py`. "Baseline is already the top tier", so only a genuinely low-RAA asset (RAA < 15) pulls it down a notch.

**Baseline Impact:** `very-high` — The comment says this mirrors `compute_impact()` on Tampering -> Integrity. "Baseline is already the top tier", so the only movement is a drop to high when Integrity is low.

### Vulnerability Scanner Privileged Credential Exposure and Lateral Movement Hub

**ID:** `vulnerability-scanner-credential-exposure`
**Location:** Native script rule — `pkg/risks/scripts/vulnerability-scanner-credential-exposure.yaml`

**Description:** A credentialed vulnerability scanner authenticates to every in-scope host with privileged access. That makes it both a credential vault for the whole enclave and a map of every host's known weaknesses. Compromising it turns a compliance tool into the most efficient lateral-movement platform in the enclave.

**Applies to:** In-scope technical assets whose technologies carry the `.attributes.vulnerability-scanner` attribute.

**Why it applies there:** The rule's `false_positives` says it fires unconditionally for every in-scope vulnerability-scanner asset by design. It's recorded as mitigated once scan-window credential scoping and management-plane isolation are confirmed.

**Baseline Likelihood:** `likely` — This is a mid tier, so possible, likely and very-likely are all reachable through the RAA delta.

**Baseline Impact:** `very-high` — Elevation-of-Privilege uses the max CIA rank. This is the ceiling, so the only change is a drop when every dimension is at or below rank 1.

---

## Network and Environment

### Air Ground Station Command-Link Hijack and Unencrypted Telemetry/Video Downlink

**ID:** `air-ground-station-c2-link-hijack`
**Location:** Native script rule — `pkg/risks/scripts/air-ground-station-c2-link-hijack.yaml`

**Description:** An air vehicle's command link is commonly line-of-sight RF, which can be attacked with far less sophisticated equipment than a satellite uplink. An unauthenticated command link lets an adversary take direct control. An unencrypted sensor or video downlink discloses everything the vehicle sees to anyone in radio range. The file cites intercepted unencrypted drone video feeds as a documented real-world case.

**Applies to:** In-scope technical assets whose technologies carry the `.attributes.air-ground-station` attribute.

**Why it applies there:** The rule's `false_positives` says it fires unconditionally for every in-scope air-ground-station asset by design. **(Structural inference)** The ground station is the endpoint of the command link and the downlink.

**Baseline Likelihood:** `likely` — This is a mid tier, so all three outcomes are reachable through the RAA delta.

**Baseline Impact:** `very-high` — Spoofing maps to Integrity. The comment's reason: "a hijacked command link is a total loss-of-control failure regardless of this asset's own rating."

### Air Vehicle GPS/PNT Spoofing-Induced Navigation Hijack and Physical Capture Data Exposure

**ID:** `air-vehicle-gps-spoofing`
**Location:** Native script rule — `pkg/risks/scripts/air-vehicle-gps-spoofing.yaml`

**Description:** An air vehicle that navigates on unauthenticated civilian GPS/PNT can be spoofed or jammed into a false position, then redirected, forced down or crashed. Separately, an airframe that is recovered without onboard protection exposes its cryptographic keys and mission data to whoever recovers it.

**Applies to:** In-scope technical assets whose technologies carry the `.attributes.air-vehicle` attribute.

**Why it applies there:** The rule's `false_positives` says it fires unconditionally for every in-scope air-vehicle asset by design. It's recorded as mitigated once independent navigation cross-checking and anti-tamper/zeroization are confirmed.

**Baseline Likelihood:** `likely` — This is a mid tier, so all three outcomes are reachable through the RAA delta.

**Baseline Impact:** `very-high` — Tampering maps to Integrity. The comment's reason: "a successfully spoofed navigation signal is a total loss-of-control failure regardless of this asset's own rating."

### CDS Data Diode Unidirectionality Verification and Feed Integrity Gap

**ID:** `cds-data-diode-unidirectionality-gap`
**Location:** Native script rule — `pkg/risks/scripts/cds-data-diode-unidirectionality-gap.yaml`

**Description:** A data diode's assurance rests on one physical property: no return path exists. It does no content inspection at all. If its one-way claim was never independently verified, it could carry an undetected return channel. Corrupted content on the forward feed also reaches the receiving side unfiltered.

**Applies to:** In-scope technical assets whose technologies carry the `.attributes.cds-data-diode` attribute.

**Why it applies there:** The rule's `false_positives` says it fires unconditionally for every in-scope CDS-data-diode asset by design. It's recorded as mitigated once recurring unidirectionality verification and receiving-side integrity checks are confirmed.

**Baseline Likelihood:** `unlikely` — This is the floor, so only the upward delta (RAA >= 40) can apply. The comment's reason: "a hardware diode's physical construction makes this a materially rarer failure than a software guard's rule-set drift."

**Baseline Impact:** `very-high` — Tampering maps to Integrity. The comment's reason: "an undetected return channel or unfiltered corrupted feed is a total failure of the one property this device provides."

### CDS Guard Filter Rule-Set Staleness and Undocumented Bypass Path

**ID:** `cds-guard-ruleset-bypass`
**Location:** Native script rule — `pkg/risks/scripts/cds-guard-ruleset-bypass.yaml`

**Description:** A cross-domain guard's release decision rests entirely on its content-inspection rule set and on there being no path around that inspection. A stale rule set or an undocumented administrative override quietly defeats the guard without looking like an outage. Content that gets through looks just as assured downstream as content that was properly inspected.

**Applies to:** In-scope technical assets whose technologies carry the `.attributes.cds-guard` attribute.

**Why it applies there:** The rule's `false_positives` says it fires unconditionally for every in-scope CDS-guard asset by design. It's recorded as mitigated once the rule-set review cadence and bypass logging/approval are confirmed.

**Baseline Likelihood:** `likely` — This is a mid tier, so all three outcomes are reachable through the RAA delta.

**Baseline Impact:** `very-high` — Tampering maps to Integrity. The comment's reason: "a guard's inspection path silently failing is a total failure of the one control it exists to provide."

### ICS/PACS Controller Unauthenticated Industrial Protocol Command Injection

**ID:** `ics-controller-unauthenticated-protocol`
**Location:** Native script rule — `pkg/risks/scripts/ics-controller-unauthenticated-protocol.yaml`

**Description:** Industrial protocols (Modbus, BACnet, DNP3) and legacy access-control wiring (Wiegand) were designed without authentication. A controller speaking one of them accepts command or configuration writes from anyone who can reach it. An attacker on the segment or the wire can inject commands or rewrite program logic as if they were the legitimate system.

**Applies to:** In-scope technical assets whose technologies carry the `.attributes.ics-controller` attribute.

**Why it applies there:** The rule's `false_positives` says it fires unconditionally for every in-scope ics-controller asset by design. It's recorded as mitigated once segmentation and the strongest available protocol authentication are confirmed.

**Baseline Likelihood:** `very-likely` — This is the ceiling, so only the downward delta (RAA < 15) can apply. The comment's reason: "these protocols lacking authentication by design is the norm, not the exception."

**Baseline Impact:** `very-high` — Tampering maps to Integrity. This is the ceiling, so only the downward (low Integrity) delta can apply. The file gives no further reason.

### Missing Network Micro-Segmentation

**ID:** `missing-network-micro-segmentation`
**Location:** Native script rule — `pkg/risks/scripts/missing-network-micro-segmentation.yaml`

**Description:** The workload has no explicit default-deny network policy, so East-West traffic inside the cluster is unrestricted. Compromising a single pod gives an attacker network reach to every other workload in the cluster. `risk_assessment` calls it medium in isolation but says it compounds sharply with any single-pod compromise.

**Applies to:** In-scope technical assets whose `machine` is `container`.

**Why it applies there:** The rule's `false_positives` says it fires unconditionally for every in-scope container asset by design. It's recorded as mitigated once a namespace-level default-deny NetworkPolicy is enforced.

**Baseline Likelihood:** `likely` — The file has no baseline comment. **(Structural inference)** The code returns very-likely, possible or likely by the standard RAA thresholds, so `likely` is the mid-tier baseline.

**Baseline Impact:** `medium` — The file has no baseline comment beyond "Information-Disclosure -> Confidentiality". **(Structural inference)** The code returns low, medium or high by Confidentiality rank.

### CSfC Network Encryptor Common-Mode Failure and Red/Black Boundary Collapse

**ID:** `network-encryptor-common-mode-failure`
**Location:** Native script rule — `pkg/risks/scripts/network-encryptor-common-mode-failure.yaml`

**Description:** CSfC requires two independent encryption layers built from diverse components, so that a flaw in one layer can't expose red (plaintext) traffic to the black side. That independence is lost in two ways: a collapsed single layer, or two layers that share a vendor, codebase or vulnerability. Classified or CUI plaintext can then cross the boundary with no outward sign of failure.

**Applies to:** In-scope technical assets whose technologies carry the `.attributes.network-encryptor` attribute.

**Why it applies there:** The rule's `false_positives` says it fires unconditionally for every in-scope network-encryptor asset by design. It's recorded as mitigated once two-layer independence and recurring re-verification are confirmed.

**Baseline Likelihood:** `unlikely` — This is the floor, so only the upward delta (RAA >= 40) can apply. The comment's reason: "a properly accredited CSfC deployment is assumed correct absent a specific reason to doubt it."

**Baseline Impact:** `very-high` — Information-Disclosure maps to Confidentiality. The comment's reason: "a collapsed boundary exposes everything the encryptor was relied upon to protect."

### Space Ground Station Unauthorized Uplink and Rogue Ground Station Impersonation

**ID:** `space-ground-station-rogue-uplink`
**Location:** Native script rule — `pkg/risks/scripts/space-ground-station-rogue-uplink.yaml`

**Description:** If a ground station's command uplink relies on link obscurity instead of cryptographic verification, it can be impersonated. A rogue ground station can then send commands the spacecraft accepts as legitimate, bypassing every control the organization's own ground segment enforces.

**Applies to:** In-scope technical assets whose technologies carry the `.attributes.space-ground-station` attribute.

**Why it applies there:** The rule's `false_positives` says it fires unconditionally for every in-scope space-ground-station asset by design. It's recorded as mitigated once cryptographic command authentication and unauthorized-uplink monitoring are confirmed.

**Baseline Likelihood:** `unlikely` — This is the floor, so only the upward delta (RAA >= 40) can apply. The comment's reason: "intercepting or spoofing a satellite uplink credibly requires materially more sophisticated capability than most RF attacks."

**Baseline Impact:** `very-high` — Spoofing maps to Integrity. The comment's reason: "a successfully impersonated ground station is a total command-authority failure."

---

## Application

### Broken Function-Level Authorization (BFLA)

**ID:** `broken-function-level-authorization`
**Location:** Native script rule — `pkg/risks/scripts/broken-function-level-authorization.yaml`

**Description:** The backend API exposes administrative or privileged endpoints that rely on client-supplied role claims or on obscurity, not server-side role verification. A low-privilege user who finds an admin endpoint can invoke privileged functions without getting an authorization error.

**Applies to:** In-scope technical assets whose technologies carry the `.attributes.request_serving_api` attribute.

**Why it applies there:** The rule's `false_positives` says it fires unconditionally for every in-scope request-serving API asset by design. It's recorded as mitigated once centralized server-side role verification is confirmed on every endpoint.

**Baseline Likelihood:** `very-likely` — The file has no baseline comment. **(Structural inference)** The code returns likely when RAA < 15 and very-likely otherwise, so it is a ceiling baseline with only the downward delta.

**Baseline Impact:** `high` — Elevation-of-Privilege uses the max rank across all three CIA dimensions. The file gives no further reason.

### Broken Object-Level Authorization (BOLA/IDOR)

**ID:** `broken-object-level-authorization`
**Location:** Native script rule — `pkg/risks/scripts/broken-object-level-authorization.yaml`

**Description:** The backend API doesn't check that an authenticated user may access a specific object. Changing an identifier in the request is enough to read, modify or delete other users' or tenants' records, with no further privilege escalation.

**Applies to:** In-scope technical assets whose technologies carry the `.attributes.request_serving_api` attribute.

**Why it applies there:** The rule's `false_positives` says it fires unconditionally for every in-scope request-serving API asset by design. It's recorded as mitigated once server-side ownership checks are confirmed on every identifier-accepting endpoint.

**Baseline Likelihood:** `very-likely` — This is the ceiling, so only the downward delta (RAA < 15) can apply.

**Baseline Impact:** `high` — Information-Disclosure maps to Confidentiality. "Not an edge tier", so medium, high and very-high are all reachable.

### Broken Object Property Level Authorization (Mass Assignment)

**ID:** `broken-object-property-level-authorization`
**Location:** Native script rule — `pkg/risks/scripts/broken-object-property-level-authorization.yaml`

**Description:** The API binds client request bodies straight to internal models with no per-field allow-list. A client can set privileged fields the UI never exposes. It can also collect sensitive fields that a response returns without meaning to.

**Applies to:** In-scope technical assets whose technologies carry the `.attributes.request_serving_api` attribute.

**Why it applies there:** The rule's `false_positives` says it fires unconditionally for every in-scope request-serving API asset by design. It's recorded as mitigated once explicit per-endpoint DTOs with server-enforced allow-lists are confirmed.

**Baseline Likelihood:** `likely` — The file has no baseline comment. **(Structural inference)** The code returns very-likely, possible or likely by the standard RAA thresholds, so `likely` is the mid-tier baseline.

**Baseline Impact:** `high` — Tampering maps to Integrity. The file gives no further reason.

### CI/CD Pipeline and Admission-Policy Tampering Outside Repository Trail

**ID:** `cicd-pipeline-tampering-outside-repo`
**Location:** Native script rule — `pkg/risks/scripts/cicd-pipeline-tampering-outside-repo.yaml`

**Description:** Anyone with access to the CI/CD platform's console can change the pipeline definition or its gate policies directly. That bypasses the source-controlled pipeline file and leaves no pull-request trail. A security gate can be silently disabled outside code review, so the gate a reviewer approved is no longer the one that runs.

**Applies to:** In-scope technical assets whose technologies carry the `.attributes.build-pipeline` attribute.

**Why it applies there:** The rule's `false_positives` says it fires unconditionally for every in-scope build-pipeline asset by design. It's recorded as mitigated once out-of-repo edits are restricted to a minimal admin group and logged to the SIEM.

**Baseline Likelihood:** `unlikely` — This is the floor, so only the upward delta (RAA >= 40) can apply.

**Baseline Impact:** `high` — Tampering maps to Integrity. "Not an edge tier", so medium, high and very-high are all reachable.

### Dependency Confusion via Unclaimed Internal Package Namespace

**ID:** `dependency-confusion-internal-namespace`
**Location:** Native script rule — `pkg/risks/scripts/dependency-confusion-internal-namespace.yaml`

**Description:** The pipeline's dependency resolver falls back to a public index when a package isn't in the internal feed. An attacker who publishes a higher-versioned package under the internal name on the public index gets the build to pull and run their code.

**Applies to:** In-scope technical assets whose technologies carry the `.attributes.build-pipeline` attribute.

**Why it applies there:** The rule's `false_positives` says it fires unconditionally for every in-scope build-pipeline asset by design. It's recorded as mitigated once internal names are restricted to the internal feed with no public fallback.

**Baseline Likelihood:** `very-likely` — This is the ceiling, so only the downward delta (RAA < 15) can apply.

**Baseline Impact:** `very-high` — Tampering maps to Integrity. This is the ceiling, so only the downward (low Integrity) delta can apply. The file gives no further reason.

### Malicious Package Install-Script Execution on CI Runner

**ID:** `malicious-install-script-execution`
**Location:** Native script rule — `pkg/risks/scripts/malicious-install-script-execution.yaml`

**Description:** The pipeline lets dependency install scripts run automatically during resolution, before any malware or vulnerability scan looks at the package. A malicious dependency's install script runs arbitrary code on the CI runner before any downstream scan can catch it.

**Applies to:** In-scope technical assets whose technologies carry the `.attributes.build-pipeline` attribute.

**Why it applies there:** The rule's `false_positives` says it fires unconditionally for every in-scope build-pipeline asset by design. It's recorded as mitigated once install scripts are suppressed by default and a publish-to-adoption cooldown is enforced.

**Baseline Likelihood:** `very-likely` — This is the ceiling, so only the downward delta (RAA < 15) can apply.

**Baseline Impact:** `very-high` — Tampering maps to Integrity. This is the ceiling, so only the downward (low Integrity) delta can apply. The file gives no further reason.

### Mishandling of Exceptional Conditions

**ID:** `mishandling-exceptional-conditions`
**Location:** Native script rule — `pkg/risks/scripts/mishandling-exceptional-conditions.yaml`

**Description:** The application doesn't treat exceptional conditions as fail-closed. An exception on an authorization- or validation-critical path can fall through to an allowed state, and an unhandled error response can leak stack traces, internal paths or library versions. An attacker can trigger such an exception on purpose to bypass a control that only runs on the success path.

**Applies to:** In-scope technical assets whose technologies carry the `.attributes.application_logic` attribute.

**Why it applies there:** The file's own comment explains why this is narrower than `frontend_related`/`backend_related`. The premise is an authorization or validation check in the asset's *own* code falling through on an exception, which requires the asset to own request/job-processing logic. Managed datastores (database, vault) and pure network plumbing (reverse proxy, load balancer, WAF) have no such code, so `application_logic` excludes them on purpose.

**Baseline Likelihood:** `likely` — The file has no likelihood comment. **(Structural inference)** The code returns very-likely, possible or likely by the standard RAA thresholds.

**Baseline Impact:** `high` — Elevation-of-Privilege uses the max CIA rank. "Not an edge tier", so medium, high and very-high are all reachable depending on rank.

### OS Command Injection

**ID:** `os-command-injection`
**Location:** Native script rule — `pkg/risks/scripts/os-command-injection.yaml`

**Description:** The asset's custom-developed request or job-processing code may build an OS shell command from unsanitized input. An adversary can then run arbitrary commands with the hosting process's privileges, which typically leads to full compromise of the host.

**Applies to:** In-scope technical assets with `custom_developed_parts` true **and** a technology carrying the `.attributes.application_logic` attribute.

**Why it applies there:** The file's comment explains the choice. Threagile's SQL/NoSQL/LDAP injection built-ins trigger on a technology-level attribute that names specific datastore products. No single technology means "shells out to the OS", because that is a code-level pattern any custom backend could contain. `application_logic` (the asset owns request/job-processing logic) combined with `custom_developed_parts` (the app team wrote that logic, not a vendor) approximates where this bug class is actually introduced.

**Baseline Likelihood:** `very-likely` — This is the ceiling, so only the downward delta (RAA < 15) can apply.

**Baseline Impact:** `very-high` — Elevation-of-Privilege uses the max CIA rank. This is the ceiling, so the only change is a drop when every dimension is at or below rank 1.

### Vulnerable and Outdated Third-Party Dependency

**ID:** `vulnerable-outdated-dependency`
**Location:** Native script rule — `pkg/risks/scripts/vulnerable-outdated-dependency.yaml`

**Description:** The asset's custom-developed code uses third-party libraries whose versions aren't continuously checked against known-vulnerability databases. This is separate from container base-image scanning and from End-of-Life tracking. A publicly disclosed vulnerability stays exploitable in production for as long as it goes undetected, even when an upstream fix already exists.

**Applies to:** In-scope technical assets with `custom_developed_parts` true.

**Why it applies there:** The file's comment says `custom_developed_parts` (a native per-asset field, not a technology attribute) is the right signal. The risk is about scanning the dependency graph of code the team actually wrote, not a vendor/COTS product's internal dependencies, "which the app team neither sees nor controls."

**Baseline Likelihood:** `very-likely` — This is the ceiling, so only the downward delta (RAA < 15) can apply.

**Baseline Impact:** `very-high` — Tampering maps to Integrity. This is the ceiling, so only the downward (low Integrity) delta can apply. The file gives no further reason.

---

## Artificial Intelligence

### Content Provenance Watermark Stripping and Forged Credential Insertion

**ID:** `ai-content-provenance-tampering`
**Location:** Native script rule — `pkg/risks/scripts/ai-content-provenance-tampering.yaml`

**Description:** A service that embeds or verifies provenance or watermark metadata on AI content can fail in two ways. Routine format conversion, recompression or cropping can strip the metadata undetected. A forged or replayed credential can make tampered or synthetic content look authentic. Downstream consumers then accept fakes as genuine, or discard genuine content whose signal was stripped.

**Applies to:** In-scope technical assets whose technologies carry the `.attributes.ai-content-provenance-service` attribute.

**Why it applies there:** The rule's `false_positives` says it fires unconditionally for every in-scope AI-content-provenance-service asset by design. It's recorded as mitigated once cryptographic signing and trusted-issuer verification are confirmed.

**Baseline Likelihood:** `likely` — This is a mid tier, so all three outcomes are reachable through the RAA delta.

**Baseline Impact:** `very-high` — Tampering maps to Integrity. The comment's reason: "a forged or stripped authenticity signal being trusted downstream is a total failure of this service's one job."

### Feature Store Lineage Gap and Unauthorized Derived-Feature Reuse

**ID:** `ai-feature-store-lineage-gap`
**Location:** Native script rule — `pkg/risks/scripts/ai-feature-store-lineage-gap.yaml`

**Description:** A feature store serving curated ML features loses track of which source dataset and classification each feature came from once other teams or models reuse it. A feature built from CUI or PII can reach a consumer that never inherited the original data's handling controls.

**Applies to:** In-scope technical assets whose technologies carry the `.attributes.ai-feature-store` attribute.

**Why it applies there:** The rule's `false_positives` says it fires unconditionally for every in-scope AI-feature-store asset by design. It's recorded as mitigated once write-time lineage recording and reuse gating are confirmed.

**Baseline Likelihood:** `likely` — This is a mid tier, so all three outcomes are reachable through the RAA delta.

**Baseline Impact:** `medium` — Tampering maps to Integrity. The file gives no further reason.

### AI Gateway Credential Sprawl and Cross-Backend Prompt Interception

**ID:** `ai-gateway-credential-sprawl`
**Location:** Native script rule — `pkg/risks/scripts/ai-gateway-credential-sprawl.yaml`

**Description:** A gateway that routes requests across multiple LLM backends holds every backend's credentials in one place. It also sees every prompt and response in the clear. Compromising it discloses all provider credentials at once and the full content of every AI interaction routed through it.

**Applies to:** In-scope technical assets whose technologies carry the `.attributes.ai-gateway` attribute.

**Why it applies there:** The rule's `false_positives` says it fires unconditionally for every in-scope AI-gateway asset by design. It's recorded as mitigated once credentials are individually vaulted and scoped and logged content is redacted.

**Baseline Likelihood:** `likely` — This is a mid tier, so all three outcomes are reachable through the RAA delta.

**Baseline Impact:** `very-high` — Information-Disclosure maps to Confidentiality. The comment's reason: "a gateway's blast radius spans every backend it routes to, regardless of this asset's own rating."

### Guardrail Bypass and Fail-Open Moderation Gap

**ID:** `ai-guardrails-bypass`
**Location:** Native script rule — `pkg/risks/scripts/ai-guardrails-bypass.yaml`

**Description:** A moderation or safety-filter layer on LLM input or output can be defeated by encoding, obfuscation or multi-turn jailbreaks. It can also fail open and pass traffic through unfiltered when it errors or times out. Either way the guardrail silently stops working, and nothing downstream is told.

**Applies to:** In-scope technical assets whose technologies carry the `.attributes.ai-guardrails` attribute.

**Why it applies there:** The rule's `false_positives` says it fires unconditionally for every in-scope AI-guardrails asset by design. It's recorded as mitigated once fail-closed behavior and recurring bypass testing are confirmed.

**Baseline Likelihood:** `likely` — This is a mid tier, so all three outcomes are reachable through the RAA delta.

**Baseline Impact:** `very-high` — Tampering maps to Integrity. The comment's reason: "a guardrail collapsing is a total control failure regardless of this asset's own rating."

### ATLAS: Adversarial Evasion Attack Against Model Decision Boundary

**ID:** `atlas-adversarial-evasion-attack`
**Location:** Native script rule — `pkg/risks/scripts/atlas-adversarial-evasion-attack.yaml`

**Description:** An adversary crafts inputs with small, often imperceptible perturbations that push the model across its decision boundary into a wrong classification or decision. The input still looks legitimate to humans and to downstream systems. This defeats any security or safety control that relies on the model's output being trustworthy.

**Applies to:** In-scope technical assets whose technologies carry `.attributes.ai-model-serving` **or** `.attributes.ai-llm-endpoint`.

**Why it applies there:** The rule's `false_positives` says it fires unconditionally for every in-scope AI model-serving/LLM-endpoint asset by design. **(Structural inference)** These are the assets that expose a model's decision boundary to inputs.

**Baseline Likelihood:** `likely` — This is a mid tier, so all three outcomes are reachable through the RAA delta.

**Baseline Impact:** `very-high` — Tampering maps to Integrity. The comment's reason: "a reliably evaded decision boundary is a total control failure regardless of this asset's own rating."

### ATLAS: AI Agent Orchestration Hijack and Persistence

**ID:** `atlas-agent-orchestration-hijack`
**Location:** Native script rule — `pkg/risks/scripts/atlas-agent-orchestration-hijack.yaml`

**Description:** The orchestration layer that plans tasks and dispatches tool calls is the highest-value target in an agentic system. It can be poisoned, reconfigured or hijacked to invoke tools or deploy rogue sub-agents. A compromised orchestrator gives an adversary persistent, automated access to every tool and data source the agent can reach.

**Applies to:** In-scope technical assets whose technologies carry the `.attributes.ai-agent-orchestrator` attribute.

**Why it applies there:** The rule's `false_positives` says it fires unconditionally for every in-scope agent-orchestrator asset by design. It's recorded as mitigated only when there is no write-capable tool access, a strictly isolated sandbox, and only pre-validated internal instructions.

**Baseline Likelihood:** `likely` — This is a mid tier, so all three outcomes are reachable through the RAA delta.

**Baseline Impact:** `very-high` — Elevation-of-Privilege uses the max CIA rank. This is the ceiling, so the only change is a drop when every dimension is at or below rank 1.

### ATLAS: Chaff Data Spamming and Detection Signal Dilution

**ID:** `atlas-chaff-data-spamming`
**Location:** Native script rule — `pkg/risks/scripts/atlas-chaff-data-spamming.yaml`

**Description:** An adversary floods an inference endpoint with plausible but meaningless input. The aim is to hide a real malicious action in the noise, or to dilute the signal that monitoring, anomaly detection or continuous learning depends on. This is distinct from volumetric DoS, because the goal is to degrade detection or learning fidelity rather than exhaust compute.

**Applies to:** In-scope technical assets whose technologies carry `.attributes.ai-model-serving` **or** `.attributes.ai-llm-endpoint`.

**Why it applies there:** The rule's `false_positives` says it fires unconditionally for every in-scope AI model-serving/LLM-endpoint asset by design. It's recorded as mitigated once plausibility/novelty scoring and dilution-aware monitoring are confirmed.

**Baseline Likelihood:** `likely` — This is a mid tier, so all three outcomes are reachable through the RAA delta.

**Baseline Impact:** `medium` — Denial-of-Service maps to Availability. The file gives no further reason.

### ATLAS: Dataset and RAG Ingest Integrity Erosion

**ID:** `atlas-dataset-ingest-integrity`
**Location:** Native script rule — `pkg/risks/scripts/atlas-dataset-ingest-integrity.yaml`

**Description:** The pipeline that chunks, embeds and writes documents into a vector store or training dataset is a high-value target for an adversary who can inject poisoned content upstream. A compromised ingest pipeline produces a poisoned knowledge base or training corpus that biases or corrupts model behavior at scale.

**Applies to:** In-scope technical assets whose technologies carry the `.attributes.ai-rag-ingest-pipeline` attribute.

**Why it applies there:** The rule's `false_positives` says it fires unconditionally for every in-scope RAG-ingest-pipeline asset by design. `risk_assessment` rates external or user-contributed content High and fully internal corpora Medium.

**Baseline Likelihood:** `likely` — This is a mid tier, so all three outcomes are reachable through the RAA delta.

**Baseline Impact:** `medium` — Tampering maps to Integrity. The file gives no further reason.

### ATLAS: AI Training Dataset Exfiltration and Integrity Attack

**ID:** `atlas-dataset-store-attack`
**Location:** Native script rule — `pkg/risks/scripts/atlas-dataset-store-attack.yaml`

**Description:** The authoritative training or evaluation dataset store is a high-value target for both exfiltration and integrity attacks. Exfiltrating it is a formal data spill. Compromising its integrity poisons downstream models until they are rebuilt from a known-good state.

**Applies to:** In-scope technical assets whose technologies carry the `.attributes.ai-dataset-store` attribute.

**Why it applies there:** The rule's `false_positives` says it fires unconditionally for every in-scope dataset-store asset by design. It's recorded as mitigated once RBAC, encryption at rest and cryptographic integrity verification are confirmed.

**Baseline Likelihood:** `likely` — This is a mid tier, so all three outcomes are reachable through the RAA delta.

**Baseline Impact:** `medium` — Information-Disclosure maps to Confidentiality. The file gives no further reason.

### ATLAS: LLM Inference API Abuse, Cost Harvesting, and Model Extraction

**ID:** `atlas-inference-api-abuse`
**Location:** Native script rule — `pkg/risks/scripts/atlas-inference-api-abuse.yaml`

**Description:** An exposed inference API can be queried systematically to extract a working copy of the model, to infer whether specific records were in the training data, or to harvest compute. Extraction undermines IP protection, membership inference can amount to a data breach, and cost harvesting drives unauthorized cloud spend.

**Applies to:** In-scope technical assets whose technologies carry the `.attributes.ai-llm-endpoint` attribute.

**Why it applies there:** The rule's `false_positives` says it fires unconditionally for every in-scope LLM-endpoint asset by design. It's recorded as mitigated once rate limiting, output perturbation and anomaly detection are all confirmed.

**Baseline Likelihood:** `very-likely` — This is the ceiling, so only the downward delta (RAA < 15) can apply.

**Baseline Impact:** `medium` — Information-Disclosure maps to Confidentiality. The file gives no further reason.

### ATLAS: AI Model Registry Supply Chain and Reputation Attack

**ID:** `atlas-model-registry-supply-chain`
**Location:** Native script rule — `pkg/risks/scripts/atlas-model-registry-supply-chain.yaml`

**Description:** A model registry is a central supply-chain chokepoint. It can be used to publish malware-embedded models, replace a trusted model version, or inflate reputation metrics. A malicious artifact deployed through it can achieve remote code execution on the serving infrastructure.

**Applies to:** In-scope technical assets whose technologies carry the `.attributes.ai-model-registry` attribute.

**Why it applies there:** The rule's `false_positives` says it fires unconditionally for every in-scope model-registry asset by design. It's recorded as mitigated only for internally trained safetensors models with privileged-CI-only writes.

**Baseline Likelihood:** `possible` — "not an edge tier", so both the upward (RAA >= 40) and downward (RAA < 15) deltas can apply.

**Baseline Impact:** `very-high` — Tampering maps to Integrity. This is the ceiling, so only the downward (low Integrity) delta can apply. The file gives no further reason.

### ATLAS: AI Model Supply Chain Compromise and Model Manipulation

**ID:** `atlas-model-supply-chain`
**Location:** Native script rule — `pkg/risks/scripts/atlas-model-supply-chain.yaml`

**Description:** The asset loads or serves trained model artifacts from external or shared registries. Those artifacts can be compromised at the weights, container or dependency level. A backdoored artifact can get remote code execution on the serving host, or produce systematically manipulated outputs that still pass standard evaluation.

**Applies to:** In-scope technical assets whose technologies carry the `.attributes.ai-model-serving` attribute.

**Why it applies there:** The rule's `false_positives` says it fires unconditionally for every in-scope model-serving asset by design. `risk_assessment` rates Pickle-format weights from public or shared registries without digest pinning as Critical.

**Baseline Likelihood:** `possible` — "not an edge tier", so both the upward and downward RAA deltas can apply.

**Baseline Impact:** `very-high` — Tampering maps to Integrity. This is the ceiling, so only the downward (low Integrity) delta can apply. The file gives no further reason.

### ATLAS: RAG Pipeline Poisoning and Data Exfiltration

**ID:** `atlas-rag-poisoning-exfil`
**Location:** Native script rule — `pkg/risks/scripts/atlas-rag-poisoning-exfil.yaml`

**Description:** A RAG pipeline grounds LLM responses in documents retrieved from a vector store. An adversary who can influence the indexed content can poison what gets retrieved. That can persistently redirect model behavior for every user asking about related topics, or exfiltrate queries to an attacker-controlled destination.

**Applies to:** In-scope technical assets whose technologies carry the `.attributes.ai-rag-pipeline` attribute.

**Why it applies there:** The rule's `false_positives` says it fires unconditionally for every in-scope RAG-pipeline asset by design. It's recorded as mitigated only when the store is populated solely by a controlled, authenticated internal ingest.

**Baseline Likelihood:** `likely` — This is a mid tier, so all three outcomes are reachable through the RAA delta.

**Baseline Impact:** `medium` — Tampering maps to Integrity. The file gives no further reason.

### ATLAS: Synthetic Data Generator Memorization and Residual Source-Data Leakage

**ID:** `atlas-synthetic-data-memorization`
**Location:** Native script rule — `pkg/risks/scripts/atlas-synthetic-data-memorization.yaml`

**Description:** A pipeline that generates synthetic data to avoid exposing real sensitive data defeats its own purpose if the underlying generative model has memorized fragments of the source data and reproduces them. The synthetic set can then carry recoverable CUI or classified fragments, undetected, to every downstream consumer.

**Applies to:** In-scope technical assets whose technologies carry the `.attributes.ai-synthetic-data-pipeline` attribute.

**Why it applies there:** The rule's `false_positives` says it fires unconditionally for every in-scope AI-synthetic-data-pipeline asset by design. It's recorded as mitigated once memorization testing before each release is confirmed.

**Baseline Likelihood:** `likely` — This is a mid tier, so all three outcomes are reachable through the RAA delta.

**Baseline Impact:** `medium` — Information-Disclosure maps to Confidentiality. The file gives no further reason.

### ATLAS: Training Data Poisoning and Model Backdoor Insertion

**ID:** `atlas-training-data-poisoning`
**Location:** Native script rule — `pkg/risks/scripts/atlas-training-data-poisoning.yaml`

**Description:** The training or fine-tuning pipeline ingests data from sources an adversary may be able to write to, such as public datasets, web scrapes or user feedback loops. A model can be backdoored to misbehave on specific trigger inputs while appearing benign on standard evaluations.

**Applies to:** In-scope technical assets whose technologies carry the `.attributes.ai-training-pipeline` attribute.

**Why it applies there:** The rule's `false_positives` says it fires unconditionally for every in-scope training-pipeline asset by design. `risk_assessment` rates continuous learning, RLHF or feedback-driven fine-tuning High and static training Medium.

**Baseline Likelihood:** `unlikely` — This is the floor, so only the upward delta (RAA >= 40) can apply.

**Baseline Impact:** `medium` — Tampering maps to Integrity. The file gives no further reason.

### ATLAS: Unbounded AI Resource Consumption and Denial of Service

**ID:** `atlas-unbounded-ai-consumption`
**Location:** Native script rule — `pkg/risks/scripts/atlas-unbounded-ai-consumption.yaml`

**Description:** The inference API has no enforced limit on request volume, concurrency, or per-request context/output size. A single caller, or a runaway legitimate client, can exhaust compute, deny service to legitimate users and drive unbounded spend. Each request can cost far more GPU/CPU to serve than it costs to send.

**Applies to:** In-scope technical assets whose technologies carry the `.attributes.ai-llm-endpoint` attribute.

**Why it applies there:** The rule's `false_positives` says it fires unconditionally for every in-scope LLM-endpoint asset by design. It's recorded as mitigated once per-user rate limits, concurrency caps and token budgets are confirmed at the gateway.

**Baseline Likelihood:** `very-likely` — This is the ceiling, so only the downward delta (RAA < 15) can apply.

**Baseline Impact:** `medium` — Denial-of-Service maps to Availability. The file gives no further reason.

### ATLAS: Vector Store Embedding Inversion and Unauthorized Similarity Query Abuse

**ID:** `atlas-vector-store-inversion`
**Location:** Native script rule — `pkg/risks/scripts/atlas-vector-store-inversion.yaml`

**Description:** A vector store is open to embedding inversion, which reconstructs source text from the vectors themselves. It is also open to similarity-query abuse that infers membership of records an attacker shouldn't see. Anyone with query access or a leaked embedding dump can recover sensitive content that no plaintext document ever exposed.

**Applies to:** In-scope technical assets whose technologies carry the `.attributes.ai-vector-store` attribute.

**Why it applies there:** The rule's `false_positives` says it fires unconditionally for every in-scope vector-store asset by design. It's recorded as mitigated once query access is authenticated and rate-limited and exports follow the source classification.

**Baseline Likelihood:** `likely` — This is a mid tier, so all three outcomes are reachable through the RAA delta.

**Baseline Impact:** `medium` — Information-Disclosure maps to Confidentiality. The file gives no further reason.

### Hyperparameter Tampering Without Baseline Diffing

**ID:** `hyperparameter-tampering-no-baseline-diff`
**Location:** Native script rule — `pkg/risks/scripts/hyperparameter-tampering-no-baseline-diff.yaml`

**Description:** Nobody diffs a training run's applied hyperparameters against an approved baseline before promoting the resulting model. An insider can bias what the model learns by changing a single hyperparameter, leave no trace in the code, and still pass standard evaluation.

**Applies to:** In-scope technical assets whose technologies carry the `.attributes.ai-training-pipeline` attribute.

**Why it applies there:** The rule's `false_positives` says it fires unconditionally for every in-scope training-pipeline asset by design. It's recorded as mitigated once a baseline diff is confirmed to run before every promotion.

**Baseline Likelihood:** `unlikely` — This is the floor, so only the upward delta (RAA >= 40) can apply.

**Baseline Impact:** `medium` — Tampering maps to Integrity. The file gives no further reason.

### OWASP LLM05: Improper Output Handling Reaching a Downstream Sink

**ID:** `llm-improper-output-handling`
**Location:** Native script rule — `pkg/risks/scripts/llm-improper-output-handling.yaml`

**Description:** LLM output goes to a downstream consumer without encoding or validation suited to that sink. Examples are a browser, a database query, a shell or code interpreter, a template engine, or another API. Upstream prompt manipulation then turns directly into XSS, SQL/command injection, SSRF or unauthorized API calls. This applies even when the output is merely wrong, because the output is trusted by default.

**Applies to:** In-scope technical assets whose technologies carry any of `.attributes.ai-llm-endpoint`, `.attributes.ai-model-serving`, `.attributes.ai-rag-pipeline` or `.attributes.ai-agent-orchestrator`.

**Why it applies there:** The rule's `false_positives` says it fires unconditionally for every in-scope asset of those four kinds by design. It's recorded as mitigated once every downstream sink applies context-appropriate encoding or validation.

**Baseline Likelihood:** `likely` — This is a mid tier, so all three outcomes are reachable through the RAA delta.

**Baseline Impact:** `very-high` — Tampering maps to Integrity. The comment's reason: "unescaped output reaching an interpreter is a total control failure at that sink regardless of this asset's own rating."

### MAESTRO L5: Evaluation Pipeline and Benchmark Poisoning

**ID:** `maestro-l5-eval-pipeline-poisoning`
**Location:** Native script rule — `pkg/risks/scripts/maestro-l5-eval-pipeline-poisoning.yaml`

**Description:** The evaluation and benchmark pipeline that gates promotion can be manipulated at the dataset, scoring or reporting layer. A backdoored or degraded model can then pass pre-production review and reach every production user undetected.

**Applies to:** In-scope technical assets whose technologies carry the `.attributes.ai-eval-pipeline` attribute.

**Why it applies there:** The rule's `false_positives` says it fires unconditionally for every in-scope eval-pipeline asset by design. It's recorded as mitigated once eval datasets are hash-protected and the eval environment is separated from training.

**Baseline Likelihood:** `unlikely` — This is the floor, so only the upward delta (RAA >= 40) can apply.

**Baseline Impact:** `medium` — Tampering maps to Integrity. The file gives no further reason.

### MAESTRO L5: AI Observability Stack Compromise and Evidence Destruction

**ID:** `maestro-l5-observability-compromise`
**Location:** Native script rule — `pkg/risks/scripts/maestro-l5-observability-compromise.yaml`

**Description:** Once an attacker has initial access, the AI-specific monitoring and anomaly-detection layer becomes a target, because blinding it hides further activity. An attacker can selectively delete inference logs, mask anomalous behavior, or exfiltrate sensitive prompts through the telemetry pipeline itself.

**Applies to:** In-scope technical assets whose technologies carry the `.attributes.ai-observability-stack` attribute.

**Why it applies there:** The rule's `false_positives` says it fires unconditionally for every in-scope AI-observability-stack asset by design. It's recorded as mitigated once telemetry goes to a write-once store the AI runtime can't modify, with PII/CUI scrubbed.

**Baseline Likelihood:** `unlikely` — This is the floor, so only the upward delta (RAA >= 40) can apply.

**Baseline Impact:** `very-high` — Information-Disclosure maps to Confidentiality. This is the ceiling, so only the downward (low Confidentiality) delta can apply. The file gives no further reason.

### MAESTRO L6: AI-Powered Security Tooling Compromise

**ID:** `maestro-l6-security-ai-compromise`
**Location:** Native script rule — `pkg/risks/scripts/maestro-l6-security-ai-compromise.yaml`

**Description:** AI-powered defensive tools that make trust decisions and trigger automated responses are themselves targets, and compromising them has outsized consequences. A compromised security AI can suppress alerts for the attacker's own activity, raise false incidents to overwhelm analysts, or pivot to other systems from a trusted context.

**Applies to:** In-scope technical assets whose technologies carry the `.attributes.ai-security-agent` attribute.

**Why it applies there:** The rule's `false_positives` says it fires unconditionally for every in-scope AI-security-agent asset by design. It's recorded as mitigated once a non-AI detection backstop and advisory-only or human-gated response scope are confirmed.

**Baseline Likelihood:** `unlikely` — This is the floor, so only the upward delta (RAA >= 40) can apply.

**Baseline Impact:** `very-high` — Elevation-of-Privilege uses the max CIA rank. This is the ceiling, so the only change is a drop when every dimension is at or below rank 1.

### MAESTRO L7: Agent Ecosystem Identity, Impersonation, and Goal Manipulation

**ID:** `maestro-l7-agent-ecosystem-identity`
**Location:** Native script rule — `pkg/risks/scripts/maestro-l7-agent-ecosystem-identity.yaml`

**Description:** Agents that delegate tasks across identity domains need strong agent identity and authorization controls at those trust boundaries. Without them, impersonation, goal manipulation and repudiation become possible. A malicious agent can impersonate a trusted one or alter another agent's objectives inside the system's own trusted execution context.

**Applies to:** In-scope technical assets whose technologies carry the `.attributes.ai-multi-agent-gateway` attribute.

**Why it applies there:** The rule's `false_positives` says it fires unconditionally for every in-scope multi-agent-gateway asset by design. It's recorded as mitigated once cryptographic agent identity, mutual authentication and a non-repudiation trail are confirmed.

**Baseline Likelihood:** `likely` — This is a mid tier, so all three outcomes are reachable through the RAA delta.

**Baseline Impact:** `very-high` — Spoofing maps to Integrity. This is the ceiling, so only the downward (low Integrity) delta can apply. The file gives no further reason.

### No Canary Prompt Testing Against Production Inference Endpoint

**ID:** `missing-canary-prompt-testing`
**Location:** Native script rule — `pkg/risks/scripts/missing-canary-prompt-testing.yaml`

**Description:** No versioned suite of known-answer prompts runs against the production endpoint on a schedule. Nothing would detect a silently swapped model, a disabled safety filter, or an unreviewed system-prompt change. Such a change can persist for a long time, because traffic-based monitoring has no independent baseline to compare against.

**Applies to:** In-scope technical assets whose technologies carry the `.attributes.ai-llm-endpoint` attribute.

**Why it applies there:** The rule's `false_positives` says it fires unconditionally for every in-scope LLM-endpoint asset by design. It's recorded as mitigated once a recurring canary suite with deviation alerting is confirmed.

**Baseline Likelihood:** `likely` — This is a mid tier, so all three outcomes are reachable through the RAA delta.

**Baseline Impact:** `medium` — Tampering maps to Integrity. The file gives no further reason.

### Missing Model Rollback and Kill-Switch Mechanism

**ID:** `missing-model-rollback-killswitch`
**Location:** Native script rule — `pkg/risks/scripts/missing-model-rollback-killswitch.yaml`

**Description:** There is no way to revert this model-serving asset to a previously validated version, or to cut its traffic with a kill switch, without rerunning the full deployment pipeline. A compromised or badly regressed model keeps serving production traffic for the whole redeployment cycle.

**Applies to:** In-scope technical assets whose technologies carry the `.attributes.ai-model-serving` attribute.

**Why it applies there:** The rule's `false_positives` says it fires unconditionally for every in-scope model-serving asset by design. It's recorded as mitigated once a tested rollback path and an independent kill switch with a safe-mode fallback are confirmed.

**Baseline Likelihood:** `likely` — This is a mid tier, so all three outcomes are reachable through the RAA delta.

**Baseline Impact:** `medium` — Denial-of-Service maps to Availability. The file gives no further reason.

### On-Device Model Extraction Resistance Gap

**ID:** `on-device-model-extraction-gap`
**Location:** Native script rule — `pkg/risks/scripts/on-device-model-extraction-gap.yaml`

**Description:** A model fielded on physical hardware that an adversary could take custody of, such as an edge or embedded deployment, gives up the full model to whoever recovers the hardware. The exception is a model running inside a trusted execution environment or secure enclave. No detection or revocation is possible afterward.

**Applies to:** In-scope technical assets whose `machine` is **not** `virtual`, `container` or `serverless` (which means physical or unset), **and** whose technologies carry `.attributes.ai-model-serving` or `.attributes.ai-llm-endpoint`.

**Why it applies there:** The file's comment explains the negated check. "physical" is `machine`'s zero value, and yaml omitempty drops it during the script engine's re-serialization, so it can never be compared as a literal. Excluding the other three values correctly captures physical and unset (which defaults to physical). The description adds that a cloud-hosted model never had physical custody as a realistic attack path.

**Baseline Likelihood:** `likely` — This is a mid tier, so all three outcomes are reachable through the RAA delta.

**Baseline Impact:** `very-high` — Information-Disclosure maps to Confidentiality. The comment's reason: "physical recovery of the device is a total extraction event regardless of this asset's own rating."

### System Prompt Leakage

**ID:** `system-prompt-leakage`
**Location:** Native script rule — `pkg/risks/scripts/system-prompt-leakage.yaml`

**Description:** A system prompt or agent instructions may encode confidential business logic, internal tool definitions or guardrail rules. Crafted queries ("repeat your instructions verbatim", encoding tricks, roleplay) can extract them. An adversary then has a blueprint for bypassing the guardrails and a list of internal tool names to target.

**Applies to:** In-scope technical assets whose technologies carry `.attributes.ai-llm-endpoint`, `.attributes.ai-rag-pipeline` or `.attributes.ai-agent-orchestrator`.

**Why it applies there:** The rule's `false_positives` says it fires unconditionally for every in-scope LLM-endpoint/RAG-pipeline/agent-orchestrator asset by design. It's recorded as mitigated once the prompt is confirmed secret-free and an output-side prompt-echo filter is confirmed active.

**Baseline Likelihood:** `very-likely` — This is the ceiling, so only the downward delta (RAA < 15) can apply.

**Baseline Impact:** `medium` — Information-Disclosure maps to Confidentiality. "Not an edge tier", so low, medium and high are all reachable.

### Training Script and Feature-Engineering Pipeline IP Exfiltration

**ID:** `training-script-ip-exfiltration`
**Location:** Native script rule — `pkg/risks/scripts/training-script-ip-exfiltration.yaml`

**Description:** Training scripts and feature-engineering pipelines don't get the access restriction and egress monitoring applied to the model artifacts they produce, even though they are often more valuable. Exfiltrating the methodology lets an adversary replicate or improve the model without triggering any of the controls built to protect the weights.

**Applies to:** In-scope technical assets whose technologies carry the `.attributes.ai-training-pipeline` attribute.

**Why it applies there:** The rule's `false_positives` says it fires unconditionally for every in-scope training-pipeline asset by design. It's recorded as mitigated once the code is access-restricted, encrypted at rest, and monitored for bulk clone/export.

**Baseline Likelihood:** `likely` — This is a mid tier, so all three outcomes are reachable through the RAA delta.

**Baseline Impact:** `medium` — Information-Disclosure maps to Confidentiality. The file gives no further reason.

### Ungoverned Production System Prompt Change

**ID:** `ungoverned-system-prompt-change`
**Location:** Native script rule — `pkg/risks/scripts/ungoverned-system-prompt-change.yaml`

**Description:** The production system prompt can be edited without version control, review or injection-hardening requirements. An unreviewed change can silently widen the model's capability or remove a safety constraint, and no runtime signal exists for a filter or detector to catch.

**Applies to:** In-scope technical assets whose technologies carry `.attributes.ai-llm-endpoint`, `.attributes.ai-rag-pipeline` or `.attributes.ai-agent-orchestrator`.

**Why it applies there:** The rule's `false_positives` says it fires unconditionally for every in-scope LLM-endpoint/RAG-pipeline/agent-orchestrator asset by design. It's recorded as mitigated once prompts are version-controlled with mandatory review and an explicit instruction-boundary structure.

**Baseline Likelihood:** `likely` — This is a mid tier, so all three outcomes are reachable through the RAA delta.

**Baseline Impact:** `medium` — Tampering maps to Integrity. The file gives no further reason.

### Untrusted Model Registry Source

**ID:** `untrusted-model-registry-source`
**Location:** Native script rule — `pkg/risks/scripts/untrusted-model-registry-source.yaml`

**Description:** The serving platform has loaded, or can load, a model whose registry host and artifact digest don't resolve to an approved internal registry. Such a model skips every certification, signing and scanning gate the approved registry enforces, and the platform can't tell it apart from a vetted one.

**Applies to:** In-scope technical assets whose technologies carry `.attributes.ai-model-serving` **or** `.attributes.ai-model-registry`.

**Why it applies there:** The rule's `false_positives` says it fires unconditionally for every in-scope model-serving/model-registry asset by design. It's recorded as mitigated once loads are confirmed restricted to the approved registry by host and digest.

**Baseline Likelihood:** `possible` — "not an edge tier", so both the upward (RAA >= 40) and downward (RAA < 15) deltas can apply.

**Baseline Impact:** `very-high` — Tampering maps to Integrity. This is the ceiling, so only the downward (low Integrity) delta can apply. The file gives no further reason.

---

## Data

### Accidental Secret Leak

**ID:** `accidental-secret-leak`
**Location:** Native script rule — `pkg/risks/scripts/accidental-secret-leak.yaml`

**Description:** A source repository or artifact registry can end up containing secrets: a pasted API token, an un-ignored .env file, a private key in a container layer, a committed connection string. They persist in history after deletion and in every published layer or version. Anyone with read access, including an attacker who compromises one developer account, can recover them and use them.

**Applies to:** In-scope technical assets whose technologies carry `.attributes.sourcecode-repository` **or** `.attributes.artifact-registry`. The title adds a "(Git)" variant when the asset carries a `git` tag.

**Why it applies there:** **(Structural inference)** The file has no comment on the match condition. Repositories and registries are where committed or published secrets persist, as its description says. Per its likelihood comment, this script rule shadows the fork's built-in `accidental-secret-leak-rule.go`, and "only this one actually fires."

**Baseline Likelihood:** `likely` — This is a mid tier, so all three outcomes are reachable through the RAA delta. The comment says it "matches the baseline this fork's built-in accidental-secret-leak-rule.go uses ... so the two agree."

**Baseline Impact:** `low` — *This rule doesn't follow the usual single-dimension baseline/delta pattern, and the file has no comment explaining it.* **(Structural inference)** `get_impact` starts at `low`. It raises to `medium` if the highest Confidentiality across the asset and its processed data assets is at least confidential, or the highest Integrity or Availability is at least critical. It raises to `high` at strictly-confidential or mission-critical.

### CUI Telemetry Spillage

**ID:** `cui-telemetry-spillage`
**Location:** Native script rule — `pkg/risks/scripts/cui-telemetry-spillage.yaml`

**Description:** CUI can end up in application logs, stack traces or observability telemetry through debug logging, ORM query logging, or auto-instrumentation that captures request headers. Once CUI reaches a log or telemetry pipeline it is a formal data spill, and it may be exposed to personnel without need-to-know.

**Applies to:** In-scope technical assets whose technologies carry `.attributes.frontend_related`, `.attributes.backend_related` or `.attributes.application_logic`.

**Why it applies there:** The file's comment says `application_logic` is OR'd in alongside `frontend_related`/`backend_related` to also catch technologies that carry neither but "genuinely have their own logging/telemetry surface". Its examples are application-server, report-engine, web-server and llm-endpoint.

**Baseline Likelihood:** `very-likely` — This is the ceiling, so only the downward delta (RAA < 15) can apply.

**Baseline Impact:** `medium` — Information-Disclosure maps to Confidentiality. The file gives no further reason.

### Hardcoded Credentials and Secrets Sprawl

**ID:** `hardcoded-credentials-secrets-sprawl`
**Location:** Native script rule — `pkg/risks/scripts/hardcoded-credentials-secrets-sprawl.yaml`

**Description:** Credentials, API keys or other secrets are embedded in source code, container images or configuration files. Copies persist across git history, image layers and build caches even after rotation. A discovered secret gives immediate authenticated access, and automated scanning often finds one within hours of exposure.

**Applies to:** In-scope technical assets carrying the `data:credential` tag, **excluding** any asset whose technologies carry the `.attributes.vault` attribute.

**Why it applies there:** The file's comment says `data:credential` stays a tag read because Threagile's DataAsset schema has "no native concept of 'this is credential-shaped data'". `false_positives` explains the vault exclusion: a vault's whole purpose is to hold the credential data this rule is about leaking elsewhere.

**Baseline Likelihood:** `very-likely` — This is the ceiling, so only the downward delta (RAA < 15) can apply.

**Baseline Impact:** `high` — Information-Disclosure maps to Confidentiality. The file gives no further reason.

### Key Management Separation-of-Duties Violation

**ID:** `key-management-separation-of-duties-violation`
**Location:** Native script rule — `pkg/risks/scripts/key-management-separation-of-duties-violation.yaml`

**Description:** A single identity can both perform key operations and administer or audit the same vault's access policy and activity log. One compromised or malicious identity can misuse a key and erase the trace, with no independent party in a position to notice.

**Applies to:** In-scope technical assets whose technologies carry the `.attributes.vault` attribute.

**Why it applies there:** The rule's `false_positives` says it fires unconditionally for every in-scope vault asset by design. It's recorded as mitigated once key-operation and administration/audit permissions are held by distinct roles.

**Baseline Likelihood:** `unlikely` — This is the floor, so only the upward delta (RAA >= 40) can apply.

**Baseline Impact:** `medium` — Elevation-of-Privilege uses the max CIA rank. The file gives no further reason.

### Key Rotation and Escrow Neglect

**ID:** `key-rotation-escrow-neglect`
**Location:** Native script rule — `pkg/risks/scripts/key-rotation-escrow-neglect.yaml`

**Description:** Key rotation is manual and done inconsistently, and no tested escrow or recovery procedure exists for a customer-managed key. A key that is never rotated has an ever-growing undetected exposure window. An untested recovery procedure can mean permanent loss of access at the moment it's needed.

**Applies to:** In-scope technical assets whose technologies carry the `.attributes.vault` attribute.

**Why it applies there:** The rule's `false_positives` says it fires unconditionally for every in-scope vault asset by design. It's recorded as mitigated once automated rotation and an escrow/recovery exercise in the current period are confirmed.

**Baseline Likelihood:** `unlikely` — This is the floor, so only the upward delta (RAA >= 40) can apply.

**Baseline Impact:** `medium` — Information-Disclosure maps to Confidentiality. The file gives no further reason.

### Key Storage and Ownership Hardening Gap

**ID:** `key-storage-ownership-hardening-gap`
**Location:** Native script rule — `pkg/risks/scripts/key-storage-ownership-hardening-gap.yaml`

**Description:** The secrets or key-management asset holds consequential key material that is either generated only in software, rather than in a hardware-backed root of trust, or encrypted under a platform-managed key where policy requires a customer-managed one. A compromised host that generated a software-only key gives up the key material directly.

**Applies to:** In-scope technical assets whose technologies carry the `.attributes.vault` attribute.

**Why it applies there:** The rule's `false_positives` says it fires unconditionally for every in-scope vault asset by design. It's recorded as mitigated once hardware-backed key generation and the right key-ownership tier are confirmed.

**Baseline Likelihood:** `unlikely` — This is the floor, so only the upward delta (RAA >= 40) can apply.

**Baseline Impact:** `medium` — Information-Disclosure maps to Confidentiality. The file gives no further reason.

### Media Sanitization Procedure Gap

**ID:** `media-sanitization-procedure-gap`
**Location:** Native script rule — `pkg/risks/scripts/media-sanitization-procedure-gap.yaml`

**Description:** The VM's persistent storage has no documented sanitization procedure aligned with NIST SP 800-88 for end-of-life, decommissioning or repurposing. CUI stays recoverable on a disk that is decommissioned, repurposed, or returned to a provider or vendor without verified sanitization.

**Applies to:** In-scope technical assets whose `machine` is `virtual`.

**Why it applies there:** The rule's `false_positives` says it fires unconditionally for every in-scope virtual-machine asset by design. `risk_assessment` notes that destroying an organization-controlled key alone counts as effective sanitization.

**Baseline Likelihood:** `likely` — The file has no baseline comment. **(Structural inference)** The code returns very-likely, possible or likely by the standard RAA thresholds.

**Baseline Impact:** `medium` — The file has no baseline comment beyond "Information-Disclosure -> Confidentiality". **(Structural inference)** The code returns low, medium or high by Confidentiality rank.

### Missing Data Retention and Disposition Schedule

**ID:** `missing-data-retention-schedule`
**Location:** Native script rule — `pkg/risks/scripts/missing-data-retention-schedule.yaml`

**Description:** The asset holds data with no documented retention period or disposition action tied to its classification. Sensitive holdings can be kept indefinitely with no owner for disposal, while records needed for a later investigation can be lost too early.

**Applies to:** In-scope technical assets whose `type` is `datastore`.

**Why it applies there:** The rule's `false_positives` says it fires unconditionally for every in-scope datastore asset by design. It's recorded as mitigated once an enforced retention/disposition schedule is confirmed for every data type held.

**Baseline Likelihood:** `likely` — This is a mid tier, so all three outcomes are reachable through the RAA delta.

**Baseline Impact:** `low` — Information-Disclosure maps to Confidentiality. This is the floor, so only the upward delta can apply. "restricted" maps to a zero delta, so only confidential or strictly-confidential visibly move it.

### Multi-Tenant Data Isolation Failure

**ID:** `multi-tenant-data-isolation`
**Location:** Native script rule — `pkg/risks/scripts/multi-tenant-data-isolation.yaml`

**Description:** The asset serves multiple organizational tenants from a shared deployment without enough isolation in database queries, caching or background jobs. An authorization failure that would expose one user's data in a single-tenant system instead exposes a whole tenant's data to another tenant's users.

**Applies to:** In-scope technical assets with the native `multi_tenant` field set to true.

**Why it applies there:** **(Structural inference)** The file has no match comment. The risk only exists where a shared deployment serves multiple tenants, which is exactly what the native `multi_tenant` field records. `false_positives` names physical per-tenant isolation as the compliant case.

**Baseline Likelihood:** `likely` — The file has no likelihood comment. **(Structural inference)** The code returns very-likely, possible or likely by the standard RAA thresholds.

**Baseline Impact:** `very-high` — Information-Disclosure maps to Confidentiality. This is the ceiling, so only the downward (low Confidentiality) case can apply. `risk_assessment` adds that individual isolation failures are "at least one level higher than equivalent single-tenant findings."

### Unencrypted Virtual Disk

**ID:** `unencrypted-virtual-disk`
**Location:** Native script rule — `pkg/risks/scripts/unencrypted-virtual-disk.yaml`

**Description:** The VM's attached disks aren't encrypted at rest, or don't use a FIPS-validated cryptographic module. An attacker or malicious insider who snapshots or detaches the disk can read its contents offline.

**Applies to:** In-scope technical assets whose `machine` is `virtual`.

**Why it applies there:** The rule's `false_positives` says it fires unconditionally for every in-scope virtual-machine asset by design. It's recorded as mitigated once at-rest encryption with a platform- or customer-managed key is confirmed.

**Baseline Likelihood:** `unlikely` — This is the floor, so only the upward delta (RAA >= 40) can apply.

**Baseline Impact:** `medium` — The file has no baseline comment beyond "Information-Disclosure -> Confidentiality". **(Structural inference)** The code returns low, medium or high by Confidentiality rank.

### Unclassified or Unscanned Data Store

**ID:** `unscanned-data-store`
**Location:** Native script rule — `pkg/risks/scripts/unscanned-data-store.yaml`

**Description:** A persistent data store has never been through an automated classification scan, so no sensitivity label is attached to its data. Controls that depend on that label (encryption tier, access policy, DLP, retention) fall back to a default posture that may not match the data's true sensitivity.

**Applies to:** In-scope technical assets whose `type` is `datastore`.

**Why it applies there:** The rule's `false_positives` says it fires unconditionally for every in-scope datastore asset by design. It's recorded as mitigated once recurring scanning and labeling are confirmed.

**Baseline Likelihood:** `likely` — This is a mid tier, so all three outcomes are reachable through the RAA delta.

**Baseline Impact:** `medium` — Information-Disclosure maps to Confidentiality. The file gives no further reason.

---

## Detection

### Baseline Security Event Logging and SIEM Forwarding Gap

**ID:** `baseline-security-event-logging-gap`
**Location:** Native script rule — `pkg/risks/scripts/baseline-security-event-logging-gap.yaml`

**Description:** The asset doesn't capture authentication failures, authorization denials and input-validation rejections and forward them to the SIEM. This is separate from the narrower logging its feature-specific detection risks already require. Sustained probing, credential stuffing and authorization-bypass attempts produce no correlated signal, so the SOC can't see the buildup to a compromise.

**Applies to:** In-scope technical assets whose technologies carry `.attributes.frontend_related`, `.attributes.backend_related` or `.attributes.application_logic`.

**Why it applies there:** The file's comment says `application_logic` is OR'd in to also catch technologies that carry neither of the other two attributes but "genuinely have their own authentication/authorization/input-validation surface worth forwarding to the SIEM". Its examples are application-server, report-engine, web-server and llm-endpoint.

**Baseline Likelihood:** `likely` — This is a mid tier, so all three outcomes are reachable through the RAA delta.

**Baseline Impact:** `medium` — Repudiation maps to Integrity, following the `STRIDE_TO_CIA_DIMENSION` convention in `inject_risks.py`. The comment's reason: "an unforwarded security event is an integrity failure of the evidence itself, not a confidentiality one."

### Container Orchestrator Control-Plane Audit Logging Gap

**ID:** `cluster-control-plane-audit-gap`
**Location:** Native script rule — `pkg/risks/scripts/cluster-control-plane-audit-gap.yaml`

**Description:** The cluster's audit policy is left at its default, which doesn't capture pod exec, port-forward, secret access or admission-controller decisions. Lateral movement inside the cluster after a compromise leaves no audit trail for an incident responder to reconstruct.

**Applies to:** In-scope technical assets whose `machine` is `container`.

**Why it applies there:** The rule's `false_positives` says it fires unconditionally for every in-scope container asset by design. It's recorded as mitigated once an explicit audit policy covering exec/attach/port-forward, secret access and admission decisions is deployed and forwarding to the SIEM.

**Baseline Likelihood:** `likely` — The file has no baseline comment. **(Structural inference)** The code returns very-likely, possible or likely by the standard RAA thresholds.

**Baseline Impact:** `medium` — The file has no explicit baseline value. Its comment maps Repudiation to Integrity because "an unlogged control-plane action is an integrity failure of the evidence itself". **(Structural inference)** The code returns low, medium or high by Integrity rank.

### Data Store Audit Logging and Anomalous Access Detection Gap

**ID:** `data-store-audit-detection-gap`
**Location:** Native script rule — `pkg/risks/scripts/data-store-audit-detection-gap.yaml`

**Description:** A data store has no operation-level audit logging and no detection tuned to abnormal access, such as bulk reads or connections from an unexpected principal. Bulk exfiltration by a compromised or malicious authorized identity produces no anomalous signal and no forensic record.

**Applies to:** In-scope technical assets whose `type` is `datastore`.

**Why it applies there:** The rule's `false_positives` says it fires unconditionally for every in-scope datastore asset by design. It's recorded as mitigated once operation-level data-plane audit logging and tuned anomaly detection are confirmed.

**Baseline Likelihood:** `likely` — This is a mid tier, so all three outcomes are reachable through the RAA delta.

**Baseline Impact:** `medium` — Repudiation maps to Integrity. The comment's reason: "no forensic record to attribute access to an identity is an integrity failure of the evidence itself, not a confidentiality one."

### Insufficient Audit Logging (AU-2 Compliance Gap)

**ID:** `insufficient-audit-logging`
**Location:** Native script rule — `pkg/risks/scripts/insufficient-audit-logging.yaml`

**Description:** The asset doesn't generate audit records for the event types NIST SP 800-53 AU-2 requires, such as authentication attempts, privilege escalation and administrative actions. The SOC can't detect or reconstruct an attack, and the gap on its own blocks ATO under DoD RMF.

**Applies to:** In-scope technical assets whose technologies carry `.attributes.frontend_related`, `.attributes.backend_related` or `.attributes.application_logic`.

**Why it applies there:** The file's comment says `application_logic` is OR'd in to also catch technologies that carry neither of the other two attributes but "genuinely have their own audit-relevant request/job-processing surface". Its examples are application-server, report-engine, web-server and llm-endpoint.

**Baseline Likelihood:** `likely` — The file has no likelihood comment. **(Structural inference)** The code returns very-likely, possible or likely by the standard RAA thresholds.

**Baseline Impact:** `medium` — Repudiation maps to Integrity. The comment's reason: "a missing or tamperable audit trail is an integrity failure of the evidence itself, not a confidentiality one."

### Security Control Tamper Resistance Gap

**ID:** `security-control-tamper-resistance-gap`
**Location:** Native script rule — `pkg/risks/scripts/security-control-tamper-resistance-gap.yaml`

**Description:** A security control (WAF, IDS/IPS, HSM, vault, or SIEM/monitoring platform) has no tamper-evident configuration and no independently stored audit trail of its own. An adversary with a foothold can disable, reconfigure or evade the exact control that would detect their next step, or erase the evidence, and nothing outside the control notices.

**Applies to:** In-scope technical assets whose technologies carry the `.attributes.security_control_related` attribute.

**Why it applies there:** The rule's `false_positives` says it fires unconditionally for every in-scope security-control asset by design. It's recorded as mitigated once the control's configuration-change trail goes to a destination its own administrators can't modify.

**Baseline Likelihood:** `unlikely` — This is the floor, so only the upward delta (RAA >= 40) can apply.

**Baseline Impact:** `very-high` — Information-Disclosure maps to Confidentiality. This is the ceiling, so only the downward (low Confidentiality) delta can apply. The file gives no further reason.

---

## Uncategorized

None. Every rule file in `pkg/risks/scripts/` maps to one of the domains above.

---

# Part 3: Custom IL5 Categories


All 87 custom risk categories defined under `custom_risk_definitions` in `models/central-security-repo/libraries/09-custom-risks-lib.yml`, grouped by that file's own `# DOMAIN N: NAME` banners. Trigger conditions are taken from the `inject()` calls in `models/central-security-repo/core-policies/inject_risks.py`. Every trigger applies only to in-scope technical assets: inject_risks.py skips any asset with `out_of_scope: true` before evaluating any tag. Baselines are per-category starting points; the per-finding Likelihood/Impact are nudged from them by asset RAA, internet reachability, and the asset's CIA rating (see `docs/risk-methodology.md`).

## Identity

### Policy Exception: Local Authentication

**ID:** `policy-exception-local-auth`  
**Location:** Custom category — `models/central-security-repo/libraries/09-custom-risks-lib.yml`, injected by `models/central-security-repo/core-policies/inject_risks.py`

**Description:** This application maintains a local credential store that bypasses the enterprise identity provider and mandatory MFA enforcement. If this risk remains unmitigated, the local store becomes a backdoor that can be brute-forced or credential-stuffed independent of enterprise conditional access policies.

**Applies to:** Technical assets tagged `exception:local-auth-fallback`.

**Why it applies there:** *Structural inference (no explanatory comment at this trigger in inject_risks.py):* an `exception:*` tag records an explicit policy waiver, so the category fires on tag presence alone with no suppression tag; the library's own `false_positives` field reads "None. This is an explicit policy waiver."

**Baseline Likelihood:** `likely` — Entry's `cwe` field: CWE-308. The entry's `references` cite only control/policy sources (no CWE/CAPEC/OWASP/MITRE vulnerability-class source). No further written justification is attached to this value.

**Baseline Impact:** `high` — The entry's `risk_assessment` reads: "High risk of unauthorized access." Value recalibrated from `medium` in commit `3e7a40e` (an audit grounded in CWE/CAPEC likelihood ratings, OWASP Top 10:2025 + API Top 10:2023, Verizon DBIR 2025, and Sophos ransomware data; no per-entry citation recorded).

### Insecure Password Reset and Credential Recovery

**ID:** `insecure-password-reset`  
**Location:** Custom category — `models/central-security-repo/libraries/09-custom-risks-lib.yml`, injected by `models/central-security-repo/core-policies/inject_risks.py`

**Description:** The asset's self-service password reset flow uses predictable or reusable reset tokens, excessive token lifetimes, or responses that reveal whether an email address is registered. If this risk remains unmitigated, an attacker can take over accounts without knowing the current password, or enumerate valid accounts to target with further attacks.

**Applies to:** Technical assets tagged `feature:password-reset`.

**Why it applies there:** *Structural inference (no explanatory comment at this trigger in inject_risks.py):* the tag declares the asset implements a self-service reset flow, which is the attack surface the category describes; there is no suppression tag.

**Baseline Likelihood:** `likely` — Entry's `cwe` field: CWE-640. Vulnerability-class references cited by the entry: OWASP Forgot Password Cheat Sheet. Value recalibrated from `very-likely` in commit `3e7a40e` (an audit grounded in CWE/CAPEC likelihood ratings, OWASP Top 10:2025 + API Top 10:2023, Verizon DBIR 2025, and Sophos ransomware data; no per-entry citation recorded).

**Baseline Impact:** `high` — The entry's `risk_assessment` reads: "High for custom-implemented reset flows." Value recalibrated from `medium` in commit `3e7a40e` (an audit grounded in CWE/CAPEC likelihood ratings, OWASP Top 10:2025 + API Top 10:2023, Verizon DBIR 2025, and Sophos ransomware data; no per-entry citation recorded).

### OAuth 2.0 and OIDC Implementation Vulnerabilities

**ID:** `oauth-oidc-vulnerabilities`  
**Location:** Custom category — `models/central-security-repo/libraries/09-custom-risks-lib.yml`, injected by `models/central-security-repo/core-policies/inject_risks.py`

**Description:** The asset issues or validates OAuth 2.0/OIDC tokens with implementation weaknesses such as unvalidated redirect URIs, a missing or unchecked state parameter, or improper JWT signature algorithm handling. If this risk remains unmitigated, an attacker can intercept authorization codes, replay tokens, or forge arbitrary tokens to gain authenticated access as another user.

**Applies to:** Technical assets tagged `feature:oauth-oidc-provider`.

**Why it applies there:** *Structural inference (no explanatory comment at this trigger in inject_risks.py):* the tag marks an asset that issues or validates OAuth/OIDC tokens, the surface the category describes; it fires unconditionally on that tag.

**Baseline Likelihood:** `likely` — Entry's `cwe` field: CWE-287. Vulnerability-class references cited by the entry: OWASP OAuth 2.0 Security Best Current Practice (draft-ietf-oauth-security-topics). No further written justification is attached to this value.

**Baseline Impact:** `high` — The entry's `risk_assessment` reads: "High for assets acting as authorization servers or custom token validation middleware." Value recalibrated from `medium` in commit `3e7a40e` (an audit grounded in CWE/CAPEC likelihood ratings, OWASP Top 10:2025 + API Top 10:2023, Verizon DBIR 2025, and Sophos ransomware data; no per-entry citation recorded).

### SAML Assertion Vulnerabilities

**ID:** `saml-assertion-vulnerabilities`  
**Location:** Custom category — `models/central-security-repo/libraries/09-custom-risks-lib.yml`, injected by `models/central-security-repo/core-policies/inject_risks.py`

**Description:** The asset processes SAML assertions from an external identity provider with XML-parsing weaknesses that can allow a submitted assertion to be altered, replayed, or misattributed to a different user. If this risk remains unmitigated, an attacker can forge or replay a SAML assertion to authenticate as any user, including administrators, without valid credentials.

**Applies to:** Technical assets tagged `feature:saml-sp`.

**Why it applies there:** *Structural inference (no explanatory comment at this trigger in inject_risks.py):* the tag marks the asset as a SAML service provider that consumes external assertions, the parsing surface the category describes.

**Baseline Likelihood:** `likely` — Entry's `cwe` field: CWE-347. Vulnerability-class references cited by the entry: OWASP SAML Security Cheat Sheet; CVE-2017-11427 (SAML comment injection). No further written justification is attached to this value.

**Baseline Impact:** `high` — The entry's `risk_assessment` reads: "High for custom or lightly-maintained SAML SP implementations." No further written justification is attached to this value.

### Missing Token Binding on Session and Refresh Tokens

**ID:** `missing-token-binding`  
**Location:** Custom category — `models/central-security-repo/libraries/09-custom-risks-lib.yml`, injected by `models/central-security-repo/core-policies/inject_risks.py`

**Description:** This asset issues session or refresh tokens as bearer artifacts, usable by whoever holds them, rather than binding them to the client that obtained them via proof-of-possession. If this risk remains unmitigated, a captured token can be replayed from any host with no further credential needed, defeating even phishing-resistant authentication performed before the token was stolen.

**Applies to:** Technical assets tagged `feature:oauth-oidc-provider` that do not also carry `ops:token-binding-enforced`.

**Why it applies there:** *Structural inference (no explanatory comment at this trigger in inject_risks.py):* nested under the OAuth/OIDC trigger, so it only applies to token-issuing assets; `ops:token-binding-enforced` is the positive-confirmation tag that suppresses it.

**Baseline Likelihood:** `likely` — Entry's `cwe` field: CWE-294. The entry's `references` cite only control/policy sources (no CWE/CAPEC/OWASP/MITRE vulnerability-class source). No further written justification is attached to this value.

**Baseline Impact:** `high` — The entry's `risk_assessment` reads: "Critical for any asset issuing bearer session/refresh tokens with no proof-of-possession binding, particularly where the asset also enforces phishing-resistant primary authentication that a bearer-token replay would otherwise bypass." No further written justification is attached to this value.

### OAuth Illicit Consent Grant via Malicious Application Registration

**ID:** `oauth-illicit-consent-grant`  
**Location:** Custom category — `models/central-security-repo/libraries/09-custom-risks-lib.yml`, injected by `models/central-security-repo/core-policies/inject_risks.py`

**Description:** This asset's OAuth authorization server allows a user to grant a third-party application delegated API access with no admin-consent gate or scope review. If this risk remains unmitigated, an attacker can register a malicious application and phish a user into granting it persistent API access that survives a password reset.

**Applies to:** Technical assets tagged `feature:oauth-oidc-provider` that do not also carry `ops:oauth-consent-governed`.

**Why it applies there:** *Structural inference (no explanatory comment at this trigger in inject_risks.py):* nested under the OAuth/OIDC trigger (only an authorization server can grant delegated consent); `ops:oauth-consent-governed` suppresses it.

**Baseline Likelihood:** `likely` — Entry's `cwe` field: CWE-285. Vulnerability-class references cited by the entry: MITRE ATT&CK T1550.001 (Application Access Token). No further written justification is attached to this value.

**Baseline Impact:** `high` — The entry's `risk_assessment` reads: "Critical for any authorization server/IdP permitting unrestricted user self-service consent to high-privilege scopes with no administrator review." No further written justification is attached to this value.

### Self-Managed Directory Tier-0 Infrastructure Compromise

**ID:** `self-managed-directory-tier0-compromise`  
**Location:** Custom category — `models/central-security-repo/libraries/09-custom-risks-lib.yml`, injected by `models/central-security-repo/core-policies/inject_risks.py`

**Description:** This asset relies on a self-managed directory service that does not inherit the enterprise identity team's Tier-0 hardening, leaving it exposed to attacks such as unconstrained delegation, AdminSDHolder tampering, or an unrotated krbtgt credential. If this risk remains unmitigated, compromise of the directory's Tier-0 infrastructure lets an attacker forge authentication for any identity it manages, with persistence that survives ordinary password resets.

**Applies to:** Technical assets tagged `mgmt:self-managed-identity` that do not also carry `mgmt:self-managed-identity-hardened`.

**Why it applies there:** inject_risks.py has no comment at this line; the library header explains the `mgmt:self-managed-*` pattern: this content is "a platform-inherited control for an app in the enterprise-managed landing zone (excluded from firing by default) but a real per-asset gap for an app that manages that infrastructure itself." The `mgmt:self-managed-identity-hardened` tag suppresses the whole cluster once confirmed.

**Baseline Likelihood:** `possible` — Entry's `cwe` field: CWE-269. Vulnerability-class references cited by the entry: MITRE ATT&CK T1558 (Steal or Forge Kerberos Tickets). Value recalibrated from `unlikely` in commit `3e7a40e` (an audit grounded in CWE/CAPEC likelihood ratings, OWASP Top 10:2025 + API Top 10:2023, Verizon DBIR 2025, and Sophos ransomware data; no per-entry citation recorded).

**Baseline Impact:** `very-high` — The entry's `risk_assessment` reads: "Critical for any self-managed directory instance where these controls have not been audited, since this framework's enterprise identity Tier-0 hardening does not extend to infrastructure the app team operates itself." No further written justification is attached to this value.

### Self-Managed Certificate Authority Template Privilege Escalation

**ID:** `self-managed-ca-template-escalation`  
**Location:** Custom category — `models/central-security-repo/libraries/09-custom-risks-lib.yml`, injected by `models/central-security-repo/core-policies/inject_risks.py`

**Description:** This asset relies on a self-managed certificate authority with an enrollment template that lets a low-privileged requester supply its own subject name. If this risk remains unmitigated, a low-privileged requester can obtain a certificate asserting a privileged identity, bypassing authentication for every system that trusts this CA.

**Applies to:** Technical assets tagged `mgmt:self-managed-identity` that do not also carry `mgmt:self-managed-identity-hardened`.

**Why it applies there:** inject_risks.py has no comment at this line; the library header explains the `mgmt:self-managed-*` pattern: this content is "a platform-inherited control for an app in the enterprise-managed landing zone (excluded from firing by default) but a real per-asset gap for an app that manages that infrastructure itself." The `mgmt:self-managed-identity-hardened` tag suppresses the whole cluster once confirmed.

**Baseline Likelihood:** `likely` — Entry's `cwe` field: CWE-269. Vulnerability-class references cited by the entry: MITRE ATT&CK T1649 (Steal or Forge Authentication Certificates). No further written justification is attached to this value.

**Baseline Impact:** `very-high` — The entry's `risk_assessment` reads: "Critical for any self-managed CA with at least one enrollment template permitting enrollee-controlled subject names combined with broad enrollment rights." No further written justification is attached to this value.

### Self-Managed Hybrid Identity Synchronization Server Compromise

**ID:** `self-managed-hybrid-sync-compromise`  
**Location:** Custom category — `models/central-security-repo/libraries/09-custom-risks-lib.yml`, injected by `models/central-security-repo/core-policies/inject_risks.py`

**Description:** This asset runs a self-managed hybrid identity synchronization server that holds working credentials for both the on-premises directory and the cloud identity tenant it bridges. If this risk remains unmitigated, compromise of the sync server lets an attacker pivot between the on-premises directory and the cloud tenant, bypassing tier separation designed around each side individually.

**Applies to:** Technical assets tagged `mgmt:self-managed-identity` that do not also carry `mgmt:self-managed-identity-hardened`.

**Why it applies there:** inject_risks.py has no comment at this line; the library header explains the `mgmt:self-managed-*` pattern: this content is "a platform-inherited control for an app in the enterprise-managed landing zone (excluded from firing by default) but a real per-asset gap for an app that manages that infrastructure itself." The `mgmt:self-managed-identity-hardened` tag suppresses the whole cluster once confirmed.

**Baseline Likelihood:** `possible` — Entry's `cwe` field: CWE-522. Vulnerability-class references cited by the entry: MITRE ATT&CK T1556 (Modify Authentication Process). Value recalibrated from `unlikely` in commit `3e7a40e` (an audit grounded in CWE/CAPEC likelihood ratings, OWASP Top 10:2025 + API Top 10:2023, Verizon DBIR 2025, and Sophos ransomware data; no per-entry citation recorded).

**Baseline Impact:** `very-high` — The entry's `risk_assessment` reads: "Critical for any hybrid identity sync server administered without Tier-0-equivalent access restriction and network isolation." No further written justification is attached to this value.

### Exposed Administrative Interface Without Hardened Access Controls

**ID:** `exposed-admin-panel`  
**Location:** Custom category — `models/central-security-repo/libraries/09-custom-risks-lib.yml`, injected by `models/central-security-repo/core-policies/inject_risks.py`

**Description:** The asset exposes an administrative interface reachable with standard application authentication alone, with no additional access control such as IP restriction, a separate factor, or server-side enforcement of role checks. If this risk remains unmitigated, compromise of an admin session yields control over all application data, user accounts, and configuration.

**Applies to:** Technical assets tagged `feature:admin-panel`.

**Why it applies there:** *Structural inference (no explanatory comment at this trigger in inject_risks.py):* the tag declares an administrative interface on the asset, the surface the category describes; there is no suppression tag.

**Baseline Likelihood:** `very-likely` — Entry's `cwe` field: CWE-284. The entry's `references` cite only control/policy sources (no CWE/CAPEC/OWASP/MITRE vulnerability-class source). No further written justification is attached to this value.

**Baseline Impact:** `high` — The entry's `risk_assessment` reads: "High for admin panels accessible on the same domain as the user-facing application without IP restriction." Value recalibrated from `medium` in commit `3e7a40e` (an audit grounded in CWE/CAPEC likelihood ratings, OWASP Top 10:2025 + API Top 10:2023, Verizon DBIR 2025, and Sophos ransomware data; no per-entry citation recorded).

### Third-Party Vendor Remote Support Access Lifecycle Gap

**ID:** `vendor-remote-support-access-gap`  
**Location:** Custom category — `models/central-security-repo/libraries/09-custom-risks-lib.yml`, injected by `models/central-security-repo/core-policies/inject_risks.py`

**Description:** This asset grants a third-party vendor's support engineer remote access that is not scoped to a specific support case and does not deactivate automatically when the case closes. If this risk remains unmitigated, vendor access can remain active long after the support engagement ends, as a standing external access path an attacker who compromises the vendor could reuse.

**Applies to:** Technical assets tagged `feature:vendor-remote-support` that do not also carry `ops:vendor-access-case-bound`.

**Why it applies there:** *Structural inference (no explanatory comment at this trigger in inject_risks.py):* the feature tag declares vendor remote access exists; `ops:vendor-access-case-bound` confirms it is case-scoped and auto-expiring, which is the gap the category describes.

**Baseline Likelihood:** `possible` — Entry's `cwe` field: CWE-269. The entry's `references` cite only control/policy sources (no CWE/CAPEC/OWASP/MITRE vulnerability-class source). Value recalibrated from `unlikely` in commit `3e7a40e` (an audit grounded in CWE/CAPEC likelihood ratings, OWASP Top 10:2025 + API Top 10:2023, Verizon DBIR 2025, and Sophos ransomware data; no per-entry citation recorded).

**Baseline Impact:** `high` — The entry's `risk_assessment` reads: "High for any asset granting vendor remote support access with no case-bound scope or automatic expiry." Value recalibrated from `medium` in commit `3e7a40e` (an audit grounded in CWE/CAPEC likelihood ratings, OWASP Top 10:2025 + API Top 10:2023, Verizon DBIR 2025, and Sophos ransomware data; no per-entry citation recorded).

### Standing Privileged Access with No Administrative Tiering

**ID:** `standing-privileged-access-no-tiering`  
**Location:** Custom category — `models/central-security-repo/libraries/09-custom-risks-lib.yml`, injected by `models/central-security-repo/core-policies/inject_risks.py`

**Description:** Privileged roles on this self-managed asset are held continuously rather than activated just-in-time, with no administrative-tiering separation preventing a high-privilege credential from authenticating out of a general-purpose workstation. If this risk remains unmitigated, compromise of any ordinary endpoint an administrator uses is sufficient to capture a standing high-privilege credential.

**Applies to:** Technical assets tagged `mgmt:self-managed-pam` that do not also carry `mgmt:self-managed-pam-hardened`.

**Why it applies there:** inject_risks.py has no comment at this line; the library header explains the `mgmt:self-managed-*` pattern: this content is "a platform-inherited control for an app in the enterprise-managed landing zone (excluded from firing by default) but a real per-asset gap for an app that manages that infrastructure itself." The `mgmt:self-managed-pam-hardened` tag suppresses the whole cluster once confirmed.

**Baseline Likelihood:** `likely` — Entry's `cwe` field: CWE-269. The entry's `references` cite only control/policy sources (no CWE/CAPEC/OWASP/MITRE vulnerability-class source). No further written justification is attached to this value.

**Baseline Impact:** `very-high` — The entry's `risk_assessment` reads: "Critical for any self-managed asset with standing (non-JIT) high-privilege role assignment and no administrative tiering." No further written justification is attached to this value.

### Privileged Session Credential Disclosure Without Vaulting or Brokering

**ID:** `privileged-session-credential-disclosure`  
**Location:** Custom category — `models/central-security-repo/libraries/09-custom-risks-lib.yml`, injected by `models/central-security-repo/core-policies/inject_risks.py`

**Description:** Shared administrative credentials for this self-managed asset are disclosed directly to administrators rather than checked out from a vault and brokered through a session that never reveals the secret. If this risk remains unmitigated, a disclosed shared credential can be retained or reused outside any brokered session, and rotating it after personnel turnover requires identifying every system it was ever used against.

**Applies to:** Technical assets tagged `mgmt:self-managed-pam` that do not also carry `mgmt:self-managed-pam-hardened`.

**Why it applies there:** inject_risks.py has no comment at this line; the library header explains the `mgmt:self-managed-*` pattern: this content is "a platform-inherited control for an app in the enterprise-managed landing zone (excluded from firing by default) but a real per-asset gap for an app that manages that infrastructure itself." The `mgmt:self-managed-pam-hardened` tag suppresses the whole cluster once confirmed.

**Baseline Likelihood:** `likely` — Entry's `cwe` field: CWE-522. The entry's `references` cite only control/policy sources (no CWE/CAPEC/OWASP/MITRE vulnerability-class source). No further written justification is attached to this value.

**Baseline Impact:** `high` — The entry's `risk_assessment` reads: "High for any self-managed asset where shared administrative credentials are disclosed directly rather than brokered through a vaulted session." Value recalibrated from `medium` in commit `3e7a40e` (an audit grounded in CWE/CAPEC likelihood ratings, OWASP Top 10:2025 + API Top 10:2023, Verizon DBIR 2025, and Sophos ransomware data; no per-entry citation recorded).

### Break-Glass Emergency Access Circular Dependency or Untested Procedure

**ID:** `break-glass-circular-dependency-untested`  
**Location:** Custom category — `models/central-security-repo/libraries/09-custom-risks-lib.yml`, injected by `models/central-security-repo/core-policies/inject_risks.py`

**Description:** Break-glass emergency access for this self-managed asset either depends on the primary identity platform it is meant to provide emergency access around, or has never actually been exercised. If this risk remains unmitigated, the break-glass procedure can fail during the exact primary-platform outage or compromise scenario it was designed for.

**Applies to:** Technical assets tagged `mgmt:self-managed-pam` that do not also carry `mgmt:self-managed-pam-hardened`.

**Why it applies there:** inject_risks.py has no comment at this line; the library header explains the `mgmt:self-managed-*` pattern: this content is "a platform-inherited control for an app in the enterprise-managed landing zone (excluded from firing by default) but a real per-asset gap for an app that manages that infrastructure itself." The `mgmt:self-managed-pam-hardened` tag suppresses the whole cluster once confirmed.

**Baseline Likelihood:** `unlikely` — Entry's `cwe` field: CWE-1008. The entry's `references` cite only control/policy sources (no CWE/CAPEC/OWASP/MITRE vulnerability-class source). No further written justification is attached to this value.

**Baseline Impact:** `medium` — The entry's `risk_assessment` reads: "High for any self-managed asset whose break-glass access depends on the primary identity platform, or whose break-glass procedure has not been exercised within the current ATO period." No further written justification is attached to this value.

### Over-Privileged Workload Identity and Cloud Control-Plane Pivot

**ID:** `overprivileged-workload-identity`  
**Location:** Custom category — `models/central-security-repo/libraries/09-custom-risks-lib.yml`, injected by `models/central-security-repo/core-policies/inject_risks.py`

**Description:** This asset's managed identity, service principal, or Kubernetes service account holds role assignments wider than its function needs -- subscription- or resource-group-scoped Contributor/Owner, or wildcard data-plane roles -- or its credential/token is reachable through the cloud instance metadata service or an automounted service-account token from code an attacker could influence. If this risk remains unmitigated, compromising the workload turns directly into cloud control-plane access: creating credentials, assigning roles, or reading every vault and store the identity's own role assignment can reach, independent of whether the application itself was the actual target.

**Applies to:** Technical assets tagged `mgmt:workload-identity-assigned` that do not also carry `mgmt:workload-identity-least-privilege`.

**Why it applies there:** inject_risks.py comment: "Deliberately NOT nested under mgmt:self-managed-*: workload role assignments are owned by the app team even when the landing zone itself is inherited, so this applies to every ordinary app workload regardless of self-managed status."

**Baseline Likelihood:** `likely` — Entry's `cwe` field: CWE-250. Vulnerability-class references cited by the entry: MITRE ATT&CK T1078.004, T1098.001, T1098.003, T1552.005, T1548.005. No further written justification is attached to this value.

**Baseline Impact:** `very-high` — The entry's `risk_assessment` reads: "Critical for any workload identity holding subscription-/resource-group-wide or wildcard data-plane roles with no documented least-privilege review, or whose credential endpoint is reachable from code outside its own trust boundary." No further written justification is attached to this value.

## Device and Infrastructure

### Container Runs as Root (Policy Exception)

**ID:** `container-runs-as-root`  
**Location:** Custom category — `models/central-security-repo/libraries/09-custom-risks-lib.yml`, injected by `models/central-security-repo/core-policies/inject_risks.py`

**Description:** This container executes as the root user or with elevated Linux capabilities rather than the least privilege its function requires. If this risk remains unmitigated, an attacker who compromises the container has a substantially easier path to escalate privileges on the underlying node.

**Applies to:** Technical assets tagged `exception:runs-as-root`.

**Why it applies there:** The library's Domain 2 comment says this entry stays tag-triggered (unlike the container checks ported to the native `machine` field) because "it's a tag-presence-triggered policy waiver, a different shape of content." No suppression tag exists.

**Baseline Likelihood:** `likely` — Entry's `cwe` field: CWE-250. The entry's `references` cite only control/policy sources (no CWE/CAPEC/OWASP/MITRE vulnerability-class source). Value recalibrated from `very-likely` in commit `3e7a40e` (an audit grounded in CWE/CAPEC likelihood ratings, OWASP Top 10:2025 + API Top 10:2023, Verizon DBIR 2025, and Sophos ransomware data; no per-entry citation recorded).

**Baseline Impact:** `high` — The entry's `risk_assessment` reads: "High risk of container breakout and full node compromise if the container is also internet-reachable or processes untrusted input — root inside the container removes the last layer between a code-execution bug and privilege escalation on the host." No further written justification is attached to this value.

### Policy Exception: Direct Admin Access

**ID:** `policy-exception-direct-admin-access`  
**Location:** Custom category — `models/central-security-repo/libraries/09-custom-risks-lib.yml`, injected by `models/central-security-repo/core-policies/inject_risks.py`

**Description:** The virtual machine has direct administrative ports exposed rather than routed through a bastion host or just-in-time access. If this risk remains unmitigated, the VM is continuously exposed to brute-force, credential-stuffing, and exploitation attempts against its remote management service.

**Applies to:** Technical assets tagged `exception:direct-admin-access`.

**Why it applies there:** The library's Domain 2 comment says this entry stays tag-triggered (unlike the VM checks ported to the native `machine` field) because "it's a tag-presence-triggered policy waiver, a different shape of content." No suppression tag exists.

**Baseline Likelihood:** `likely` — Entry's `cwe` field: CWE-668. The entry's `references` cite only control/policy sources (no CWE/CAPEC/OWASP/MITRE vulnerability-class source). No further written justification is attached to this value.

**Baseline Impact:** `high` — The entry's `risk_assessment` reads: "High risk of unauthorized administrative access." Value recalibrated from `medium` in commit `3e7a40e` (an audit grounded in CWE/CAPEC likelihood ratings, OWASP Top 10:2025 + API Top 10:2023, Verizon DBIR 2025, and Sophos ransomware data; no per-entry citation recorded).

### Self-Managed Out-of-Band Management Controller Compromise

**ID:** `self-managed-bmc-compromise`  
**Location:** Custom category — `models/central-security-repo/libraries/09-custom-risks-lib.yml`, injected by `models/central-security-repo/core-policies/inject_risks.py`

**Description:** This self-managed physical host's out-of-band management controller (BMC/iDRAC/iLO/IPMI) has not been confirmed hardened, and runs its own processor and network stack independent of the host OS. If this risk remains unmitigated, a default or weak BMC credential grants an attacker remote, OS-invisible control of the host, including the ability to remotely reimage it.

**Applies to:** Technical assets with `machine: physical` that are tagged `mgmt:self-managed-hardware` and not `mgmt:self-managed-hardware-hardened`.

**Why it applies there:** inject_risks.py comment: Physical Host Hardening Audits apply to "self-managed bare metal only -- BMC/firmware/boot-chain don't apply to a cloud-provisioned VM, where the hypervisor host is the cloud provider's responsibility."

**Baseline Likelihood:** `likely` — Entry's `cwe` field: CWE-284. The entry's `references` cite only control/policy sources (no CWE/CAPEC/OWASP/MITRE vulnerability-class source). No further written justification is attached to this value.

**Baseline Impact:** `very-high` — The entry's `risk_assessment` reads: "Critical for any self-managed physical host whose BMC has not been confirmed to use non-default credentials and isolated network placement." No further written justification is attached to this value.

### Self-Managed Below-OS Firmware Persistence Gap

**ID:** `self-managed-firmware-persistence-gap`  
**Location:** Custom category — `models/central-security-repo/libraries/09-custom-risks-lib.yml`, injected by `models/central-security-repo/core-policies/inject_risks.py`

**Description:** This self-managed physical host's patch management covers only the operating system, leaving UEFI/BIOS, TPM, and other below-OS firmware unpatched. If this risk remains unmitigated, a firmware-level implant persists across a full OS reimage and is invisible to any OS-level integrity check.

**Applies to:** Technical assets with `machine: physical` that are tagged `mgmt:self-managed-hardware` and not `mgmt:self-managed-hardware-hardened`.

**Why it applies there:** inject_risks.py comment: Physical Host Hardening Audits apply to "self-managed bare metal only -- BMC/firmware/boot-chain don't apply to a cloud-provisioned VM, where the hypervisor host is the cloud provider's responsibility."

**Baseline Likelihood:** `unlikely` — Entry's `cwe` field: CWE-1395. The entry's `references` cite only control/policy sources (no CWE/CAPEC/OWASP/MITRE vulnerability-class source). No further written justification is attached to this value.

**Baseline Impact:** `very-high` — The entry's `risk_assessment` reads: "Critical for any self-managed physical host with no firmware patch tracking independent of OS patch management." No further written justification is attached to this value.

### Self-Managed Boot Integrity Bypass

**ID:** `self-managed-boot-integrity-bypass`  
**Location:** Custom category — `models/central-security-repo/libraries/09-custom-risks-lib.yml`, injected by `models/central-security-repo/core-policies/inject_risks.py`

**Description:** This self-managed physical host has no secure boot or measured-boot attestation confirmed, so its boot-chain integrity is unverifiable. If this risk remains unmitigated, a tampered bootloader or bootkit survives indefinitely and produces no signal to any control that only runs after the OS has loaded.

**Applies to:** Technical assets with `machine: physical` that are tagged `mgmt:self-managed-hardware` and not `mgmt:self-managed-hardware-hardened`.

**Why it applies there:** inject_risks.py comment: Physical Host Hardening Audits apply to "self-managed bare metal only -- BMC/firmware/boot-chain don't apply to a cloud-provisioned VM, where the hypervisor host is the cloud provider's responsibility."

**Baseline Likelihood:** `unlikely` — Entry's `cwe` field: CWE-1326. The entry's `references` cite only control/policy sources (no CWE/CAPEC/OWASP/MITRE vulnerability-class source). No further written justification is attached to this value.

**Baseline Impact:** `very-high` — The entry's `risk_assessment` reads: "High for any self-managed physical host with secure boot disabled or no TPM-backed measured-boot attestation." Value recalibrated from `medium` in commit `3e7a40e` (an audit grounded in CWE/CAPEC likelihood ratings, OWASP Top 10:2025 + API Top 10:2023, Verizon DBIR 2025, and Sophos ransomware data; no per-entry citation recorded).

## Network and Environment

### No Macro or Micro-Segmentation of Self-Managed Network

**ID:** `self-managed-network-no-segmentation`  
**Location:** Custom category — `models/central-security-repo/libraries/09-custom-risks-lib.yml`, injected by `models/central-security-repo/core-policies/inject_risks.py`

**Description:** This asset's self-managed network permits workload-to-workload traffic by default rather than restricting it to an explicit, allow-listed baseline. If this risk remains unmitigated, compromise of a single host on the network gives an attacker unrestricted reachability to every other host on it.

**Applies to:** Technical assets tagged `mgmt:self-managed-network` that do not also carry `mgmt:self-managed-network-hardened`.

**Why it applies there:** 09-custom-risks-lib.yml's section 3.1 comment: for an enterprise-landing-zone asset, segmentation, wireless admission, and external routing "are inherited platform controls"; these risks exist for "an asset whose network architecture the application team configures and owns itself." The `mgmt:self-managed-network-hardened` tag suppresses the cluster.

**Baseline Likelihood:** `likely` — Entry's `cwe` field: CWE-653. The entry's `references` cite only control/policy sources (no CWE/CAPEC/OWASP/MITRE vulnerability-class source). No further written justification is attached to this value.

**Baseline Impact:** `high` — The entry's `risk_assessment` reads: "Critical for any self-managed network with no mapped, default-deny segmentation between trust tiers." No further written justification is attached to this value.

### Rogue Access Point and Evil-Twin Credential Harvesting on Self-Managed Wireless

**ID:** `self-managed-rogue-ap-credential-harvesting`  
**Location:** Custom category — `models/central-security-repo/libraries/09-custom-risks-lib.yml`, injected by `models/central-security-repo/core-policies/inject_risks.py`

**Description:** This asset's self-managed wireless network has no confirmed detection for a rogue access point impersonating its own SSID. If this risk remains unmitigated, a nearby evil-twin access point can harvest client credentials directly over the air, bypassing every wired-side control.

**Applies to:** Technical assets tagged `mgmt:self-managed-network` that do not also carry `mgmt:self-managed-network-hardened`.

**Why it applies there:** 09-custom-risks-lib.yml's section 3.1 comment: for an enterprise-landing-zone asset, segmentation, wireless admission, and external routing "are inherited platform controls"; these risks exist for "an asset whose network architecture the application team configures and owns itself." The `mgmt:self-managed-network-hardened` tag suppresses the cluster.

**Baseline Likelihood:** `unlikely` — Entry's `cwe` field: CWE-300. The entry's `references` cite only control/policy sources (no CWE/CAPEC/OWASP/MITRE vulnerability-class source). No further written justification is attached to this value.

**Baseline Impact:** `medium` — The entry's `risk_assessment` reads: "High for any self-managed wireless network with no rogue access point detection and a wireless authentication method vulnerable to credential harvesting by an impersonating access point." No further written justification is attached to this value.

### Missing Route Origin Validation on Self-Managed External Routing

**ID:** `self-managed-missing-rpki-route-validation`  
**Location:** Custom category — `models/central-security-repo/libraries/09-custom-risks-lib.yml`, injected by `models/central-security-repo/core-policies/inject_risks.py`

**Description:** This asset's self-managed external routing has no route origin authorization or RPKI validation confirmed. If this risk remains unmitigated, an accepted bogus route announcement can redirect this asset's traffic onto an attacker-influenced path with no firewall rule ever triggered.

**Applies to:** Technical assets tagged `mgmt:self-managed-network` that do not also carry `mgmt:self-managed-network-hardened`.

**Why it applies there:** 09-custom-risks-lib.yml's section 3.1 comment: for an enterprise-landing-zone asset, segmentation, wireless admission, and external routing "are inherited platform controls"; these risks exist for "an asset whose network architecture the application team configures and owns itself." The `mgmt:self-managed-network-hardened` tag suppresses the cluster.

**Baseline Likelihood:** `unlikely` — Entry's `cwe` field: CWE-346. The entry's `references` cite only control/policy sources (no CWE/CAPEC/OWASP/MITRE vulnerability-class source). No further written justification is attached to this value.

**Baseline Impact:** `medium` — The entry's `risk_assessment` reads: "High for any self-managed asset with an external routing adjacency and no RPKI route origin validation." No further written justification is attached to this value.

### CDS: Classification Marking Validation Bypass

**ID:** `cds-marking-validation-bypass`  
**Location:** Custom category — `models/central-security-repo/libraries/09-custom-risks-lib.yml`, injected by `models/central-security-repo/core-policies/inject_risks.py`

**Description:** The application validates that classification markings exist before submitting content to the CDS for low-to-high transfer, but cannot verify that those markings are correct. If this risk remains unmitigated, incorrectly classified content can reach the CDS and result in a formal data spill.

**Applies to:** Technical assets tagged `cds:low-side-submitter`.

**Why it applies there:** 09-custom-risks-lib.yml's section 3.2 comment: these risks "cover the low-side application's interface with an external, UCDMO-approved CDS. The CDS itself is outside the ATO boundary." The entry's own risk_assessment adds that "the application is the last validation point before content reaches the CDS."

**Baseline Likelihood:** `likely` — Entry's `cwe` field: CWE-345. The entry's `references` cite only control/policy sources (no CWE/CAPEC/OWASP/MITRE vulnerability-class source). No further written justification is attached to this value.

**Baseline Impact:** `very-high` — The entry's `risk_assessment` reads: "Critical for any low-to-high transfer path." No further written justification is attached to this value.

### CDS: Misclassification and Insufficient Transfer Audit Trail

**ID:** `cds-misclassification-audit-gap`  
**Location:** Custom category — `models/central-security-repo/libraries/09-custom-risks-lib.yml`, injected by `models/central-security-repo/core-policies/inject_risks.py`

**Description:** Classification correctness on the low-to-high transfer path is a human judgment the application cannot technically enforce, so its main contribution to spillage prevention is the completeness of the audit trail it produces. If this risk remains unmitigated, an incomplete or tampered audit trail prevents a spillage event from being reconstructed or attributed after the fact.

**Applies to:** Technical assets tagged `cds:low-side-submitter` or `cds:high-side-submitter` (injected under separate finding titles per side).

**Why it applies there:** 09-custom-risks-lib.yml's section 3.2 comment: these risks "cover the low-side application's interface with an external, UCDMO-approved CDS. The CDS itself is outside the ATO boundary." The same category is also injected from the high-side submitter block, where the code comment notes that side is "in-scope when both sides modeled in single ATO package."

**Baseline Likelihood:** `likely` — Entry's `cwe` field: CWE-778. The entry's `references` cite only control/policy sources (no CWE/CAPEC/OWASP/MITRE vulnerability-class source). No further written justification is attached to this value.

**Baseline Impact:** `medium` — The entry's `risk_assessment` reads: "High." No further written justification is attached to this value.

### CDS: Unsafe Processing of CDS-Sourced Inbound Content

**ID:** `cds-unsafe-inbound-content`  
**Location:** Custom category — `models/central-security-repo/libraries/09-custom-risks-lib.yml`, injected by `models/central-security-repo/core-policies/inject_risks.py`

**Description:** The receiving application processes CDS-approved content from the high side with less rigorous validation than it would apply to directly user-supplied data, even though CDS approval reflects releasability, not safety for parsing. If this risk remains unmitigated, an approved document can still exploit a parser vulnerability or poison the receiving application's data store.

**Applies to:** Technical assets tagged `cds:low-side-receiver`.

**Why it applies there:** 09-custom-risks-lib.yml's section 3.2 comment: these risks "cover the low-side application's interface with an external, UCDMO-approved CDS. The CDS itself is outside the ATO boundary."

**Baseline Likelihood:** `likely` — Entry's `cwe` field: CWE-20. The entry's `references` cite only control/policy sources (no CWE/CAPEC/OWASP/MITRE vulnerability-class source). No further written justification is attached to this value.

**Baseline Impact:** `high` — The entry's `risk_assessment` reads: "High for applications parsing complex file formats (Office, PDF, XML)." No further written justification is attached to this value.

### CDS: Transfer Broker Unauthorized Write and Queue Injection

**ID:** `cds-broker-queue-injection`  
**Location:** Custom category — `models/central-security-repo/libraries/09-custom-risks-lib.yml`, injected by `models/central-security-repo/core-policies/inject_risks.py`

**Description:** The message broker staging content between the application and the CDS interface is a critical security boundary; direct write access to it bypasses the application's own classification marking validation. If this risk remains unmitigated, injected content reaches the CDS or the receiving application with no application audit record of it.

**Applies to:** Technical assets tagged `cds:low-side-broker`.

**Why it applies there:** 09-custom-risks-lib.yml's section 3.2 comment: these risks "cover the low-side application's interface with an external, UCDMO-approved CDS. The CDS itself is outside the ATO boundary."

**Baseline Likelihood:** `unlikely` — Entry's `cwe` field: CWE-284. The entry's `references` cite only control/policy sources (no CWE/CAPEC/OWASP/MITRE vulnerability-class source). No further written justification is attached to this value.

**Baseline Impact:** `very-high` — The entry's `risk_assessment` reads: "Critical." No further written justification is attached to this value.

### CDS: Inadvertent Above-Releasable Content Inclusion in Downward Release

**ID:** `cds-above-releasable-content-inclusion`  
**Location:** Custom category — `models/central-security-repo/libraries/09-custom-risks-lib.yml`, injected by `models/central-security-repo/core-policies/inject_risks.py`

**Description:** Content proposed for downward release via the CDS relies primarily on human review, which can miss above-releasable material embedded in file metadata, revision history, or embedded objects. If this risk remains unmitigated, above-releasable content that passes the CDS filter constitutes a formal downward spill requiring incident response.

**Applies to:** Technical assets tagged `cds:high-side-submitter`.

**Why it applies there:** inject_risks.py comment on the high-side block: "in-scope when both sides modeled in single ATO package."

**Baseline Likelihood:** `very-likely` — Entry's `cwe` field: CWE-212. The entry's `references` cite only control/policy sources (no CWE/CAPEC/OWASP/MITRE vulnerability-class source). No further written justification is attached to this value.

**Baseline Impact:** `very-high` — The entry's `risk_assessment` reads: "Critical for any automated or partially-automated downward release workflow." No further written justification is attached to this value.

### CDS: Release Authority Bypass on High-Side Downward Transfer

**ID:** `cds-release-authority-bypass`  
**Location:** Custom category — `models/central-security-repo/libraries/09-custom-risks-lib.yml`, injected by `models/central-security-repo/core-policies/inject_risks.py`

**Description:** The high-side submission workflow requires release authority approval before content is queued for downward transfer, and this approval gate can potentially be bypassed through workflow logic flaws, direct broker writes, or privilege escalation. If this risk remains unmitigated, unreviewed content can reach the CDS without ever passing the mandatory human release-authority judgment.

**Applies to:** Technical assets tagged `cds:high-side-submitter`.

**Why it applies there:** inject_risks.py comment on the high-side block: "in-scope when both sides modeled in single ATO package."

**Baseline Likelihood:** `unlikely` — Entry's `cwe` field: CWE-841. The entry's `references` cite only control/policy sources (no CWE/CAPEC/OWASP/MITRE vulnerability-class source). No further written justification is attached to this value.

**Baseline Impact:** `very-high` — The entry's `risk_assessment` reads: "Critical." No further written justification is attached to this value.

### CDS: Malicious Insider Abuse of Authorized Release Privileges

**ID:** `cds-malicious-insider-release-abuse`  
**Location:** Custom category — `models/central-security-repo/libraries/09-custom-risks-lib.yml`, injected by `models/central-security-repo/core-policies/inject_risks.py`

**Description:** A cleared individual who legitimately holds submitter access or release authority can knowingly use that access to move content they know is not authorized for release, with no technical control bypassed. If this risk remains unmitigated, an authorized insider can cause an unauthorized disclosure identical in consequence to any other downward spill, with no compensating technical control available afterward.

**Applies to:** Technical assets tagged `cds:high-side-submitter`.

**Why it applies there:** inject_risks.py comment: distinct from the accidental above-releasable-content and workflow-circumvention release-authority-bypass risks, "this one is a legitimately authorized individual deliberately misusing access no technical control can revoke."

**Baseline Likelihood:** `unlikely` — Entry's `cwe` field: CWE-654. The entry's `references` cite only control/policy sources (no CWE/CAPEC/OWASP/MITRE vulnerability-class source). No further written justification is attached to this value.

**Baseline Impact:** `very-high` — The entry's `risk_assessment` reads: "Critical for any high-side submitter or release authority role, regardless of how well the technical sanitization and approval workflow is implemented — this risk is orthogonal to those controls rather than a failure mode of them." No further written justification is attached to this value.

### CDS: Low-to-High Content Integrity and Influence Risk

**ID:** `cds-low-to-high-influence`  
**Location:** Custom category — `models/central-security-repo/libraries/09-custom-risks-lib.yml`, injected by `models/central-security-repo/core-policies/inject_risks.py`

**Description:** The high-side receiver processes content from the low side that the CDS validates as authorized for ingestion but does not validate for accuracy, so a compromised low-side system could send subtly manipulated data that appears legitimate. If this risk remains unmitigated, corrupted data ingested into the high-side environment can compromise the integrity of analysis or decisions that depend on it, without triggering any content-inspection alert.

**Applies to:** Technical assets tagged `cds:high-side-receiver`.

**Why it applies there:** inject_risks.py comment on the high-side block: "in-scope when both sides modeled in single ATO package."

**Baseline Likelihood:** `likely` — Entry's `cwe` field: CWE-345. The entry's `references` cite only control/policy sources (no CWE/CAPEC/OWASP/MITRE vulnerability-class source). No further written justification is attached to this value.

**Baseline Impact:** `high` — The entry's `risk_assessment` reads: "High for high-side systems that make operational or analytical decisions based on low-side data feeds." No further written justification is attached to this value.

### CDS: High-Side Transfer Broker Unauthorized Access and Queue Tampering

**ID:** `cds-high-side-broker-tampering`  
**Location:** Custom category — `models/central-security-repo/libraries/09-custom-risks-lib.yml`, injected by `models/central-security-repo/core-policies/inject_risks.py`

**Description:** The high-side message broker staging content for the CDS interface is a critical security boundary; unauthorized write access to its outbound queue bypasses the release authority and sanitization gates. If this risk remains unmitigated, injected content can reach the CDS for downward release without ever passing through the controls meant to review it.

**Applies to:** Technical assets tagged `cds:high-side-broker`.

**Why it applies there:** inject_risks.py comment on the high-side block: "in-scope when both sides modeled in single ATO package."

**Baseline Likelihood:** `unlikely` — Entry's `cwe` field: CWE-284. The entry's `references` cite only control/policy sources (no CWE/CAPEC/OWASP/MITRE vulnerability-class source). No further written justification is attached to this value.

**Baseline Impact:** `very-high` — The entry's `risk_assessment` reads: "Critical." No further written justification is attached to this value.

### CDS: Transfer Interface Covert Channel Exposure

**ID:** `cds-transfer-interface-covert-channel`  
**Location:** Custom category — `models/central-security-repo/libraries/09-custom-risks-lib.yml`, injected by `models/central-security-repo/core-policies/inject_risks.py`

**Description:** A covert channel -- timing, storage, or feedback-based -- can carry information across a CDS transfer interface without passing through the CDS content filter or being authorized by transfer policy. If this risk remains unmitigated, a low-bandwidth but persistent exfiltration or signaling path exists that content inspection alone cannot detect.

**Applies to:** Technical assets tagged any of `cds:low-side-submitter`, `cds:low-side-receiver`, `cds:high-side-submitter`, or `cds:high-side-receiver` (brokers excluded).

**Why it applies there:** inject_risks.py comment: "Covert channel -- fires on any CDS transfer submitter/receiver interface (timing/storage/feedback channel exposure, assessed per side)."

**Baseline Likelihood:** `unlikely` — Entry's `cwe` field: CWE-514. The entry's `references` cite only control/policy sources (no CWE/CAPEC/OWASP/MITRE vulnerability-class source). No further written justification is attached to this value.

**Baseline Impact:** `medium` — The entry's `risk_assessment` reads: "High for timing and storage channels on any CDS submitter or receiver interface — low bandwidth but persistent and hard to detect through content inspection alone." No further written justification is attached to this value.

## Application

### Server-Side Template Injection and RCE

**ID:** `dynamic-code-rce`  
**Location:** Custom category — `models/central-security-repo/libraries/09-custom-risks-lib.yml`, injected by `models/central-security-repo/core-policies/inject_risks.py`

**Description:** The application executes dynamic code, expressions, or templates built from user-supplied input, creating a server-side template injection vector. If this risk remains unmitigated, an attacker can achieve remote code execution and full compromise of the container running the application.

**Applies to:** Technical assets tagged `feature:dynamic-code-execution`.

**Why it applies there:** *Structural inference (no explanatory comment at this trigger in inject_risks.py):* the tag declares the asset evaluates dynamic code/templates, the injection vector the category describes; there is no suppression tag.

**Baseline Likelihood:** `very-likely` — Entry's `cwe` field: CWE-1336. The entry's `references` cite only control/policy sources (no CWE/CAPEC/OWASP/MITRE vulnerability-class source). No further written justification is attached to this value.

**Baseline Impact:** `very-high` — The entry's `risk_assessment` reads: "Critical risk if raw user input is evaluated directly as code or templates." No further written justification is attached to this value.

### Malicious File Parsing and XXE

**ID:** `malicious-file-parsing`  
**Location:** Custom category — `models/central-security-repo/libraries/09-custom-risks-lib.yml`, injected by `models/central-security-repo/core-policies/inject_risks.py`

**Description:** The application parses complex user-uploaded files such as XML, PDF, or ZIP archives, which can carry XXE, path traversal, or decompression-bomb payloads. If this risk remains unmitigated, a crafted file can cause server-side request forgery, unauthorized file reads, or denial of service.

**Applies to:** Technical assets tagged `feature:file-upload-processing`.

**Why it applies there:** *Structural inference (no explanatory comment at this trigger in inject_risks.py):* the tag declares the asset parses uploaded files, the parser attack surface the category describes.

**Baseline Likelihood:** `likely` — Entry's `cwe` field: CWE-611. The entry's `references` cite only control/policy sources (no CWE/CAPEC/OWASP/MITRE vulnerability-class source). Value recalibrated from `very-likely` in commit `3e7a40e` (an audit grounded in CWE/CAPEC likelihood ratings, OWASP Top 10:2025 + API Top 10:2023, Verizon DBIR 2025, and Sophos ransomware data; no per-entry citation recorded).

**Baseline Impact:** `medium` — The entry's `risk_assessment` reads: "High if parsing untrusted B2B or external user files." No further written justification is attached to this value.

### Insecure Deserialization

**ID:** `insecure-deserialization`  
**Location:** Custom category — `models/central-security-repo/libraries/09-custom-risks-lib.yml`, injected by `models/central-security-repo/core-policies/inject_risks.py`

**Description:** The asset deserializes objects from user-supplied or externally sourced data using a mechanism capable of instantiating arbitrary objects, such as Java native serialization or Python pickle. If this risk remains unmitigated, a crafted serialized payload can execute a gadget chain achieving remote code execution with the application's own privileges.

**Applies to:** Technical assets tagged `feature:deserialization`.

**Why it applies there:** *Structural inference (no explanatory comment at this trigger in inject_risks.py):* the tag declares the asset deserializes external data, the surface the category describes.

**Baseline Likelihood:** `likely` — Entry's `cwe` field: CWE-502. Vulnerability-class references cited by the entry: OWASP Top 10: A08:2021 (Software and Data Integrity Failures); CWE-502. Value recalibrated from `very-likely` in commit `3e7a40e` (an audit grounded in CWE/CAPEC likelihood ratings, OWASP Top 10:2025 + API Top 10:2023, Verizon DBIR 2025, and Sophos ransomware data; no per-entry citation recorded).

**Baseline Impact:** `very-high` — The entry's `risk_assessment` reads: "Critical for Java applications using ObjectInputStream or .NET applications using BinaryFormatter on externally-sourced data." No further written justification is attached to this value.

### Server-Side PDF Generation Injection

**ID:** `pdf-generation-injection`  
**Location:** Custom category — `models/central-security-repo/libraries/09-custom-risks-lib.yml`, injected by `models/central-security-repo/core-policies/inject_risks.py`

**Description:** The asset generates PDFs server-side by rendering HTML templates with a headless browser or HTML-to-PDF library, which can resolve attacker-supplied URLs or file paths during rendering. If this risk remains unmitigated, injected HTML or CSS can be used to read local files or reach the cloud metadata endpoint from the rendering process.

**Applies to:** Technical assets tagged `feature:pdf-generation`.

**Why it applies there:** *Structural inference (no explanatory comment at this trigger in inject_risks.py):* the tag declares server-side HTML-to-PDF rendering, the surface the category describes.

**Baseline Likelihood:** `likely` — Entry's `cwe` field: CWE-918. The entry's `references` cite only control/policy sources (no CWE/CAPEC/OWASP/MITRE vulnerability-class source). No further written justification is attached to this value.

**Baseline Impact:** `medium` — The entry's `risk_assessment` reads: "High for renderers with JavaScript enabled that incorporate unsanitized user content." No further written justification is attached to this value.

### Email Header Injection and Sending Abuse

**ID:** `email-header-injection`  
**Location:** Custom category — `models/central-security-repo/libraries/09-custom-risks-lib.yml`, injected by `models/central-security-repo/core-policies/inject_risks.py`

**Description:** The asset constructs outbound email from user-supplied input without sanitizing recipient or header fields, allowing CRLF-based header injection. If this risk remains unmitigated, an attacker can redirect mail to unintended recipients or turn the application into an open relay for spam and phishing.

**Applies to:** Technical assets tagged `feature:email-sending`.

**Why it applies there:** *Structural inference (no explanatory comment at this trigger in inject_risks.py):* the tag declares the asset builds outbound email, the CRLF-injection surface the category describes.

**Baseline Likelihood:** `very-likely` — Entry's `cwe` field: CWE-93. Vulnerability-class references cited by the entry: CWE-93 (CRLF Injection). No further written justification is attached to this value.

**Baseline Impact:** `medium` — The entry's `risk_assessment` reads: "Medium for applications sending transactional email with partial user-controlled content." No further written justification is attached to this value.

### Webhook Signature Verification Bypass

**ID:** `webhook-signature-bypass`  
**Location:** Custom category — `models/central-security-repo/libraries/09-custom-risks-lib.yml`, injected by `models/central-security-repo/core-policies/inject_risks.py`

**Description:** The asset receives inbound webhook callbacks and acts on their payload without verifying a cryptographic signature on the request. If this risk remains unmitigated, anyone who knows the endpoint URL can send a fabricated payload and trigger business logic with attacker-controlled data.

**Applies to:** Technical assets tagged `feature:webhook-receiver`.

**Why it applies there:** *Structural inference (no explanatory comment at this trigger in inject_risks.py):* the tag declares an inbound webhook endpoint, the surface the category describes; there is no suppression tag.

**Baseline Likelihood:** `likely` — Entry's `cwe` field: CWE-347. The entry's `references` cite only control/policy sources (no CWE/CAPEC/OWASP/MITRE vulnerability-class source). No further written justification is attached to this value.

**Baseline Impact:** `medium` — The entry's `risk_assessment` reads: "High for webhooks that trigger write operations, financial transactions, or account management actions." No further written justification is attached to this value.

### Bulk Import/Export Data Abuse

**ID:** `bulk-import-export-abuse`  
**Location:** Custom category — `models/central-security-repo/libraries/09-custom-risks-lib.yml`, injected by `models/central-security-repo/core-policies/inject_risks.py`

**Description:** The asset supports bulk data import or export without per-record authorization checks or bounded scope, exposing it to formula injection, mass overwrite, and unbounded data exposure. If this risk remains unmitigated, a low-privilege user can export an entire dataset beyond what individual record access would allow, or overwrite authoritative records at scale.

**Applies to:** Technical assets tagged `feature:import-export`.

**Why it applies there:** *Structural inference (no explanatory comment at this trigger in inject_risks.py):* the tag declares bulk import/export functionality, the surface the category describes. The same tag also drives the DLP egress check.

**Baseline Likelihood:** `likely` — Entry's `cwe` field: CWE-862. Vulnerability-class references cited by the entry: OWASP CSV Injection. No further written justification is attached to this value.

**Baseline Impact:** `medium` — The entry's `risk_assessment` reads: "High for export operations on CUI datasets without per-user scoping." No further written justification is attached to this value.

### GraphQL Introspection, Query Depth, and Authorization Gaps

**ID:** `graphql-security-gaps`  
**Location:** Custom category — `models/central-security-repo/libraries/09-custom-risks-lib.yml`, injected by `models/central-security-repo/core-policies/inject_risks.py`

**Description:** The asset exposes a GraphQL API with production introspection enabled, no query-depth limiting, and authorization checks that may not extend to individual fields or mutations. If this risk remains unmitigated, introspection reveals the full schema to accelerate further attacks, and a single deeply nested query can exhaust backend resources.

**Applies to:** Technical assets tagged `feature:graphql-endpoint`.

**Why it applies there:** *Structural inference (no explanatory comment at this trigger in inject_risks.py):* the tag declares a GraphQL API, whose introspection/depth/field-authorization surface is what the category describes.

**Baseline Likelihood:** `very-likely` — Entry's `cwe` field: CWE-200. Vulnerability-class references cited by the entry: OWASP GraphQL Cheat Sheet. No further written justification is attached to this value.

**Baseline Impact:** `medium` — The entry's `risk_assessment` reads: "High if introspection is enabled in production or if query depth/complexity limits are absent." No further written justification is attached to this value.

### Search Index Abuse and Data Exposure

**ID:** `search-index-abuse`  
**Location:** Custom category — `models/central-security-repo/libraries/09-custom-risks-lib.yml`, injected by `models/central-security-repo/core-policies/inject_risks.py`

**Description:** The application relies on a search index such as Elasticsearch or Solr for query functionality, and index-level authorization may not be strictly enforced. If this risk remains unmitigated, an attacker can craft queries that bypass application-layer access controls to scrape data or exhaust backend resources.

**Applies to:** Technical assets tagged `feature:search-index`.

**Why it applies there:** *Structural inference (no explanatory comment at this trigger in inject_risks.py):* the tag declares reliance on a search index, the surface the category describes.

**Baseline Likelihood:** `likely` — Entry's `cwe` field: CWE-285. The entry's `references` cite only control/policy sources (no CWE/CAPEC/OWASP/MITRE vulnerability-class source). No further written justification is attached to this value.

**Baseline Impact:** `medium` — The entry's `risk_assessment` reads: "High risk if the raw search endpoint is exposed or if queries are unbounded." No further written justification is attached to this value.

### WebSocket Origin Validation and Authentication Gaps

**ID:** `websocket-security-gaps`  
**Location:** Custom category — `models/central-security-repo/libraries/09-custom-risks-lib.yml`, injected by `models/central-security-repo/core-policies/inject_risks.py`

**Description:** The asset uses persistent WebSocket connections without validating the Origin header on the upgrade handshake or revalidating session state on individual messages. If this risk remains unmitigated, a malicious page on another origin can hijack an authenticated WebSocket connection and read or send messages as the victim.

**Applies to:** Technical assets tagged `feature:websocket`.

**Why it applies there:** *Structural inference (no explanatory comment at this trigger in inject_risks.py):* the tag declares persistent WebSocket connections, the surface the category describes.

**Baseline Likelihood:** `likely` — Entry's `cwe` field: CWE-1385. Vulnerability-class references cited by the entry: OWASP HTML5 Security Cheat Sheet; CWE-346 (Origin Validation Error). No further written justification is attached to this value.

**Baseline Impact:** `medium` — The entry's `risk_assessment` reads: "Medium for read-only WebSocket endpoints." No further written justification is attached to this value.

### Permissive CORS and Missing Browser Framing/Content Policy

**ID:** `permissive-cors-framing-policy`  
**Location:** Custom category — `models/central-security-repo/libraries/09-custom-risks-lib.yml`, injected by `models/central-security-repo/core-policies/inject_risks.py`

**Description:** This browser-facing asset either reflects arbitrary origins in its CORS policy with credentials allowed, or lacks a restrictive Content-Security-Policy frame-ancestors (or X-Frame-Options) directive on its rendered pages. If this risk remains unmitigated, a hostile site can read this asset's authenticated API responses cross-origin, or overlay its UI to capture clicks on privileged actions (clickjacking/UI redressing), without the victim's awareness.

**Applies to:** Technical assets tagged `feature:browser-facing` that do not also carry `ops:cors-csp-hardened`.

**Why it applies there:** *Structural inference (no explanatory comment at this trigger in inject_risks.py):* only browser-rendered/browser-called assets are subject to CORS and framing policy; `ops:cors-csp-hardened` is the positive-confirmation tag that suppresses it.

**Baseline Likelihood:** `likely` — Entry's `cwe` field: CWE-942. Vulnerability-class references cited by the entry: OWASP Top 10:2025 A02; CWE-942; CWE-1021; MITRE CAPEC-103, CAPEC-111. No further written justification is attached to this value.

**Baseline Impact:** `medium` — The entry's `risk_assessment` reads: "Medium for any browser-facing asset with a permissive CORS policy or no frame-ancestors/X-Frame-Options directive." No further written justification is attached to this value.

### Background Job Parameter Injection and Authorization Bypass

**ID:** `background-job-security`  
**Location:** Custom category — `models/central-security-repo/libraries/09-custom-risks-lib.yml`, injected by `models/central-security-repo/core-policies/inject_risks.py`

**Description:** The asset processes background jobs whose parameters originate from earlier user input, without re-validating the user's authorization at execution time. If this risk remains unmitigated, a job can execute with permissions the user no longer holds, or with parameters altered by anyone with access to the queue.

**Applies to:** Technical assets tagged `feature:background-jobs`.

**Why it applies there:** *Structural inference (no explanatory comment at this trigger in inject_risks.py):* the tag declares asynchronous job processing, the surface the category describes.

**Baseline Likelihood:** `likely` — Entry's `cwe` field: CWE-863. Vulnerability-class references cited by the entry: CWE-367 (TOCTOU Race Condition). No further written justification is attached to this value.

**Baseline Impact:** `medium` — The entry's `risk_assessment` reads: "Medium for background jobs processing non-CUI data." No further written justification is attached to this value.

### Application Cache Poisoning and Sensitive Data Persistence

**ID:** `cache-poisoning-data-persistence`  
**Location:** Custom category — `models/central-security-repo/libraries/09-custom-risks-lib.yml`, injected by `models/central-security-repo/core-policies/inject_risks.py`

**Description:** The asset uses an application-level cache to serve responses, with cache keys that may not incorporate every parameter affecting the response, or a cache server reachable without authentication. If this risk remains unmitigated, one user's cached response -- including sensitive data -- can be served to a different user, or a cache server can be read or written directly by anyone on the internal network.

**Applies to:** Technical assets tagged `feature:caching-layer`.

**Why it applies there:** *Structural inference (no explanatory comment at this trigger in inject_risks.py):* the tag declares an application-level cache, the surface the category describes.

**Baseline Likelihood:** `likely` — Entry's `cwe` field: CWE-524. Vulnerability-class references cited by the entry: OWASP Cache Poisoning. No further written justification is attached to this value.

**Baseline Impact:** `medium` — The entry's `risk_assessment` reads: "High for Redis/Memcached instances without authentication accessible to multiple application pods." No further written justification is attached to this value.

### Unauthorized Marketplace Plugin

**ID:** `unauthorized-marketplace-plugin`  
**Location:** Custom category — `models/central-security-repo/libraries/09-custom-risks-lib.yml`, injected by `models/central-security-repo/core-policies/inject_risks.py`

**Description:** The application allows installation of third-party marketplace plugins that execute code directly within the application's core process. If this risk remains unmitigated, a malicious or supply-chain-compromised plugin runs with the full privilege of the application, enabling complete compromise.

**Applies to:** Technical assets tagged `feature:third-party-plugins`.

**Why it applies there:** *Structural inference (no explanatory comment at this trigger in inject_risks.py):* the tag declares in-process third-party plugin support, the surface the category describes.

**Baseline Likelihood:** `likely` — Entry's `cwe` field: CWE-829. The entry's `references` cite only control/policy sources (no CWE/CAPEC/OWASP/MITRE vulnerability-class source). No further written justification is attached to this value.

**Baseline Impact:** `very-high` — The entry's `risk_assessment` reads: "Critical if end-user or admin plugin installation is permitted without vetting." No further written justification is attached to this value.

### VDI Clipboard Data Exfiltration

**ID:** `vdi-clipboard-data-exfiltration`  
**Location:** Custom category — `models/central-security-repo/libraries/09-custom-risks-lib.yml`, injected by `models/central-security-repo/core-policies/inject_risks.py`

**Description:** This asset's VDI session allows clipboard redirection between the remote session and the local endpoint, a channel most network-layer DLP controls do not inspect. If this risk remains unmitigated, a malicious insider can exfiltrate data through the clipboard without generating any network-layer alert.

**Applies to:** Technical assets tagged `feature:vdi-path`.

**Why it applies there:** *Structural inference (no explanatory comment at this trigger in inject_risks.py):* the tag declares a VDI session path, whose clipboard redirection channel the category describes.

**Baseline Likelihood:** `unlikely` — Entry's `cwe` field: CWE-200. The entry's `references` cite only control/policy sources (no CWE/CAPEC/OWASP/MITRE vulnerability-class source). No further written justification is attached to this value.

**Baseline Impact:** `medium` — The entry's `risk_assessment` reads: "High for deployments permitting non-GFE or personally-owned device access to AVD sessions containing CUI." No further written justification is attached to this value.

### Public API Abuse and Asymmetric DoS

**ID:** `public-api-abuse`  
**Location:** Custom category — `models/central-security-repo/libraries/09-custom-risks-lib.yml`, injected by `models/central-security-repo/core-policies/inject_risks.py`

**Description:** The application exposes an internet-facing API without rate limiting, pagination, or computational throttling. If this risk remains unmitigated, an attacker can degrade service, exhaust database resources, or drive up cloud consumption costs.

**Applies to:** Technical assets tagged `feature:public-api-endpoint`.

**Why it applies there:** *Structural inference (no explanatory comment at this trigger in inject_risks.py):* the tag declares an internet-facing API, the resource-exhaustion surface the category describes; there is no suppression tag.

**Baseline Likelihood:** `very-likely` — Entry's `cwe` field: CWE-770. The entry's `references` cite only control/policy sources (no CWE/CAPEC/OWASP/MITRE vulnerability-class source). No further written justification is attached to this value.

**Baseline Impact:** `medium` — The entry's `risk_assessment` reads: "Medium risk of availability disruption during high-volume events." No further written justification is attached to this value.

### Improper API Inventory Management

**ID:** `improper-api-inventory-management`  
**Location:** Custom category — `models/central-security-repo/libraries/09-custom-risks-lib.yml`, injected by `models/central-security-repo/core-policies/inject_risks.py`

**Description:** The API surface includes undocumented, deprecated, or non-production (beta/staging/debug) endpoints or versions that remain reachable but fall outside the organization's current inventory, documentation, and patch/monitoring scope. If this risk remains unmitigated, an old API version retains the vulnerabilities and weaker controls of whatever state it was frozen in, while receiving none of the monitoring, patching, or rate-limiting applied to the current version -- and because it isn't inventoried, nobody notices it's still reachable.

**Applies to:** Technical assets tagged `feature:public-api-endpoint`.

**Why it applies there:** *Structural inference (no explanatory comment at this trigger in inject_risks.py):* injected alongside Public API Abuse on every public API endpoint, since any published API surface can carry un-inventoried versions; there is no suppression tag.

**Baseline Likelihood:** `likely` — Entry's `cwe` field: CWE-1059. Vulnerability-class references cited by the entry: OWASP API Security Top 10: API9:2023 (Improper Inventory Management). No further written justification is attached to this value.

**Baseline Impact:** `medium` — The entry's `risk_assessment` reads: "Medium as a standalone structural gap; escalates sharply once any deprecated version is confirmed to carry a control the current version has since fixed (a removed rate limit, a patched vulnerability, weaker authentication), since that gap is now silently exploitable." No further written justification is attached to this value.

### Unrestricted Access to Sensitive Business Flows

**ID:** `business-flow-abuse`  
**Location:** Custom category — `models/central-security-repo/libraries/09-custom-risks-lib.yml`, injected by `models/central-security-repo/core-policies/inject_risks.py`

**Description:** This asset implements a multi-step business process valuable enough to be worth automating or abusing at scale -- bulk account creation, ticket or inventory scalping, loan or claim application submission, bulk coupon redemption -- without a control distinguishing legitimate human usage from automated abuse of the flow itself. Distinct from Public API Abuse and Asymmetric DoS, which is about raw request volume/compute exhaustion regardless of what the request does; this is about the business value of the specific flow being automated at scale even at ordinary request rates. If this risk remains unmitigated, an adversary can automate a legitimate business process at a volume and speed no human user could achieve, extracting business value (inventory, credentials, approved applications) the flow was never designed to yield at scale.

**Applies to:** Technical assets tagged `feature:sensitive-business-flow`.

**Why it applies there:** inject_risks.py comment: OWASP API Security Top 10:2023 API6, "distinct from the asymmetric-DoS/rate-limiting framing above: this is about automated/bulk abuse of a legitimate multi-step business process itself ... not raw request volume."

**Baseline Likelihood:** `likely` — Entry's `cwe` field: CWE-799. Vulnerability-class references cited by the entry: OWASP API Security Top 10: API6:2023 (Unrestricted Access to Sensitive Business Flows); OWASP Automated Threats to Web Applications (OAT). No further written justification is attached to this value.

**Baseline Impact:** `medium` — The entry's `risk_assessment` reads: "High for any publicly-reachable flow with direct business value (inventory, credential issuance, financial approval) and no anti-automation control distinct from generic rate limiting." No further written justification is attached to this value.

### Unsafe Consumption of APIs

**ID:** `unsafe-api-consumption`  
**Location:** Custom category — `models/central-security-repo/libraries/09-custom-risks-lib.yml`, injected by `models/central-security-repo/core-policies/inject_risks.py`

**Description:** This asset sends requests to an external, third-party API and trusts the response content and schema without validation, treating "came from a legitimate external API" as equivalent to "safe to consume." Distinct from Server-Side Request Forgery, which is about this asset's own request being hijacked to reach an unintended target; this is about the response from an intended, legitimate target being trusted without verification. If this risk remains unmitigated, a compromised, misconfigured, or simply buggy upstream API can inject unexpected data shapes, oversized payloads, or malicious content directly into this asset's own processing logic, since no boundary exists between "external API response" and "trusted internal data."

**Applies to:** Technical assets tagged `net:external-api-consumer`.

**Why it applies there:** inject_risks.py comment: OWASP API Security Top 10:2023 API10, "the inverse of SSRF: this asset calls a legitimate external API and trusts its response content/schema without validation."

**Baseline Likelihood:** `likely` — Entry's `cwe` field: CWE-20. Vulnerability-class references cited by the entry: OWASP API Security Top 10: API10:2023 (Unsafe Consumption of APIs). No further written justification is attached to this value.

**Baseline Impact:** `high` — The entry's `risk_assessment` reads: "Medium as a standalone structural gap; escalates to High if the consumed API is a soft or unauthenticated third-party integration whose own security posture this organization cannot verify." Value recalibrated from `medium` in commit `3e7a40e` (an audit grounded in CWE/CAPEC likelihood ratings, OWASP Top 10:2025 + API Top 10:2023, Verizon DBIR 2025, and Sophos ransomware data; no per-entry citation recorded).

### Missing Web Application Firewall on Internet-Facing Asset

**ID:** `missing-waf-internet-facing`  
**Location:** Custom category — `models/central-security-repo/libraries/09-custom-risks-lib.yml`, injected by `models/central-security-repo/core-policies/inject_risks.py`

**Description:** This internet-facing asset has no Web Application Firewall with a managed ruleset in its ingress path. If this risk remains unmitigated, the application relies entirely on its own application-layer controls, with no network-layer blocking of common injection and protocol-level attacks.

**Applies to:** Technical assets tagged `zone:dmz` whose `technology` is not `waf` and that do not carry `ops:waf-enabled`.

**Why it applies there:** inject_risks.py comment: auto-suppressed when the asset's own `technology:` is `waf`, "a stronger and less error-prone signal" than the tag; `ops:waf-enabled` remains a fallback for "a separate upstream WAF asset (e.g. an external CDN-level WAF) not modeled as this asset's own technology."

**Baseline Likelihood:** `very-likely` — Entry's `cwe` field: CWE-693. The entry's `references` cite only control/policy sources (no CWE/CAPEC/OWASP/MITRE vulnerability-class source). No further written justification is attached to this value.

**Baseline Impact:** `medium` — The entry's `risk_assessment` reads: "Medium as a standalone finding." No further written justification is attached to this value.

### Dangling DNS Record and Subdomain Takeover

**ID:** `dangling-dns-subdomain-takeover`  
**Location:** Custom category — `models/central-security-repo/libraries/09-custom-risks-lib.yml`, injected by `models/central-security-repo/core-policies/inject_risks.py`

**Description:** This internet-facing asset's DNS record points at a cloud resource that is not reconciled against that resource's actual live state. If this risk remains unmitigated, a deprovisioned resource's name becomes reclaimable, letting an attacker stand up content or a certificate under the organization's own trusted subdomain.

**Applies to:** Technical assets tagged `zone:dmz` that do not also carry `ops:dns-record-reconciled`.

**Why it applies there:** inject_risks.py comment: "Internet-facing assets without reconciled DNS records" -- `zone:dmz` marks the internet-facing edge, and `ops:dns-record-reconciled` confirms the reconciliation the category asks for.

**Baseline Likelihood:** `possible` — Entry's `cwe` field: CWE-672. Vulnerability-class references cited by the entry: OWASP Testing Guide (Subdomain Takeover). Value recalibrated from `very-likely` in commit `3e7a40e` (an audit grounded in CWE/CAPEC likelihood ratings, OWASP Top 10:2025 + API Top 10:2023, Verizon DBIR 2025, and Sophos ransomware data; no per-entry citation recorded).

**Baseline Impact:** `medium` — The entry's `risk_assessment` reads: "High for any internet-facing asset with DNS records that are not reconciled against live resource state on a recurring schedule." No further written justification is attached to this value.

## Artificial Intelligence

### ATLAS: LLM Prompt Injection (Direct) and Jailbreak

**ID:** `atlas-direct-prompt-injection-jailbreak`  
**Location:** Custom category — `models/central-security-repo/libraries/09-custom-risks-lib.yml`, injected by `models/central-security-repo/core-policies/inject_risks.py`

**Description:** The asset accepts free-form natural language input from users and forwards it to an LLM, which an adversary can use to override the system prompt or bypass safety guardrails through roleplay, encoding tricks, or adversarial prompt crafting. If this risk remains unmitigated, an adversary can extract system prompt secrets, bypass content guardrails, and coerce the model into unauthorized actions if it has tool access.

**Applies to:** Technical assets tagged `ai:user-prompt-input`.

**Why it applies there:** inject_risks.py comment: "Prompt input surface (direct injection, jailbreak, system prompt extraction)."

**Baseline Likelihood:** `very-likely` — Entry's `cwe` field: CWE-1427. Vulnerability-class references cited by the entry: MITRE ATLAS AML.T0051.000 (Direct Prompt Injection), AML.T0054 (LLM Jailbreak), AML.T0056 (Extract LLM System Prompt), AML.T0057 (LLM Data Leakage), AML.T0062 (Discover LLM Hallucinations), AML.T0065 (LLM Prompt Crafting), AML.T0068 (LLM Prompt Obfuscation), AML.T0069 (Discover LLM System Information); OWASP LLM01:2025, LLM02:2025. No further written justification is attached to this value.

**Baseline Impact:** `high` — The entry's `risk_assessment` reads: "Critical when the model has tool/plugin access." No further written justification is attached to this value.

### ATLAS: Indirect Prompt Injection and Trusted Output Manipulation

**ID:** `atlas-indirect-prompt-injection`  
**Location:** Custom category — `models/central-security-repo/libraries/09-custom-risks-lib.yml`, injected by `models/central-security-repo/core-policies/inject_risks.py`

**Description:** The asset retrieves or processes third-party or user-controlled content that an LLM subsequently interprets, letting an adversary embed instructions in that content to hijack the model's behavior. If this risk remains unmitigated, an adversary can exfiltrate session data or user context, pivot to connected tool actions, or persist an attack across future sessions, all without the user's awareness.

**Applies to:** Four separate triggers: (1) assets tagged `ai:indirect-prompt-input`; (2) assets whose `technology` is `ai-rag-pipeline`; (3) assets whose `technology` is `ai-agent-orchestrator` and (4) assets whose `technology` is `ai-multi-agent-gateway` -- the last two only when not already tagged `ai:indirect-prompt-input`.

**Why it applies there:** inject_risks.py comments: indirect injection surface is "emails, docs, web content fed to LLM"; "RAG retrieval is inherently an indirect prompt injection surface"; "Orchestrators that process external content also inherit indirect injection"; multi-agent gateways inherit it "since agents interpret messages from other agents as instructions," guarded to avoid double-injecting onto an asset already tagged.

**Baseline Likelihood:** `very-likely` — Entry's `cwe` field: CWE-1427. Vulnerability-class references cited by the entry: MITRE ATLAS AML.T0051.001 (Indirect Prompt Injection), AML.T0051.002 (Triggered), AML.T0066 (Retrieval Content Crafting), AML.T0067 (Trusted Output Components Manipulation), AML.T0073 (Impersonation), AML.T0074 (Masquerading), AML.T0093 (Prompt Infiltration via Public-Facing App), AML.T0094 (Delay Execution); OWASP LLM01:2025. No further written justification is attached to this value.

**Baseline Impact:** `high` — The entry's `risk_assessment` reads: "Critical in any agentic or RAG deployment that processes untrusted third-party content and has tool-use or write capabilities." No further written justification is attached to this value.

### ATLAS: AI Agent Tool and Plugin Compromise

**ID:** `atlas-agent-tool-plugin-compromise`  
**Location:** Custom category — `models/central-security-repo/libraries/09-custom-risks-lib.yml`, injected by `models/central-security-repo/core-policies/inject_risks.py`

**Description:** The LLM or agent has access to external tools or function-calling APIs whose definitions, credentials, or registry listings can be poisoned or replaced by an adversary. If this risk remains unmitigated, tool compromise can allow credential theft, data exfiltration, or attacker-controlled commands, all within the agent's legitimate trust context.

**Applies to:** Technical assets tagged `ai:plugin-tool-use`.

**Why it applies there:** inject_risks.py comment: "Tool/plugin surface (tool poisoning, credential theft, exfil via tool calls)."

**Baseline Likelihood:** `likely` — Entry's `cwe` field: CWE-829. Vulnerability-class references cited by the entry: MITRE ATLAS AML.T0053 (AI Agent Tool Invocation), AML.T0083 (Credentials from AI Agent Config), AML.T0085.001 (Data from AI Agent Tools), AML.T0086 (Exfiltration via Agent Tool Invocation), AML.T0098 (Tool Credential Harvesting), AML.T0099 (Tool Data Poisoning), AML.T0100 (AI Agent Clickbait), AML.T0104 (Publish Poisoned Tool), AML.T0110 (AI Agent Tool Poisoning), AML.T0011.002 (Poisoned AI Agent Tool); OWASP LLM06:2025. No further written justification is attached to this value.

**Baseline Impact:** `very-high` — The entry's `risk_assessment` reads: "Critical for write-capable tool access." No further written justification is attached to this value.

### ATLAS: AI Agent Memory and Session State Poisoning

**ID:** `atlas-agent-memory-poisoning`  
**Location:** Custom category — `models/central-security-repo/libraries/09-custom-risks-lib.yml`, injected by `models/central-security-repo/core-policies/inject_risks.py`

**Description:** The AI agent maintains persistent memory or session state across turns, which an adversary can poison or silently alter to change the model's conversational context. If this risk remains unmitigated, an adversary can maintain influence over agent behavior indefinitely and establish persistence that survives an agent restart.

**Applies to:** Technical assets tagged `ai:agent-memory`.

**Why it applies there:** inject_risks.py comment: "Agent persistent memory (memory/thread poisoning, chat history manipulation)."

**Baseline Likelihood:** `likely` — Entry's `cwe` field: CWE-345. Vulnerability-class references cited by the entry: MITRE ATLAS AML.T0080 (AI Agent Context Poisoning — T0080.000 Memory, T0080.001 Thread), AML.T0081 (Modify AI Agent Configuration), AML.T0092 (Manipulate User LLM Chat History); OWASP LLM04:2025, LLM06:2025. No further written justification is attached to this value.

**Baseline Impact:** `medium` — The entry's `risk_assessment` reads: "High for persistent-memory agentic systems with multi-session continuity." No further written justification is attached to this value.

### MAESTRO L3: Agent Framework and Dependency Supply Chain Compromise

**ID:** `maestro-l3-agent-framework-supply-chain`  
**Location:** Custom category — `models/central-security-repo/libraries/09-custom-risks-lib.yml`, injected by `models/central-security-repo/core-policies/inject_risks.py`

**Description:** The AI agent framework layer -- the libraries used to build and run agents and their transitive dependencies -- is itself a supply chain attack surface distinct from model artifacts or tool definitions. If this risk remains unmitigated, a compromised framework package propagates automatically to every agent deployment that installs it, executing with the full privilege of the agent runtime.

**Applies to:** Technical assets tagged `ai:agent-framework`.

**Why it applies there:** inject_risks.py comment: "Agent framework dependency supply chain (MAESTRO L3)," listed under "MAESTRO GAP COVERAGE."

**Baseline Likelihood:** `possible` — Entry's `cwe` field: CWE-1357. Vulnerability-class references cited by the entry: MAESTRO L3 (Agent Frameworks) — Compromised Framework Components, Supply Chain Attacks, Input Validation Attacks. Value recalibrated from `unlikely` in commit `3e7a40e` (an audit grounded in CWE/CAPEC likelihood ratings, OWASP Top 10:2025 + API Top 10:2023, Verizon DBIR 2025, and Sophos ransomware data; no per-entry citation recorded).

**Baseline Impact:** `very-high` — The entry's `risk_assessment` reads: "Critical for any agent built on a publicly-sourced AI framework with an uncontrolled transitive dependency graph." No further written justification is attached to this value.

### AI Output Path to OT or Safety-Critical Actuation Without Human Gate

**ID:** `ai-ot-actuation-boundary-gap`  
**Location:** Custom category — `models/central-security-repo/libraries/09-custom-risks-lib.yml`, injected by `models/central-security-repo/core-policies/inject_risks.py`

**Description:** This AI system's output has a path to an operational technology actuator or safety-critical process with no technical, AI-unbypassable human authorization gate in between. If this risk remains unmitigated, a model failure -- hallucination, prompt injection, or adversarial manipulation -- can directly trigger a physical-world safety incident with no human decision point to catch it.

**Applies to:** Technical assets tagged `ai:ot-adjacent-output`.

**Why it applies there:** inject_risks.py places it under "AI OPERATIONAL AND DEPLOYMENT HARDENING GAPS -- Beyond standard ATLAS/MAESTRO coverage"; a code note states this check "reads only ai:ot-adjacent-output, standalone." There is no suppression tag.

**Baseline Likelihood:** `likely` — Entry's `cwe` field: CWE-1426. Vulnerability-class references cited by the entry: MAESTRO L6 (Security and Compliance). No further written justification is attached to this value.

**Baseline Impact:** `very-high` — The entry's `risk_assessment` reads: "Critical for any AI system with output reaching an OT actuator or safety-critical process through any path not mediated by an unbypassable human gate." No further written justification is attached to this value.

### Offline or Air-Gapped Model Package Integrity Gap

**ID:** `air-gapped-model-package-integrity-gap`  
**Location:** Custom category — `models/central-security-repo/libraries/09-custom-risks-lib.yml`, injected by `models/central-security-repo/core-policies/inject_risks.py`

**Description:** A model destined for a disconnected enclave is not verified as a single signed package at every load, only at the point of initial transfer. If this risk remains unmitigated, a substituted or tampered model artifact sitting inside the enclave has no external signal to catch it and no way to be detected short of per-load cryptographic verification.

**Applies to:** Technical assets tagged `ai:air-gapped-model-delivery` that do not also carry `ai:model-package-signed`.

**Why it applies there:** inject_risks.py comment: this stays tag-triggered (not ported natively) because "'air-gapped/disconnected' has no native field to trigger off (internet: false is set on far too many ordinary internal assets to serve as a proxy)."

**Baseline Likelihood:** `unlikely` — Entry's `cwe` field: CWE-494. The entry's `references` cite only control/policy sources (no CWE/CAPEC/OWASP/MITRE vulnerability-class source). No further written justification is attached to this value.

**Baseline Impact:** `very-high` — The entry's `risk_assessment` reads: "Critical for any model delivered into a disconnected/air-gapped enclave without per-load signature verification against an externally-held key." No further written justification is attached to this value.

### Ungoverned Third-Party Foundation Model API Dependency

**ID:** `ungoverned-third-party-model-api`  
**Location:** Custom category — `models/central-security-repo/libraries/09-custom-risks-lib.yml`, injected by `models/central-security-repo/core-policies/inject_risks.py`

**Description:** This asset sends requests to a vendor-hosted foundation model API with no restriction on which data classifications may be transmitted, no confirmed training-use opt-out, and no recurring review of the vendor's security posture. If this risk remains unmitigated, sending CUI to the vendor API can constitute a data disclosure to a third party the organization does not control.

**Applies to:** Technical assets tagged `ai:third-party-model-api` that do not also carry `ai:vendor-model-governed`.

**Why it applies there:** *Structural inference (no explanatory comment at this trigger in inject_risks.py):* the first tag declares a vendor-hosted model API dependency; `ai:vendor-model-governed` confirms the data-transmission and vendor-review governance whose absence the category describes.

**Baseline Likelihood:** `likely` — Entry's `cwe` field: CWE-201. The entry's `references` cite only control/policy sources (no CWE/CAPEC/OWASP/MITRE vulnerability-class source). No further written justification is attached to this value.

**Baseline Impact:** `medium` — The entry's `risk_assessment` reads: "Critical for any asset transmitting CUI-adjacent or classification-sensitive content (directly or via RAG context) to a vendor model API with no data-transmission restriction or confirmed training-use opt-out." No further written justification is attached to this value.

### AI-Generated Decision Support Without Verification Signal

**ID:** `ai-overreliance-misinformation`  
**Location:** Custom category — `models/central-security-repo/libraries/09-custom-risks-lib.yml`, injected by `models/central-security-repo/core-policies/inject_risks.py`

**Description:** This asset presents AI-generated output to a human as input to a consequential decision, with no confidence indicator, citation/provenance, or mandatory verification step to help the human catch a confidently wrong (hallucinated) answer. If this risk remains unmitigated, a human decision-maker can act on a fluent, confident, but factually wrong AI output -- misclassifying data, misreporting status, or authorizing an action based on a fabricated summary of CUI -- with no built-in signal distinguishing a well-grounded answer from a hallucinated one.

**Applies to:** Technical assets tagged `ai:decision-support-output` that do not also carry `ai:output-confidence-disclosed`.

**Why it applies there:** *Structural inference (no explanatory comment at this trigger in inject_risks.py):* the first tag declares AI output feeds a human decision; `ai:output-confidence-disclosed` confirms the confidence/provenance signal whose absence the category describes.

**Baseline Likelihood:** `likely` — Entry's `cwe` field: CWE-1426. Vulnerability-class references cited by the entry: OWASP LLM09:2025 (Misinformation); MAESTRO L6 (Security and Compliance). No further written justification is attached to this value.

**Baseline Impact:** `medium` — The entry's `risk_assessment` reads: "High where the AI output directly informs a consequential decision (classification, compliance status, operational action) with no citation or confidence signal." No further written justification is attached to this value.

## Data

### Missing Privacy Impact Assessment

**ID:** `missing-privacy-impact-assessment`  
**Location:** Custom category — `models/central-security-repo/libraries/09-custom-risks-lib.yml`, injected by `models/central-security-repo/core-policies/inject_risks.py`

**Description:** This asset processes or stores PII on individuals, but no current Privacy Impact Assessment documents what is collected, why, and how it is protected, as required by Section 208 of the E-Government Act of 2002. If this risk remains unmitigated, privacy risks in the system's actual design go unreviewed until an incident, audit, or FOIA request forces the question, at which point remediation is far more disruptive than a documented assessment would have been.

**Applies to:** Technical assets tagged `data:pii` that do not also carry `data:pia-documented`.

**Why it applies there:** inject_risks.py comment: "PIA requirement (E-Gov Act Sec. 208) attaches to processing PII at all, not just persisting it -- deliberately not nested under storage:persistent."

**Baseline Likelihood:** `likely` — Entry's `cwe` field: CWE-359. The entry's `references` cite only control/policy sources (no CWE/CAPEC/OWASP/MITRE vulnerability-class source). No further written justification is attached to this value.

**Baseline Impact:** `medium` — The entry's `risk_assessment` reads: "High for any asset processing PII with no current PIA on file, or a PIA that predates a material change to what PII is collected or how it is used." No further written justification is attached to this value.

### Missing Data Provenance and Lineage Chain-of-Custody

**ID:** `missing-data-provenance-chain`  
**Location:** Custom category — `models/central-security-repo/libraries/09-custom-risks-lib.yml`, injected by `models/central-security-repo/core-policies/inject_risks.py`

**Description:** Data ingested from an external or upstream source has no origin register or append-only provenance record checked at the point of consumption. If this risk remains unmitigated, a substituted or tampered source is indistinguishable from a legitimate one, since there is nothing to compare it against.

**Applies to:** Technical assets tagged `data:external-feed-ingest` or whose `technology` is `ai-dataset-store`, in either case without `data:provenance-tracked`.

**Why it applies there:** inject_risks.py's note on the ported dataset-store rule explains this check reads the native `technology:` field instead of the removed `ai:dataset-store` tag, "ORed with the unrelated data:external-feed-ingest tag." Otherwise, *structural inference:* both mark ingestion of externally sourced data.

**Baseline Likelihood:** `likely` — Entry's `cwe` field: CWE-345. The entry's `references` cite only control/policy sources (no CWE/CAPEC/OWASP/MITRE vulnerability-class source). No further written justification is attached to this value.

**Baseline Impact:** `medium` — The entry's `risk_assessment` reads: "High for any pipeline ingesting external or third-party data that feeds a decision, a model, or a downstream mission system, where no origin/integrity record exists." No further written justification is attached to this value.

### Data Loss Prevention Egress Path Blind Spot

**ID:** `dlp-egress-blind-spot`  
**Location:** Custom category — `models/central-security-repo/libraries/09-custom-risks-lib.yml`, injected by `models/central-security-repo/core-policies/inject_risks.py`

**Description:** One or more of this asset's data egress paths -- bulk export, attachment, or file transfer -- is not inspected against data classification labels before content leaves. If this risk remains unmitigated, a malicious insider or compromised account can move CUI out through a legitimate export feature without triggering any control.

**Applies to:** Technical assets tagged `feature:import-export` that do not also carry `ops:dlp-egress-inspected`.

**Why it applies there:** *Structural inference (no explanatory comment at this trigger in inject_risks.py):* bulk export is an egress path; `ops:dlp-egress-inspected` confirms DLP inspection of it. The section header comment says this group is "absence-fires-risk."

**Baseline Likelihood:** `likely` — Entry's `cwe` field: CWE-200. The entry's `references` cite only control/policy sources (no CWE/CAPEC/OWASP/MITRE vulnerability-class source). No further written justification is attached to this value.

**Baseline Impact:** `medium` — The entry's `risk_assessment` reads: "High for any asset with a bulk-export, attachment, or external-transfer feature that is not covered by the enterprise DLP policy." No further written justification is attached to this value.

### Media Downgrading Procedure Gap

**ID:** `media-downgrade-procedure-gap`  
**Location:** Custom category — `models/central-security-repo/libraries/09-custom-risks-lib.yml`, injected by `models/central-security-repo/core-policies/inject_risks.py`

**Description:** Media moved from a higher-classification enclave to a lower one is handled under a generic sanitization procedure rather than a distinct, verified downgrading process. If this risk remains unmitigated, residual higher-classification content surviving an incomplete downgrade is disclosed directly into a lower-classification environment.

**Applies to:** Technical assets tagged `cds:high-side-submitter` or `cds:high-side-broker` that do not also carry `data:downgrade-procedure-documented`.

**Why it applies there:** *Structural inference (no explanatory comment at this trigger in inject_risks.py):* high-side submitters and brokers are where content moves from a higher to a lower classification; the section header comment says this group is "absence-fires-risk."

**Baseline Likelihood:** `unlikely` — Entry's `cwe` field: CWE-212. The entry's `references` cite only control/policy sources (no CWE/CAPEC/OWASP/MITRE vulnerability-class source). No further written justification is attached to this value.

**Baseline Impact:** `medium` — The entry's `risk_assessment` reads: "Critical for any asset performing high-to-low media or dataset downgrading without a documented, independently verified procedure distinct from routine disposal." No further written justification is attached to this value.

### Released Dataset Re-Identification Risk

**ID:** `dataset-reidentification-risk`  
**Location:** Custom category — `models/central-security-repo/libraries/09-custom-risks-lib.yml`, injected by `models/central-security-repo/core-policies/inject_risks.py`

**Description:** A dataset slated for release has been de-identified but never tested against a motivated-intruder re-identification attempt using auxiliary data an adversary could reasonably access. If this risk remains unmitigated, a dataset believed to be anonymized can be re-identified after release, constituting a privacy disclosure.

**Applies to:** Technical assets tagged `data:release-candidate` that do not also carry `data:reidentification-tested`.

**Why it applies there:** *Structural inference (no explanatory comment at this trigger in inject_risks.py):* the first tag marks data slated for release; `data:reidentification-tested` confirms the motivated-intruder test whose absence the category describes.

**Baseline Likelihood:** `possible` — Entry's `cwe` field: CWE-202. The entry's `references` cite only control/policy sources (no CWE/CAPEC/OWASP/MITRE vulnerability-class source). Value recalibrated from `unlikely` in commit `3e7a40e` (an audit grounded in CWE/CAPEC likelihood ratings, OWASP Top 10:2025 + API Top 10:2023, Verizon DBIR 2025, and Sophos ransomware data; no per-entry citation recorded).

**Baseline Impact:** `medium` — The entry's `risk_assessment` reads: "High for any dataset containing PII or CUI-adjacent personal attributes released externally or broadly shared without a documented re-identification test." No further written justification is attached to this value.

### Missing Data Rights Management on Released Files

**ID:** `missing-data-rights-management`  
**Location:** Custom category — `models/central-security-repo/libraries/09-custom-risks-lib.yml`, injected by `models/central-security-repo/core-policies/inject_risks.py`

**Description:** A file released beyond its originating boundary carries no persistent rights binding that travels with the copy. If this risk remains unmitigated, the releasing organization has no technical means to restrict, expire, or revoke access to a released copy after the fact.

**Applies to:** Technical assets tagged `data:release-candidate` that do not also carry `data:rights-managed`.

**Why it applies there:** *Structural inference (no explanatory comment at this trigger in inject_risks.py):* the first tag marks data slated for release beyond its boundary; `data:rights-managed` confirms a persistent rights binding.

**Baseline Likelihood:** `likely` — Entry's `cwe` field: CWE-311. The entry's `references` cite only control/policy sources (no CWE/CAPEC/OWASP/MITRE vulnerability-class source). No further written justification is attached to this value.

**Baseline Impact:** `low` — The entry's `risk_assessment` reads: "Medium, escalating to High for CUI releases to external or lower-trust recipients where no revocation capability exists once the file has left the boundary." No further written justification is attached to this value.

### FIPS Non-Compliant Cryptography

**ID:** `fips-non-compliant-cryptography`  
**Location:** Custom category — `models/central-security-repo/libraries/09-custom-risks-lib.yml`, injected by `models/central-security-repo/core-policies/inject_risks.py`

**Description:** This asset performs cryptographic operations without confirmed use of a FIPS-validated module. If this risk remains unmitigated, the finding independently blocks IL5 authorization regardless of the underlying algorithm's strength.

**Applies to:** Technical assets tagged `net:tls-terminator` that do not also carry `compliance:fips-validated`.

**Why it applies there:** inject_risks.py comment: "TLS termination: FIPS compliance check (skip if already tagged compliant)."

**Baseline Likelihood:** `unlikely` — Entry's `cwe` field: CWE-1240. The entry's `references` cite only control/policy sources (no CWE/CAPEC/OWASP/MITRE vulnerability-class source). No further written justification is attached to this value.

**Baseline Impact:** `medium` — The entry's `risk_assessment` reads: "High risk to ATO." No further written justification is attached to this value.

### Deprecated TLS Versions and Weak Cipher Suites

**ID:** `deprecated-tls-weak-ciphers`  
**Location:** Custom category — `models/central-security-repo/libraries/09-custom-risks-lib.yml`, injected by `models/central-security-repo/core-policies/inject_risks.py`

**Description:** This TLS termination asset supports deprecated protocol versions or weak cipher suites exploitable via known attacks such as POODLE or SWEET32. If this risk remains unmitigated, a network-positioned adversary can decrypt protected traffic or perform a protocol downgrade attack.

**Applies to:** Technical assets tagged `net:tls-terminator` (no suppression tag).

**Why it applies there:** inject_risks.py comment: "TLS termination: deprecated protocol / weak cipher check (always fires on tls-terminator)."

**Baseline Likelihood:** `possible` — Entry's `cwe` field: CWE-327. The entry's `references` cite only control/policy sources (no CWE/CAPEC/OWASP/MITRE vulnerability-class source). Value recalibrated from `very-likely` in commit `3e7a40e` (an audit grounded in CWE/CAPEC likelihood ratings, OWASP Top 10:2025 + API Top 10:2023, Verizon DBIR 2025, and Sophos ransomware data; no per-entry citation recorded).

**Baseline Impact:** `medium` — The entry's `risk_assessment` reads: "Medium (CAT II STIG finding)." No further written justification is attached to this value.

## Detection

### API Abuse and Enumeration Logging Gap

**ID:** `api-abuse-enumeration-logging-gap`  
**Location:** Custom category — `models/central-security-repo/libraries/09-custom-risks-lib.yml`, injected by `models/central-security-repo/core-policies/inject_risks.py`

**Description:** This public API endpoint does not log the request patterns that indicate enumeration or abuse, such as sequential object-ID probing or repeated authorization failures from one caller. If this risk remains unmitigated, an attacker pacing requests below the rate limit produces no throttling event and remains invisible to the SOC.

**Applies to:** Technical assets tagged `feature:public-api-endpoint` that do not also carry `ops:api-abuse-logging-enabled`.

**Why it applies there:** *Structural inference (no explanatory comment at this trigger in inject_risks.py):* nested under the public-API trigger alongside Public API Abuse; `ops:api-abuse-logging-enabled` confirms the enumeration-pattern logging whose absence the category describes.

**Baseline Likelihood:** `likely` — Entry's `cwe` field: CWE-778. Vulnerability-class references cited by the entry: OWASP API Security Top 10 (API4:2023 Unrestricted Resource Consumption, API1:2023 Broken Object Level Authorization). No further written justification is attached to this value.

**Baseline Impact:** `medium` — The entry's `risk_assessment` reads: "High for any public API where object identifiers are part of the request path/body and no correlation rule exists for per-caller authorization-failure or object-enumeration patterns." No further written justification is attached to this value.

### Network Intrusion Detection and Traffic Anomaly Blind Spot

**ID:** `network-ids-blind-spot`  
**Location:** Custom category — `models/central-security-repo/libraries/09-custom-risks-lib.yml`, injected by `models/central-security-repo/core-policies/inject_risks.py`

**Description:** This internet-reachable asset has no network-based intrusion detection or traffic-anomaly monitoring observing traffic crossing its trust boundary. If this risk remains unmitigated, an attacker's network-layer reconnaissance, exploitation attempts, and command-and-control traffic pass without generating any alert for the SOC to act on.

**Applies to:** Technical assets tagged `net:internet-reachable` or `zone:dmz` that do not also carry `net:ids-monitored`.

**Why it applies there:** inject_risks.py comment: uses the broader `net:internet-reachable` tag, not just `zone:dmz`, "since an NIDS/NDR sensor placed at the actual edge component doesn't automatically cover traffic to the real application a few hops behind it."

**Baseline Likelihood:** `likely` — Entry's `cwe` field: CWE-778. The entry's `references` cite only control/policy sources (no CWE/CAPEC/OWASP/MITRE vulnerability-class source). No further written justification is attached to this value.

**Baseline Impact:** `medium` — The entry's `risk_assessment` reads: "High for any internet-reachable or zone:dmz asset with no network-based detection observing its ingress/egress traffic." No further written justification is attached to this value.

## Response

### Undocumented Incident Containment Disposition

**ID:** `undocumented-containment-disposition`  
**Location:** Custom category — `models/central-security-repo/libraries/09-custom-risks-lib.yml`, injected by `models/central-security-repo/core-policies/inject_risks.py`

**Description:** A business-critical or mission-critical asset has no documented answer to whether it may be automatically isolated during a suspected compromise or requires human approval first. If this risk remains unmitigated, response to an active incident is delayed by an ad hoc approval decision, or the asset is isolated in a way that causes unintended operational impact.

**Applies to:** Technical assets lacking `ir:containment-disposition-documented` where any of: the model's `business_criticality` is critical/mission-critical, the asset is tagged `net:internet-reachable`, or it carries any `exception:*` or `cds:*` tag.

**Why it applies there:** inject_risks.py comment: fires on "internet-reachable, exception-bearing, or CDS-interface assets, and on every tagged asset once the model itself is business-critical/mission-critical"; uses `net:internet-reachable` because "an incident responder needs a containment disposition for whatever asset is a plausible compromise target."

**Baseline Likelihood:** `unlikely` — Entry's `cwe` field: CWE-1059. The entry's `references` cite only control/policy sources (no CWE/CAPEC/OWASP/MITRE vulnerability-class source). No further written justification is attached to this value.

**Baseline Impact:** `medium` — The entry's `risk_assessment` reads: "High for any business-critical or mission-critical asset with no documented containment disposition." No further written justification is attached to this value.

### Undocumented Credential Blast Radius for Incident-Driven Rotation

**ID:** `undocumented-credential-blast-radius`  
**Location:** Custom category — `models/central-security-repo/libraries/09-custom-risks-lib.yml`, injected by `models/central-security-repo/core-policies/inject_risks.py`

**Description:** If this asset's credentials were compromised, there is no inventory sufficient to identify and rotate every consumer of them without an improvised discovery effort during the response itself. If this risk remains unmitigated, a credential missed during rotation because it was never inventoried gives an adversary a return path after an incident is declared contained.

**Applies to:** Technical assets tagged `sec:secrets-broker` or `data:credential` that do not also carry `ir:credential-inventory-documented`.

**Why it applies there:** inject_risks.py comment: "Credential blast radius -- fires on secrets brokers and any asset holding credential material."

**Baseline Likelihood:** `unlikely` — Entry's `cwe` field: CWE-1059. The entry's `references` cite only control/policy sources (no CWE/CAPEC/OWASP/MITRE vulnerability-class source). No further written justification is attached to this value.

**Baseline Impact:** `medium` — The entry's `risk_assessment` reads: "High for any asset holding or issuing credentials where no consumer inventory exists to support a complete post-compromise rotation." No further written justification is attached to this value.

### Untested Incident Response Plan

**ID:** `untested-incident-response-plan`  
**Location:** Custom category — `models/central-security-repo/libraries/09-custom-risks-lib.yml`, injected by `models/central-security-repo/core-policies/inject_risks.py`

**Description:** This business-critical or mission-critical asset falls under an incident response plan that has never been exercised through a tabletop or live-fire drill, only documented. If this risk remains unmitigated, roles, escalation paths, and technical procedures assumed to work during an actual incident are tested for the first time under real pressure, when gaps are most costly to discover.

**Applies to:** Every in-scope technical asset when the model's `business_criticality` is critical/mission-critical, unless the asset carries `ir:plan-tested`.

**Why it applies there:** inject_risks.py comment: IR plan testing, breach-notification ownership, and forensic chain-of-custody are "conceptually program-level facts", but are injected per asset because "risk acceptance/disposition is tracked per finding via risk_tracking, and that sign-off has to happen per asset."

**Baseline Likelihood:** `likely` — Entry's `cwe` field: CWE-1008. The entry's `references` cite only control/policy sources (no CWE/CAPEC/OWASP/MITRE vulnerability-class source). No further written justification is attached to this value.

**Baseline Impact:** `medium` — The entry's `risk_assessment` reads: "High for any business-critical or mission-critical asset whose incident response plan has not been exercised within the current ATO period." No further written justification is attached to this value.

### DFARS 252.204-7012 72-Hour Cyber Incident Reporting Gap

**ID:** `dfars-breach-notification-gap`  
**Location:** Custom category — `models/central-security-repo/libraries/09-custom-risks-lib.yml`, injected by `models/central-security-repo/core-policies/inject_risks.py`

**Description:** This business-critical or mission-critical asset has no documented procedure identifying the contract-mandated cyber incident reporting timeline or the party responsible for executing it. If this risk remains unmitigated, a genuine incident is discovered without a clear owner or timeline for DoD-mandated reporting, risking a missed 72-hour reporting window and the contractual and legal consequences that follow.

**Applies to:** Every in-scope technical asset when the model's `business_criticality` is critical/mission-critical, unless the asset carries `ir:breach-notification-procedure-documented`.

**Why it applies there:** inject_risks.py comment: IR plan testing, breach-notification ownership, and forensic chain-of-custody are "conceptually program-level facts", but are injected per asset because "risk acceptance/disposition is tracked per finding via risk_tracking, and that sign-off has to happen per asset."

**Baseline Likelihood:** `unlikely` — Entry's `cwe` field: CWE-1059. The entry's `references` cite only control/policy sources (no CWE/CAPEC/OWASP/MITRE vulnerability-class source). No further written justification is attached to this value.

**Baseline Impact:** `medium` — The entry's `risk_assessment` reads: "High for any business-critical or mission-critical asset covered by a DFARS 252.204-7012 clause with no documented reporting procedure or owner." No further written justification is attached to this value.

### Forensic Evidence Chain-of-Custody Gap

**ID:** `forensic-chain-of-custody-gap`  
**Location:** Custom category — `models/central-security-repo/libraries/09-custom-risks-lib.yml`, injected by `models/central-security-repo/core-policies/inject_risks.py`

**Description:** This business-critical or mission-critical asset has no documented procedure for acquiring, logging, and transferring forensic evidence during an incident affecting it. If this risk remains unmitigated, evidence collected during an incident cannot be shown to be unaltered or continuously accounted for, undermining its use in legal proceedings, contract disputes, or a defensible after-action record.

**Applies to:** Every in-scope technical asset when the model's `business_criticality` is critical/mission-critical, unless the asset carries `ir:evidence-handling-documented`.

**Why it applies there:** inject_risks.py comment: IR plan testing, breach-notification ownership, and forensic chain-of-custody are "conceptually program-level facts", but are injected per asset because "risk acceptance/disposition is tracked per finding via risk_tracking, and that sign-off has to happen per asset."

**Baseline Likelihood:** `unlikely` — Entry's `cwe` field: CWE-1059. The entry's `references` cite only control/policy sources (no CWE/CAPEC/OWASP/MITRE vulnerability-class source). No further written justification is attached to this value.

**Baseline Impact:** `medium` — The entry's `risk_assessment` reads: "High for any business-critical or mission-critical asset with no documented forensic evidence-handling procedure." No further written justification is attached to this value.

## Recovery

### Backup Integrity and Recovery Assurance Gap

**ID:** `backup-integrity-recovery-gap`  
**Location:** Custom category — `models/central-security-repo/libraries/09-custom-risks-lib.yml`, injected by `models/central-security-repo/core-policies/inject_risks.py`

**Description:** The asset is flagged as requiring backup for DR/COOP, but backup integrity, encryption, access control, or recovery testing has not been verified. If this risk remains unmitigated, a ransomware attack or infrastructure failure can result in permanent data loss because the backup's actual recoverability was never confirmed.

**Applies to:** Technical assets tagged `ops:requires-backup` (no suppression tag).

**Why it applies there:** inject_risks.py comment: "Backup integrity -- fires on all assets requiring backup."

**Baseline Likelihood:** `possible` — Entry's `cwe` field: CWE-693. The entry's `references` cite only control/policy sources (no CWE/CAPEC/OWASP/MITRE vulnerability-class source). Value recalibrated from `unlikely` in commit `3e7a40e` (an audit grounded in CWE/CAPEC likelihood ratings, OWASP Top 10:2025 + API Top 10:2023, Verizon DBIR 2025, and Sophos ransomware data; no per-entry citation recorded).

**Baseline Impact:** `high` — The entry's `risk_assessment` reads: "High for assets storing CUI where backup procedures have never been tested or where backup storage is co-located with or accessible from the primary environment." Value recalibrated from `medium` in commit `3e7a40e` (an audit grounded in CWE/CAPEC likelihood ratings, OWASP Top 10:2025 + API Top 10:2023, Verizon DBIR 2025, and Sophos ransomware data; no per-entry citation recorded).

### Backup Administrative Privilege Separation Gap

**ID:** `backup-admin-privilege-separation-gap`  
**Location:** Custom category — `models/central-security-repo/libraries/09-custom-risks-lib.yml`, injected by `models/central-security-repo/core-policies/inject_risks.py`

**Description:** Backup platform administrators share identity with production administrators, or destructive backup operations are not protected by dual authorization. If this risk remains unmitigated, a single compromised production admin account can delete the backups meant to recover from that same compromise.

**Applies to:** Technical assets tagged `ops:requires-backup` that do not also carry `ops:backup-admin-segregated`.

**Why it applies there:** inject_risks.py comment: these are "sharper, independently-triggerable backup/DR risks alongside the bundled one" (Backup Integrity and Recovery Assurance Gap), nested under `ops:requires-backup`; each has its own suppression tag (see 03-tags-lib.yml's "Backup and Recovery Hardening" tags).

**Baseline Likelihood:** `likely` — Entry's `cwe` field: CWE-653. The entry's `references` cite only control/policy sources (no CWE/CAPEC/OWASP/MITRE vulnerability-class source). Value recalibrated from `unlikely` in commit `3e7a40e` (an audit grounded in CWE/CAPEC likelihood ratings, OWASP Top 10:2025 + API Top 10:2023, Verizon DBIR 2025, and Sophos ransomware data; no per-entry citation recorded), whose message attributes this raise to "Sophos 2024 backup-targeting data".

**Baseline Impact:** `very-high` — The entry's `risk_assessment` reads: "Critical for any asset where the same identity or role holds both production administrative access and destructive backup permissions." No further written justification is attached to this value.

### Backup Immutability Not Enforced

**ID:** `backup-immutability-not-enforced`  
**Location:** Custom category — `models/central-security-repo/libraries/09-custom-risks-lib.yml`, injected by `models/central-security-repo/core-policies/inject_risks.py`

**Description:** The backup store uses a retention lock a sufficiently privileged account can shorten or remove, rather than a compliance-mode lock no account can alter before the retention period expires. If this risk remains unmitigated, a privileged account -- including one obtained by an attacker -- can delete backups within the stated retention window.

**Applies to:** Technical assets tagged `ops:requires-backup` that do not also carry `ops:backup-immutable`.

**Why it applies there:** inject_risks.py comment: these are "sharper, independently-triggerable backup/DR risks alongside the bundled one" (Backup Integrity and Recovery Assurance Gap), nested under `ops:requires-backup`; each has its own suppression tag (see 03-tags-lib.yml's "Backup and Recovery Hardening" tags).

**Baseline Likelihood:** `likely` — Entry's `cwe` field: CWE-284. The entry's `references` cite only control/policy sources (no CWE/CAPEC/OWASP/MITRE vulnerability-class source). Value recalibrated from `unlikely` in commit `3e7a40e` (an audit grounded in CWE/CAPEC likelihood ratings, OWASP Top 10:2025 + API Top 10:2023, Verizon DBIR 2025, and Sophos ransomware data; no per-entry citation recorded), whose message attributes this raise to "Sophos 2024 backup-targeting data".

**Baseline Impact:** `very-high` — The entry's `risk_assessment` reads: "Critical for any asset whose backup store's immutability lock can be disabled or shortened by any account, including its own administrators." No further written justification is attached to this value.

### Backup Encryption Key Rotation and Retention Mismatch

**ID:** `backup-key-rotation-retention-mismatch`  
**Location:** Custom category — `models/central-security-repo/libraries/09-custom-risks-lib.yml`, injected by `models/central-security-repo/core-policies/inject_risks.py`

**Description:** This asset's backup encryption keys have no documented rotation cadence tied to the longest retention period any backup copy carries. If this risk remains unmitigated, a key rotated without regard to retention leaves older backups permanently undecryptable, invisible until a restore from them is attempted.

**Applies to:** Technical assets tagged `ops:requires-backup` that do not also carry `ops:backup-key-rotation-aligned`.

**Why it applies there:** inject_risks.py comment: these are "sharper, independently-triggerable backup/DR risks alongside the bundled one" (Backup Integrity and Recovery Assurance Gap), nested under `ops:requires-backup`; each has its own suppression tag (see 03-tags-lib.yml's "Backup and Recovery Hardening" tags).

**Baseline Likelihood:** `unlikely` — Entry's `cwe` field: CWE-1008. The entry's `references` cite only control/policy sources (no CWE/CAPEC/OWASP/MITRE vulnerability-class source). No further written justification is attached to this value.

**Baseline Impact:** `low` — The entry's `risk_assessment` reads: "High for any asset with a documented key rotation cadence that does not explicitly account for its backup retention period, or no documented cadence at all." No further written justification is attached to this value.

### Recovery Objective Definition Gap

**ID:** `recovery-objective-definition-gap`  
**Location:** Custom category — `models/central-security-repo/libraries/09-custom-risks-lib.yml`, injected by `models/central-security-repo/core-policies/inject_risks.py`

**Description:** This asset has no documented RTO/RPO derived from its criticality tier, or its declared figures have never been validated against an actual restore test. If this risk remains unmitigated, an actual incident reveals the asset's true recovery time and data-loss window for the first time, when the gap can no longer be closed quietly.

**Applies to:** Technical assets tagged `ops:requires-backup` that do not also carry `ops:recovery-objectives-defined`.

**Why it applies there:** inject_risks.py comment: these are "sharper, independently-triggerable backup/DR risks alongside the bundled one" (Backup Integrity and Recovery Assurance Gap), nested under `ops:requires-backup`; each has its own suppression tag (see 03-tags-lib.yml's "Backup and Recovery Hardening" tags).

**Baseline Likelihood:** `likely` — Entry's `cwe` field: CWE-1059. The entry's `references` cite only control/policy sources (no CWE/CAPEC/OWASP/MITRE vulnerability-class source). No further written justification is attached to this value.

**Baseline Impact:** `low` — The entry's `risk_assessment` reads: "Medium, escalating to High for business-critical or mission-critical assets with no validated RTO/RPO." No further written justification is attached to this value.

### Untested Restoration Procedure

**ID:** `untested-restoration-procedure`  
**Location:** Custom category — `models/central-security-repo/libraries/09-custom-risks-lib.yml`, injected by `models/central-security-repo/core-policies/inject_risks.py`

**Description:** Backups for this asset pass integrity checks, but no restoration has actually been performed using only the written procedure rather than institutional knowledge. If this risk remains unmitigated, an incomplete or outdated restoration procedure is discovered during an actual incident, at the worst possible time to discover it.

**Applies to:** Technical assets tagged `ops:requires-backup` that do not also carry `ops:backup-recovery-tested`.

**Why it applies there:** inject_risks.py comment: these are "sharper, independently-triggerable backup/DR risks alongside the bundled one" (Backup Integrity and Recovery Assurance Gap), nested under `ops:requires-backup`; each has its own suppression tag (see 03-tags-lib.yml's "Backup and Recovery Hardening" tags).

**Baseline Likelihood:** `likely` — Entry's `cwe` field: CWE-1059. The entry's `references` cite only control/policy sources (no CWE/CAPEC/OWASP/MITRE vulnerability-class source). No further written justification is attached to this value.

**Baseline Impact:** `medium` — The entry's `risk_assessment` reads: "High for any business-critical or mission-critical asset whose restoration procedure has not been exercised, by someone other than its author, within the current ATO period." No further written justification is attached to this value.

### Unsupported or SaaS Service Backup Gap

**ID:** `unsupported-saas-backup-gap`  
**Location:** Custom category — `models/central-security-repo/libraries/09-custom-risks-lib.yml`, injected by `models/central-security-repo/core-policies/inject_risks.py`

**Description:** This asset is a SaaS tenant or vendor-hosted service the enterprise backup platform cannot enroll, with no export job routing its data into enterprise-controlled storage. If this risk remains unmitigated, the asset has no recovery path at all if the vendor tenant is deleted, compromised, or becomes unavailable.

**Applies to:** Technical assets tagged `ops:vendor-hosted-service` that do not also carry `ops:saas-export-configured`.

**Why it applies there:** inject_risks.py comment: "SaaS/vendor-hosted assets the enterprise backup platform can't enroll"; `ops:saas-export-configured` confirms an export into enterprise-controlled storage.

**Baseline Likelihood:** `likely` — Entry's `cwe` field: CWE-1008. The entry's `references` cite only control/policy sources (no CWE/CAPEC/OWASP/MITRE vulnerability-class source). No further written justification is attached to this value.

**Baseline Impact:** `medium` — The entry's `risk_assessment` reads: "High for any SaaS or vendor-hosted asset with no independent, enterprise-controlled backup export configured." No further written justification is attached to this value.

## Governance

### Policy Exception: Cleartext Internal Transit

**ID:** `policy-exception-cleartext-internal`  
**Location:** Custom category — `models/central-security-repo/libraries/09-custom-risks-lib.yml`, injected by `models/central-security-repo/core-policies/inject_risks.py`

**Description:** This component transmits data in plaintext over the internal network. If this risk remains unmitigated, an attacker who breaches the internal network can sniff sensitive data or credentials in transit.

**Applies to:** Technical assets tagged `exception:cleartext-internal`.

**Why it applies there:** inject_risks.py groups it under "POLICY EXCEPTIONS (Explicit Bad)": the tag records a documented waiver, so it fires on presence alone with no suppression tag.

**Baseline Likelihood:** `likely` — Entry's `cwe` field: CWE-319. The entry's `references` cite only control/policy sources (no CWE/CAPEC/OWASP/MITRE vulnerability-class source). No further written justification is attached to this value.

**Baseline Impact:** `medium` — The entry's `risk_assessment` reads: "Medium risk of internal data interception." No further written justification is attached to this value.

### EOL Component in ATO Boundary

**ID:** `eol-component-ato-boundary`  
**Location:** Custom category — `models/central-security-repo/libraries/09-custom-risks-lib.yml`, injected by `models/central-security-repo/core-policies/inject_risks.py`

**Description:** A software component within the ATO boundary has reached end-of-life and no longer receives security patches from its vendor. If this risk remains unmitigated, the component accumulates unpatched CVEs indefinitely, and any newly discovered vulnerability in it is effectively a zero-day for as long as it remains in the boundary.

**Applies to:** Technical assets tagged `exception:eol-component`.

**Why it applies there:** inject_risks.py groups it under "POLICY EXCEPTIONS (Explicit Bad)": the tag records a documented waiver, so it fires on presence alone with no suppression tag.

**Baseline Likelihood:** `very-likely` — Entry's `cwe` field: CWE-1104. The entry's `references` cite only control/policy sources (no CWE/CAPEC/OWASP/MITRE vulnerability-class source). No further written justification is attached to this value.

**Baseline Impact:** `medium` — The entry's `risk_assessment` reads: "High." No further written justification is attached to this value.
