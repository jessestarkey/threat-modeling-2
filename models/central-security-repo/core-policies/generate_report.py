"""Builds report.pdf directly from Threagile's structured output, instead of
post-processing Threagile's own rendered PDF (see trim_report.py, which this
replaces). Threagile's rendered report mixes its own layout engine with the
data; that made a bolted-on Table of Contents (added by trim_report.py, in a
different renderer) drift out of visual sync with the original pages. This
script sources every section from risks.json/risks.xlsx/threagile_injected.yml/
stats.json/the diagram SVGs instead, and renders the whole thing -- content,
TOC, and PDF bookmarks -- through one Jinja2 + WeasyPrint pass, so there is
only one layout engine to keep consistent.

Two data sources are merged per finding: risks.json (machine-readable fields:
severity, synthetic_id, status, most_relevant_*) and risks.xlsx (the Action/
Mitigation narrative text -- present for Threagile's ~36 native rule
categories as well as our ~120 custom-injected ones, whereas the richer
custom-risks-lib.yml fields like asvs/cheat_sheet/references only exist for
our own custom categories).

The two diagrams are rendered by threagile_dfd_to_html.py's build_svg(),
not embedded from Threagile's native PNG or its default Graphviz styling.
Threagile normally discards its own DOT source after rendering and never
exposes it; this custom engine build (jessestarkey/threagile, not the
threagile:0.9.1 the baseline threat-modeling repo still pins) is invoked
with --keep-diagram-source-files, which writes data-flow-diagram.gv /
data-asset-diagram.gv directly into the output directory under those
exact names -- no PATH-shadowing dot-wrapper trick needed (see git
history for how that worked before this migration). This script then
re-renders those with our own restyled shapes/palette instead of
Threagile's -- see threagile_dfd_to_html.py for the design tokens.

Usage:
  python generate_report.py --model threagile_injected.yml --output-dir threagile/output
"""

import argparse
import json
import os
import re
import sys
import tempfile
from pathlib import Path

import openpyxl
import yaml
from jinja2 import Environment, FileSystemLoader
from weasyprint import HTML

SCRIPT_DIR = Path(__file__).resolve().parent
LIBRARIES_DIR = SCRIPT_DIR.parent / "libraries"
TEMPLATES_DIR = SCRIPT_DIR / "templates"

sys.path.insert(0, str(SCRIPT_DIR))
import threagile_dfd_to_html as dfd  # noqa: E402

SEVERITY_ORDER = ["critical", "high", "elevated", "medium", "low"]
# "accepted" used to sit in CLOSED_STATUSES alongside mitigated/false-positive,
# but an accepted risk's underlying vulnerability is still present -- someone
# made a documented risk-acceptance decision to tolerate it, which is a
# different fact from "we fixed it" (mitigated) or "it was never real"
# (false-positive). Grouping it with genuinely-resolved findings under a
# "Closed" section header understates residual risk to a reader (an AO
# reviewing this report especially) doing anything less than a full read of
# each row's own Status column. Kept as its own status set/section instead
# -- see ACCEPTED_STATUSES and the three-way split below.
CLOSED_STATUSES = {"mitigated", "false-positive"}
ACCEPTED_STATUSES = {"accepted"}

# Threagile's built-in rules that flag model-authoring problems (unreferenced
# assets, incomplete boundary/link content) rather than architectural
# vulnerabilities -- kept out of "Identified Risks by Vulnerability Category"
# and surfaced in their own "Potential Model Failures" section instead.
MODEL_FAILURE_CATEGORY_IDS = {
    "incomplete-model",
    "unnecessary-communication-link",
    "unnecessary-data-asset",
    "unnecessary-data-transfer",
    "unnecessary-technical-asset",
    "wrong-communication-link-content",
    "wrong-trust-boundary-content",
}

# 09-custom-risks-lib.yml's own DOMAIN N: NAME banners (see that file's
# header) -- the order the report groups "Identified Risks by Vulnerability
# Category" and the two Impact Analysis sections into. A category whose
# domain isn't resolved (custom or built-in) falls into FALLBACK_DOMAIN,
# always rendered last, rather than the report failing to build.
DOMAIN_ORDER = [
    "Identity",
    "Device and Infrastructure",
    "Network and Environment",
    "Application",
    "Artificial Intelligence",
    "Data",
    "Detection",
    "Response",
    "Recovery",
    "Governance",
]
FALLBACK_DOMAIN = "Uncategorized"

# Threagile's own built-in risk rules aren't in our custom-risks-lib.yml --
# they're compiled into the pinned threagile/threagile:0.9.1 binary, so
# there's no file to derive their domain from the way load_custom_risk_domains()
# does for our own categories. This map was built from the actual category
# IDs observed firing across every real generated risks.json in this
# session's local artifact runs (confluence, exposed-ai-chat, llm-chat,
# transfer, and the upstream example/stub models) -- not from Threagile's
# source, which we don't have. A category ID this map doesn't recognize
# (a new built-in rule from a future Threagile version bump, or one no
# local model has triggered yet) falls back to FALLBACK_DOMAIN rather than
# breaking report generation -- deliberately not exhaustive by design.
THREAGILE_BUILTIN_DOMAIN_MAP = {
    # Identity
    "missing-authentication": "Identity",
    "missing-authentication-second-factor": "Identity",
    "missing-identity-propagation": "Identity",
    "missing-identity-provider-isolation": "Identity",
    "missing-identity-store": "Identity",
    # Device and Infrastructure
    "container-baseimage-backdooring": "Device and Infrastructure",
    "missing-cloud-hardening": "Device and Infrastructure",
    "missing-hardening": "Device and Infrastructure",
    "mixed-targets-on-shared-runtime": "Device and Infrastructure",
    # Network and Environment
    "dos-risky-access-across-trust-boundary": "Network and Environment",
    "missing-network-segmentation": "Network and Environment",
    "missing-waf": "Network and Environment",
    "unguarded-access-from-internet": "Network and Environment",
    "unguarded-direct-datastore-access": "Network and Environment",
    # Application (incl. supply chain/CI-CD, 4.5)
    "code-backdooring": "Application",
    "cross-site-request-forgery": "Application",
    "cross-site-scripting": "Application",
    "ldap-injection": "Application",
    "missing-build-infrastructure": "Application",
    "missing-file-validation": "Application",
    "path-traversal": "Application",
    "push-instead-of-pull-deployment": "Application",
    "search-query-injection": "Application",
    "server-side-request-forgery": "Application",
    "sql-nosql-injection": "Application",
    "unchecked-deployment": "Application",
    "untrusted-deserialization": "Application",
    "xml-external-entity": "Application",
    # Data (incl. secrets/crypto, 6.2)
    "accidental-secret-leak": "Data",
    "missing-vault": "Data",
    "missing-vault-isolation": "Data",
    "unencrypted-asset": "Data",
    "unencrypted-communication": "Data",
    # unnecessary-data-transfer is deliberately absent here even though it's
    # a real built-in category id: it's also in MODEL_FAILURE_CATEGORY_IDS
    # above, and model-failure categories are always routed to
    # model_failure_categories instead of going through this map (see that
    # set's own comment) -- an entry for it here could never actually be
    # consulted.
    # No confirmed real-world mapping yet -- Threagile's generic anomalous-
    # model-shape catch-all doesn't correspond to any one security domain;
    # left unmapped deliberately rather than force-fit, falls to
    # FALLBACK_DOMAIN.
    # "something-strange": ...,
}

# 02-abuse-and-reqs-lib.yml is a reference catalog (see that file's own
# header), never read by any script including this one -- so, like
# THREAGILE_BUILTIN_DOMAIN_MAP above, this is a hardcoded snapshot rather
# than a live derivation. Keyed by the *exact* title string (not a bare
# ID/chapter prefix) because a handful of titles legitimately share a
# prefix across two different domains for two different scenarios (e.g.
# bare "SC-7:" appears once under Device and Infrastructure and twice
# under Network and Environment) -- prefix-only matching would silently
# misattribute whichever entry lost the collision. An app author's own
# hand-written security_requirements/abuse_cases entry (not copied from
# this library) simply won't be in this map and falls back to
# FALLBACK_DOMAIN, same as an unrecognized Threagile built-in category id.
# Regenerate by dumping {title: domain} for every abuse_case/
# security_requirement across every category in the current
# 02-abuse-and-reqs-lib.yml if that file's content changes.
SVS_REQUIREMENT_DOMAIN_MAP = {
    # Identity
    "ASVS V6.3: Credential Stuffing and Authentication Endpoint Abuse": "Identity",
    "ASVS V7.2: Post-Authentication Session Hijacking": "Identity",
    "ASVS V7.5: Session Token Replay via AiTM Proxy or Infostealer": "Identity",
    "ASVS V8.2: Vertical Privilege Escalation": "Identity",
    "ASVS V8.3: Horizontal Privilege Escalation (IDOR)": "Identity",
    "ASVS V8.4: Multi-Tenant Data Isolation Failure": "Identity",
    "ASVS V9.1: JWT Algorithm Confusion and Signature Bypass": "Identity",
    "ASVS V10.1: OAuth and SAML Authentication Flow Abuse": "Identity",
    "ASVS V10.7: OAuth Illicit Consent Grant via Malicious Application": "Identity",
    "AC-2(7): Self-Managed Directory Tier-0 Compromise": "Identity",
    "AC-2(6): Standing Credential Theft from a General-Purpose Endpoint": "Identity",
    "ASVS V6.1: Authentication Documentation": "Identity",
    "ASVS V6.2: Password Security": "Identity",
    "ASVS V6.3: General Authentication Security": "Identity",
    "ASVS V6.4: Authentication Factor Lifecycle and Recovery": "Identity",
    "ASVS V6.5: General Multi-factor authentication requirements": "Identity",
    "ASVS V6.6: Out-of-Band authentication mechanisms": "Identity",
    "ASVS V6.7: Cryptographic authentication mechanism": "Identity",
    "ASVS V6.8: Authentication with an Identity Provider": "Identity",
    "ASVS V7.1: Session Management Documentation": "Identity",
    "ASVS V7.2: Fundamental Session Management Security": "Identity",
    "ASVS V7.3: Session Timeout": "Identity",
    "ASVS V7.4: Session Termination": "Identity",
    "ASVS V7.5: Defenses Against Session Abuse": "Identity",
    "ASVS V7.6: Federated Re-authentication": "Identity",
    "ASVS V8.1: Authorization Documentation": "Identity",
    "ASVS V8.2: General Authorization Design": "Identity",
    "ASVS V8.3: Operation Level Authorization": "Identity",
    "ASVS V8.4: Other Authorization Considerations": "Identity",
    "ASVS V9.1: Token source and integrity": "Identity",
    "ASVS V9.2: Token content": "Identity",
    "ASVS V10.1: Generic OAuth and OIDC Security": "Identity",
    "ASVS V10.2: OAuth Client": "Identity",
    "ASVS V10.3: OAuth Resource Server": "Identity",
    "ASVS V10.4: OAuth Authorization Server": "Identity",
    "ASVS V10.5: OIDC Client": "Identity",
    "ASVS V10.6: OpenID Provider": "Identity",
    "ASVS V10.7: Consent Management": "Identity",
    "AC-2(7): Self-Managed Directory and PKI Hardening": "Identity",
    "AC-2(6): Self-Managed Privileged Access Management": "Identity",
    # Device and Infrastructure
    "CM-7: Container Breakout and Host Takeover": "Device and Infrastructure",
    "SC-7(21): Cloud Metadata API Abuse (IMDS)": "Device and Infrastructure",
    "AC-6(1): Kubernetes Service Account Token Theft": "Device and Infrastructure",
    "SC-7(21): East-West Lateral Movement": "Device and Infrastructure",
    "SC-5: Shared Runtime Resource Exhaustion (Noisy Neighbor)": "Device and Infrastructure",
    "CM-14: Container Supply Chain Poisoning": "Device and Infrastructure",
    "AC-17: Administrative Interface Brute-Force and Credential Stuffing": "Device and Infrastructure",
    "SI-2: Persistent Rootkit and Malware Installation": "Device and Infrastructure",
    "AC-6(5): Lateral Movement via Local Managed Identity": "Device and Infrastructure",
    "SC-28: Offline Data Disk Exfiltration": "Device and Infrastructure",
    "SC-7: Host-to-VNet Pivot and Internal Scanning": "Device and Infrastructure",
    "PE-3: Physical Host Compromise via Default BMC Credentials": "Device and Infrastructure",
    "CM-14: Immutable and Trusted Image Supply Chain": "Device and Infrastructure",
    "CM-7: Least-Privilege, Read-Only Container Execution": "Device and Infrastructure",
    "SC-7(21): Zero-Trust Network Micro-Segmentation": "Device and Infrastructure",
    "SC-5: Resource Quotas and Limit Enforcement": "Device and Infrastructure",
    "AC-6: Least-Privilege Workload and Node Identity": "Device and Infrastructure",
    "CM-6: Hardened Baseline Operating System Configuration": "Device and Infrastructure",
    "SI-2: Automated Vulnerability and Patch Management": "Device and Infrastructure",
    "SI-4: Continuous Endpoint Monitoring": "Device and Infrastructure",
    "AC-17: Secure Administrative Access (JIT and Bastion)": "Device and Infrastructure",
    "SC-28: Host-Level Data-at-Rest Encryption": "Device and Infrastructure",
    "PE-3 / SI-7: Self-Managed Physical Host Hardening": "Device and Infrastructure",
    # Network and Environment
    "ASVS V12.1: TLS Downgrade and Weak Cipher Exploitation": "Network and Environment",
    "ASVS V12.3: Internal Service-to-Service Traffic Left Unencrypted": "Network and Environment",
    "SC-7: Lateral Movement on a Flat Self-Managed Network": "Network and Environment",
    "AC-18: Rogue Access Point and Evil-Twin Credential Harvesting": "Network and Environment",
    "AC-4(19): Classification Marking Validation Bypass": "Network and Environment",
    "AC-4(6): Intentional Misclassification for Unauthorized Exfiltration": "Network and Environment",
    "AC-4(8): Malicious Content Injection via Inbound Transfer Channel": "Network and Environment",
    "AC-3: Transfer Broker Queue Injection": "Network and Environment",
    "AC-4(25): Inadvertent Classified Content Inclusion in Downward Release": "Network and Environment",
    "AC-4(9): Release Authority Bypass on High-Side Downward Transfer": "Network and Environment",
    "SC-31: Cross-Domain Covert Channel via Transfer Pattern": "Network and Environment",
    "MP-8: Media Downgraded Without a Verified Downgrading Procedure": "Network and Environment",
    "ASVS V12.1: General TLS Security Guidance": "Network and Environment",
    "ASVS V12.2: HTTPS Communication with External Facing Services": "Network and Environment",
    "ASVS V12.3: General Service to Service Communication Security": "Network and Environment",
    "SC-7: Self-Managed Network Segmentation": "Network and Environment",
    "AC-18: Self-Managed Wireless Access Control": "Network and Environment",
    "AC-4(19): Server-Side Classification Marking Validation": "Network and Environment",
    "AU-9: Tamper-Evident Transfer Audit Trail": "Network and Environment",
    "AC-4(8) / SI-3: Defense-in-Depth Validation of Inbound CDS Content": "Network and Environment",
    "AC-3: Transfer Broker Access Control and Integrity": "Network and Environment",
    "AC-4(25) / AC-4(9): High-Side Sanitization and Release Authority Gating": "Network and Environment",
    "SI-7: High-Side Inbound Content Integrity Validation": "Network and Environment",
    "SC-31: Covert Channel Analysis and Transfer Rate Controls": "Network and Environment",
    "MP-8: Verified Media Downgrading Procedure": "Network and Environment",
    "CA-3: Current Interconnection Security Agreement": "Network and Environment",
    # Application
    "ASVS V1.3: Server-Side PDF Generator Exploitation": "Application",
    "ASVS V1.3: Server-Side Template Injection and RCE": "Application",
    "ASVS V2.3: Bulk Export Scope Bypass": "Application",
    "ASVS V2.3: Business Workflow Step Skipping": "Application",
    "ASVS V2.4: Application-Layer Data Exfiltration": "Application",
    "ASVS V3.2: Stored XSS via Unsanitized Rich-Text or Markdown Content": "Application",
    "ASVS V4.1: Asymmetric Application Denial of Service": "Application",
    "ASVS V4.2: Webhook and Callback Spoofing": "Application",
    "ASVS V5.2: Malicious Payload Distribution via File Upload": "Application",
    "ASVS V13.3: Hardcoded Secret Discovered in Build Artifact or Config": "Application",
    "ASVS V15.2: Known-Vulnerable Dependency Exploited for RCE": "Application",
    "ASVS V17.1: Unauthenticated TURN Relay Abused for Amplification": "Application",
    "ASVS V1.1: Encoding and Sanitization Architecture": "Application",
    "ASVS V1.2: Injection Prevention": "Application",
    "ASVS V1.3: Sanitization": "Application",
    "ASVS V1.4: Memory, String, and Unmanaged Code": "Application",
    "ASVS V1.5: Safe Deserialization": "Application",
    "ASVS V2.1: Validation and Business Logic Documentation": "Application",
    "ASVS V2.2: Input Validation": "Application",
    "ASVS V2.3: Business Logic Security": "Application",
    "ASVS V2.4: Anti-automation": "Application",
    "ASVS V3.1: Web Frontend Security Documentation": "Application",
    "ASVS V3.2: Unintended Content Interpretation": "Application",
    "ASVS V3.3: Cookie Setup": "Application",
    "ASVS V3.4: Browser Security Mechanism Headers": "Application",
    "ASVS V3.5: Browser Origin Separation": "Application",
    "ASVS V3.6: External Resource Integrity": "Application",
    "ASVS V3.7: Other Browser Security Considerations": "Application",
    "ASVS V4.1: Generic Web Service Security": "Application",
    "ASVS V4.2: HTTP Message Structure Validation": "Application",
    "ASVS V4.3: GraphQL": "Application",
    "ASVS V4.4: WebSocket": "Application",
    "ASVS V5.1: File Handling Documentation": "Application",
    "ASVS V5.2: File Upload and Content": "Application",
    "ASVS V5.3: File Storage": "Application",
    "ASVS V5.4: File Download": "Application",
    "ASVS V13.1: Configuration Documentation": "Application",
    "ASVS V13.2: Backend Communication Configuration": "Application",
    "ASVS V13.3: Secret Management": "Application",
    "ASVS V13.4: Unintended Information Leakage": "Application",
    "ASVS V15.1: Secure Coding and Architecture Documentation": "Application",
    "ASVS V15.2: Security Architecture and Dependencies": "Application",
    "ASVS V15.3: Defensive Coding": "Application",
    "ASVS V15.4: Safe Concurrency": "Application",
    "ASVS V17.1: TURN Server": "Application",
    "ASVS V17.2: Media": "Application",
    "ASVS V17.3: Signaling": "Application",
    # Artificial Intelligence
    "AISVS C1.3: Training Data Poisoning and Backdoor Insertion": "Artificial Intelligence",
    "AISVS C2.1: Direct Prompt Injection and LLM Jailbreak": "Artificial Intelligence",
    "AISVS C2.1: Indirect Prompt Injection via External Content": "Artificial Intelligence",
    "AISVS C3.1: Model Substitution Inside a Disconnected Enclave": "Artificial Intelligence",
    "AISVS C3.1: Undetected Model Swap or Guardrail Disablement": "Artificial Intelligence",
    "AISVS C3.2: Evaluation Pipeline Manipulation": "Artificial Intelligence",
    "AISVS C3.5: Insider Hyperparameter Sabotage": "Artificial Intelligence",
    "AISVS C4.3: Physical Model Extraction from Edge Hardware": "Artificial Intelligence",
    "AISVS C5.2: Vendor Model API Data Exposure via Overlooked RAG Context": "Artificial Intelligence",
    "AISVS C6.1: ML Model Supply Chain Compromise": "Artificial Intelligence",
    "AISVS C6.2: AI Agent Framework Supply Chain Attack": "Artificial Intelligence",
    "AISVS C7.3: AI-Triggered Actuation Without Human Authorization": "Artificial Intelligence",
    "AISVS C8.2: RAG Knowledge Base Poisoning": "Artificial Intelligence",
    "AISVS C9.1: Inference API Cost Harvesting and Denial of AI Service": "Artificial Intelligence",
    "AISVS C9.3: AI Agent Tool Abuse and Privilege Escalation": "Artificial Intelligence",
    "AISVS C10.1: Malicious or Compromised MCP Server Grants Unintended Access": "Artificial Intelligence",
    "AISVS C11.3: Model Extraction and Intellectual Property Theft": "Artificial Intelligence",
    "AISVS C1.1: Training Data Origin & Data Security": "Artificial Intelligence",
    "AISVS C1.2: Data Labeling and Annotation Security": "Artificial Intelligence",
    "AISVS C1.3: Training Data Quality and Security Assurance": "Artificial Intelligence",
    "AISVS C2.1: Prompt Injection Defenses": "Artificial Intelligence",
    "AISVS C2.2: Content & Policy Screening": "Artificial Intelligence",
    "AISVS C3.1: Model Authorization & Integrity": "Artificial Intelligence",
    "AISVS C3.2: Model Validation & Testing": "Artificial Intelligence",
    "AISVS C3.3: Controlled Deployment & Rollback": "Artificial Intelligence",
    "AISVS C3.4: Secure Development Practices": "Artificial Intelligence",
    "AISVS C3.5: Pipeline Fine-Tuning": "Artificial Intelligence",
    "AISVS C4.1: AI Workload Sandboxing & Validation": "Artificial Intelligence",
    "AISVS C4.2: AI Hardware Security": "Artificial Intelligence",
    "AISVS C4.3: Edge & Distributed AI Security": "Artificial Intelligence",
    "AISVS C5.1: Authentication": "Artificial Intelligence",
    "AISVS C5.2: AI Resource Authorization & Classification": "Artificial Intelligence",
    "AISVS C5.3: Multi-Tenant Isolation": "Artificial Intelligence",
    "AISVS C6.1: Model Artifact Integrity": "Artificial Intelligence",
    "AISVS C6.2: AI BOM & Supply Chain Monitoring": "Artificial Intelligence",
    "AISVS C7.1: Output Format Enforcement": "Artificial Intelligence",
    "AISVS C7.2: Hallucination Detection & Mitigation": "Artificial Intelligence",
    "AISVS C7.3: Output Safety": "Artificial Intelligence",
    "AISVS C7.4: Source Attribution & Citation Integrity": "Artificial Intelligence",
    "AISVS C8.1: Access Controls on Memory & RAG Indices": "Artificial Intelligence",
    "AISVS C8.2: Embedding Sanitization & Validation": "Artificial Intelligence",
    "AISVS C8.3: Memory Expiry & Revocation": "Artificial Intelligence",
    "AISVS C9.1: Execution Budgets, Loop Control, and Circuit Breakers": "Artificial Intelligence",
    "AISVS C9.2: High-Impact Action Approval and Irreversibility Controls": "Artificial Intelligence",
    "AISVS C9.3: Component Isolation and Tool Authorization": "Artificial Intelligence",
    "AISVS C9.4: Agent and Orchestrator Identity": "Artificial Intelligence",
    "AISVS C9.5: Agent Authorization, Delegation, and Continuous Enforcement": "Artificial Intelligence",
    "AISVS C9.6: Shutdown and Graceful Degradation": "Artificial Intelligence",
    "AISVS C10.1: Component Integrity": "Artificial Intelligence",
    "AISVS C10.2: Authentication & Authorization": "Artificial Intelligence",
    "AISVS C10.3: Secure Transport": "Artificial Intelligence",
    "AISVS C10.4: Schema, Message, and Input Validation": "Artificial Intelligence",
    "AISVS C11.1: Model Alignment, Safety, and Robustness Testing and Training": "Artificial Intelligence",
    "AISVS C11.2: Membership-Inference and Model-Inversion Mitigation": "Artificial Intelligence",
    "AISVS C11.3: Model-Extraction Defense": "Artificial Intelligence",
    # Data
    "ASVS V11.1: Self-Authorized Key Misuse and Trace Removal": "Data",
    "ASVS V11.2: Custom Cryptography Exploitation": "Data",
    "ASVS V11.7: Software-Only Key Theft via Host Compromise": "Data",
    "ASVS V14.1: Exfiltration from an Unclassified Data Store": "Data",
    "ASVS V14.2: Substituted Content in an Unverified External Feed": "Data",
    "ASVS V14.2: Bulk Exfiltration via an Uninspected Export Path": "Data",
    "ASVS V14.2: Re-Identification of a Released De-Identified Dataset": "Data",
    "ASVS V11.1: Cryptographic Inventory and Documentation": "Data",
    "ASVS V11.2: Secure Cryptography Implementation": "Data",
    "ASVS V11.3: Encryption Algorithms": "Data",
    "ASVS V11.4: Hashing and Hash-based Functions": "Data",
    "ASVS V11.5: Random Values": "Data",
    "ASVS V11.6: Public Key Cryptography": "Data",
    "ASVS V11.7: In-Use Data Cryptography": "Data",
    "ASVS V14.1: Data Protection Documentation": "Data",
    "ASVS V14.2: General Data Protection": "Data",
    "ASVS V14.3: Client-side Data Protection": "Data",
    # Detection
    "ASVS V16.3: Enumeration Paced Under the Rate Limit": "Detection",
    "ASVS V16.4: Audit Trail Evasion and Tampering": "Detection",
    "AISVS C12.3: Model Drift Masked by Absence of Behavioral Baseline Monitoring": "Detection",
    "ASVS V16.1: Security Logging Documentation": "Detection",
    "ASVS V16.2: General Logging": "Detection",
    "ASVS V16.3: Security Events": "Detection",
    "ASVS V16.4: Log Protection": "Detection",
    "ASVS V16.5: Error Handling": "Detection",
    "AISVS C11.4: Model Runtime Anomaly Detection": "Detection",
    "AISVS C12.1: Request & Response Logging": "Detection",
    "AISVS C12.2: Detection and Alerting": "Detection",
    "AISVS C12.3: Model, Data, and Performance Drift Detection": "Detection",
    "AISVS C12.4: Proactive Security Behavior Monitoring": "Detection",
    "AISVS C12.5: Training Data & Model Lifecycle Audit": "Detection",
    # Response
    "IR-4: Incomplete Credential Rotation After a Breach": "Response",
    "IR-3: Incident Response Plan Fails Under Real Conditions": "Response",
    "IR-4: Containment Disposition": "Response",
    "IR-4: Credential Inventory for Incident-Driven Rotation": "Response",
    "IR-3: Regularly Tested Incident Response Plan": "Response",
    "IR-6: Mandatory Incident Reporting Timeline": "Response",
    # Recovery
    "CP-9: Ransomware Deletes Co-Administered Backups": "Recovery",
    "CP-4: Undiscovered Restoration Gap During an Actual Incident": "Recovery",
    "CP-9 / AC-5: Backup Access Separation and Immutability": "Recovery",
    "CP-2: Criticality-Derived Recovery Objectives": "Recovery",
    "CP-4: Tested Restoration Procedure": "Recovery",
    "SA-9: Independent Export for SaaS and Vendor-Hosted Services": "Recovery",
    "SC-12: Backup Encryption Key Rotation and Retention": "Recovery",
}

# Same reasoning and same hardcoded-snapshot caveat as SVS_REQUIREMENT_DOMAIN_MAP
# above, for 01-metadata-lib.yml's own current 35 capability-clustered
# questions -- Open Questions otherwise has no domain grouping at all, unlike
# Abuse Cases and Security Requirements, since build_context() previously just
# sorted the flat questions: dict alphabetically. An app author's own
# hand-written question (not copied from this library) falls back to
# FALLBACK_DOMAIN. Regenerate by dumping {title: domain} for every question
# across every category in the current 01-metadata-lib.yml if that file's
# content changes.
QUESTION_DOMAIN_MAP = {
    # Identity
    "How are users and non-person entities authenticated and where is that documented? For example, are passwords, MFA, out-of-band codes, certs, or a federated IdP login utilized?": "Identity",
    "Walk through session handling end to end: how long sessions live, what kills them early, and what happens on re-authentication after a federated login.": "Identity",
    "Who can access what, and how is that enforced at the function, data, and field level? What protects the admin interface specifically?": "Identity",
    "If this asset issues or accepts OAuth/OIDC tokens, how are they validated and scoped? What secures the client, resource-server, authorization-server, and consent flows involved?": "Identity",
    "If the application runs its own directory, CA, or hybrid-sync service instead of the enterprise tenant, how is it hardened, and who governs privileged access to it?": "Identity",
    # Device and Infrastructure
    "What hardens the containers and VMs? Cover image/OS provenance, least-privilege runtime, network segmentation, resource limits, patching, endpoint monitoring, admin access, and encryption at rest.": "Device and Infrastructure",
    "Does the application utilize any self-managed hardware? If so, have default BMC/iDRAC credentials been changed, is firmware tracked separately from OS patching, and is secure boot enabled?": "Device and Infrastructure",
    # Network and Environment
    "How is TLS implemented, both for external-facing traffic and for service-to-service calls inside the network?": "Network and Environment",
    "If the application manages its own network segmentation, how is it segmented, and what controls wireless access?": "Network and Environment",
    "Does content cross a cross-domain solution? If so, how are classification markings checked, how is the content inspected and sanitized, and who signs off before release?": "Network and Environment",
    "Does the application send or receive data across the authorization boundary? If so, how is the transfer path governed? Are controls such as broker access restrictions, a tamper-evident audit trail, covert-channel mitigation, and a signed interconnection agreement in place?": "Network and Environment",
    # Application
    "What prevents injection and unsafe deserialization? Is there a defined encoding and sanitization architecture, are memory-safety protections in place, and is XML/object deserialization handled safely?": "Application",
    "What stops someone from skipping steps in the application business logic or scripting abuse of it at volume?": "Application",
    "On the frontend, how are cookies configured, what security headers are set, how is CSRF/origin separation enforced, and are external resources integrity-checked?": "Application",
    "What secures HTTP, GraphQL, and WebSocket handling specifically? Are protections like request-smuggling defenses, GraphQL query depth limits, and WebSocket origin checks in place?": "Application",
    "Describe the file handling process, to include upload validation, storage isolation, and safe download.": "Application",
    "How is configuration managed, how do backend services authenticate to each other, and where do secrets actually live?": "Application",
    "How does the application track third-party dependency risk and what defensive coding practices are actually enforced rather than just documented?": "Application",
    "If the application is running WebRTC, what secures the TURN relay and signaling?": "Application",
    # Artificial Intelligence
    "How is training and labeling data secured and what detects poisoning attempts?": "Artificial Intelligence",
    "What stops a prompt injection and how is untrusted input screened before it reaches the model?": "Artificial Intelligence",
    "How does the application verify a model artifact's integrity and provenance? Is it signed, is there an AI-BOM for it, and is its source tracked? What controls safe deployment and rollback?": "Artificial Intelligence",
    "How are AI workloads isolated? Are enforcement mechanisms such as sandboxing, GPU/accelerator access restrictions, or protected edge-deployed models utilized?": "Artificial Intelligence",
    "Who can access the application's AI resources and how is that authenticated? If multiple tenants share the infrastructure, how are they kept apart?": "Artificial Intelligence",
    "What validates and bounds model output before a user sees it? Does anything catch hallucinations or check source attribution?": "Artificial Intelligence",
    "For the memory/RAG index: who can access it, is content sanitized before embedding, and does old material actually expire?": "Artificial Intelligence",
    "What constrains the agent? Are safeguards such as execution budgets, a kill-switch, human approval before high-impact actions, tool isolation, and identity distinction in place?": "Artificial Intelligence",
    "For each MCP server the agent talks to: where did it come from, how is it authenticated, what's the transport, and is input validated against a schema?": "Artificial Intelligence",
    "What hardens the model against adversarial inputs, membership inference, and someone trying to extract it wholesale?": "Artificial Intelligence",
    # Data
    "How are cryptographic keys managed? Is there an inventory, are the algorithms approved, and is data protected while it's in use?": "Data",
    "How is sensitive data classified and what protects it at rest, in transit, and on the client?": "Data",
    # Detection
    "What gets logged and what happens when something fails? Does the error message leak anything it shouldn't?": "Detection",
    "What's watching the model itself? Is there anomaly detection, do jailbreak or injection attempts trigger alerts, is it drift detected, and is there a lifecycle audit trail?": "Detection",
    # Response
    "If this asset gets compromised, what's the plan for containment and credential rotation, and has any of it been tested rather than just written down? What's the reporting timeline?": "Response",
    # Recovery
    "What backs this up, what's the RTO/RPO, and has a restore actually been tested? If any part of this is vendor-hosted or SaaS, how are independent exports handled?": "Recovery",
}

TAG_LINE_RE = re.compile(r"^\s*-\s*(\S+)\s*(?:#\s*(.*))?$")
RISK_LIB_DOMAIN_BANNER_RE = re.compile(r"^\s*#\s*DOMAIN\s+\d+:\s*(.+?)\s*$")
RISK_LIB_ENTRY_ID_RE = re.compile(r"^\s*id:\s*(\S+)\s*$")
SVS_ROW_RE = re.compile(r"^([\w.]+)\s*\|\s*(.+?)\s*\|\s*([123])$")


def load_model(model_path: str) -> dict:
    with open(model_path, encoding="utf-8") as f:
        return yaml.safe_load(f)


def load_risks_json(output_dir: str) -> list:
    with open(os.path.join(output_dir, "risks.json"), encoding="utf-8") as f:
        return json.load(f)


def load_raa_by_id(output_dir: str) -> dict:
    """Returns {asset_id: RAA} -- Relative Attacker Attractiveness, a score
    Threagile computes per asset (not present in the model YAML we author,
    only in its own analysis output) that its rule engine also feeds into
    several risk categories' own likelihood scoring."""
    with open(os.path.join(output_dir, "technical-assets.json"), encoding="utf-8") as f:
        data = json.load(f)
    return {aid: a["RAA"] for aid, a in data.items()}


def load_risks_xlsx(output_dir: str) -> dict:
    """Returns {synthetic_id: {'action': ..., 'mitigation': ..., 'cwe': ...,
    'risk_category_title': ..., 'justification': ..., 'checked_by': ...,
    'closed_date': ..., 'ticket': ...}} keyed by the xlsx 'ID' column, which
    is the same [category]@[asset] string as risks.json's synthetic_id."""
    # read_only=True would stream off the workbook's declared XML <dimension>,
    # which Threagile's xlsx writer leaves stale (reports A1:A1 on a real
    # A1:T152 sheet) -- load normally so openpyxl scans actual cells instead.
    wb = openpyxl.load_workbook(os.path.join(output_dir, "risks.xlsx"))
    ws = wb.worksheets[0]
    rows = ws.iter_rows(values_only=True)
    headers = next(rows)
    by_id = {}
    for row in rows:
        d = dict(zip(headers, row))
        rid = d.get("ID")
        if not rid:
            continue
        by_id[rid] = {
            # Threagile's own xlsx export already strips the <b>/<i> markup
            # its risks.json title/mitigation text embeds (meant for its own
            # PDF renderer) -- prefer this title over risks.json's tagged one.
            "title": d.get("Identified Risk") or "",
            "action": d.get("Action") or "",
            "mitigation": d.get("Mitigation") or "",
            "cwe": d.get("CWE") or "",
            "stride": d.get("STRIDE") or "",
            "function": d.get("Function") or "",
            "risk_category_title": d.get("Risk Category") or "",
            "justification": d.get("Justification") or "",
            "checked_by": d.get("Checked by") or "",
            "closed_date": d.get("Date") or "",
            "ticket": d.get("Ticket") or "",
        }
    return by_id


def load_custom_risk_defs() -> dict:
    """Returns {category_id: definition_dict} for our own custom risks, keyed
    by the same id used in synthetic_id/category (not the human title the
    library file itself is keyed by)."""
    path = LIBRARIES_DIR / "09-custom-risks-lib.yml"
    with open(path, encoding="utf-8") as f:
        lib = yaml.safe_load(f)["custom_risk_definitions"]
    return {entry["id"]: entry for entry in lib.values()}


def load_builtin_risk_defs() -> dict:
    """Returns {category_id: definition_dict} for Threagile's own built-in
    risk categories, sourced from 10-threagile-builtin-risks-lib.yml (see
    that file's header for provenance -- it's Threagile's own upstream
    text, not ours, extracted once from the pinned Docker image rather
    than hand-authored). Distinct file from 09-custom-risks-lib.yml since
    this content isn't ours to maintain the way our own risk definitions
    are, but merged into the same enrichment lookup at the call site so
    the template doesn't need to care which source a given category's
    enrichment came from. Covers only the ~32 built-ins that actually
    fired somewhere across our real models plus Threagile's own example
    model -- a built-in category with no entry here (never fired
    anywhere, or a pure model-failure category) simply has no enrichment,
    same as every built-in category before this file existed."""
    path = LIBRARIES_DIR / "10-threagile-builtin-risks-lib.yml"
    if not path.exists():
        return {}
    with open(path, encoding="utf-8") as f:
        lib = yaml.safe_load(f)["builtin_risks"]
    return lib


def load_custom_risk_domains() -> dict:
    """Returns {category_id: domain_name} derived from 09-custom-risks-lib.yml's
    own `# DOMAIN N: NAME` banner comments (see that file's header) --
    yaml.safe_load discards comments, so this walks the raw lines instead,
    tracking the current domain and pairing it with each entry's `id:` field
    as it's encountered, the same technique load_tag_descriptions() below
    uses for 03-tags-lib.yml's trailing tag-meaning comments."""
    # The banner text itself is ALL CAPS in the file (e.g. "DOMAIN 1:
    # IDENTITY AND ACCESS") -- normalize against DOMAIN_ORDER's canonical
    # Title Case spelling so the two agree; a banner name DOMAIN_ORDER
    # doesn't recognize (the file added a domain this map wasn't updated
    # for) is kept verbatim rather than silently dropped, so it's still
    # visible in the rendered report instead of vanishing into the
    # fallback bucket.
    canonical_by_upper = {name.upper(): name for name in DOMAIN_ORDER}

    path = LIBRARIES_DIR / "09-custom-risks-lib.yml"
    domains = {}
    current_domain = None
    with open(path, encoding="utf-8") as f:
        for line in f:
            m = RISK_LIB_DOMAIN_BANNER_RE.match(line)
            if m:
                raw = m.group(1)
                current_domain = canonical_by_upper.get(raw.upper(), raw)
                continue
            m = RISK_LIB_ENTRY_ID_RE.match(line)
            if m and current_domain:
                domains[m.group(1)] = current_domain
    return domains


def resolve_domain(category_id: str, custom_domains: dict) -> str:
    return custom_domains.get(category_id) \
        or THREAGILE_BUILTIN_DOMAIN_MAP.get(category_id) \
        or FALLBACK_DOMAIN


def load_tag_descriptions() -> dict:
    """03-tags-lib.yml documents each tag's meaning as a trailing YAML
    comment, e.g. `- zone:dmz  # Internet-facing...`, which yaml.safe_load
    discards -- parse the raw lines instead."""
    path = LIBRARIES_DIR / "03-tags-lib.yml"
    descriptions = {}
    with open(path, encoding="utf-8") as f:
        for line in f:
            m = TAG_LINE_RE.match(line)
            if m:
                descriptions[m.group(1)] = (m.group(2) or "").strip()
    return descriptions


def merge_findings(risks_json: list, xlsx_by_id: dict, assets_by_id: dict,
                    boundary_by_id: dict = None, runtime_by_id: dict = None,
                    data_assets_by_id: dict = None) -> list:
    boundary_by_id = boundary_by_id or {}
    runtime_by_id = runtime_by_id or {}
    data_assets_by_id = data_assets_by_id or {}
    merged = []
    for r in risks_json:
        extra = xlsx_by_id.get(r["synthetic_id"], {})
        asset_id = r.get("most_relevant_technical_asset") or ""

        # Most findings are about a specific technical asset, but a handful
        # of Threagile's own rules (missing-cloud-hardening chief among
        # them) score a trust boundary or shared runtime instead -- e.g.
        # "Azure Global Tenant Services" isn't a technical asset in this
        # model, it's a boundary. Falling through the other most_relevant_*
        # fields Threagile itself populates means the Asset column always
        # shows the actual subject instead of an em dash for the ~4-5% of
        # findings (confirmed against real runs) this affects.
        if asset_id:
            subject = assets_by_id.get(asset_id, asset_id)
        elif r.get("most_relevant_trust_boundary"):
            bid = r["most_relevant_trust_boundary"]
            subject = boundary_by_id.get(bid, bid)
        elif r.get("most_relevant_shared_runtime"):
            rtid = r["most_relevant_shared_runtime"]
            subject = runtime_by_id.get(rtid, rtid)
        elif r.get("most_relevant_data_asset"):
            did = r["most_relevant_data_asset"]
            subject = data_assets_by_id.get(did, did)
        elif r.get("most_relevant_communication_link"):
            # Already a descriptive string, not an id -- no lookup needed.
            subject = r["most_relevant_communication_link"]
        else:
            subject = ""

        merged.append({
            **r,
            **extra,
            "title": extra.get("title") or r["title"],
            "most_relevant_technical_asset": subject,
        })
    return merged


# Fields checked for cross-finding uniformity within a category (see
# _shared_fields below) -- everything a category's "Identified Risks by
# Vulnerability Category" block would otherwise restate per finding, other
# than the asset identity itself (the whole point of the per-asset table)
# and the free-text title (which often embeds asset-specific detail, e.g.
# "... covering communication link X from Y to Z", so collapsing it would
# lose real information rather than just redundant boilerplate).
#
# These describe the vulnerability class itself -- confirmed empirically
# (see the commit history) to be identical across every finding in a
# category, 100% of the time, for every category checked so far, both
# custom and built-in. Severity/likelihood/impact/status are deliberately
# NOT included here even though they're often also uniform for our own
# custom categories (a flat severity per tag trigger, not per-asset CIA
# math): those stay broken out per asset in the collapsed rendering's
# table regardless, rather than switching to a flat text list on the
# categories where they happen to match everywhere too -- a deliberate
# visual-consistency choice so every collapsed category has the same
# shape, at the cost of a few more (but still compact) rows on categories
# whose scoring happens to be identical throughout.
NARRATIVE_FIELDS = ("stride", "function", "cwe", "action", "mitigation")


def _shared_fields(items: list, fields: tuple) -> dict | None:
    """Returns the shared values for `fields` if every finding in this
    category agrees on all of them, else None. Trivially true for a
    single-finding category (nothing to disagree with) -- that's
    deliberate, not a special case: it routes a single-finding category
    through the same collapsed rendering as every other category, just
    with a one-row table, rather than a structurally different fallback
    block, so the whole section has one consistent shape throughout."""
    first = {k: items[0].get(k) for k in fields}
    for it in items[1:]:
        if {k: it.get(k) for k in fields} != first:
            return None
    return first


def group_by_category(findings: list, custom_defs: dict, custom_domains: dict) -> list:
    by_category = {}
    for f in findings:
        by_category.setdefault(f["category"], []).append(f)

    def severity_rank(f):
        return SEVERITY_ORDER.index(f["severity"]) if f["severity"] in SEVERITY_ORDER else len(SEVERITY_ORDER)

    categories = []
    for slug, items in by_category.items():
        items.sort(key=lambda f: (severity_rank(f), f["title"]))
        title = items[0].get("risk_category_title") or slug
        categories.append({
            "slug": slug,
            "title": title,
            "findings": items,
            "enrichment": custom_defs.get(slug),
            "domain": resolve_domain(slug, custom_domains),
            "shared": _shared_fields(items, NARRATIVE_FIELDS),
        })
    categories.sort(key=lambda c: c["title"])
    return categories


def group_by_domain(categories: list) -> list:
    """Buckets an already-flat group_by_category() list into DOMAIN_ORDER-
    sequenced groups for the report's domain-organized presentation --
    additive, not a replacement: callers keep using the flat list (TOC
    entries, `| length` counts) exactly as before, and pass this alongside
    it only where the template renders domain headings."""
    order_index = {name: i for i, name in enumerate(DOMAIN_ORDER)}

    def domain_rank(name):
        return order_index.get(name, len(DOMAIN_ORDER))

    buckets = {}
    for c in categories:
        buckets.setdefault(c["domain"], []).append(c)

    groups = []
    for domain in sorted(buckets, key=domain_rank):
        cats = sorted(buckets[domain], key=lambda c: c["title"])
        groups.append({
            "domain": domain,
            "slug": re.sub(r"[^a-z0-9]+", "-", domain.lower()).strip("-"),
            "categories": cats,
        })
    return groups


def group_svs_entries_by_domain(entries: list, title_key: str = "title",
                                 domain_map: dict = SVS_REQUIREMENT_DOMAIN_MAP) -> list:
    """Same DOMAIN_ORDER-sequenced bucketing as group_by_domain(), for the
    Security Requirements and Abuse Cases sections -- but does NOT re-sort
    entries within a domain the way group_by_domain() alphabetizes
    `categories`. These entries are ASVS/AISVS-subsection-ordered or NIST-
    control-ordered on input (see build_context()'s own file-order comment),
    and alphabetizing a string like "V10.1" before "V2.3" would scramble
    that back into the exact bug this ordering was built to avoid.

    domain_map defaults to SVS_REQUIREMENT_DOMAIN_MAP (Abuse Cases/Security
    Requirements); Open Questions passes QUESTION_DOMAIN_MAP instead -- a
    different title universe, so a different lookup table, not a different
    function."""
    order_index = {name: i for i, name in enumerate(DOMAIN_ORDER)}

    def domain_rank(name):
        return order_index.get(name, len(DOMAIN_ORDER))

    buckets = {}
    for e in entries:
        title = e[title_key] if isinstance(e, dict) else e[0]
        domain = domain_map.get(title, FALLBACK_DOMAIN)
        buckets.setdefault(domain, []).append(e)

    groups = []
    for domain in sorted(buckets, key=domain_rank):
        groups.append({
            "domain": domain,
            "slug": re.sub(r"[^a-z0-9]+", "-", domain.lower()).strip("-"),
            "entries": buckets[domain],
        })
    return groups


def build_trust_boundary_tree(trust_boundaries: dict, assets_by_id: dict) -> list:
    if not trust_boundaries:
        return []
    by_id = {}
    for title, node in trust_boundaries.items():
        by_id[node["id"]] = {**node, "title": title}

    child_ids = set()
    for node in by_id.values():
        child_ids.update(node.get("trust_boundaries_nested") or [])

    def resolve(node_id):
        node = by_id[node_id]
        return {
            "title": node["title"],
            "type": node.get("type", ""),
            "description": node.get("description", ""),
            "tags": node.get("tags") or [],
            "assets": [assets_by_id.get(a, a) for a in (node.get("technical_assets_inside") or [])],
            "children": [resolve(c) for c in (node.get("trust_boundaries_nested") or [])],
        }

    roots = [node_id for node_id in by_id if node_id not in child_ids]
    return [resolve(r) for r in sorted(roots, key=lambda i: by_id[i]["title"])]


_VPC_ICON_TAGS = {"icon:aws-vpc", "icon:azure-vnet"}


def compute_vpc_by_asset_id(trust_boundaries: dict) -> dict:
    """Maps each technical asset id to the id of its nearest enclosing
    VPC/VNet trust boundary (identified the same way the diagram already
    does -- an icon:aws-vpc/icon:azure-vnet tag, see 03-tags-lib.yml's
    "DIAGRAM ICON TAGS"), or None if it isn't inside one at all (e.g. an
    external entity, or an AWS/Azure-managed service that sits directly
    under a non-VPC boundary like "AWS PaaS Services"). Used by
    classify_edge()'s Network Path fallback: a link crosses that boundary
    -- and only that one, not every trust-boundary nesting level -- when
    its two endpoints resolve to different VPC ids (None counts as its own
    distinct "no VPC" bucket, so a link from an external entity into a VPC
    still correctly counts as crossing)."""
    if not trust_boundaries:
        return {}

    by_id = {node["id"]: node for node in trust_boundaries.values()}
    parent_of = {}
    for bid, node in by_id.items():
        for child_id in (node.get("trust_boundaries_nested") or []):
            parent_of[child_id] = bid

    def nearest_vpc(bid):
        while bid is not None:
            tags = by_id.get(bid, {}).get("tags") or []
            if _VPC_ICON_TAGS & set(tags):
                return bid
            bid = parent_of.get(bid)
        return None

    vpc_by_asset_id = {}
    for bid, node in by_id.items():
        vpc = nearest_vpc(bid)
        for asset_id in (node.get("technical_assets_inside") or []):
            vpc_by_asset_id[asset_id] = vpc
    return vpc_by_asset_id


def build_shared_runtimes(shared_runtimes: dict, assets_by_id: dict) -> list:
    result = []
    for title, node in (shared_runtimes or {}).items():
        result.append({
            "title": title,
            "description": node.get("description", ""),
            "tags": node.get("tags") or [],
            "assets": [assets_by_id.get(a, a) for a in (node.get("technical_assets_running") or [])],
        })
    result.sort(key=lambda r: r["title"])
    return result


def render_diagram_svg(gv_path: str, title: str, confidentiality_by_label: dict = None,
                        icon_by_label: dict = None, print_size_in: tuple = (6.8, 8.0),
                        vpc_by_label: dict = None,
                        devops_link_pairs: set = None,
                        path_tags_by_pair: dict = None) -> str:
    """Renders the restyled diagram for report embedding, and also writes it
    out as standalone .svg/.html files next to the .gv source -- the report
    only ever shows this diagram at page size, so anyone wanting to actually
    inspect it (zoom, pan, view outside the PDF) needs a file of their own."""
    with open(gv_path, encoding="utf-8") as f:
        dot_source = f.read()

    # Two separate renders, not one reused for both: the PDF-bound copy
    # (returned below) needs for_print=True so any icon WeasyPrint can't
    # render correctly (see threagile_dfd_to_html.py's
    # _icon_needs_print_raster) gets swapped for a rasterized PNG; the
    # standalone .svg file keeps the original vendored SVG throughout,
    # since browsers render it correctly as-is and it's the one place a
    # reader can zoom in on the actual vector art.
    svg_for_pdf = dfd.build_svg(dot_source, title=title, print_size_in=print_size_in,
                                 confidentiality_by_label=confidentiality_by_label,
                                 icon_by_label=icon_by_label,
                                 vpc_by_label=vpc_by_label,
                                 devops_link_pairs=devops_link_pairs,
                                 path_tags_by_pair=path_tags_by_pair,
                                 for_print=True)
    svg_for_file = dfd.build_svg(dot_source, title=title, print_size_in=print_size_in,
                                  confidentiality_by_label=confidentiality_by_label,
                                  icon_by_label=icon_by_label,
                                  vpc_by_label=vpc_by_label,
                                  devops_link_pairs=devops_link_pairs,
                                  path_tags_by_pair=path_tags_by_pair)

    base = os.path.splitext(gv_path)[0]
    with open(base + ".svg", "w", encoding="utf-8") as f:
        f.write(svg_for_file)
    with open(base + ".html", "w", encoding="utf-8") as f:
        f.write(dfd.build_html(dot_source, title=title,
                                confidentiality_by_label=confidentiality_by_label,
                                icon_by_label=icon_by_label,
                                vpc_by_label=vpc_by_label,
                                devops_link_pairs=devops_link_pairs,
                                path_tags_by_pair=path_tags_by_pair))

    # Threagile's own container renders this same diagram as a .png before
    # we ever see the .gv (it needs one for its own native report) -- now
    # fully superseded by the .svg/.html above (smaller, vector, our own
    # styling), so drop it rather than ship dead weight. It's the single
    # largest file pair in the output dir (~1-2MB each vs ~50-70KB per svg).
    png_path = base + ".png"
    if os.path.exists(png_path):
        os.remove(png_path)

    return svg_for_pdf


def parse_svs_rows(text: str) -> list | None:
    """security_requirements sourced from ASVS/AISVS (02-abuse-and-reqs-lib.yml)
    store each subsection's numbered requirements as `<# > | <description> |
    <Level>` rows, one per line, inside a single literal-block string --
    matching the standard's own table layout (#, Description, Level) so the
    template can render it as an actual table. Returns None for a
    hand-authored entry not in this shape (a plain prose paragraph, or an
    app fragment not yet re-copied from the ASVS/AISVS-sourced library),
    which the template then falls back to rendering as-is."""
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    if not lines:
        return None
    rows = []
    for line in lines:
        m = SVS_ROW_RE.match(line)
        if not m:
            return None
        rows.append({"num": m.group(1), "description": m.group(2), "level": m.group(3)})
    return rows


def build_context(model: dict, output_dir: str) -> dict:
    risks_json = load_risks_json(output_dir)
    xlsx_by_id = load_risks_xlsx(output_dir)
    custom_defs = {**load_custom_risk_defs(), **load_builtin_risk_defs()}
    custom_domains = load_custom_risk_domains()
    tag_descriptions = load_tag_descriptions()

    technical_assets = model.get("technical_assets") or {}
    data_assets = model.get("data_assets") or {}
    assets_by_id = {node["id"]: title for title, node in technical_assets.items()}
    boundary_by_id = {node["id"]: title for title, node in (model.get("trust_boundaries") or {}).items()}
    runtime_by_id = {node["id"]: title for title, node in (model.get("shared_runtimes") or {}).items()}
    data_assets_by_id = {node["id"]: title for title, node in data_assets.items()}

    # Confidentiality-level fill for the data-asset diagram (its stand-in for
    # the data-flow diagram's boundary-type shading, since it has no trust
    # boundaries of its own) -- keyed by title, since that's what ends up as
    # the rendered node label in both diagrams. Data assets and technical
    # assets share the same confidentiality enum and don't usually collide
    # by name -- warn rather than fail if they ever do, since the only
    # consequence is one node's diagram color being wrong (whichever of the
    # two the dict-merge below overwrites), not a wrong finding.
    shared_titles = set(technical_assets) & set(data_assets)
    if shared_titles:
        print(f"WARNING: technical_assets and data_assets share title(s) {sorted(shared_titles)} -- "
              f"the data-asset diagram's confidentiality shading will silently use whichever one's "
              f"listed last for each shared title.")

    confidentiality_by_label = {
        title: node.get("confidentiality")
        for title, node in {**technical_assets, **data_assets}.items()
    }

    # Icon selection for the data-flow diagram's nodes and trust boundaries
    # (see 03-tags-lib.yml's "DIAGRAM ICON TAGS") -- a dedicated icon: tag
    # namespace rather than technology/boundary type, since those tags carry
    # no ambiguity (unlike an asset's other, often-multiple, security tags).
    # Trust boundaries carry tags too (00-threagile-field-reference.yml), so
    # this covers both technical_assets and trust_boundaries from one loop.
    # A technical asset can carry more than one icon: tag (e.g. an ALB
    # tagged both icon:aws-waf and icon:aws-alb renders both side by side,
    # see render_node) -- collected here in tag order; a trust boundary's
    # corner badge only ever uses the first (see build_svg).
    icon_by_label = {}
    for title, node in {**technical_assets, **(model.get("trust_boundaries") or {})}.items():
        for t in (node.get("tags") or []):
            if t.startswith("icon:"):
                icon_by_label.setdefault(title, []).append(t.split(":", 1)[1])

    # Feeds the standalone HTML diagrams' filter-links bar (see
    # threagile_dfd_to_html.py's classify_edge()): Threagile's own `usage`
    # enum on a communication_link is only business/devops, so it cleanly
    # covers Mission Flows/Log-Telemetry; Network Path is inferred
    # structurally instead (see compute_vpc_by_asset_id): a link crosses
    # between two different VPC/VNet trust boundaries. Identity Path has
    # no equivalent structural signal, so it's never inferred -- it only
    # ever comes from an explicit path:identity tag (see path_tags_by_pair
    # below); an untagged identity link shows up as mission/network
    # instead, which is a more honest failure mode than guessing from
    # something like endpoint `technology` and sometimes being wrong.
    vpc_by_asset_id = compute_vpc_by_asset_id(model.get("trust_boundaries") or {})
    vpc_by_label = {
        title: vpc_by_asset_id.get(node["id"]) for title, node in technical_assets.items()
    }
    devops_link_pairs = {
        (title, assets_by_id[link["target"]])
        for title, node in technical_assets.items()
        for link in (node.get("communication_links") or {}).values()
        if link.get("usage") == "devops" and link.get("target") in assets_by_id
    }

    # Explicit path:<category> tag(s) on a communication_link itself (see
    # 03-tags-lib.yml's "COMMUNICATION LINK PATH-FILTER TAGS") -- takes
    # priority over both devops_link_pairs and the vpc_by_label guess in
    # classify_edge(), since this is authored intent rather than an
    # inference from unrelated fields. A link can carry more than one
    # (e.g. a shared perimeter hop that carries both authentication and
    # ordinary chat traffic is both Identity Path and Network Path), so
    # each pair maps to a set.
    path_tags_by_pair = {}
    for title, node in technical_assets.items():
        for link in (node.get("communication_links") or {}).values():
            if link.get("target") not in assets_by_id:
                continue
            for t in (link.get("tags") or []):
                if t.startswith("path:"):
                    key = (title, assets_by_id[link["target"]])
                    path_tags_by_pair.setdefault(key, set()).add(t.split(":", 1)[1])

    # classify_edge() (see threagile_dfd_to_html.py) looks up an edge's
    # filter-bar category by (tail_label, head_label) alone -- it has no way
    # to tell two distinct communication_links between the same asset pair
    # apart, so path_tags_by_pair/devops_link_pairs above would silently
    # blend both links' tags onto both edges in that case. Never happened
    # on a real app model as of this writing -- warn rather than fail,
    # since the only consequence is the standalone HTML diagrams' filter
    # bar mis-classifying one of the edges, not a wrong finding.
    seen_pairs = {}
    for title, node in technical_assets.items():
        for link_name, link in (node.get("communication_links") or {}).items():
            target = link.get("target")
            if target not in assets_by_id:
                continue
            pair = (title, assets_by_id[target])
            seen_pairs.setdefault(pair, []).append(link_name)
    duplicate_pairs = {pair: names for pair, names in seen_pairs.items() if len(names) > 1}
    if duplicate_pairs:
        for (source, target), names in duplicate_pairs.items():
            print(f"WARNING: {source} has {len(names)} separate communication_links to {target} "
                  f"({', '.join(names)}) -- the filter-links bar can't tell them apart and will "
                  f"blend their path:/usage tags onto both edges.")

    all_findings = merge_findings(risks_json, xlsx_by_id, assets_by_id,
                                   boundary_by_id, runtime_by_id, data_assets_by_id)
    findings = [f for f in all_findings if f["category"] not in MODEL_FAILURE_CATEGORY_IDS]
    model_failure_findings = [f for f in all_findings if f["category"] in MODEL_FAILURE_CATEGORY_IDS]
    remaining_findings = [f for f in findings
                           if f["risk_status"] not in CLOSED_STATUSES
                           and f["risk_status"] not in ACCEPTED_STATUSES]
    accepted_findings = [f for f in findings if f["risk_status"] in ACCEPTED_STATUSES]
    closed_findings = [f for f in findings if f["risk_status"] in CLOSED_STATUSES]

    all_categories = group_by_category(findings, custom_defs, custom_domains)
    remaining_categories = group_by_category(remaining_findings, custom_defs, custom_domains)
    accepted_categories = group_by_category(accepted_findings, custom_defs, custom_domains)
    closed_categories = group_by_category(closed_findings, custom_defs, custom_domains)
    model_failure_categories = group_by_category(model_failure_findings, custom_defs, custom_domains)

    # Domain-organized presentation, additive alongside the flat lists above
    # (see group_by_domain()'s docstring) -- not built for model failures,
    # which are model-authoring problems, not security domains.
    all_domain_groups = group_by_domain(all_categories)
    remaining_domain_groups = group_by_domain(remaining_categories)
    accepted_domain_groups = group_by_domain(accepted_categories)
    closed_domain_groups = group_by_domain(closed_categories)

    raa_by_id = load_raa_by_id(output_dir)
    asset_list = sorted(
        ({**node, "title": title, "raa": raa_by_id.get(node["id"])}
         for title, node in technical_assets.items()),
        key=lambda a: a["title"],
    )
    out_of_scope_assets = [a for a in asset_list if a.get("out_of_scope")]

    data_asset_list = sorted(
        ({**node, "title": title} for title, node in (model.get("data_assets") or {}).items()),
        key=lambda a: a["title"],
    )

    # tags_available lets tags land on technical_assets, communication_links,
    # trust_boundaries, shared_runtimes, and data_assets (00-threagile-field-
    # reference.yml) -- counting only technical_assets would wrongly zero out
    # tags that only ever appear on a boundary (e.g. mgmt:csp-managed).
    tag_usage = {}

    def _count_tags(node):
        for t in (node.get("tags") or []):
            tag_usage[t] = tag_usage.get(t, 0) + 1

    for a in technical_assets.values():
        _count_tags(a)
        for link in (a.get("communication_links") or {}).values():
            _count_tags(link)
    for b in (model.get("trust_boundaries") or {}).values():
        _count_tags(b)
    for rt in (model.get("shared_runtimes") or {}).values():
        _count_tags(rt)
    for da in (model.get("data_assets") or {}).values():
        _count_tags(da)

    tags = [
        {"name": t, "description": tag_descriptions.get(t, ""), "usage_count": tag_usage.get(t, 0)}
        for t in sorted(model.get("tags_available") or [])
        if tag_usage.get(t, 0) > 0
    ]

    with open(os.path.join(output_dir, "stats.json"), encoding="utf-8") as f:
        stats = json.load(f)

    security_requirements = [
        {"title": title, "text": text, "rows": parse_svs_rows(text)}
        for title, text in (model.get("security_requirements") or {}).items()
    ]
    abuse_cases = list((model.get("abuse_cases") or {}).items())

    return {
        "title": model.get("title", ""),
        "date": model.get("date"),
        "author": model.get("author") or {},
        "business_criticality": model.get("business_criticality", ""),
        "management_summary_comment": model.get("management_summary_comment", ""),
        "business_overview": model.get("business_overview") or {},
        "technical_overview": model.get("technical_overview") or {},
        "stats": stats.get("risks", {}),
        "severity_order": SEVERITY_ORDER,
        "total_finding_count": len(findings),
        "remaining_finding_count": len(remaining_findings),
        "accepted_finding_count": len(accepted_findings),
        "closed_finding_count": len(closed_findings),
        "all_categories": all_categories,
        "remaining_categories": remaining_categories,
        "accepted_categories": accepted_categories,
        "closed_categories": closed_categories,
        "model_failure_categories": model_failure_categories,
        "all_domain_groups": all_domain_groups,
        "remaining_domain_groups": remaining_domain_groups,
        "accepted_domain_groups": accepted_domain_groups,
        "closed_domain_groups": closed_domain_groups,
        # File order, not sorted() -- ASVS/AISVS-sourced titles are numeric
        # (V1.1, V10.1, V2.3, ...) and a plain alphabetical sort scrambles
        # that (V10 before V2), whereas 02-abuse-and-reqs-lib.yml's own file
        # order is already chapter-ascending; an app author copy-pasting
        # from it preserves that order into their own fragment.
        "security_requirements": security_requirements,
        "security_requirement_domain_groups": group_svs_entries_by_domain(
            security_requirements, title_key="title"),
        "abuse_cases": abuse_cases,
        "abuse_case_domain_groups": group_svs_entries_by_domain(abuse_cases),
        "questions": sorted((model.get("questions") or {}).items()),
        "question_domain_groups": group_svs_entries_by_domain(
            sorted((model.get("questions") or {}).items()),
            domain_map=QUESTION_DOMAIN_MAP),
        "tags": tags,
        "trust_boundary_tree": build_trust_boundary_tree(model.get("trust_boundaries") or {}, assets_by_id),
        "shared_runtimes": build_shared_runtimes(model.get("shared_runtimes") or {}, assets_by_id),
        "technical_assets": asset_list,
        "out_of_scope_assets": out_of_scope_assets,
        "data_assets": data_asset_list,
        "data_flow_diagram": render_diagram_svg(
            os.path.join(output_dir, "data-flow-diagram.gv"), "Data-Flow Diagram",
            icon_by_label=icon_by_label,
            vpc_by_label=vpc_by_label,
            devops_link_pairs=devops_link_pairs,
            path_tags_by_pair=path_tags_by_pair,
        ),
        "data_asset_diagram": render_diagram_svg(
            os.path.join(output_dir, "data-asset-diagram.gv"), "Data Asset Diagram",
            confidentiality_by_label=confidentiality_by_label,
            icon_by_label=icon_by_label,
            vpc_by_label=vpc_by_label,
            devops_link_pairs=devops_link_pairs,
            path_tags_by_pair=path_tags_by_pair,
            # This diagram is reliably tall-and-narrow (a long column of data
            # assets crossed against a long column of technical assets), so
            # it's height-bound against print_size_in almost every time --
            # it never shares a page with the section's heading/intro text
            # (too big to fit below them), always landing on its own full
            # page. That page's usable content height is 9.0in (11in letter
            # minus 1in top+bottom margins -- see @page in report.css); 8.7in
            # leaves a small buffer rather than using the theoretical max.
            print_size_in=(6.8, 8.7),
        ),
    }


def run_self_checks(context: dict, risks_json_count: int) -> bool:
    """Cross-checks the data this report is about to render against the
    structured output it was built from. Returns False (after printing why)
    on any mismatch -- the caller must treat that as fatal, not merely
    logged: a wrong report that renders and ships anyway is the actual
    failure mode this exists to catch, and a mismatch here means either a
    bug in build_context()'s merge/grouping logic or a Threagile output
    file this script didn't fully account for. Either way, better to fail
    the run than publish a report making claims risks.json/stats.json
    don't back up."""
    ok = True
    model_failure_count = sum(len(c["findings"]) for c in context["model_failure_categories"])
    rendered_count = sum(len(c["findings"]) for c in context["all_categories"]) + model_failure_count
    if rendered_count != risks_json_count:
        print(f"ERROR: rendered {rendered_count} findings but risks.json has {risks_json_count}")
        ok = False

    stats = context["stats"]
    stats_total = sum(sum(by_status.values()) for by_status in stats.values())
    combined_total = context["total_finding_count"] + model_failure_count
    if stats_total != combined_total:
        print(f"ERROR: stats.json totals {stats_total} findings but merged findings list has "
              f"{combined_total}")
        ok = False

    split_total = (context["remaining_finding_count"] + context["accepted_finding_count"]
                   + context["closed_finding_count"])
    if split_total != context["total_finding_count"]:
        print(f"ERROR: open ({context['remaining_finding_count']}) + accepted "
              f"({context['accepted_finding_count']}) + closed ({context['closed_finding_count']}) = "
              f"{split_total}, but total_finding_count is {context['total_finding_count']}")
        ok = False

    return ok


def render(context: dict, output_path: str) -> None:
    env = Environment(loader=FileSystemLoader(str(TEMPLATES_DIR)), autoescape=True)
    template = env.get_template("report.html.jinja")
    html_string = template.render(**context)

    out_dir = os.path.dirname(os.path.abspath(output_path)) or "."
    fd, tmp_path = tempfile.mkstemp(dir=out_dir, suffix=".pdf")
    os.close(fd)
    try:
        HTML(string=html_string, base_url=str(TEMPLATES_DIR)).write_pdf(
            tmp_path, stylesheets=[str(TEMPLATES_DIR / "report.css")]
        )
        os.replace(tmp_path, output_path)
    except Exception:
        os.remove(tmp_path)
        raise

    categories = len(context["all_categories"])
    findings = context["total_finding_count"]
    print(f"Generated {output_path}: {findings} findings across {categories} categories")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--model", required=True, help="path to the injected model YAML")
    parser.add_argument("--output-dir", required=True,
                         help="Threagile output dir containing risks.json/risks.xlsx/stats.json/diagrams")
    parser.add_argument("-o", "--out", default=None, help="output PDF path (default: <output-dir>/report.pdf)")
    args = parser.parse_args()

    out_path = args.out or os.path.join(args.output_dir, "report.pdf")

    model = load_model(args.model)
    context = build_context(model, args.output_dir)
    if not run_self_checks(context, len(load_risks_json(args.output_dir))):
        sys.exit(1)
    render(context, out_path)


if __name__ == "__main__":
    main()
