"""Builds report.pdf directly from Threagile's structured output, rather than from Threagile's
own rendered PDF. It reads risks.json, risks.xlsx, risk-categories.json, the injected model,
stats.json, and the diagram sources, and renders the content, table of contents, and PDF
bookmarks in one Jinja2 and WeasyPrint pass, so there is one layout engine to keep consistent.

Each finding merges two sources: risks.json for the structured fields (severity, synthetic_id,
status, and most_relevant_*), and risks.xlsx for the Action and Mitigation text. The richer report
text (ASVS, cheat sheet, references) comes from libraries 09 and 10.

The two diagrams are re-rendered by threagile_dfd_to_html.py's build_svg() from the Graphviz
sources that the fork writes with --keep-diagram-source-files (data-flow-diagram.gv and
data-asset-diagram.gv), using this project's shapes and palette rather than Threagile's.

Usage:
  python generate_report.py --model threagile_injected.yml --output-dir threagile/output"""

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
# An accepted risk stays separate from the closed ones: its vulnerability is still present, and
# grouping it with mitigated or false-positive findings would understate residual risk.
CLOSED_STATUSES = {"mitigated", "false-positive"}
ACCEPTED_STATUSES = {"accepted"}

# Threagile's model-authoring checks, which the report lists under Potential Model Failures
# rather than with the vulnerabilities.
MODEL_FAILURE_CATEGORY_IDS = {
    "incomplete-model",
    "unnecessary-communication-link",
    "unnecessary-data-asset",
    "unnecessary-data-transfer",
    "unnecessary-technical-asset",
    "wrong-communication-link-content",
    "wrong-trust-boundary-content",
}

# The focus areas, in report order (09-custom-risks-lib.yml's FOCUS AREA banners). A category
# whose focus area is unknown falls into FALLBACK_DOMAIN, which renders last.
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

# The focus area of each Threagile built-in category. The report cannot read the fork's source,
# so this map is kept by hand, and an unknown id falls back to FALLBACK_DOMAIN.
THREAGILE_BUILTIN_DOMAIN_MAP = {
    "cluster-control-plane-audit-gap": "Detection",
    # Identity
    "missing-authentication": "Identity",
    "missing-authentication-second-factor": "Identity",
    "missing-identity-propagation": "Identity",
    "missing-identity-provider-isolation": "Identity",
    "missing-identity-store": "Identity",
    # Device and Infrastructure
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
    # unnecessary-data-transfer is a model-failure category (see MODEL_FAILURE_CATEGORY_IDS), so it
    # never reaches this map, and something-strange fits no single focus area.
    # "something-strange": ...,
}

# The focus area of each of the fork's script rules (pkg/risks/scripts/*.yaml). The scripts live
# in another repository, so this map is kept by hand, and an id it does not know falls back to
# FALLBACK_DOMAIN. Update it when the fork's scripts change.
THREAGILE_FORK_SCRIPT_DOMAIN_MAP = {
    # Identity
    "certificate-validation-soft-fail": "Identity",
    "insecure-session-management": "Identity",
    # Device and Infrastructure
    "dangerous-container-capabilities": "Device and Infrastructure",
    "endpoint-security-manager-fleet-compromise": "Device and Infrastructure",
    "mutable-container-filesystem": "Device and Infrastructure",
    "missing-endpoint-security-agents": "Device and Infrastructure",
    "space-vehicle-bus-segmentation-gap": "Device and Infrastructure",
    "unhardened-os-missing-patch-management": "Device and Infrastructure",
    "untrusted-container-image": "Device and Infrastructure",
    "vulnerability-scanner-credential-exposure": "Device and Infrastructure",
    # Network and Environment
    "air-ground-station-c2-link-hijack": "Network and Environment",
    "air-vehicle-gps-spoofing": "Network and Environment",
    "cds-data-diode-unidirectionality-gap": "Network and Environment",
    "cds-guard-ruleset-bypass": "Network and Environment",
    "ics-controller-unauthenticated-protocol": "Network and Environment",
    "missing-network-micro-segmentation": "Network and Environment",
    "network-encryptor-common-mode-failure": "Network and Environment",
    "space-ground-station-rogue-uplink": "Network and Environment",
    # Application (incl. supply chain/CI-CD, matching THREAGILE_BUILTIN_DOMAIN_MAP's own grouping)
    "broken-function-level-authorization": "Application",
    "broken-object-level-authorization": "Application",
    "broken-object-property-level-authorization": "Application",
    "cicd-pipeline-tampering-outside-repo": "Application",
    "dependency-confusion-internal-namespace": "Application",
    "malicious-install-script-execution": "Application",
    "mishandling-exceptional-conditions": "Application",
    "os-command-injection": "Application",
    "vulnerable-outdated-dependency": "Application",
    # Artificial Intelligence
    "ai-content-provenance-tampering": "Artificial Intelligence",
    "ai-adversarial-evasion": "Artificial Intelligence",
    "ai-rag-corpus-poisoning": "Artificial Intelligence",
    "ai-security-tooling-compromise": "Artificial Intelligence",
    "ai-supply-chain-compromise": "Artificial Intelligence",
    "ai-training-data-model-poisoning": "Artificial Intelligence",
    "ai-unbounded-consumption": "Artificial Intelligence",
    "ai-agent-identity-privilege-abuse": "Artificial Intelligence",
    "ai-cascading-agent-failures": "Artificial Intelligence",
    "ai-excessive-agency-tool-misuse": "Artificial Intelligence",
    "ai-insecure-inter-agent-communication": "Artificial Intelligence",
    "ai-operational-control-gap": "Artificial Intelligence",
    "ai-retrieval-resilience-gap": "Artificial Intelligence",
    "ai-cross-context-bleed": "Artificial Intelligence",
    "ai-hidden-context-exposure": "Artificial Intelligence",
    "ai-improper-output-handling": "Artificial Intelligence",
    "ai-inference-data-reconstruction": "Artificial Intelligence",
    "ai-model-exfiltration": "Artificial Intelligence",
    "ai-sensitive-information-disclosure": "Artificial Intelligence",
    "ai-synthetic-data-leakage": "Artificial Intelligence",
    "ai-telemetry-prompt-log-leakage": "Artificial Intelligence",
    "ai-unsafe-nl-data-gateway": "Artificial Intelligence",
    "ai-vector-store-exposure": "Artificial Intelligence",
    # Data (incl. secrets/crypto/data lifecycle, matching THREAGILE_BUILTIN_DOMAIN_MAP's own grouping)
    "cui-telemetry-spillage": "Data",
    "hardcoded-credentials-secrets-sprawl": "Data",
    "key-management-separation-of-duties-violation": "Data",
    "key-rotation-escrow-neglect": "Data",
    "key-storage-ownership-hardening-gap": "Data",
    "media-sanitization-procedure-gap": "Data",
    "missing-data-retention-schedule": "Data",
    "multi-tenant-data-isolation": "Data",
    "unscanned-data-store": "Data",
    # Detection
    "data-store-audit-detection-gap": "Detection",
    "insufficient-audit-logging": "Detection",
    "security-control-tamper-resistance-gap": "Detection",
}

# The focus area of each library abuse case and requirement, keyed by exact title, since a few
# control IDs (such as SC-7) appear in more than one focus area. An author's own entry falls back
# to FALLBACK_DOMAIN. Regenerate it from 02-abuse-and-reqs-lib.yml when that file changes.
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
    "ASVS V13.3: Software-Only Key Theft via Host Compromise": "Application",
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

def load_question_library() -> tuple:
    """({question: focus area}, {feature: details}, {question: asked_when}) from
    01-metadata-lib.yml, which the report reads directly so that the questions and the feature
    checklist stay in one place. A question or feature an author writes themselves falls back to
    FALLBACK_DOMAIN. asked_when is None for a question that is always asked, and otherwise a list
    of (feature, option) pairs, any one of which makes the question apply."""
    data = yaml.safe_load((LIBRARIES_DIR / "01-metadata-lib.yml").read_text(encoding="utf-8")) or {}
    questions, features, asked_when = {}, {}, {}
    for block in data.get("categories") or []:
        for entry in block.get("questions") or []:
            questions[entry["question"]] = block["name"]
            when = entry.get("asked_when", "always")
            asked_when[entry["question"]] = None if when == "always" else [
                tuple(part.strip() for part in condition.split(":", 1)) for condition in when]
        for item in block.get("features") or []:
            options = [o if isinstance(o, str) else o["option"] for o in item.get("options") or []]
            option_tags = {(o if isinstance(o, str) else o["option"]): ([] if isinstance(o, str) else list(o.get("tags") or []))
                           for o in item.get("options") or []}
            option_fields = {(o if isinstance(o, str) else o["option"]): ([] if isinstance(o, str) else list(o.get("fields") or []))
                             for o in item.get("options") or []}
            features[item["feature"]] = {"domain": block["name"], "affects": item.get("affects", ""),
                                         "options": options, "option_tags": option_tags, "option_fields": option_fields,
                                         "multiple": item.get("select", "multiple") == "multiple"}
    return questions, features, asked_when


QUESTION_DOMAIN_MAP, FEATURE_INDEX, QUESTION_ASKED_WHEN = load_question_library()
FEATURE_PREFIX = "Feature: "


ANSWER_REQUIRED = "[ANSWER REQUIRED]"


def question_status(questions: dict, checklist: list) -> dict:
    """{focus area: [entry]} for the library questions a model does not answer, in every focus
    area the model covers (one where it answers a question or a checklist item). Each entry has a
    status: "not asked" when none of the question's selections are made, "pending" when it depends
    on a checklist item that is not answered yet, and "missing" when it applies but the model does
    not ask it."""
    selected = {(row["feature"], o["label"]) for row in checklist for o in row["options"] if o["selected"]}
    answered = {row["feature"] for row in checklist if row["answered"]}
    # A focus area applies when the model answers one of its questions or makes any selection in
    # it other than None or No. It is ruled out when its checklist items are answered but every
    # answer is None or No, for example an application that uses no AI.
    covered = {QUESTION_DOMAIN_MAP[q] for q in questions if q in QUESTION_DOMAIN_MAP}
    covered |= {row["domain"] for row in checklist
                if any(o["selected"] and o["label"] not in ("None", "No") for o in row["options"])}
    ruled_out = {row["domain"] for row in checklist if row["answered"]} - covered
    out = {}
    for question, area in QUESTION_DOMAIN_MAP.items():
        if question in questions:
            continue
        if area in ruled_out:
            out.setdefault(area, []).append({"question": question, "status": "not asked",
                                             "reason": f"every checklist item in the {area} focus area is answered None or No"})
            continue
        if area not in covered:
            continue
        when = QUESTION_ASKED_WHEN.get(question)
        if when is None or any(pair in selected for pair in when):
            entry = {"question": question, "status": "missing", "reason": ""}
        else:
            features = list(dict.fromkeys(feature for feature, _ in when))
            open_items = [f for f in features if f not in answered]
            outside = sorted({FEATURE_INDEX[f]["domain"] for f in features if f in FEATURE_INDEX} - covered)
            if outside and all(FEATURE_INDEX.get(f, {}).get("domain") not in covered for f in features):
                entry = {"question": question, "status": "not asked",
                         "reason": f"the {', '.join(outside)} focus area does not apply to this model"}
            elif open_items:
                entry = {"question": question, "status": "pending",
                         "reason": "depends on the unanswered checklist item " + ", ".join(open_items)}
            else:
                options = ", ".join(option for _, option in when)
                entry = {"question": question, "status": "not asked",
                         "reason": f"none of these is selected: {options}"}
        out.setdefault(area, []).append(entry)
    return out


def feature_checklist(questions: dict) -> list:
    """The "Feature: ..." entries of the questions map as checklist rows, in domain order and
    then library order. An answer is the selected options separated by commas, matched to the
    item's options without regard to case, and [ANSWER REQUIRED] marks it as unconfirmed.
    Selections that are not one of the item's options are kept in "unknown" so that the
    self-checks can report them."""
    order = {name: i for i, name in enumerate(DOMAIN_ORDER)}
    library_order = {name: i for i, name in enumerate(FEATURE_INDEX)}
    rows = []
    for key, answer in questions.items():
        if not key.startswith(FEATURE_PREFIX):
            continue
        name = key[len(FEATURE_PREFIX):].strip()
        known = FEATURE_INDEX.get(name, {})
        raw = " ".join(str(answer or "").split())
        confirm = ANSWER_REQUIRED.lower() in raw.lower()
        raw = raw.replace(ANSWER_REQUIRED, "").replace(ANSWER_REQUIRED.lower(), "")
        chosen = [s.strip() for s in raw.split(",") if s.strip()]
        by_lower = {o.lower(): o for o in known.get("options", [])}
        selected = {by_lower[c.lower()] for c in chosen if c.lower() in by_lower}
        rows.append({
            "domain": known.get("domain", FALLBACK_DOMAIN), "feature": name, "affects": known.get("affects", ""),
            "options": [{"label": o, "selected": o in selected} for o in known.get("options", [])],
            "unknown": [c for c in chosen if c.lower() not in by_lower],
            # Tags the selections imply, for a reviewer to check against the model.
            "tags": sorted({tag for o in selected for tag in known.get("option_tags", {}).get(o, [])}),
            "fields": [f for o in known.get("options", []) if o in selected for f in known.get("option_fields", {}).get(o, [])],
            "multiple": known.get("multiple", True), "answered": bool(chosen), "confirm": confirm,
        })
    rows.sort(key=lambda r: (order.get(r["domain"], len(DOMAIN_ORDER)), library_order.get(r["feature"], 10 ** 6)))
    return rows

TAG_LINE_RE = re.compile(r"^\s*-\s*(\S+)\s*(?:#\s*(.*))?$")
RISK_LIB_DOMAIN_BANNER_RE = re.compile(r"^\s*#\s*FOCUS AREA\s+\d+:\s*(.+?)\s*$")
RISK_LIB_ENTRY_ID_RE = re.compile(r"^\s*id:\s*(\S+)\s*$")
SVS_ROW_RE = re.compile(r"^([\w.]+)\s*\|\s*(.+?)\s*\|\s*([123])$")


def load_model(model_path: str) -> dict:
    with open(model_path, encoding="utf-8") as f:
        return yaml.safe_load(f)


def load_risks_json(output_dir: str) -> list:
    with open(os.path.join(output_dir, "risks.json"), encoding="utf-8") as f:
        findings = json.load(f)
    # risks.json omits a field that holds its enum's first value (Go omitempty), so the fields
    # accessed directly below are filled in once here.
    defaults = {
        "risk_status": "unchecked",
        "severity": "low",
        "exploitation_likelihood": "unlikely",
        "exploitation_impact": "low",
    }
    for f in findings:
        for key, default in defaults.items():
            f.setdefault(key, default)
    return findings


def load_raa_by_id(output_dir: str) -> dict:
    """Returns {asset_id: RAA}, the Relative Attacker Attractiveness that Threagile computes for
    each asset in its analysis output (technical-assets.json, under the key "raa")."""
    with open(os.path.join(output_dir, "technical-assets.json"), encoding="utf-8") as f:
        data = json.load(f)
    return {aid: a["raa"] for aid, a in data.items()}


def load_risks_xlsx(output_dir: str) -> dict:
    """Returns {synthetic_id: {'action': ..., 'mitigation': ..., 'cwe': ...,
    'risk_category_title': ..., 'justification': ..., 'checked_by': ...,
    'closed_date': ..., 'ticket': ..., 'communication_link': ...}} keyed by
    the xlsx 'ID' column, which is the same [category]@[asset] string as
    risks.json's synthetic_id."""
    # Not read_only: that mode trusts the workbook's declared dimension, which Threagile's writer
    # leaves stale (A1:A1), so it would read no rows.
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
            # The xlsx title has none of the <b> and <i> markup that risks.json embeds, so it is
            # preferred.
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
            # The xlsx holds the link's title (such as "Log Forwarding"), so the PDF shows the same
            # text as the xlsx.
            "communication_link": d.get("Communication Link") or "",
        }
    return by_id


def mission_criticality_title(model: dict) -> str:
    """The model's mission criticality for display ("Mission Essential"), reading the older
    business_criticality key and values the same way inject_risks.py does."""
    legacy = {"archive": "administrative", "operational": "administrative", "important": "mission-support",
              "critical": "mission-essential", "mission-critical": "mission-critical"}
    value = str(model.get("mission_criticality") or model.get("business_criticality") or "").strip().lower()
    value = value if value in ("administrative", "mission-support", "mission-essential", "mission-critical") \
        else legacy.get(value, value)
    return value.replace("-", " ").title()


def load_risk_categories(output_dir: str) -> dict:
    """Returns {category_id: category_dict} from risk-categories.json, which the jessestarkey/
    threagile fork writes next to risks.json: every category with a finding, from all three
    rule layers, with its finding_class and risk_assessment. Empty when the file is absent (an
    older image), in which case finding classes come from risks.json alone."""
    path = os.path.join(output_dir, "risk-categories.json")
    if not os.path.exists(path):
        return {}
    with open(path, encoding="utf-8") as f:
        return {c["id"]: c for c in json.load(f) if c.get("id")}


# What each finding class means for the reader; the class itself is set per rule in the fork
# (built-in and script rules) and in 09-custom-risks-lib.yml (custom categories). See
# docs/risk-methodology.md, "Risk calibration".
FINDING_CLASS_WEAKNESS = "weakness-shown"
FINDING_CLASS_CONTROL = "control-not-evidenced"
FINDING_CLASS_LABELS = {
    FINDING_CLASS_WEAKNESS: "Model Weakness",
    FINDING_CLASS_CONTROL: "Control Verification",
}


def annotate_finding_classes(categories: list, category_meta: dict) -> None:
    """Adds finding_class / finding_class_label / risk_assessment_if_missing to each category
    from group_by_category(), in place. The class comes from the category's own findings
    (risks.json carries it per finding), falling back to risk-categories.json. The risk
    assessment is the 09/10 library enrichment where one exists, else the rule's own text."""
    for c in categories:
        meta = category_meta.get(c["slug"], {})
        classes = {f.get("finding_class") for f in c["findings"] if f.get("finding_class")}
        c["finding_class"] = classes.pop() if len(classes) == 1 else meta.get("finding_class", "")
        c["finding_class_label"] = FINDING_CLASS_LABELS.get(c["finding_class"], "")
        c["risk_assessment_if_missing"] = ((c.get("enrichment") or {}).get("risk_assessment")
                                           or meta.get("risk_assessment", ""))


def split_by_finding_class(categories: list) -> tuple:
    """(weakness-shown, control-not-evidenced, unclassified) categories, in their given order."""
    weaknesses = [c for c in categories if c["finding_class"] == FINDING_CLASS_WEAKNESS]
    controls = [c for c in categories if c["finding_class"] == FINDING_CLASS_CONTROL]
    unclassified = [c for c in categories if c["finding_class"] not in FINDING_CLASS_LABELS]
    return weaknesses, controls, unclassified


def load_custom_risk_defs() -> dict:
    """Returns {category_id: definition_dict} for our own custom risks, keyed
    by the same id used in synthetic_id/category (not the human title the
    library file itself is keyed by)."""
    path = LIBRARIES_DIR / "09-custom-risks-lib.yml"
    with open(path, encoding="utf-8") as f:
        lib = yaml.safe_load(f)["custom_risk_definitions"]
    return {entry["id"]: entry for entry in lib.values()}


def load_builtin_risk_defs() -> dict:
    """Returns {category_id: definition} for Threagile's built-in categories from
    10-threagile-builtin-risks-lib.yml, which supplies their report text. Action and Mitigation come
    from Threagile's risks.xlsx instead, which takes them from each rule's Go source in the fork. A
    built-in with no entry has no enrichment."""
    path = LIBRARIES_DIR / "10-threagile-builtin-risks-lib.yml"
    if not path.exists():
        return {}
    with open(path, encoding="utf-8") as f:
        lib = yaml.safe_load(f)["builtin_risks"]
    return lib


def load_custom_risk_domains() -> dict:
    """Returns {category_id: focus area} from 09-custom-risks-lib.yml's FOCUS AREA banner
    comments. yaml.safe_load discards comments, so this walks the raw lines, as
    load_tag_descriptions() does for 03-tags-lib.yml."""
    # Banners are upper case, so they are matched against DOMAIN_ORDER's spelling. An unknown
    # banner is kept as written, so it still appears in the report.
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
        or THREAGILE_FORK_SCRIPT_DOMAIN_MAP.get(category_id) \
        or FALLBACK_DOMAIN


def load_tag_descriptions() -> dict:
    """03-tags-lib.yml gives each tag's meaning as a trailing comment (such as
    `- zone:dmz  # Internet-facing...`), which yaml.safe_load discards, so the raw lines are parsed."""
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

        # A few rules (missing-cloud-hardening chief among them) score a trust boundary or shared
        # runtime rather than a technical asset, so the other most_relevant_* fields are tried.
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
            # Already a descriptive string, not an id.
            subject = r["most_relevant_communication_link"]
        else:
            subject = ""

        merged.append({
            **r,
            **extra,
            "title": extra.get("title") or r["title"],
            "most_relevant_technical_asset": subject,
            "communication_link": link_label(r.get("most_relevant_communication_link") or "",
                                             extra.get("communication_link") or "", asset_id, assets_by_id),
        })
    return merged


def link_label(link_id: str, link_title: str, asset_id: str, assets_by_id: dict) -> str:
    """The Communication Link column: the link's title, prefixed with its source
    when the source isn't the row's own asset. Link titles are only unique per
    source, so several sources reaching one target (three components each
    forwarding logs to one workspace) would otherwise print identical rows.
    link_id is risks.json's "<source-id>><link-slug>"."""
    if not link_title:
        return ""
    source_id = link_id.split(">", 1)[0] if ">" in link_id else ""
    if not source_id or source_id == asset_id:
        return link_title
    return f"{assets_by_id.get(source_id, source_id)} → {link_title}"


# The fields that describe a category's vulnerability class, which the report shows once when
# every finding in the category agrees on them. The title is left out, since it often names the
# asset, and severity, likelihood, impact, and status stay per asset in the table, so that every
# category has the same shape.
NARRATIVE_FIELDS = ("stride", "function", "cwe", "action", "mitigation")


def _shared_fields(items: list, fields: tuple) -> dict | None:
    """Returns the shared values for `fields` if every finding in the category agrees on them,
    else None. A single-finding category always agrees, so it renders in the same shape as every
    other category."""
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
    """Groups a flat group_by_category() list by focus area, in DOMAIN_ORDER. Callers keep the
    flat list for the table of contents and counts, and pass this only where the template renders
    focus area headings."""
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
    """Groups requirements, abuse cases, or questions by focus area, like group_by_domain(), but
    keeps their input order within each focus area, since sorting would put V10.1 before V2.3.
    domain_map is SVS_REQUIREMENT_DOMAIN_MAP for requirements and abuse cases, and
    QUESTION_DOMAIN_MAP for questions."""
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
    """Maps each technical asset id to its nearest enclosing VPC or VNet trust boundary (one
    tagged icon:aws-vpc or icon:azure-vnet), or None. classify_edge() treats a link as a Network
    Path when its endpoints resolve to different values, and None counts as its own value, so a link
    from an external entity into a VPC still crosses."""
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
    """Renders the restyled diagram for the report, and also writes it as standalone .svg and
    .html files next to the .gv source, since the report shows it only at page size."""
    with open(gv_path, encoding="utf-8") as f:
        dot_source = f.read()

    # Two renders: the PDF copy swaps in raster PNGs for any icon WeasyPrint cannot draw (see
    # threagile_dfd_to_html.py's _icon_needs_print_raster), while the standalone .svg keeps the
    # vector icons.
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

    # Threagile's own PNG of the diagram is superseded by the .svg and .html, and it is the largest
    # file in the output, so it is removed.
    png_path = base + ".png"
    if os.path.exists(png_path):
        os.remove(png_path)

    return svg_for_pdf


def question_groups(questions: dict, checklist: list) -> list:
    """The answered questions grouped by focus area, each group also carrying the library
    questions in that focus area that the model does not answer (see question_status)."""
    answered = sorted((k, v) for k, v in questions.items() if not k.startswith(FEATURE_PREFIX))
    groups = group_svs_entries_by_domain(answered, domain_map=QUESTION_DOMAIN_MAP)
    # Questions the checklist rules out are left out of the report altogether.
    absent = {area: [e for e in entries if e["status"] != "not asked"]
              for area, entries in question_status(questions, checklist).items()}
    absent = {area: entries for area, entries in absent.items() if entries}
    by_area = {g["domain"]: g for g in groups}
    for g in groups:
        g["absent"] = absent.get(g["domain"], [])
    for area, entries in absent.items():
        if area not in by_area:
            groups.append({"domain": area, "entries": [], "absent": entries})
    order = {name: i for i, name in enumerate(DOMAIN_ORDER)}
    groups.sort(key=lambda g: order.get(g["domain"], len(DOMAIN_ORDER)))
    return groups


def not_applicable_reason(text: str) -> str:
    """The reason a requirement section was tailored out, or "" when it applies. An author
    tailors a section out by replacing its rows with "Not applicable: <reason>" (see
    01-metadata-lib.yml), so the report can show what was ruled out and why."""
    m = re.match(r"\s*Not applicable:\s*(.*)", text or "", re.S | re.I)
    return " ".join(m.group(1).split()) if m else ""


def control_ids(title: str) -> list:
    """The control IDs an abuse-case or requirement title is keyed on:
    'CP-9 / AC-5: Backups' -> ['CP-9', 'AC-5'], 'ASVS V6.3: ...' -> ['ASVS V6.3']."""
    return [part.strip() for part in title.split(":", 1)[0].split("/") if part.strip()]


def _base_control(control_id: str) -> str:
    """A NIST control enhancement's base control: 'AC-6(1)' -> 'AC-6'. ASVS/AISVS
    subsection IDs have no enhancements and are returned unchanged."""
    return re.sub(r"\(\d+\)$", "", control_id)


def pair_abuse_cases(security_requirements: list, abuse_cases: list) -> tuple:
    """Attach each abuse case to the requirement section whose controls answer it,
    matched on the control ID both titles are keyed on. An exact ID match wins;
    failing that, a NIST enhancement pairs with its base control or a sibling
    enhancement ('AC-6(1)' with 'AC-6', 'SC-7' with 'SC-7(21)'). ASVS subsections
    never pair across numbers -- V11.7 is not V11.1.

    Returns ({requirement index: [(title, text), ...]}, [(title, text), ...] unmapped)."""
    req_ids = [control_ids(r["title"]) for r in security_requirements]
    attached = {i: [] for i in range(len(security_requirements))}
    unmapped = []
    for title, text in abuse_cases:
        ids = control_ids(title)
        aid = ids[0] if ids else ""
        match = next((i for i, rids in enumerate(req_ids) if aid in rids), None)
        if match is None and aid and not aid.upper().startswith(("ASVS", "AISVS")):
            match = next((i for i, rids in enumerate(req_ids)
                          if _base_control(aid) in {_base_control(r) for r in rids}), None)
        if match is None:
            unmapped.append((title, text))
        else:
            attached[match].append((title, text))
    return attached, unmapped


def group_requirements_with_abuse_cases(security_requirements: list, abuse_cases: list) -> list:
    """The Security Requirements and Abuse Cases section: requirement sections by
    domain, each carrying the abuse cases it answers, and any abuse case no
    requirement section answers listed at the end of its own domain."""
    attached, unmapped = pair_abuse_cases(security_requirements, abuse_cases)
    entries = [dict(req, abuse_cases=attached[i]) for i, req in enumerate(security_requirements)]
    groups = group_svs_entries_by_domain(entries, title_key="title")
    by_domain = {g["domain"]: g for g in groups}
    for g in groups:
        g["unmapped"] = []
    for ug in group_svs_entries_by_domain(unmapped):
        if ug["domain"] in by_domain:
            by_domain[ug["domain"]]["unmapped"] = ug["entries"]
        else:
            groups.append({"domain": ug["domain"], "entries": [], "unmapped": ug["entries"]})
    order_index = {name: i for i, name in enumerate(DOMAIN_ORDER)}
    groups.sort(key=lambda g: order_index.get(g["domain"], len(DOMAIN_ORDER)))
    return groups


def parse_svs_rows(text: str) -> list | None:
    """Parses a requirement section's `<#> | <description> | <Level>` rows into a list for the
    table. Returns None for text in another shape, which the template renders as it is."""
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

    # Confidentiality fill for the data-asset diagram, keyed by title. A data asset and a technical
    # asset with the same title only get one color, so that is a warning, not a failure.
    shared_titles = set(technical_assets) & set(data_assets)
    if shared_titles:
        print(f"WARNING: technical_assets and data_assets share title(s) {sorted(shared_titles)} -- "
              f"the data-asset diagram's confidentiality shading will silently use whichever one's "
              f"listed last for each shared title.")

    confidentiality_by_label = {
        title: node.get("confidentiality")
        for title, node in {**technical_assets, **data_assets}.items()
    }

    # Diagram icons come from icon: tags (see 03-tags-lib.yml, "DIAGRAM ICON TAGS") on technical
    # assets and trust boundaries. An asset can show several icons side by side, while a trust
    # boundary's corner badge uses the first.
    icon_by_label = {}
    for title, node in {**technical_assets, **(model.get("trust_boundaries") or {})}.items():
        for t in (node.get("tags") or []):
            if t.startswith("icon:"):
                icon_by_label.setdefault(title, []).append(t.split(":", 1)[1])

    # The HTML diagrams' filter bar (see threagile_dfd_to_html.py's classify_edge()). A link's usage
    # gives Mission Flows or Log-Telemetry, and a link between two VPC or VNet boundaries is a
    # Network Path. Identity Path has no structural signal, so it comes only from a path:identity
    # tag, rather than a guess that might be wrong.
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

    # A link's path: tags (see 03-tags-lib.yml, "COMMUNICATION LINK PATH-FILTER TAGS") take
    # priority over the inferred categories, since they record the author's intent. A link can
    # carry several, so each pair maps to a set.
    path_tags_by_pair = {}
    for title, node in technical_assets.items():
        for link in (node.get("communication_links") or {}).values():
            if link.get("target") not in assets_by_id:
                continue
            for t in (link.get("tags") or []):
                if t.startswith("path:"):
                    key = (title, assets_by_id[link["target"]])
                    path_tags_by_pair.setdefault(key, set()).add(t.split(":", 1)[1])

    # classify_edge() looks an edge up by its two endpoint labels, so two links between the same
    # pair would share their tags. That only misclassifies a filter, so it is a warning.
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

    category_meta = load_risk_categories(output_dir)
    for group in (all_categories, remaining_categories, accepted_categories, closed_categories):
        annotate_finding_classes(group, category_meta)
    # Open risks split by what the model can show: weaknesses its own facts show, and controls
    # it can't evidence (the rule fires because an interface exists; a reviewer confirms it).
    (remaining_weakness_categories, remaining_control_categories,
     remaining_unclassified_categories) = split_by_finding_class(remaining_categories)

    # Focus area groupings, alongside the flat lists above. Model failures are not grouped, since
    # they are authoring problems rather than threats.
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

    # Tags can sit on technical assets, links, trust boundaries, shared runtimes, and data assets,
    # so every kind is counted (a tag such as mgmt:csp-managed may appear only on a boundary).
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

    checklist = feature_checklist(model.get("questions") or {})
    security_requirements = [
        {"title": title, "text": text, "rows": parse_svs_rows(text), "not_applicable": not_applicable_reason(text)}
        for title, text in (model.get("security_requirements") or {}).items()
    ]
    abuse_cases = list((model.get("abuse_cases") or {}).items())

    return {
        "title": model.get("title", ""),
        "date": model.get("date"),
        "author": model.get("author") or {},
        "mission_criticality": mission_criticality_title(model),
        "management_summary_comment": model.get("management_summary_comment", ""),
        # threat_landscape; business_overview is its older name, still read
        "threat_landscape": model.get("threat_landscape") or model.get("business_overview") or {},
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
        "remaining_weakness_domain_groups": group_by_domain(remaining_weakness_categories),
        "remaining_control_domain_groups": group_by_domain(remaining_control_categories),
        "remaining_unclassified_domain_groups": group_by_domain(remaining_unclassified_categories),
        "remaining_weakness_finding_count": sum(len(c["findings"]) for c in remaining_weakness_categories),
        "remaining_control_finding_count": sum(len(c["findings"]) for c in remaining_control_categories),
        "remaining_unclassified_finding_count": sum(len(c["findings"]) for c in remaining_unclassified_categories),
        "accepted_domain_groups": accepted_domain_groups,
        "closed_domain_groups": closed_domain_groups,
        # File order, not sorted(), since a plain sort puts V10 before V2, while the library's file
        # order is already by chapter.
        "security_requirements": security_requirements,
        "security_requirement_domain_groups": group_svs_entries_by_domain(
            security_requirements, title_key="title"),
        "abuse_cases": abuse_cases,
        "requirement_abuse_groups": group_requirements_with_abuse_cases(security_requirements, abuse_cases),
        "not_applicable_requirement_count": sum(1 for r in security_requirements if r["not_applicable"]),
        "questions": sorted((model.get("questions") or {}).items()),
        "feature_checklist": checklist,
        "question_domain_groups": question_groups(model.get("questions") or {}, checklist),
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
            # This diagram is tall and narrow, so it always fills its own page: 9.0in of usable
            # height (see @page in report.css), less a small buffer.
            print_size_in=(6.8, 8.7),
        ),
    }


def run_self_checks(context: dict, risks_json_count: int) -> bool:
    """Cross-checks the data the report is about to render against Threagile's output, and returns
    False after printing why on any mismatch. The caller treats that as fatal, since a report that
    renders with wrong numbers is the failure this check exists to catch."""
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

    # Not fatal: an abuse case no requirement section answers still renders (at the
    # end of its domain), but it is usually a mis-keyed control ID, so say so.
    for group in context.get("requirement_abuse_groups", []):
        for title, _ in group["unmapped"]:
            print(f"WARNING: abuse case '{title}' pairs with no security requirement section "
                  f"(control ID {control_ids(title)[:1]}); add the section or fix the ID")
    # Also not fatal: a library question that the checklist says applies, but that the model
    # does not ask, leaves part of the focus area unexamined.
    for group in context.get("question_domain_groups", []):
        for entry in group.get("absent", []):
            if entry["status"] == "missing":
                print(f"WARNING: question '{entry['question']}' applies to this model but is not answered")
    # Also not fatal: a checklist selection outside the item's options, or several
    # selections on a single-choice item, is almost always a typo in the model.
    for row in context.get("feature_checklist", []):
        if row["unknown"] and row["options"]:
            print(f"WARNING: feature '{row['feature']}' has selections that are not among its options: "
                  f"{', '.join(row['unknown'])}")
        if not row["multiple"] and sum(o["selected"] for o in row["options"]) > 1:
            print(f"WARNING: feature '{row['feature']}' takes one selection but has several")
    for group in context.get("requirement_abuse_groups", []):
        # Also not fatal: an abuse case under a section marked not applicable states a threat
        # that the model says has no control, so either the tailoring or the abuse case is wrong.
        for entry in group["entries"]:
            if entry.get("not_applicable"):
                for title, _ in entry["abuse_cases"]:
                    print(f"WARNING: abuse case '{title}' pairs with '{entry['title']}', which is marked "
                          f"not applicable; remove the abuse case or reconsider the tailoring")

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
