"""Calibration checks for the custom risk engine.

Every custom category must produce the final rating approved in docs/risk-methodology.md ("Risk
calibration" and its appendix) on the typical IL5 reference asset (profile T: confidential /
critical / important, mid RAA, not internet-facing), and carry its approved finding class. A
change to a baseline in 09-custom-risks-lib.yml, or to the engine's scoring, that moves a rating
fails here, so it has to be a deliberate change to both.
"""
import contextlib
import io
import sys
import tempfile
import unittest
from pathlib import Path

import yaml

CORE_POLICIES = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(CORE_POLICIES))
import inject_risks  # noqa: E402

DEFINITIONS = {
    entry["id"]: entry
    for entry in yaml.safe_load(
        (CORE_POLICIES.parent / "libraries" / "09-custom-risks-lib.yml").read_text(encoding="utf-8")
    )["custom_risk_definitions"].values()
}
PROFILE_T = {"confidentiality": "confidential", "integrity": "critical", "availability": "important"}
PROFILE_T_RAA = 30.0
FINDING_CLASSES = {"weakness-shown", "control-not-evidenced"}

# id -> (likelihood on profile T, impact on profile T, finding class); generated from the
# approved calibration table.
APPROVED = {
    "ai-agent-memory-poisoning": ("possible", "high", "control-not-evidenced"),
    "ai-direct-prompt-injection": ("very-likely", "high", "weakness-shown"),
    "ai-endpoint-assistant-overreach": ("unlikely", "medium", "control-not-evidenced"),
    "ai-indirect-prompt-injection": ("very-likely", "high", "weakness-shown"),
    "ai-labeler-overexposure": ("unlikely", "medium", "control-not-evidenced"),
    "ai-ot-actuation-boundary-gap": ("possible", "very-high", "weakness-shown"),
    "ai-overreliance-trust-exploitation": ("likely", "medium", "control-not-evidenced"),
    "ai-unexpected-code-execution": ("likely", "very-high", "weakness-shown"),
    "ai-unvetted-agent-skills": ("possible", "high", "control-not-evidenced"),
    "air-gapped-model-package-integrity-gap": ("unlikely", "very-high", "control-not-evidenced"),
    "api-abuse-enumeration-logging-gap": ("possible", "medium", "control-not-evidenced"),
    "background-job-security": ("possible", "medium", "control-not-evidenced"),
    "backup-admin-privilege-separation-gap": ("likely", "high", "control-not-evidenced"),
    "backup-immutability-not-enforced": ("likely", "high", "control-not-evidenced"),
    "backup-integrity-recovery-gap": ("possible", "medium", "control-not-evidenced"),
    "backup-key-rotation-retention-mismatch": ("unlikely", "medium", "control-not-evidenced"),
    "break-glass-circular-dependency-untested": ("unlikely", "medium", "control-not-evidenced"),
    "bulk-import-export-abuse": ("possible", "high", "control-not-evidenced"),
    "business-flow-abuse": ("likely", "medium", "control-not-evidenced"),
    "cache-poisoning-data-persistence": ("possible", "high", "control-not-evidenced"),
    "cds-above-releasable-content-inclusion": ("likely", "high", "control-not-evidenced"),
    "cds-broker-queue-injection": ("unlikely", "high", "control-not-evidenced"),
    "cds-high-side-broker-tampering": ("unlikely", "high", "control-not-evidenced"),
    "cds-low-to-high-influence": ("possible", "high", "control-not-evidenced"),
    "cds-malicious-insider-release-abuse": ("unlikely", "very-high", "control-not-evidenced"),
    "cds-marking-validation-bypass": ("likely", "high", "control-not-evidenced"),
    "cds-misclassification-audit-gap": ("possible", "medium", "control-not-evidenced"),
    "cds-release-authority-bypass": ("unlikely", "high", "control-not-evidenced"),
    "cds-transfer-interface-covert-channel": ("unlikely", "medium", "control-not-evidenced"),
    "cds-unsafe-inbound-content": ("possible", "high", "control-not-evidenced"),
    "container-runs-as-root": ("possible", "high", "weakness-shown"),
    "dangling-dns-subdomain-takeover": ("possible", "medium", "control-not-evidenced"),
    "dataset-reidentification-risk": ("possible", "high", "control-not-evidenced"),
    "deprecated-tls-weak-ciphers": ("unlikely", "medium", "control-not-evidenced"),
    "dfars-breach-notification-gap": ("unlikely", "medium", "control-not-evidenced"),
    "dlp-egress-blind-spot": ("possible", "medium", "control-not-evidenced"),
    "dynamic-code-rce": ("likely", "very-high", "control-not-evidenced"),
    "email-header-injection": ("unlikely", "medium", "control-not-evidenced"),
    "eol-component-ato-boundary": ("likely", "high", "weakness-shown"),
    "exposed-admin-panel": ("possible", "very-high", "control-not-evidenced"),
    "fips-non-compliant-cryptography": ("unlikely", "medium", "control-not-evidenced"),
    "forensic-chain-of-custody-gap": ("unlikely", "medium", "control-not-evidenced"),
    "graphql-security-gaps": ("likely", "medium", "control-not-evidenced"),
    "improper-api-inventory-management": ("possible", "medium", "control-not-evidenced"),
    "insecure-deserialization": ("possible", "very-high", "control-not-evidenced"),
    "insecure-password-reset": ("possible", "high", "control-not-evidenced"),
    "malicious-file-parsing": ("possible", "high", "control-not-evidenced"),
    "media-downgrade-procedure-gap": ("unlikely", "high", "control-not-evidenced"),
    "missing-data-provenance-chain": ("possible", "medium", "control-not-evidenced"),
    "missing-data-rights-management": ("likely", "medium", "control-not-evidenced"),
    "missing-privacy-impact-assessment": ("possible", "medium", "control-not-evidenced"),
    "missing-token-binding": ("likely", "high", "control-not-evidenced"),
    "missing-waf-internet-facing": ("possible", "medium", "control-not-evidenced"),
    "network-ids-blind-spot": ("possible", "medium", "control-not-evidenced"),
    "oauth-illicit-consent-grant": ("possible", "high", "control-not-evidenced"),
    "oauth-oidc-vulnerabilities": ("possible", "high", "control-not-evidenced"),
    "overprivileged-workload-identity": ("likely", "very-high", "control-not-evidenced"),
    "pdf-generation-injection": ("possible", "high", "control-not-evidenced"),
    "permissive-cors-framing-policy": ("possible", "medium", "control-not-evidenced"),
    "policy-exception-cleartext-internal": ("possible", "high", "weakness-shown"),
    "policy-exception-direct-admin-access": ("likely", "very-high", "weakness-shown"),
    "policy-exception-local-auth": ("likely", "high", "weakness-shown"),
    "privileged-session-credential-disclosure": ("likely", "very-high", "control-not-evidenced"),
    "public-api-abuse": ("likely", "medium", "control-not-evidenced"),
    "recovery-objective-definition-gap": ("possible", "medium", "control-not-evidenced"),
    "saml-assertion-vulnerabilities": ("unlikely", "very-high", "control-not-evidenced"),
    "search-index-abuse": ("possible", "high", "control-not-evidenced"),
    "self-managed-bmc-compromise": ("possible", "very-high", "control-not-evidenced"),
    "self-managed-boot-integrity-bypass": ("unlikely", "high", "control-not-evidenced"),
    "self-managed-ca-template-escalation": ("likely", "very-high", "control-not-evidenced"),
    "self-managed-directory-tier0-compromise": ("possible", "very-high", "control-not-evidenced"),
    "self-managed-firmware-persistence-gap": ("unlikely", "high", "control-not-evidenced"),
    "self-managed-hybrid-sync-compromise": ("possible", "very-high", "control-not-evidenced"),
    "self-managed-missing-rpki-route-validation": ("unlikely", "medium", "control-not-evidenced"),
    "self-managed-network-no-segmentation": ("possible", "medium", "control-not-evidenced"),
    "self-managed-rogue-ap-credential-harvesting": ("unlikely", "high", "control-not-evidenced"),
    "standing-privileged-access-no-tiering": ("likely", "very-high", "control-not-evidenced"),
    "unauthorized-marketplace-plugin": ("likely", "high", "control-not-evidenced"),
    "undocumented-containment-disposition": ("unlikely", "medium", "control-not-evidenced"),
    "undocumented-credential-blast-radius": ("unlikely", "medium", "control-not-evidenced"),
    "ungoverned-third-party-model-api": ("likely", "medium", "control-not-evidenced"),
    "unsafe-api-consumption": ("possible", "high", "control-not-evidenced"),
    "unsupported-saas-backup-gap": ("unlikely", "high", "control-not-evidenced"),
    "untested-incident-response-plan": ("possible", "medium", "control-not-evidenced"),
    "untested-restoration-procedure": ("possible", "medium", "control-not-evidenced"),
    "vdi-clipboard-data-exfiltration": ("unlikely", "medium", "control-not-evidenced"),
    "vendor-remote-support-access-gap": ("possible", "high", "control-not-evidenced"),
    "webhook-signature-bypass": ("possible", "medium", "control-not-evidenced"),
    "websocket-security-gaps": ("possible", "medium", "control-not-evidenced"),
}


# id -> the CIA dimension its impact steps on (C, I, A, or CIA for the highest of the three); from
# the approved calibration table. Profile T rates confidentiality and integrity at the same rank,
# so it can't tell a category stepping on the wrong one; the single-dimension profiles below can.
APPROVED_DIMENSION = {
    "ai-agent-memory-poisoning": "I",
    "ai-direct-prompt-injection": "CIA",
    "ai-endpoint-assistant-overreach": "C",
    "ai-indirect-prompt-injection": "CIA",
    "ai-labeler-overexposure": "C",
    "ai-ot-actuation-boundary-gap": "CIA",
    "ai-overreliance-trust-exploitation": "I",
    "ai-unexpected-code-execution": "CIA",
    "ai-unvetted-agent-skills": "I",
    "air-gapped-model-package-integrity-gap": "I",
    "api-abuse-enumeration-logging-gap": "I",
    "background-job-security": "CIA",
    "backup-admin-privilege-separation-gap": "I",
    "backup-immutability-not-enforced": "I",
    "backup-integrity-recovery-gap": "I",
    "backup-key-rotation-retention-mismatch": "C",
    "break-glass-circular-dependency-untested": "A",
    "bulk-import-export-abuse": "C",
    "business-flow-abuse": "A",
    "cache-poisoning-data-persistence": "C",
    "cds-above-releasable-content-inclusion": "C",
    "cds-broker-queue-injection": "I",
    "cds-high-side-broker-tampering": "I",
    "cds-low-to-high-influence": "I",
    "cds-malicious-insider-release-abuse": "C",
    "cds-marking-validation-bypass": "C",
    "cds-misclassification-audit-gap": "I",
    "cds-release-authority-bypass": "CIA",
    "cds-transfer-interface-covert-channel": "C",
    "cds-unsafe-inbound-content": "CIA",
    "container-runs-as-root": "CIA",
    "dangling-dns-subdomain-takeover": "I",
    "dataset-reidentification-risk": "C",
    "deprecated-tls-weak-ciphers": "C",
    "dfars-breach-notification-gap": "A",
    "dlp-egress-blind-spot": "C",
    "dynamic-code-rce": "CIA",
    "email-header-injection": "I",
    "eol-component-ato-boundary": "CIA",
    "exposed-admin-panel": "CIA",
    "fips-non-compliant-cryptography": "C",
    "forensic-chain-of-custody-gap": "I",
    "graphql-security-gaps": "C",
    "improper-api-inventory-management": "CIA",
    "insecure-deserialization": "CIA",
    "insecure-password-reset": "I",
    "malicious-file-parsing": "I",
    "media-downgrade-procedure-gap": "C",
    "missing-data-provenance-chain": "I",
    "missing-data-rights-management": "C",
    "missing-privacy-impact-assessment": "C",
    "missing-token-binding": "I",
    "missing-waf-internet-facing": "I",
    "network-ids-blind-spot": "C",
    "oauth-illicit-consent-grant": "I",
    "oauth-oidc-vulnerabilities": "I",
    "overprivileged-workload-identity": "CIA",
    "pdf-generation-injection": "C",
    "permissive-cors-framing-policy": "I",
    "policy-exception-cleartext-internal": "C",
    "policy-exception-direct-admin-access": "CIA",
    "policy-exception-local-auth": "I",
    "privileged-session-credential-disclosure": "CIA",
    "public-api-abuse": "A",
    "recovery-objective-definition-gap": "A",
    "saml-assertion-vulnerabilities": "I",
    "search-index-abuse": "C",
    "self-managed-bmc-compromise": "CIA",
    "self-managed-boot-integrity-bypass": "I",
    "self-managed-ca-template-escalation": "I",
    "self-managed-directory-tier0-compromise": "I",
    "self-managed-firmware-persistence-gap": "I",
    "self-managed-hybrid-sync-compromise": "CIA",
    "self-managed-missing-rpki-route-validation": "I",
    "self-managed-network-no-segmentation": "CIA",
    "self-managed-rogue-ap-credential-harvesting": "I",
    "standing-privileged-access-no-tiering": "CIA",
    "unauthorized-marketplace-plugin": "CIA",
    "undocumented-containment-disposition": "A",
    "undocumented-credential-blast-radius": "CIA",
    "ungoverned-third-party-model-api": "C",
    "unsafe-api-consumption": "I",
    "unsupported-saas-backup-gap": "A",
    "untested-incident-response-plan": "A",
    "untested-restoration-procedure": "A",
    "vdi-clipboard-data-exfiltration": "C",
    "vendor-remote-support-access-gap": "CIA",
    "webhook-signature-bypass": "I",
    "websocket-security-gaps": "I",
}
SINGLE_DIMENSION_PROFILES = {
    "confidentiality only": {"confidentiality": "confidential", "integrity": "operational", "availability": "operational"},
    "integrity only": {"confidentiality": "internal", "integrity": "critical", "availability": "operational"},
    "availability only": {"confidentiality": "internal", "integrity": "operational", "availability": "critical"},
}

# Built-in id -> (approved starting likelihood, approved starting impact). The report prints each
# built-in's risk_assessment from 10-threagile-builtin-risks-lib.yml, so its scoring sentence must
# match the calibration.
APPROVED_BUILTIN_BASELINES = {
    "cluster-control-plane-audit-gap": ("Likely", "Low"),
    "accidental-secret-leak": ("Likely", "Low"),
    "code-backdooring": ("Possible", "Medium"),
    "container-platform-escape": ("Unlikely", "High"),
    "cross-site-request-forgery": ("Possible", "Low"),
    "cross-site-scripting": ("Likely", "Medium"),
    "dos-risky-access-across-trust-boundary": ("Possible", "Low"),
    "ldap-injection": ("Possible", "Medium"),
    "missing-authentication": ("Likely", "Medium"),
    "missing-authentication-second-factor": ("Likely", "Medium"),
    "missing-build-infrastructure": ("Unlikely", "Low"),
    "missing-cloud-hardening": ("Possible", "Low"),
    "missing-file-validation": ("Possible", "Medium"),
    "missing-hardening": ("Unlikely", "Low"),
    "missing-identity-propagation": ("Possible", "Low"),
    "missing-identity-provider-isolation": ("Possible", "Medium"),
    "missing-identity-store": ("Unlikely", "Low"),
    "missing-network-segmentation": ("Unlikely", "Low"),
    "missing-vault": ("Unlikely", "Low"),
    "missing-vault-isolation": ("Unlikely", "Medium"),
    "missing-waf": ("Possible", "Low"),
    "mixed-targets-on-shared-runtime": ("Unlikely", "Low"),
    "path-traversal": ("Likely", "Medium"),
    "push-instead-of-pull-deployment": ("Unlikely", "Low"),
    "search-query-injection": ("Possible", "Medium"),
    "server-side-request-forgery": ("Possible", "Low"),
    "service-registry-poisoning": ("Unlikely", "Medium"),
    "sql-nosql-injection": ("Likely", "High"),
    "unchecked-deployment": ("Likely", "Low"),
    "unencrypted-asset": ("Unlikely", "Low"),
    "unencrypted-communication": ("Possible", "Medium"),
    "unguarded-access-from-internet": ("Likely", "Low"),
    "unguarded-direct-datastore-access": ("Possible", "Low"),
    "untrusted-deserialization": ("Possible", "High"),
    "xml-external-entity": ("Possible", "Medium"),
}
BUILTIN_LIBRARY = yaml.safe_load(
    (CORE_POLICIES.parent / "libraries" / "10-threagile-builtin-risks-lib.yml").read_text(encoding="utf-8")
)["builtin_risks"]

class Calibration(unittest.TestCase):
    def test_every_category_has_an_approved_rating_and_no_stale_entries(self):
        self.assertEqual(sorted(set(DEFINITIONS) - set(APPROVED)), [], "categories with no approved rating")
        self.assertEqual(sorted(set(APPROVED) - set(DEFINITIONS)), [], "approved ratings for missing categories")

    def test_every_category_matches_its_approved_rating_on_profile_t(self):
        for cid, (likelihood, impact, _) in APPROVED.items():
            with self.subTest(category=cid):
                definition = DEFINITIONS[cid]
                self.assertEqual(inject_risks.compute_likelihood(definition, PROFILE_T_RAA, False), likelihood)
                self.assertEqual(inject_risks.compute_impact(definition, PROFILE_T), impact)

    def test_every_category_carries_its_approved_finding_class(self):
        for cid, (_, _, finding_class) in APPROVED.items():
            with self.subTest(category=cid):
                self.assertIn(DEFINITIONS[cid].get("finding_class"), FINDING_CLASSES)
                self.assertEqual(DEFINITIONS[cid]["finding_class"], finding_class)

    def test_finding_class_reaches_the_injected_model(self):
        model = {
            "title": "harness",
            "business_criticality": "important",
            "data_assets": {},
            "technical_assets": {"Asset probe": {
                "id": "probe", "type": "process", "usage": "business", "size": "service",
                "technology": "web-application", "machine": "container", "encryption": "none",
                "owner": "test", "confidentiality": "confidential", "integrity": "critical",
                "availability": "important", "tags": ["ai:user-prompt-input"],
            }},
        }
        with tempfile.TemporaryDirectory() as directory:
            source, output = Path(directory) / "model.yml", Path(directory) / "out.yml"
            source.write_text(yaml.safe_dump(model), encoding="utf-8")
            with contextlib.redirect_stdout(io.StringIO()):
                inject_risks.inject_risks(str(source), str(output))
            injected = yaml.safe_load(output.read_text(encoding="utf-8"))["custom_risk_categories"]
        self.assertTrue(injected, "the probe asset should produce at least one custom finding")
        for category in injected:
            with self.subTest(category=category["id"]):
                self.assertEqual(category.get("finding_class"), APPROVED[category["id"]][2])


    def test_every_category_steps_impact_on_its_approved_dimension(self):
        self.assertEqual(sorted(APPROVED_DIMENSION), sorted(APPROVED))
        for name, profile in SINGLE_DIMENSION_PROFILES.items():
            ranks = {d: inject_risks.CIA_RANK[profile[k]] for d, k in
                     (("C", "confidentiality"), ("I", "integrity"), ("A", "availability"))}
            ranks["CIA"] = max(ranks.values())
            for cid, dimension in APPROVED_DIMENSION.items():
                with self.subTest(profile=name, category=cid):
                    baseline = inject_risks.IMPACT_ORDER.index(DEFINITIONS[cid]["baseline_impact"])
                    step = inject_risks.CIA_RANK_TO_DELTA[ranks[dimension]]
                    expected = inject_risks.IMPACT_ORDER[max(0, min(3, baseline + step))]
                    self.assertEqual(inject_risks.compute_impact(DEFINITIONS[cid], profile), expected)

    def test_builtin_report_text_states_the_approved_starting_rating(self):
        self.assertEqual(sorted(BUILTIN_LIBRARY), sorted(APPROVED_BUILTIN_BASELINES))
        for rule_id, (likelihood, impact) in APPROVED_BUILTIN_BASELINES.items():
            with self.subTest(rule=rule_id):
                text = " ".join(BUILTIN_LIBRARY[rule_id]["risk_assessment"].split())
                self.assertRegex(text, rf"^Likelihood starts at (a flat )?{likelihood}(?![a-z])")
                self.assertRegex(text, rf"impact starts at (a flat )?{impact}(?![a-z])")


if __name__ == "__main__":
    unittest.main()
