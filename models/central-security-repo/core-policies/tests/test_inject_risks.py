"""Harness for the custom risk engine (inject_risks.py + 09-custom-risks-lib.yml + 03-tags-lib.yml).

Standard-library unittest on purpose: CI installs only pinned dependencies (pyyaml), and pytest
also discovers and runs these as-is. Run from the repo root:

    python -m unittest discover -s models/central-security-repo/core-policies/tests -v

Most checks here are generic, derived from the engine's own source, so a new tag-triggered rule
is covered the moment it is wired in:
  * every trigger tag fires something on its own, and every suppression tag suppresses something;
  * every injected key has a library definition, and every definition is injected somewhere;
  * every tag the engine reads is documented.
RULE_BEHAVIOUR at the bottom holds explicit per-rule cases; add a row when a rule's trigger is
more specific than "this tag alone".
"""

import contextlib
import io
import re
import sys
import tempfile
import unittest
from pathlib import Path

import yaml

CORE_POLICIES = Path(__file__).resolve().parent.parent
LIBRARIES = CORE_POLICIES.parent / "libraries"
sys.path.insert(0, str(CORE_POLICIES))

import inject_risks  # noqa: E402  (needs the sys.path entry above)

ENGINE_SOURCE = (CORE_POLICIES / "inject_risks.py").read_text(encoding="utf-8")
DEFINITIONS = yaml.safe_load((LIBRARIES / "09-custom-risks-lib.yml").read_text(encoding="utf-8"))[
    "custom_risk_definitions"
]
DOCUMENTED_TAGS = set(
    yaml.safe_load((LIBRARIES / "03-tags-lib.yml").read_text(encoding="utf-8"))["tags_available"]
)

TAG_LITERAL = r"'([a-z0-9]+:[a-z0-9.-]+)'"
ENGINE_TAGS = set(re.findall(TAG_LITERAL, ENGINE_SOURCE))
# A suppression tag is only ever checked for absence. A tag checked both ways (e.g.
# ai:indirect-prompt-input, whose absence also stops a second branch injecting the same finding)
# is a trigger.
POSITIVE_TAGS = set(re.findall(TAG_LITERAL + r" in tags", ENGINE_SOURCE))
SUPPRESSION_TAGS = set(re.findall(TAG_LITERAL + r" not in tags", ENGINE_SOURCE)) - POSITIVE_TAGS
TRIGGER_TAGS = ENGINE_TAGS - SUPPRESSION_TAGS
ENGINE_TAG_PREFIXES = set(re.findall(r"startswith\('([a-z0-9]+:)'\)", ENGINE_SOURCE))
INJECTED_KEYS = set(re.findall(r'inject\(\s*"([^"]+)"', ENGINE_SOURCE))

REQUIRED_FIELDS = (
    "id", "baseline_likelihood", "baseline_impact", "description", "impact", "asvs",
    "cheat_sheet", "action", "mitigation", "references", "risk_assessment", "false_positives",
    "function", "stride", "cwe",
)
FUNCTIONS = {"business-side", "architecture", "development", "operations"}
STRIDE = {
    "spoofing", "tampering", "repudiation", "information-disclosure", "denial-of-service",
    "elevation-of-privilege",
}

# Definitions deliberately present in the library but not injected by any engine branch.
# Every entry needs a reason; the test fails on a stale entry.
DEFINITIONS_NOT_INJECTED = {}


def probe_asset(tags, **fields):
    """An in-scope physical process, so machine-gated branches can fire too."""
    asset = {
        "id": "probe",
        "type": "process",
        "machine": "physical",
        "technology": "web-application",
        "confidentiality": "confidential",
        "integrity": "critical",
        "availability": "operational",
        "tags": list(tags),
    }
    asset.update(fields)
    return asset


def run_engine(*assets, business_criticality="important"):
    """Run inject_risks on a model of the given assets.

    Returns {category title: {risk name: risk entry}}, i.e. every finding keyed by its category
    and its per-call-site risk name ("<title> at <asset>").
    """
    model = {
        "title": "harness",
        "business_criticality": business_criticality,
        "data_assets": {},
        "technical_assets": {f"Asset {asset['id']}": asset for asset in assets},
    }
    with tempfile.TemporaryDirectory() as directory:
        source = Path(directory) / "model.yml"
        output = Path(directory) / "out.yml"
        source.write_text(yaml.safe_dump(model), encoding="utf-8")
        with contextlib.redirect_stdout(io.StringIO()):
            inject_risks.inject_risks(str(source), str(output))
        result = yaml.safe_load(output.read_text(encoding="utf-8"))
    return {
        category["title"]: dict(category.get("risks_identified") or {})
        for category in result.get("custom_risk_categories") or []
    }


def findings(result):
    return {(title, name) for title, risks in result.items() for name in risks}


class LibraryIntegrity(unittest.TestCase):
    def test_every_definition_has_required_fields_and_valid_values(self):
        for key, definition in DEFINITIONS.items():
            with self.subTest(definition=key):
                for field in REQUIRED_FIELDS:
                    self.assertTrue(definition.get(field), f"missing or empty {field!r}")
                self.assertEqual(definition.get("risks_identified"), {}, "risks_identified must be {}")
                self.assertIn(definition["baseline_likelihood"], inject_risks.LIKELIHOOD_ORDER)
                self.assertIn(definition["baseline_impact"], inject_risks.IMPACT_ORDER)
                self.assertIn(definition["function"], FUNCTIONS)
                self.assertIn(definition["stride"], STRIDE)
                self.assertIsInstance(definition["cwe"], int)
                self.assertRegex(definition["id"], r"^[a-z0-9]+(-[a-z0-9]+)*$")

    def test_definition_ids_are_unique(self):
        ids = [definition["id"] for definition in DEFINITIONS.values()]
        duplicates = sorted({risk_id for risk_id in ids if ids.count(risk_id) > 1})
        self.assertEqual(duplicates, [])


class EngineMatchesLibrary(unittest.TestCase):
    def test_every_injected_key_has_a_definition(self):
        # A missing key is a KeyError, but only on a model that hits that branch.
        self.assertEqual(sorted(INJECTED_KEYS - set(DEFINITIONS)), [])

    def test_every_definition_is_injected_somewhere(self):
        for key in DEFINITIONS_NOT_INJECTED:
            self.assertIn(key, DEFINITIONS, f"stale DEFINITIONS_NOT_INJECTED entry {key!r}")
            self.assertNotIn(key, INJECTED_KEYS, f"{key!r} is injected now; remove it from the allowlist")
        dead = set(DEFINITIONS) - INJECTED_KEYS - set(DEFINITIONS_NOT_INJECTED)
        self.assertEqual(sorted(dead), [], "library entries no engine branch injects")

    def test_every_tag_the_engine_reads_is_documented(self):
        self.assertEqual(sorted(ENGINE_TAGS - DOCUMENTED_TAGS), [])
        for prefix in ENGINE_TAG_PREFIXES:
            with self.subTest(prefix=prefix):
                self.assertTrue(
                    any(tag.startswith(prefix) for tag in DOCUMENTED_TAGS),
                    f"no documented tag uses the {prefix!r} prefix the engine matches on",
                )


class TagBehaviour(unittest.TestCase):
    def test_baseline_probe_asset_fires_nothing(self):
        self.assertEqual(run_engine(probe_asset([])), {})

    def test_every_trigger_tag_fires_something_on_its_own(self):
        for tag in sorted(TRIGGER_TAGS):
            with self.subTest(tag=tag):
                self.assertTrue(
                    run_engine(probe_asset([tag])),
                    f"{tag!r} is read as a trigger but injects nothing on its own: dead branch, or "
                    "it needs more context (add a RULE_BEHAVIOUR row and exempt it here)",
                )

    def test_every_suppression_tag_suppresses_something(self):
        # Mission-critical, so the model-level incident-response branches (gated on business
        # criticality, not a tag) are live for their suppression tags to act on.
        critical = "mission-critical"
        everything = findings(run_engine(probe_asset(TRIGGER_TAGS), business_criticality=critical))
        self.assertTrue(everything)
        for tag in sorted(SUPPRESSION_TAGS):
            with self.subTest(tag=tag):
                suppressed = everything - findings(
                    run_engine(probe_asset(TRIGGER_TAGS | {tag}), business_criticality=critical)
                )
                self.assertTrue(suppressed, f"{tag!r} is read as a suppression tag but suppresses nothing")

    def test_out_of_scope_asset_gets_nothing(self):
        self.assertEqual(run_engine(probe_asset(ENGINE_TAGS, out_of_scope=True)), {})

    def test_every_finding_is_scored_on_the_engine_scales(self):
        for title, risks in run_engine(probe_asset(TRIGGER_TAGS)).items():
            for name, risk in risks.items():
                with self.subTest(finding=name):
                    self.assertIn(risk["severity"], inject_risks.SEVERITY_ORDER)
                    self.assertIn(risk["exploitation_likelihood"], inject_risks.LIKELIHOOD_ORDER)
                    self.assertIn(risk["exploitation_impact"], inject_risks.IMPACT_ORDER)
                    self.assertEqual(risk["most_relevant_technical_asset"], "probe")


# (description, asset tags, extra asset fields, category title, should fire)
RULE_BEHAVIOUR = [
    ("credential blast radius fires on credential material",
     ["data:credential"], {}, "Undocumented Credential Blast Radius for Incident-Driven Rotation", True),
    ("credential blast radius fires on a secrets broker",
     ["sec:secrets-broker"], {}, "Undocumented Credential Blast Radius for Incident-Driven Rotation", True),
    ("credential blast radius suppressed by a documented inventory",
     ["data:credential", "ir:credential-inventory-documented"], {},
     "Undocumented Credential Blast Radius for Incident-Driven Rotation", False),
    ("RAG technology alone triggers indirect prompt injection",
     [], {"technology": "ai-rag-pipeline"},
     "ATLAS: Indirect Prompt Injection and Trusted Output Manipulation", True),
    ("self-managed hardware needs a physical machine",
     ["mgmt:self-managed-hardware"], {"machine": "virtual"},
     "Self-Managed Boot Integrity Bypass", False),
    ("self-managed hardware fires on a physical machine",
     ["mgmt:self-managed-hardware"], {"machine": "physical"},
     "Self-Managed Boot Integrity Bypass", True),
]


class RuleBehaviour(unittest.TestCase):
    def test_rule_behaviour_table(self):
        for description, tags, fields, title, should_fire in RULE_BEHAVIOUR:
            with self.subTest(case=description):
                self.assertIn(title, DEFINITIONS, "RULE_BEHAVIOUR names an unknown category")
                fired = title in run_engine(probe_asset(tags, **fields))
                self.assertEqual(fired, should_fire)


if __name__ == "__main__":
    unittest.main()
