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
from unittest import mock
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
    "function", "stride", "cwe", "finding_class",
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


def run_engine(*assets, business_criticality="important", trust_boundaries=None):
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
    if trust_boundaries:
        model["trust_boundaries"] = trust_boundaries
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

    def test_every_tag_the_reference_libraries_name_is_documented_or_native(self):
        # 01-metadata-lib.yml / 02-abuse-and-reqs-lib.yml trigger lists and the intake questionnaire
        # name tags for authors to apply; a retired tag there silently stops matching anything.
        native_prefixes = ("technology:", "type:", "machine:", "multi_tenant:")
        for name in ("01-metadata-lib.yml", "02-abuse-and-reqs-lib.yml", "11-intake-questionnaire-lib.yml"):
            lines = (LIBRARIES / name).read_text(encoding="utf-8").split("\n")
            body = "\n".join(line for line in lines if not line.lstrip().startswith("#"))
            named = set(re.findall(r"(?<![\w/.-])([a-z0-9]+:[a-z0-9][a-z0-9.-]*)", body))
            named = {t for t in named if not t.startswith(("http", "https")) and not t.startswith(native_prefixes)}
            with self.subTest(library=name):
                self.assertEqual(sorted(named - DOCUMENTED_TAGS), [], "retired or undocumented tags")

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
        # Some branches trigger on native fields rather than a tag (internet-facing, a browser
        # caller), so the probe sets those too for their suppression tags to act on.
        browser = probe_asset([], id="browser", technology="browser", type="external-entity", out_of_scope=True,
                              communication_links={"Use": link("probe")})

        def run(tags):
            return findings(run_engine(probe_asset(tags, internet=True), browser, business_criticality=critical))

        everything = run(TRIGGER_TAGS)
        self.assertTrue(everything)
        for tag in sorted(SUPPRESSION_TAGS):
            with self.subTest(tag=tag):
                suppressed = everything - run(TRIGGER_TAGS | {tag})
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
     "Indirect Prompt Injection and Goal Hijack", True),
    ("vetted skills suppress the unvetted-skills risk",
     ["ai:skills-enabled", "ai:skills-vetted"], {}, "Unvetted Agent Skills and Instructions", False),
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


def likelihood_of(result, title):
    risks = list(result[title].values())
    assert len(risks) == 1, risks
    return risks[0]["exploitation_likelihood"]


def link(target, readonly=False):
    return {"target": target, "readonly": readonly}


@mock.patch.object(inject_risks, "compute_raa_by_id", lambda model: {})
class LikelihoodSteps(unittest.TestCase):
    """Steps that branches take from model facts. RAA is pinned (every asset gets the default 1.0,
    one level below baseline) so only the step under test varies."""

    def test_guardrail_on_the_request_path_lowers_prompt_injection(self):
        title = "Direct Prompt Injection and Jailbreak"
        unguarded = run_engine(probe_asset(["ai:user-prompt-input"]))
        guard_calls = run_engine(
            probe_asset(["ai:user-prompt-input"]),
            probe_asset([], id="guard", technology="ai-guardrails", communication_links={"Screen": link("probe")}))
        probe_calls = run_engine(
            probe_asset(["ai:user-prompt-input"], communication_links={"Check": link("guard")}),
            probe_asset([], id="guard", technology="ai-guardrails"))
        self.assertEqual(likelihood_of(unguarded, title), "likely")
        self.assertEqual(likelihood_of(guard_calls, title), "possible")
        self.assertEqual(likelihood_of(probe_calls, title), "possible")

    def test_inline_guardrail_does_not_count_when_another_caller_bypasses_it(self):
        title = "Direct Prompt Injection and Jailbreak"
        bypassed = run_engine(
            probe_asset(["ai:user-prompt-input"]),
            probe_asset([], id="guard", technology="ai-guardrails", communication_links={"Screen": link("probe")}),
            probe_asset([], id="ui", communication_links={"Direct": link("probe")}))
        self.assertEqual(likelihood_of(bypassed, title), "likely")

    def test_guardrail_also_lowers_indirect_injection_from_technology(self):
        title = "Indirect Prompt Injection and Goal Hijack"
        unguarded = run_engine(probe_asset([], technology="ai-rag-pipeline"))
        guarded = run_engine(
            probe_asset([], technology="ai-rag-pipeline", communication_links={"Check": link("guard")}),
            probe_asset([], id="guard", technology="ai-guardrails"))
        self.assertEqual(likelihood_of(unguarded, title), "likely")
        self.assertEqual(likelihood_of(guarded, title), "possible")

    def test_memory_written_from_outside_its_boundary_raises_likelihood(self):
        title = "Agent Memory and Context Poisoning"
        boundaries = {"Core": {"id": "core", "technical_assets_inside": ["probe", "inside"]},
                      "Partner": {"id": "partner", "technical_assets_inside": ["outside"]}}
        writer_inside = run_engine(
            probe_asset(["ai:agent-memory"]),
            probe_asset([], id="inside", communication_links={"Write": link("probe")}),
            trust_boundaries=boundaries)
        writer_outside = run_engine(
            probe_asset(["ai:agent-memory"]),
            probe_asset([], id="outside", communication_links={"Write": link("probe")}),
            trust_boundaries=boundaries)
        reader_outside = run_engine(
            probe_asset(["ai:agent-memory"]),
            probe_asset([], id="outside", communication_links={"Read": link("probe", readonly=True)}),
            trust_boundaries=boundaries)
        self.assertEqual(likelihood_of(writer_inside, title), "unlikely")
        self.assertEqual(likelihood_of(writer_outside, title), "possible")
        self.assertEqual(likelihood_of(reader_outside, title), "unlikely")

    def test_code_execution_without_isolation_raises_likelihood(self):
        title = "Unexpected Code Execution and Weak Sandbox"
        # Only an explicitly physical machine steps up: a VM is an isolation boundary, and a
        # missing machine says nothing (2026-11-18 review).
        for machine, expected in (("physical", "likely"), ("virtual", "possible"), (None, "possible"),
                                  ("container", "possible"), ("serverless", "possible")):
            with self.subTest(machine=machine):
                asset = probe_asset(["ai:code-execution"], machine=machine)
                if machine is None:
                    del asset["machine"]
                result = run_engine(asset)
                self.assertEqual(likelihood_of(result, title), expected)



@mock.patch.object(inject_risks, "compute_raa_by_id", lambda model: {})
class ReviewRegressions(unittest.TestCase):
    """Cases the independent review reproduced as wrong output."""

    def test_tagged_rag_pipeline_gets_one_indirect_injection_finding(self):
        result = run_engine(probe_asset(["ai:indirect-prompt-input"], technology="ai-rag-pipeline"))
        self.assertEqual(len(result["Indirect Prompt Injection and Goal Hijack"]), 1)

    def test_memory_outside_step_does_not_stack_with_the_internet_tag(self):
        title = "Agent Memory and Context Poisoning"
        boundaries = {"Core": {"id": "core", "technical_assets_inside": ["probe"]},
                      "DMZ": {"id": "dmz", "technical_assets_inside": ["outside"]}}
        tagged = run_engine(
            probe_asset(["ai:agent-memory", "net:internet-reachable"]),
            probe_asset([], id="outside", communication_links={"Write": link("probe")}),
            trust_boundaries=boundaries)
        # Baseline possible, RAA pinned low (-1), internet tag +1, outside writer suppressed: possible.
        self.assertEqual(likelihood_of(tagged, title), "possible")

    def test_internal_backend_in_another_boundary_is_not_an_outside_writer(self):
        title = "Agent Memory and Context Poisoning"
        boundaries = {"Core": {"id": "core", "technical_assets_inside": ["probe"]},
                      "Partner": {"id": "partner", "technical_assets_inside": ["backend"]}}
        result = run_engine(
            probe_asset(["ai:agent-memory"]),
            probe_asset([], id="backend", technology="web-service-rest", communication_links={"Write": link("probe")}),
            trust_boundaries=boundaries)
        self.assertEqual(likelihood_of(result, title), "unlikely")

    def test_execution_environment_boundaries_are_looked_through(self):
        title = "Agent Memory and Context Poisoning"
        boundaries = {"VPC": {"id": "vpc", "type": "network-cloud-provider", "trust_boundaries_nested": ["pod-a", "pod-b"]},
                      "PodA": {"id": "pod-a", "type": "execution-environment", "technical_assets_inside": ["probe"]},
                      "PodB": {"id": "pod-b", "type": "execution-environment", "technical_assets_inside": ["ui"]}}
        result = run_engine(
            probe_asset(["ai:agent-memory"]),
            probe_asset([], id="ui", communication_links={"Write": link("probe")}),
            trust_boundaries=boundaries)
        self.assertEqual(likelihood_of(result, title), "unlikely", "same network boundary: not outside")

    def test_technologies_list_is_read(self):
        asset = probe_asset([])
        del asset["technology"]
        asset["technologies"] = ["ai-rag-pipeline"]
        self.assertIn("Indirect Prompt Injection and Goal Hijack", run_engine(asset))

    def test_self_managed_segmentation_leaves_containers_to_the_fork(self):
        # 2026-11-18 review: the fork's missing-network-micro-segmentation owns containers.
        title = "No Macro or Micro-Segmentation of Self-Managed Network"
        tags = ["mgmt:self-managed-network"]
        self.assertIn(title, run_engine(probe_asset(tags, machine="virtual")))
        self.assertNotIn(title, run_engine(probe_asset(tags, machine="container")))

    def test_native_triggers_replace_tags_that_restated_the_model(self):
        # 2026-11-18 review: these read the model's own fields instead of (or before) a tag.
        dns, ids = "Dangling DNS Record and Subdomain Takeover", "Network Intrusion Detection and Traffic Anomaly Blind Spot"
        public_side = probe_asset([], id="user", type="external-entity", out_of_scope=True,
                                  communication_links={"Use": link("probe")})
        internal = probe_asset([], id="svc", communication_links={"Call": link("probe")})
        for title in (dns, ids):
            with self.subTest(title=title):
                self.assertIn(title, run_engine(probe_asset([], internet=True), public_side), "public endpoint")
                self.assertNotIn(title, run_engine(probe_asset([], internet=True), internal),
                                 "internet-connected but only called internally (an egress firewall)")
        self.assertNotIn(dns, run_engine(probe_asset(["zone:dmz"]), public_side), "not internet-facing itself")

        cors = "Permissive CORS and Missing Browser Framing/Content Policy"
        self.assertIn(cors, run_engine(probe_asset([]), probe_asset([], id="c", technology="browser",
                                                                    communication_links={"Use": link("probe")})))
        for caller in (probe_asset([], id="c", technology="desktop", used_as_client_by_human=True,
                                   communication_links={"Use": link("probe")}), internal):
            self.assertNotIn(cors, run_engine(probe_asset([]), caller), "CORS and framing are browser mechanisms")

        ws = "WebSocket Origin Validation and Authentication Gaps"
        socket_link = {"target": "probe", "protocol": "wss"}
        self.assertIn(ws, run_engine(probe_asset([]), probe_asset([], id="c", communication_links={"Socket": socket_link})))
        self.assertIn(ws, run_engine(probe_asset(["feature:websocket"])), "tag fallback where the protocol isn't modeled")

        search = "Search Index Abuse and Data Exposure"
        result = run_engine(probe_asset(["feature:search-index"], communication_links={"Query": link("engine")}),
                            probe_asset([], id="engine", technology="search-engine"))
        self.assertEqual([name.split(" at ")[-1] for name in result[search]], ["Asset engine"],
                         "the modeled search engine carries it, not also every app that queries it")
        self.assertIn(search, run_engine(probe_asset(["feature:search-index"])), "search built into the app")

    def test_direct_admin_waiver_defers_to_the_built_in_where_it_fires(self):
        # 2026-11-18: no second finding where the built-in unguarded-access-from-internet already
        # raises the exposure; still raised where the built-in stays silent.
        title = "Policy Exception: Direct Admin Access"
        tags = ["exception:direct-admin-access"]

        def internet_admin(vpn=False):
            return probe_asset([], id="admin", internet=True,
                               communication_links={"SSH": {"target": "probe", "vpn": vpn}})

        self.assertNotIn(title, run_engine(probe_asset(tags), internet_admin()),
                         "confidential VM reached from an internet-facing source: the built-in covers it")
        self.assertIn(title, run_engine(probe_asset(tags, confidentiality="internal", integrity="operational"),
                                        internet_admin()), "lower-value VM: the built-in's rating gate skips it")
        self.assertIn(title, run_engine(probe_asset(tags)), "admin path not modeled as a link")
        self.assertIn(title, run_engine(probe_asset(tags), internet_admin(vpn=True)), "the built-in skips VPN links")

    def test_wireless_and_routing_findings_land_once_per_network(self):
        # 2026-11-18 review: rogue AP and RPKI are properties of the network, not of each workload.
        tags = ["mgmt:self-managed-network"]
        boundaries = {"Core": {"id": "core", "type": "network-on-prem", "technical_assets_inside": ["app", "db", "proxy"]},
                      "Branch": {"id": "branch", "type": "network-on-prem", "technical_assets_inside": ["b-app", "b-svc", "b-hard"]}}
        result = run_engine(
            probe_asset(tags, id="app"), probe_asset(tags, id="db"),
            probe_asset(tags, id="proxy", technology="reverse-proxy"),
            probe_asset(tags, id="b-svc"), probe_asset(tags, id="b-app"),
            probe_asset(tags + ["mgmt:self-managed-network-hardened"], id="b-hard"),
            trust_boundaries=boundaries)
        for title in ("Rogue Access Point and Evil-Twin Credential Harvesting on Self-Managed Wireless",
                      "Missing Route Origin Validation on Self-Managed External Routing"):
            with self.subTest(title=title):
                self.assertEqual(sorted(result[title]), sorted([
                    next(name for name in result[title] if name.endswith("at Asset proxy")),
                    next(name for name in result[title] if name.endswith("at Asset b-app")),
                ]), "core: on its edge asset (the reverse proxy); branch: no edge asset, so the first tagged asset by id")
                self.assertEqual(len(result[title]), 2)
        self.assertEqual(len(result["No Macro or Micro-Segmentation of Self-Managed Network"]), 5,
                         "segmentation stays per workload (every unhardened, non-container asset)")

    def test_agent_indirect_injection_needs_a_content_source(self):
        # 2026-11-18 noise review: an agent inherits indirect injection only when it reads content
        # (retrieval, tool results, other agents, anything external), not unconditionally.
        title = "Indirect Prompt Injection and Goal Hijack"
        own_stores_only = run_engine(
            probe_asset([], technology="ai-agent-orchestrator",
                        communication_links={"Complete": link("llm"), "Save": link("db")}),
            probe_asset([], id="llm", technology="ai-llm-endpoint"),
            probe_asset([], id="db", technology="database", type="datastore"))
        self.assertNotIn(title, own_stores_only, "talks only to its LLM and its own database")
        for source, technology, extra in (("vectors", "ai-vector-store", {}),
                                          ("tools", "ai-tool-server", {}),
                                          ("web", "web-server", {"out_of_scope": True})):
            with self.subTest(source=source):
                result = run_engine(
                    probe_asset([], technology="ai-agent-orchestrator",
                                communication_links={"Read": link(source, readonly=True)}),
                    probe_asset([], id=source, technology=technology, **extra))
                self.assertIn(title, result)


if __name__ == "__main__":
    unittest.main()
