"""Finding-class handling in the report: annotate_finding_classes and split_by_finding_class.

generate_report.py imports WeasyPrint at module level, which needs native GTK libraries that CI
installs but a developer machine may not; these tests touch only the data handling, so they stub
that one import.
"""
import re
import sys
import types
import unittest
from pathlib import Path

sys.modules.setdefault("weasyprint", types.SimpleNamespace(HTML=object, CSS=object))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import generate_report as report  # noqa: E402


def category(slug, *finding_classes, enrichment=None):
    return {"slug": slug, "enrichment": enrichment,
            "findings": [{"finding_class": c} if c else {} for c in finding_classes]}


def req(title):
    return {"title": title, "text": "", "rows": None}


class AbuseCasePairing(unittest.TestCase):
    def test_pairs_on_the_control_id_both_titles_are_keyed_on(self):
        reqs = [req("ASVS V6.3: General Authentication Security"), req("CP-9 / AC-5: Backups"),
                req("AC-6: Least Privilege"), req("SC-7(21): Micro-Segmentation"), req("ASVS V11.1: Inventory")]
        cases = [("ASVS V6.3: Credential Stuffing", "x"), ("CP-9: Ransomware Deletes Backups", "x"),
                 ("AC-6(1): Token Theft", "x"), ("SC-7: Host Pivot", "x"), ("ASVS V11.7: Key Theft", "x")]
        attached, unmapped = report.pair_abuse_cases(reqs, cases)
        self.assertEqual([t for t, _ in attached[0]], ["ASVS V6.3: Credential Stuffing"])
        self.assertEqual([t for t, _ in attached[1]], ["CP-9: Ransomware Deletes Backups"], "any ID in a combined title")
        self.assertEqual([t for t, _ in attached[2]], ["AC-6(1): Token Theft"], "enhancement to its base control")
        self.assertEqual([t for t, _ in attached[3]], ["SC-7: Host Pivot"], "base control to an enhancement")
        self.assertEqual(attached[4], [], "ASVS subsections never pair across numbers")
        self.assertEqual([t for t, _ in unmapped], ["ASVS V11.7: Key Theft"])

    def test_every_abuse_case_lands_exactly_once(self):
        reqs = [req("ASVS V6.3: General Authentication Security")]
        cases = [("ASVS V6.3: Credential Stuffing", "x"), ("ASVS V99.9: Nowhere", "x")]
        groups = report.group_requirements_with_abuse_cases(reqs, cases)
        placed = [t for g in groups for e in g["entries"] for t, _ in e["abuse_cases"]]
        placed += [t for g in groups for t, _ in g["unmapped"]]
        self.assertEqual(sorted(placed), sorted(t for t, _ in cases))

    def test_every_library_abuse_case_pairs_within_its_own_block(self):
        # A model copies a whole domain block, so each abuse case must be answered
        # by a requirement section in that same block.
        import yaml
        library = Path(__file__).resolve().parents[2] / "libraries" / "02-abuse-and-reqs-lib.yml"
        for block in yaml.safe_load(library.read_text(encoding="utf-8"))["categories"]:
            reqs = [req(t) for t in (block.get("security_requirements") or {})]
            _, unmapped = report.pair_abuse_cases(reqs, list((block.get("abuse_cases") or {}).items()))
            with self.subTest(block=block["name"]):
                self.assertEqual([t for t, _ in unmapped], [])


class Scoping(unittest.TestCase):
    def test_not_applicable_sections_carry_their_reason(self):
        self.assertEqual(report.not_applicable_reason("Not applicable: every login federates to Entra ID."),
                         "every login federates to Entra ID.")
        self.assertEqual(report.not_applicable_reason("  not applicable:\n  no files are handled"), "no files are handled")
        self.assertEqual(report.not_applicable_reason("6.2.1 | Verify that passwords ... | 1"), "")

    def test_features_section_comes_before_the_requirements(self):
        template = (Path(report.__file__).parent / "templates" / "report.html.jinja").read_text(encoding="utf-8")
        self.assertLess(template.index('<section id="application-features"'),
                        template.index('<section id="security-requirements"'))
        self.assertNotIn("open-questions", template)

    def test_library_questions_and_checklist_load_with_their_domains(self):
        import yaml
        library = Path(__file__).resolve().parents[2] / "libraries" / "01-metadata-lib.yml"
        blocks = yaml.safe_load(library.read_text(encoding="utf-8"))["categories"]
        questions = [q["question"] for block in blocks for q in (block.get("questions") or [])]
        features = [f for block in blocks for f in (block.get("features") or [])]
        self.assertEqual(len(questions), 28)
        self.assertEqual(len(features), 24)
        self.assertTrue(all("asked_when" in q for block in blocks for q in block["questions"]))
        self.assertEqual(sorted(report.QUESTION_DOMAIN_MAP), sorted(questions))
        for item in features:
            with self.subTest(feature=item["feature"][:60]):
                self.assertTrue(item.get("affects") and item.get("scoping"), "every item names what it affects and how")
                self.assertIn(item["feature"], report.FEATURE_INDEX)

    def test_confluence_questions_all_come_from_the_library(self):
        # An author's own question has no domain and renders under Uncategorized, so the
        # fixture model sticks to library questions.
        import yaml
        model = Path(__file__).resolve().parents[3] / "modular-apps-repo" / "confluence" / "01-metadata.yml"
        questions = yaml.safe_load(model.read_text(encoding="utf-8"))["questions"]
        for question in questions:
            with self.subTest(question=question[:60]):
                if question.startswith(report.FEATURE_PREFIX):
                    self.assertIn(question[len(report.FEATURE_PREFIX):], report.FEATURE_INDEX)
                else:
                    self.assertIn(question, report.QUESTION_DOMAIN_MAP)

    def test_questions_follow_the_checklist(self):
        model = {
            "Feature: OAuth, OIDC, and SAML roles": "",
            "Describe how each authentication mechanism is implemented, enforced, and documented": "Via Entra ID.",
        }
        rows = report.feature_checklist(model)
        status = {e["question"]: e for e in report.question_status(model, rows)["Identity"]}
        self.assertEqual(status["For each OAuth or OIDC role the asset plays, describe how tokens are validated and "
                                "scoped, and how the flows are secured"]["status"], "pending")
        self.assertEqual(status["Describe how sessions are created, timed out, ended, and re-authenticated"]["status"],
                         "missing", "an always-asked question the model leaves out")
        self.assertNotIn("Describe how each authentication mechanism is implemented, enforced, and documented", status)
        detection = {e["question"]: e for e in report.question_status({"Describe what is logged, where the logs go, and "
                                                                        "what error messages reveal": "SIEM."}, [])["Detection"]}
        monitoring = detection["Describe how the model is monitored for anomalies, abuse, and drift, and whether its lifecycle is audited"]
        self.assertEqual(monitoring["status"], "not asked", "its checklist item is in a focus area the model does not cover")
        no_ai = {"Feature: AI use and model sourcing": "None", "Feature: Agent capabilities": "None"}
        ai = report.question_status(no_ai, report.feature_checklist(no_ai))["Artificial Intelligence"]
        self.assertTrue(ai and all(e["status"] == "not asked" for e in ai), "an application that uses no AI")

    def test_every_asked_when_names_a_real_checklist_option(self):
        for question, when in report.QUESTION_ASKED_WHEN.items():
            for feature, option in (when or []):
                with self.subTest(question=question[:50]):
                    self.assertIn(option, report.FEATURE_INDEX[feature]["options"])

    def test_feature_checklist_marks_the_selected_options(self):
        rows = report.feature_checklist({
            "Feature: Authentication mechanisms": "enterprise idp, MFA, Smartcards [ANSWER REQUIRED]",
            "Feature: Vendor-hosted or SaaS components": "",
            "Describe how each authentication mechanism is implemented, enforced, and documented": "Via Entra ID.",
        })
        self.assertEqual([r["feature"] for r in rows], ["Authentication mechanisms", "Vendor-hosted or SaaS components"])
        auth, vendor = rows
        self.assertEqual(auth["domain"], "Identity")
        self.assertEqual([o["label"] for o in auth["options"] if o["selected"]], ["Enterprise IdP", "MFA"],
                         "matched to the library's options without regard to case")
        self.assertEqual(auth["unknown"], ["Smartcards"])
        self.assertTrue(auth["confirm"])
        self.assertFalse(vendor["answered"])
        self.assertFalse(vendor["multiple"])

    def test_implied_tags_exist_and_follow_the_selection(self):
        tag_library = (Path(__file__).resolve().parents[2] / "libraries" / "03-tags-lib.yml").read_text(encoding="utf-8")
        known = set(re.findall(r"^  - ([a-z_]+:[a-z0-9-]+)", tag_library, re.M))
        for name, item in report.FEATURE_INDEX.items():
            for option, tags in item["option_tags"].items():
                for tag in tags:
                    with self.subTest(feature=name, option=option):
                        self.assertIn(tag, known)
        rows = report.feature_checklist({"Feature: Content handling": "File uploads, Bulk import or export"})
        self.assertEqual(rows[0]["tags"], ["feature:file-upload-processing", "feature:import-export", "risk:malware-vector"])

    def test_every_checklist_item_has_options_and_a_selection_mode(self):
        for name, item in report.FEATURE_INDEX.items():
            with self.subTest(feature=name):
                self.assertGreaterEqual(len(item["options"]), 2)
                self.assertFalse(any("," in o for o in item["options"]), "options are comma-separated in answers")


class CustomFocusAreas(unittest.TestCase):
    def test_every_custom_category_has_a_focus_area(self):
        import yaml
        library = Path(__file__).resolve().parents[2] / "libraries" / "09-custom-risks-lib.yml"
        ids = {d["id"] for d in yaml.safe_load(library.read_text(encoding="utf-8"))["custom_risk_definitions"].values()}
        domains = report.load_custom_risk_domains()
        self.assertEqual(set(domains), ids, "every category sits under a FOCUS AREA banner")
        self.assertLessEqual(set(domains.values()), set(report.DOMAIN_ORDER))


class LinkLabels(unittest.TestCase):
    def test_link_shows_its_source_unless_the_source_is_the_row_asset(self):
        titles = {"gw": "App Gateway", "fw": "Azure Firewall", "law": "Log Workspace"}
        self.assertEqual(report.link_label("gw>log-forwarding", "Log Forwarding", "law", titles),
                         "App Gateway → Log Forwarding")
        self.assertEqual(report.link_label("fw>log-forwarding", "Log Forwarding", "fw", titles), "Log Forwarding")
        self.assertEqual(report.link_label("", "", "law", titles), "")

class FindingClasses(unittest.TestCase):
    def test_class_comes_from_the_findings_then_the_category_export(self):
        from_findings = category("a", "weakness-shown", "weakness-shown")
        from_export = category("b", None)
        mixed = category("c", "weakness-shown", "control-not-evidenced")
        unknown = category("d", None)
        meta = {"b": {"finding_class": "control-not-evidenced"}, "c": {"finding_class": "control-not-evidenced"}}

        report.annotate_finding_classes([from_findings, from_export, mixed, unknown], meta)

        self.assertEqual(from_findings["finding_class"], "weakness-shown")
        self.assertEqual(from_findings["finding_class_label"], "Model Weakness")
        self.assertEqual(from_export["finding_class"], "control-not-evidenced")
        self.assertEqual(mixed["finding_class"], "control-not-evidenced",
                         "findings that disagree fall back to the category's own class")
        self.assertEqual(unknown["finding_class"], "")
        self.assertEqual(unknown["finding_class_label"], "")

    def test_categories_without_a_library_entry_take_the_exported_text(self):
        library = category("a", "weakness-shown", enrichment={"description": "from the library"})
        script = category("b", "weakness-shown")
        undescribed = category("c", "weakness-shown")
        meta = {"a": {"description": "from the export"},
                "b": {"description": "d", "impact": "i", "asvs": "V2", "cheat_sheet": "", "references": "CWE-1",
                      "mitigation": "not report text"},
                "c": {"finding_class": "weakness-shown"}}

        report.fill_missing_enrichment([library, script, undescribed], meta)

        self.assertEqual(library["enrichment"], {"description": "from the library"})
        self.assertEqual(script["enrichment"], {"description": "d", "impact": "i", "asvs": "V2", "references": "CWE-1"})
        self.assertIsNone(undescribed["enrichment"])

    def test_mission_criticality_title_reads_both_keys(self):
        self.assertEqual(report.mission_criticality_title({"mission_criticality": "mission-essential"}), "Mission Essential")
        self.assertEqual(report.mission_criticality_title({"business_criticality": "critical"}), "Mission Essential")
        self.assertEqual(report.mission_criticality_title({"business_criticality": "operational"}), "Administrative")

    def test_mission_criticality_table_uses_the_four_levels(self):
        import jinja2
        env = jinja2.Environment(loader=jinja2.FileSystemLoader(str(Path(report.__file__).parent / "templates")))
        source = env.loader.get_source(env, "report.html.jinja")[0]
        section = source[source.index("<h2>Mission Criticality</h2>"):]
        section = section[:section.index("</table>")]
        html = env.from_string(section).render(mission_criticality="Mission Essential")
        for level in ("Administrative", "Mission Support", "Mission Essential", "Mission Critical"):
            self.assertIn(level, html)
        for old in ("Archive", "Operational", "Important", "Mission-Critical"):
            self.assertNotIn(old, html)
        self.assertIn("<strong>Mission Essential</strong>", html)
        self.assertNotIn("(this model)", html)

    def test_mitigation_leads_with_the_action_and_lists_one_step_per_line(self):
        import jinja2
        env = jinja2.Environment(loader=jinja2.FileSystemLoader(str(Path(report.__file__).parent / "templates")),
                                 autoescape=True)
        source = env.loader.get_source(env, "report.html.jinja")[0]
        macro = source[source.index("{% macro mitigation("):]
        macro = macro[:macro.index("{% endmacro %}") + len("{% endmacro %}")]
        render = lambda call: " ".join(env.from_string(macro + call).render().split())

        listed = render("{{ mitigation('Do X.', 'Step one.\\n\\nStep two.') }}")
        self.assertIn("<strong>Mitigation:</strong> Do X.</p>", listed)
        self.assertIn("<li>Step one.</li><li>Step two.</li>", listed)

        paragraph = render("{{ mitigation('Do X.', 'One paragraph.') }}")
        self.assertIn("<p>One paragraph.</p>", paragraph)
        self.assertNotIn("<li>", paragraph)

        self.assertIn("<strong>Mitigation:</strong> Only text.", render("{{ mitigation('', 'Only text.') }}"))
        self.assertEqual(render("{{ mitigation('', '') }}"), "")

    def test_split_keeps_every_category_exactly_once(self):
        cats = [category("w", "weakness-shown"), category("c", "control-not-evidenced"), category("u", None)]
        report.annotate_finding_classes(cats, {})

        weaknesses, controls, unclassified = report.split_by_finding_class(cats)

        self.assertEqual([c["slug"] for c in weaknesses], ["w"])
        self.assertEqual([c["slug"] for c in controls], ["c"])
        self.assertEqual([c["slug"] for c in unclassified], ["u"])


if __name__ == "__main__":
    unittest.main()
