"""Finding-class handling in the report: annotate_finding_classes and split_by_finding_class.

generate_report.py imports WeasyPrint at module level, which needs native GTK libraries that CI
installs but a developer machine may not; these tests touch only the data handling, so they stub
that one import.
"""
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

    def test_risk_assessment_prefers_the_library_enrichment(self):
        enriched = category("a", "control-not-evidenced", enrichment={"risk_assessment": "from the library"})
        plain = category("b", "control-not-evidenced")
        meta = {"a": {"risk_assessment": "from the rule"}, "b": {"risk_assessment": "from the rule"}}

        report.annotate_finding_classes([enriched, plain], meta)

        self.assertEqual(enriched["risk_assessment_if_missing"], "from the library")
        self.assertEqual(plain["risk_assessment_if_missing"], "from the rule")

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
        self.assertIn("Mission Essential (this model)", html)

    def test_split_keeps_every_category_exactly_once(self):
        cats = [category("w", "weakness-shown"), category("c", "control-not-evidenced"), category("u", None)]
        report.annotate_finding_classes(cats, {})

        weaknesses, controls, unclassified = report.split_by_finding_class(cats)

        self.assertEqual([c["slug"] for c in weaknesses], ["w"])
        self.assertEqual([c["slug"] for c in controls], ["c"])
        self.assertEqual([c["slug"] for c in unclassified], ["u"])


if __name__ == "__main__":
    unittest.main()
