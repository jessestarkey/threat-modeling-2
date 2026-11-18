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


class FindingClasses(unittest.TestCase):
    def test_class_comes_from_the_findings_then_the_category_export(self):
        from_findings = category("a", "weakness-shown", "weakness-shown")
        from_export = category("b", None)
        mixed = category("c", "weakness-shown", "control-not-evidenced")
        unknown = category("d", None)
        meta = {"b": {"finding_class": "control-not-evidenced"}, "c": {"finding_class": "control-not-evidenced"}}

        report.annotate_finding_classes([from_findings, from_export, mixed, unknown], meta)

        self.assertEqual(from_findings["finding_class"], "weakness-shown")
        self.assertEqual(from_findings["finding_class_label"], "Weakness shown in the model")
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

    def test_split_keeps_every_category_exactly_once(self):
        cats = [category("w", "weakness-shown"), category("c", "control-not-evidenced"), category("u", None)]
        report.annotate_finding_classes(cats, {})

        weaknesses, controls, unclassified = report.split_by_finding_class(cats)

        self.assertEqual([c["slug"] for c in weaknesses], ["w"])
        self.assertEqual([c["slug"] for c in controls], ["c"])
        self.assertEqual([c["slug"] for c in unclassified], ["u"])


if __name__ == "__main__":
    unittest.main()
