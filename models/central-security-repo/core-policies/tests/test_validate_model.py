"""Tests for validate_model.py's internet_reachable checks: the warning for an asset behind an
internet-facing one, and the error for the retired net:internet-reachable tag."""
import os
import sys
import tempfile
import unittest

import yaml

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import validate_model  # noqa: E402


def asset(id_, **fields):
    return {"id": id_, "type": "process", **fields}


def link(target, usage="business"):
    return {"target": target, "usage": usage}


class InternetReachableWarnings(unittest.TestCase):
    def test_an_asset_behind_the_edge_without_the_field_is_flagged(self):
        assets = {"Gateway": asset("gw", internet=True, communication_links={"App": link("app")}),
                  "App": asset("app")}
        warnings = validate_model.internet_reachable_warnings(assets)
        self.assertEqual(len(warnings), 1)
        self.assertIn("'App' receives a link from internet-facing 'Gateway'", warnings[0])

    def test_the_field_or_a_devops_link_silences_the_warning(self):
        assets = {"Gateway": asset("gw", internet=True, communication_links={
                      "App": link("app"), "Logs": link("logs", usage="devops")}),
                  "App": asset("app", internet_reachable=True),
                  "Logs": asset("logs")}
        self.assertEqual(validate_model.internet_reachable_warnings(assets), [])

    def test_links_from_assets_that_are_not_internet_facing_are_ignored(self):
        assets = {"App": asset("app", communication_links={"Db": link("db")}), "Db": asset("db")}
        self.assertEqual(validate_model.internet_reachable_warnings(assets), [])


class RetiredTags(unittest.TestCase):
    def test_the_retired_tag_fails_validation(self):
        with tempfile.TemporaryDirectory() as app:
            fragments = {name: {} for name in validate_model.CANONICAL_FRAGMENTS}
            fragments["03-tags.yml"] = {"tags_available": ["net:internet-reachable"]}
            fragments["05-tech-assets.yml"] = {"technical_assets": {
                "App": asset("app", out_of_scope=True, tags=["net:internet-reachable"])}}
            for name, data in fragments.items():
                with open(os.path.join(app, name), "w", encoding="utf-8") as f:
                    yaml.safe_dump(data, f)
            errors, _ = validate_model.validate_app(app)
        self.assertEqual(errors, ["tag 'net:internet-reachable' is retired: set the technical "
                                  "asset's internet_reachable field instead"])


if __name__ == "__main__":
    unittest.main()
