#!/usr/bin/env python3
"""Validates every modular app folder under models/modular-apps-repo/, independent of any CI
workflow's matrix, so an app is checked as soon as its folder exists rather than once someone adds
it to a workflow.

Checks per app folder:
  1. Exactly the 8 canonical fragment filenames exist, with no stray or misnamed file.
  2. Every technical asset's communication_link target resolves to a real technical asset id.
  3. Every trust boundary's technical_assets_inside and trust_boundaries_nested references
     resolve, every in-scope, non-external technical asset sits in exactly one boundary, and no
     boundary has more than one parent. Several root boundaries are legitimate (such as a
     CSP-managed identity tenant outside the app's subscription), so the root count is not
     checked.
  4. Every shared_runtime's technical_assets_running reference resolves to a real technical
     asset id.
  5. tags_available matches the tags actually used, in both directions.
  6. No technical asset and data asset share a title, since the diagrams key their colors by title
     (generate_report.py only warns about this).
  7. No two communication_links share a (source, target) pair, since the diagram filter bar cannot
     tell them apart.
  8. No asset uses a retired tag, such as net:internet-reachable, which the internet_reachable
     field replaced.

It also warns, without failing, about an asset that receives a link from an internet-facing asset
(internet: true) but sets neither internet nor internet_reachable. The author decides, since a
link from the edge does not always carry internet traffic onward (see docs/risk-methodology.md).

Usage:
  python validate_model.py                  # validate every app folder
  python validate_model.py confluence        # validate just one app
  python validate_model.py confluence llm-chat

Exit code is 0 only if every checked app passes every check."""

import glob
import os
import sys

import yaml

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
APPS_ROOT = os.path.abspath(os.path.join(SCRIPT_DIR, "..", "..", "modular-apps-repo"))

CANONICAL_FRAGMENTS = [
    "01-metadata.yml",
    "02-abuse-and-reqs.yml",
    "03-tags.yml",
    "04-data-assets.yml",
    "05-tech-assets.yml",
    "06-boundaries.yml",
    "07-shared-runtimes.yml",
    "08-risk-tracking.yml",
]


def deep_merge(a: dict, b: dict) -> dict:
    """The same semantics as the workflows' `yq eval-all '. as $item ireduce ({}; . * $item)'`:
    later fragments' scalars and lists win, and dicts merge recursively. Fragments own disjoint
    top-level keys, so in practice this is a union."""
    for k, v in b.items():
        if k in a and isinstance(a[k], dict) and isinstance(v, dict):
            deep_merge(a[k], v)
        else:
            a[k] = v
    return a


RETIRED_TAGS = {
    "net:internet-reachable": "set the technical asset's internet_reachable field instead",
}


def internet_reachable_warnings(technical_assets: dict) -> list:
    """Assets that an internet-facing asset links to over a business link, but that set neither
    internet nor internet_reachable. A devops link (log forwarding or management) carries no
    internet traffic onward, so it is skipped."""
    by_id = {n["id"]: (title, n) for title, n in technical_assets.items() if isinstance(n, dict) and "id" in n}
    warnings = []
    for title, node in technical_assets.items():
        if not isinstance(node, dict) or not node.get("internet"):
            continue
        for link in (node.get("communication_links") or {}).values():
            if link.get("usage") == "devops":
                continue
            target_title, target = by_id.get(link.get("target"), (None, None))
            if target is None or target.get("out_of_scope") or target.get("internet") or target.get("internet_reachable"):
                continue
            warnings.append(f"05-tech-assets.yml: '{target_title}' receives a link from internet-facing "
                            f"'{title}' but does not set internet_reachable. Set it if internet "
                            f"traffic reaches this asset through '{title}'.")
    return sorted(set(warnings))


def validate_app(app_dir: str) -> tuple:
    """Returns (errors, warnings) as lists of human-readable strings. The app passes when errors is
    empty."""
    app = os.path.basename(app_dir)
    errors = []

    # 1. Exactly the canonical fragment filenames, no more and no fewer.
    actual = sorted(os.path.basename(f) for f in glob.glob(os.path.join(app_dir, "*.yml")))
    expected = sorted(CANONICAL_FRAGMENTS)
    if actual != expected:
        missing = sorted(set(expected) - set(actual))
        extra = sorted(set(actual) - set(expected))
        if missing:
            errors.append(f"missing fragment file(s): {missing}")
        if extra:
            errors.append(f"unexpected file(s) present (never read by the real merge -- "
                           f"either belongs here as one of the 8 canonical names, or shouldn't "
                           f"be in this folder at all): {extra}")
        # Without every canonical file, the merge is unsafe, so this app stops here rather than
        # validating half a model.
        if missing:
            return errors, []

    model = {}
    for fname in CANONICAL_FRAGMENTS:
        fpath = os.path.join(app_dir, fname)
        if not os.path.exists(fpath):
            continue
        with open(fpath, encoding="utf-8") as f:
            try:
                data = yaml.safe_load(f) or {}
            except yaml.YAMLError as e:
                errors.append(f"{fname}: does not parse as YAML: {e}")
                return errors, []
        deep_merge(model, data)

    technical_assets = model.get("technical_assets") or {}
    data_assets = model.get("data_assets") or {}
    trust_boundaries = model.get("trust_boundaries") or {}
    shared_runtimes = model.get("shared_runtimes") or {}

    assets_by_id = {}
    for title, node in technical_assets.items():
        if not isinstance(node, dict) or "id" not in node:
            errors.append(f"technical_assets.'{title}' has no 'id' field")
            continue
        assets_by_id[node["id"]] = title

    # 2. communication_link targets resolve.
    for title, node in technical_assets.items():
        for link_name, link in (node.get("communication_links") or {}).items():
            target = link.get("target")
            if target not in assets_by_id:
                errors.append(f"05-tech-assets.yml: '{title}' communication_link "
                               f"'{link_name}' targets undefined asset id '{target}'")

    # 3. trust_boundaries: references resolve, placement is exactly-once,
    # exactly one root.
    boundary_ids = set()
    for title, node in trust_boundaries.items():
        if not isinstance(node, dict) or "id" not in node:
            errors.append(f"trust_boundaries.'{title}' has no 'id' field")
            continue
        boundary_ids.add(node["id"])

    nested_by = {}
    placed = {}
    for title, node in trust_boundaries.items():
        for aid in (node.get("technical_assets_inside") or []):
            if aid.startswith("<") and aid.endswith(">"):
                continue  # explicit fill-in-the-blank placeholder, not a real ref
            if aid not in assets_by_id:
                errors.append(f"06-boundaries.yml: '{title}' technical_assets_inside "
                               f"references undefined asset id '{aid}'")
            placed.setdefault(aid, []).append(title)
        for bid in (node.get("trust_boundaries_nested") or []):
            if bid not in boundary_ids:
                errors.append(f"06-boundaries.yml: '{title}' trust_boundaries_nested "
                               f"references undefined boundary id '{bid}'")
            nested_by.setdefault(bid, []).append(title)

    for aid, titles in placed.items():
        if len(titles) > 1:
            errors.append(f"06-boundaries.yml: asset id '{aid}' placed in more than one "
                           f"boundary: {titles}")

    for bid, parents in nested_by.items():
        if len(parents) > 1:
            errors.append(f"06-boundaries.yml: boundary id '{bid}' nested under more than "
                           f"one parent boundary: {parents}")

    non_external_ids = {
        node["id"] for node in technical_assets.values()
        if isinstance(node, dict) and node.get("type") != "external-entity"
        and not node.get("out_of_scope") and "id" in node
    }
    unplaced = non_external_ids - set(placed.keys())
    if unplaced:
        errors.append(f"06-boundaries.yml: asset id(s) never placed in any boundary: "
                       f"{sorted(unplaced)}")

    # 4. shared_runtimes references resolve.
    for title, node in shared_runtimes.items():
        for aid in (node.get("technical_assets_running") or []):
            if aid not in assets_by_id:
                errors.append(f"07-shared-runtimes.yml: '{title}' technical_assets_running "
                               f"references undefined asset id '{aid}'")

    # 5. tags_available reconciles exactly against tags actually used.
    declared = set(model.get("tags_available") or [])
    used = set()

    def collect_tags(node):
        if isinstance(node, dict):
            for t in (node.get("tags") or []):
                used.add(t)

    for node in technical_assets.values():
        collect_tags(node)
        for link in (node.get("communication_links") or {}).values():
            collect_tags(link)
    for node in trust_boundaries.values():
        collect_tags(node)
    for node in shared_runtimes.values():
        collect_tags(node)
    for node in data_assets.values():
        collect_tags(node)

    used_not_declared = sorted(used - declared)
    declared_not_used = sorted(declared - used)
    if used_not_declared:
        errors.append(f"03-tags.yml: tag(s) used but not declared in tags_available: "
                       f"{used_not_declared}")
    if declared_not_used:
        errors.append(f"03-tags.yml: tag(s) declared in tags_available but never used: "
                       f"{declared_not_used}")

    # 6. No title shared by a technical asset and a data asset, since the diagrams key their colors
    # by title (see generate_report.py's confidentiality_by_label).
    shared_titles = set(technical_assets) & set(data_assets)
    if shared_titles:
        errors.append(f"technical_assets and data_assets share title(s), which the report "
                       f"generator's confidentiality shading can't tell apart: "
                       f"{sorted(shared_titles)}")

    # 7. No duplicate (source, target) link pairs, since the diagram filter bar cannot tell them
    # apart.
    seen_pairs = {}
    for title, node in technical_assets.items():
        for link_name, link in (node.get("communication_links") or {}).items():
            target = link.get("target")
            if target not in assets_by_id:
                continue
            pair = (title, assets_by_id[target])
            seen_pairs.setdefault(pair, []).append(link_name)
    for (source, target), names in seen_pairs.items():
        if len(names) > 1:
            errors.append(f"05-tech-assets.yml: '{source}' has {len(names)} separate "
                           f"communication_links to '{target}' ({', '.join(names)}) -- the "
                           f"filter-links bar can't tell them apart")

    # 8. No retired tags.
    for tag in sorted(used & set(RETIRED_TAGS)):
        errors.append(f"tag '{tag}' is retired: {RETIRED_TAGS[tag]}")

    return errors, internet_reachable_warnings(technical_assets)


def main():
    requested = sys.argv[1:]
    if requested:
        app_dirs = [os.path.join(APPS_ROOT, name) for name in requested]
    else:
        app_dirs = sorted(
            d for d in glob.glob(os.path.join(APPS_ROOT, "*"))
            if os.path.isdir(d)
        )

    if not app_dirs:
        print(f"No app folders found under {APPS_ROOT}")
        sys.exit(1)

    overall_ok = True
    for app_dir in app_dirs:
        app = os.path.basename(app_dir)
        if not os.path.isdir(app_dir):
            print(f"FAIL {app}: not a directory ({app_dir})")
            overall_ok = False
            continue
        errors, warnings = validate_app(app_dir)
        if errors:
            overall_ok = False
            print(f"FAIL {app}:")
            for e in errors:
                print(f"  - {e}")
        else:
            print(f"OK   {app}")
        for w in warnings:
            print(f"  warning: {w}")

    sys.exit(0 if overall_ok else 1)


if __name__ == "__main__":
    main()
