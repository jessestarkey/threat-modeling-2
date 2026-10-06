#!/usr/bin/env python3
"""Validates every modular app folder under models/modular-apps-repo/,
independent of either CI workflow's matrix -- matrix membership is not a
prerequisite for being checked. Run this over an app the moment its folder
exists, not only once someone remembers to wire it into a workflow.

This exists because nothing else catches this class of bug:
exposed-ai-chat's 08-risk-tracking-template.yml had the wrong body (see
364525a) and sat undetected for as long as it did specifically because
that app wasn't in the modular workflow's matrix yet -- the one thing
that *did* validate app content only ever ran against apps already
believed to be fine.

Checks per app folder:
  1. Exactly the 8 canonical fragment filenames exist -- no stray or
     misnamed file (5105f80 fixed the *.yml glob's blast radius for
     apps already in the matrix; this catches the same class for an
     app that isn't).
  2. Every technical_asset's communication_link target resolves to a
     real technical asset id.
  3. Every trust_boundary's technical_assets_inside /
     trust_boundaries_nested reference resolves; every non-external,
     non-out-of-scope technical asset is placed in exactly one
     boundary; no boundary is nested under more than one parent.
     (Multiple *root* boundaries are legitimate here -- e.g. a
     CSP-managed identity tenant or an out-of-scope external CDS
     guard domain that isn't inside this app's own cloud subscription
     -- so root count is deliberately not checked.)
  4. Every shared_runtime's technical_assets_running reference
     resolves to a real technical asset id.
  5. tags_available reconciles exactly against tags actually used,
     both directions (used-but-not-declared and declared-but-not-used
     must both be empty).
  6. No title collision between technical_assets and data_assets (see
     6735ebd's runtime warning in generate_report.py -- the same check,
     enforced here before a report is ever generated, not just warned
     about while building one).
  7. No two communication_links share the same (source, target) pair
     (same rationale as #6).

Usage:
  python validate_model.py                  # validate every app folder
  python validate_model.py confluence        # validate just one app
  python validate_model.py confluence llm-chat

Exit code is 0 only if every checked app passes every check.
"""

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
    """Same semantics as the workflows' `yq eval-all '. as $item ireduce
    ({}; . * $item)'` -- later fragments' scalar/list values win, dicts
    merge recursively. Fragments don't overlap in practice (each owns a
    disjoint top-level key), so this is really just a union, but written
    to match the real merge behavior rather than assume that."""
    for k, v in b.items():
        if k in a and isinstance(a[k], dict) and isinstance(v, dict):
            deep_merge(a[k], v)
        else:
            a[k] = v
    return a


def validate_app(app_dir: str) -> list:
    """Returns a list of human-readable error strings; empty means the
    app passed every check."""
    app = os.path.basename(app_dir)
    errors = []

    # 1. Exactly the canonical fragment filenames -- no more, no fewer.
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
        # A missing canonical file means we can't safely merge -- bail out
        # for this app rather than risk validating a half-model.
        if missing:
            return errors

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
                return errors
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

    # 6. No title collision between technical_assets and data_assets --
    # both diagrams' enrichment is keyed by title (see generate_report.py's
    # confidentiality_by_label), so a shared title silently corrupts one.
    shared_titles = set(technical_assets) & set(data_assets)
    if shared_titles:
        errors.append(f"technical_assets and data_assets share title(s), which the report "
                       f"generator's confidentiality shading can't tell apart: "
                       f"{sorted(shared_titles)}")

    # 7. No duplicate (source, target) communication_link pairs -- the
    # diagram filter-links bar can't tell two such links apart (see
    # 6735ebd's runtime warning in generate_report.py).
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

    return errors


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
        errors = validate_app(app_dir)
        if errors:
            overall_ok = False
            print(f"FAIL {app}:")
            for e in errors:
                print(f"  - {e}")
        else:
            print(f"OK   {app}")

    sys.exit(0 if overall_ok else 1)


if __name__ == "__main__":
    main()
