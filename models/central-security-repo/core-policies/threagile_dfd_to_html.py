#!/usr/bin/env python3
"""
threagile_dfd_to_html.py
Convert a Threagile data-flow-diagram .gv file into a self-contained HTML file
that exactly reproduces the Graphviz layout coordinates.

Usage:
  python threagile_dfd_to_html.py --dot data-flow-diagram.dot --out dfd.html
"""

import argparse
from dataclasses import dataclass
from string import Template
import base64
import functools
import html
import re
import shutil
import subprocess
import sys
import textwrap
from pathlib import Path

PPI = 72.0  # Graphviz points per inch
ICONS_DIR = Path(__file__).resolve().parent / "icons"

# ---------------------------------------------------------------------------
# Design tokens
# ---------------------------------------------------------------------------
# Editorial palette: neutral ink on paper, with one accent color reserved for external and
# out-of-scope entities (Threagile's octagon shape), the diagram's natural focal point. These are
# the LIGHT (print) theme's colors, and DARK below is the on-screen theme. The font
# is local FreeSans, which is what Graphviz resolves "Verdana" to when it sizes node boxes, so
# another font would overflow the precomputed label boxes.
PAPER    = "#ffffff"
INK      = "#1a1a1a"
MUTED    = "#767676"
ACCENT   = "#1a3a5c"   # matches the report's own navy accent (report.css)
HAIRLINE = 1.25
RADIUS   = 6
FONT     = "FreeSans, sans-serif"

# Solid pastel fills per trust-boundary type, lightest first. A boundary nested inside others of
# the same type takes the next shade, so the nesting stays visible, and depth is measured by
# geometric containment in build_svg, since DOT source order is not guaranteed.
#
# These are IL5 models, so the palette is green, which reads as inside the accreditation
# boundary. The exception is network-cloud-provider at depth 0, which is grey: that is always
# the outermost CSP-owned tenant (tagged mgmt:csp-managed), outside this system's ATO boundary.
# Depth 1 of that type is where the model enters its ATO boundary, so the ramp turns green there.
BOUNDARY_FILL = {
    "network-cloud-provider": ["#e9e9e6", "#e6f4ea", "#cfe8d6"],
    "network-cloud-security-group": ["#d3ecda", "#b3ddbe", "#8fcc9f", "#6bbb80"],
    "network-policy-namespace-isolation": ["#eaf7ee", "#d8f0dd"],
    "network-on-prem": ["#e6ece7", "#d4e0d6", "#c2d4c5"],
    "network-dedicated-hoster": ["#e6ece7", "#d4e0d6", "#c2d4c5"],
    "network-virtual-lan": ["#eaf0ea", "#d8e4d8", "#c6d8c6"],
}

# An execution environment never nests inside another, so its own ramp would always give shade
# 0, a color that breaks from the hierarchy around it. Instead, it follows the
# network-cloud-security-group ramp, the type it sits inside, and takes the next shade past its
# parent subnet (see render_cluster and build_svg).
FOLLOWS_RAMP_OF = {
    "execution-environment": "network-cloud-security-group",
}

# Alternate impact-level palettes for a higher-classification model. Uncomment exactly one
# block, since each reassigns BOUNDARY_FILL and the last one wins. Each keeps the grey depth-0
# network-cloud-provider shade and hue-rotates the IL5 green at matching lightness, so the
# nesting still reads. They have not been checked visually, so review one in a browser before
# using it.
#
# IL6, red
# BOUNDARY_FILL = {
#     "network-cloud-provider": ["#e9e6e6", "#f4e6e6", "#e8cfcf"],
#     "network-cloud-security-group": ["#ecd3d3", "#ddb3b3", "#cc8f8f", "#bb6b6b"],
#     "network-policy-namespace-isolation": ["#f7eaea", "#f0d8d8"],
#     "network-on-prem": ["#ece6e6", "#e0d4d4", "#d4c2c2"],
#     "network-dedicated-hoster": ["#ece6e6", "#e0d4d4", "#d4c2c2"],
#     "network-virtual-lan": ["#f0eaea", "#e4d8d8", "#d8c6c6"],
#     # execution-environment follows network-cloud-security-group (see FOLLOWS_RAMP_OF).
# }
#
# IL6+, yellow (the first of three environments that need a distinct hue)
# BOUNDARY_FILL = {
#     "network-cloud-provider": ["#e9e8e6", "#f4f1e6", "#e8e3cf"],
#     "network-cloud-security-group": ["#ece7d3", "#ddd5b3", "#ccc08f", "#bbab6b"],
#     "network-policy-namespace-isolation": ["#f7f4ea", "#f0ebd8"],
#     "network-on-prem": ["#ecebe6", "#e0ded4", "#d4d0c2"],
#     "network-dedicated-hoster": ["#ecebe6", "#e0ded4", "#d4d0c2"],
#     "network-virtual-lan": ["#f0efea", "#e4e2d8", "#d8d4c6"],
#     # execution-environment follows network-cloud-security-group (see FOLLOWS_RAMP_OF).
# }
#
# IL6+, purple (the second environment)
# BOUNDARY_FILL = {
#     "network-cloud-provider": ["#e8e6e9", "#ede6f4", "#dccfe8"],
#     "network-cloud-security-group": ["#e0d3ec", "#c8b3dd", "#ad8fcc", "#926bbb"],
#     "network-policy-namespace-isolation": ["#f0eaf7", "#e4d8f0"],
#     "network-on-prem": ["#e9e6ec", "#dad4e0", "#cbc2d4"],
#     "network-dedicated-hoster": ["#e9e6ec", "#dad4e0", "#cbc2d4"],
#     "network-virtual-lan": ["#edeaf0", "#ded8e4", "#cfc6d8"],
#     # execution-environment follows network-cloud-security-group (see FOLLOWS_RAMP_OF).
# }
#
# IL6+, orange (the third environment)
# BOUNDARY_FILL = {
#     "network-cloud-provider": ["#e9e7e6", "#f4ede6", "#e8dbcf"],
#     "network-cloud-security-group": ["#ecdfd3", "#ddc7b3", "#ccab8f", "#bb8f6b"],
#     "network-policy-namespace-isolation": ["#f7f0ea", "#f0e3d8"],
#     "network-on-prem": ["#ece9e6", "#e0dad4", "#d4cac2"],
#     "network-dedicated-hoster": ["#ece9e6", "#e0dad4", "#d4cac2"],
#     "network-virtual-lan": ["#f0edea", "#e4ded8", "#d8cec6"],
#     # execution-environment follows network-cloud-security-group (see FOLLOWS_RAMP_OF).
# }

# Fill per confidentiality level, used only on the data-asset diagram, which has no trust
# boundaries to shade. It follows the usual classification colors (public green through
# strictly confidential red), distinct from BOUNDARY_FILL, so the two diagrams' colors are not
# read as the same encoding.
CONFIDENTIALITY_FILL = {
    "public": "#eaf7ee",
    "internal": "#eaf1fb",
    "restricted": "#fdf6e3",
    "confidential": "#fbe9dd",
    "strictly-confidential": "#fbe0e0",
}


@dataclass(frozen=True)
class Theme:
    """Every color the diagram and its HTML page use. LIGHT is the print theme, which the PDF
    report embeds, and DARK is the on-screen theme of the standalone .svg and .html files. In DARK,
    boundaries keep a dark grey fill and carry their green in the border and label instead."""
    paper: str              # the canvas
    node_fill: str          # an asset box (a data-asset diagram's confidentiality fill overrides it)
    ink: str                # node borders, primary links, and text
    muted: str              # background links, such as telemetry
    accent: str             # external and out-of-scope entities, and boundary borders in LIGHT
    highlight: str          # the clicked asset, its links, and filtered links
    boundary_fill: dict     # per boundary type, by nesting depth (see BOUNDARY_FILL)
    boundary_stroke: dict   # per boundary type, by nesting depth, or accent where a type is absent
    boundary_stroke_width: float
    confidentiality_fill: dict    # data-asset diagram: node fill per confidentiality level
    confidentiality_stroke: dict  # data-asset diagram: node border per confidentiality level
    page: dict              # the HTML page's own colors (see _CSS)


LIGHT = Theme(
    paper=PAPER, node_fill=PAPER, ink=INK, muted=MUTED, accent=ACCENT, highlight=ACCENT,
    boundary_fill=BOUNDARY_FILL, boundary_stroke={}, boundary_stroke_width=HAIRLINE,
    confidentiality_fill=CONFIDENTIALITY_FILL, confidentiality_stroke={},
    page={"page_bg": "#f0f2f5", "chrome_bg": "#ffffff", "chrome_border": "#dde1e9",
          "title": "#1a1a2e", "badge_bg": "#eef2ff", "badge_text": "#4361ee", "label": "#8a8f98",
          "chip_bg": "#ffffff", "chip_text": "#555555", "chip_hover_border": "#b7bfcc",
          "chip_hover_text": "#1a1a2e", "chip_active_bg": ACCENT, "chip_active_text": "#ffffff",
          "shadow": "rgba(0,0,0,.08)"},
)

# The depth-0 cloud provider (the CSP-owned tenant, outside the ATO boundary) keeps a grey
# border, as it keeps a grey fill in LIGHT. The green brightens with nesting.
DARK = Theme(
    paper="#1b1c1f", node_fill="#2b2d31", ink="#e3e5e8", muted="#8e939b", accent="#7aa7e0",
    highlight="#ffffff",
    boundary_fill={
        "network-cloud-provider": ["#222326", "#26282b", "#2a2c30"],
        "network-cloud-security-group": ["#2c2e32", "#303236", "#34363b", "#383a3f"],
        "network-policy-namespace-isolation": ["#2e3034", "#33353a"],
        "network-on-prem": ["#222326", "#26282b", "#2a2c30"],
        "network-dedicated-hoster": ["#222326", "#26282b", "#2a2c30"],
        "network-virtual-lan": ["#26282b", "#2a2c30", "#2e3034"],
    },
    boundary_stroke={
        "network-cloud-provider": ["#8e939b", "#3f9d5c", "#5cb877"],
        "network-cloud-security-group": ["#4caf6e", "#6bbb80", "#8fcc9f", "#b3ddbe"],
        "network-policy-namespace-isolation": ["#6bbb80", "#8fcc9f"],
        "network-on-prem": ["#3f9d5c", "#5cb877", "#7cc791"],
        "network-dedicated-hoster": ["#3f9d5c", "#5cb877", "#7cc791"],
        "network-virtual-lan": ["#3f9d5c", "#5cb877", "#7cc791"],
    },
    boundary_stroke_width=HAIRLINE * 1.4,
    # The report's confidentiality badge scale (report.css), brightened to read on dark.
    confidentiality_fill={},
    confidentiality_stroke={
        "public": "#7fb069",
        "internal": "#6ea8fe",
        "restricted": "#e6c34a",
        "confidential": "#f08c3a",
        "strictly-confidential": "#e5484d",
    },
    page={"page_bg": "#111214", "chrome_bg": "#1b1c1f", "chrome_border": "#2e3034",
          "title": "#e3e5e8", "badge_bg": "#2b2d31", "badge_text": "#7aa7e0", "label": "#8e939b",
          "chip_bg": "#2b2d31", "chip_text": "#c4c7cc", "chip_hover_border": "#5a5e66",
          "chip_hover_text": "#ffffff", "chip_active_bg": "#e3e5e8", "chip_active_text": "#1b1c1f",
          "shadow": "rgba(0,0,0,.4)"},
)

# Icons, keyed by the value of an icon: tag (see 03-tags-lib.yml, "DIAGRAM ICON TAGS"), as
# paths under ICONS_DIR with one folder per source. The Azure and AWS icons are the official
# architecture icons, vendored unmodified. Their terms permit this use provided an icon is not
# cropped, rotated, or distorted, which is why render_icon() embeds each file's bytes rather than
# redrawing it. To add one, drop the SVG into icons/ and add an entry here.
ICON_FILES = {
    "azure-waf": "azure/azure-waf.svg",
    "azure-ngfw": "azure/azure-ngfw.svg",
    "azure-vnet": "azure/azure-vnet.svg",
    "azure-aks": "azure/azure-aks.svg",
    "azure-key-vault": "azure/azure-key-vault.svg",
    "azure-database": "azure/azure-database.svg",
    "azure-storage": "azure/azure-storage.svg",
    "azure-monitor": "azure/azure-monitor.svg",
    "azure-avd": "azure/azure-avd.svg",
    "azure-entra-id": "azure/azure-entra-id.svg",
    "azure-private-link": "azure/azure-private-link.svg",
    "azure-subscription": "azure/azure-subscription.svg",
    # Azure has one subnet icon for both public and private subnets.
    "azure-subnet": "azure/azure-subnet.svg",
    # A subnet-level security control, tagged alongside icon:azure-subnet rather than instead of
    # it.
    "azure-nsg": "azure/azure-nsg.svg",
    # AWS: one tag per Azure counterpart above (aws-vpc for azure-vnet, aws-eks for azure-aks).
    "aws-waf": "aws/aws-waf.svg",
    "aws-ngfw": "aws/aws-ngfw.svg",
    "aws-vpc": "aws/aws-vpc.svg",
    "aws-eks": "aws/aws-eks.svg",
    "aws-secrets-manager": "aws/aws-secrets-manager.svg",
    "aws-database": "aws/aws-database.svg",
    "aws-storage": "aws/aws-storage.svg",
    "aws-monitor": "aws/aws-monitor.svg",
    "aws-workspaces": "aws/aws-workspaces.svg",
    "aws-identity-center": "aws/aws-identity-center.svg",
    "aws-private-link": "aws/aws-private-link.svg",
    "aws-organizations": "aws/aws-organizations.svg",
    "aws-cloud": "aws/aws-cloud.svg",
    # AWS has separate public and private subnet icons, so both are kept as tags.
    "aws-subnet-public": "aws/aws-subnet-public.svg",
    "aws-subnet-private": "aws/aws-subnet-private.svg",
    # AWS has no NSG icon. A NACL is the closest analog, since both apply at the subnet, so it is
    # tagged alongside icon:aws-subnet-public or icon:aws-subnet-private.
    "aws-nacl": "aws/aws-nacl.svg",
    # AWS services with no Azure counterpart tag.
    "aws-bedrock": "aws/aws-bedrock.svg",
    "aws-api-gateway": "aws/aws-api-gateway.svg",
    "aws-alb": "aws/aws-alb.svg",
    "azure-app-gateway": "azure/azure-app-gateway.svg",
    "azure-load-balancer": "azure/azure-load-balancer.svg",
    "azure-openai": "azure/azure-openai.svg",
    "azure-management-groups": "azure/azure-management-groups.svg",
    # Kubernetes icons, independent of the cloud provider, so one tag covers a namespace under AKS
    # or EKS (see 03-tags-lib.yml).
    "k8s-namespace": "opensource/k8s-namespace.svg",
    "kubernetes": "opensource/kubernetes.svg",
    # Software that runs inside an application's own compute, independent of any cloud provider.
    # Each is a Simple Icons glyph (CC0) recolored onto a 64x64 brand-colored square, the same
    # visual language as the vendor sets. Confluence is commercial, but it is built the same way.
    "keycloak": "opensource/keycloak.svg",
    "postgresql": "opensource/postgresql.svg",
    "nginx": "opensource/nginx.svg",
    "temporal": "opensource/temporal.svg",
    "qdrant": "opensource/qdrant.svg",
    "confluence": "opensource/confluence.svg",
    "splunk": "opensource/splunk.svg",
    "jira": "opensource/jira.svg",
    "gitlab": "opensource/gitlab.svg",
    "litellm": "opensource/litellm.svg",
    "k8s-secret-csi": "opensource/k8s-secret-csi.svg",
    "etcd": "opensource/etcd.svg",
    "guacamole": "opensource/guacamole.svg",
    "vault": "opensource/vault.svg",
    "grafana": "opensource/grafana.svg",
    "mcp": "opensource/mcp.svg",
    # Generic external-actor icons, not product logos (see icons/NOTICE.md).
    "human-web": "opensource/human-web.svg",
    "human-vdi": "opensource/human-vdi.svg",
    "machine-client": "opensource/machine-client.svg",
    # A generic badge for the execution-environment boundary type, not a product logo (see
    # icons/NOTICE.md).
    "execution-environment": "opensource/execution-environment.svg",
    # Open WebUI's official favicon, a raster PNG in an SVG wrapper and its only logo asset. It is
    # vendored unmodified (see BRANDING.md in its repository).
    "open-webui": "opensource/open-webui.svg",
}

ICON_MARGIN = 3  # inset from the boundary's own corner (render_icon's anchor)

# Security-control icons (NSG and NACL) go in the boundary's top-left corner, apart from its
# identity icon at the top right, since one says what the boundary is and the other what governs
# it. Keyed by ICON_FILES tag name (see render_cluster).
BOUNDARY_LEFT_CORNER_ICONS = frozenset({"azure-nsg", "aws-nacl"})

NODE_ICON_GAP  = 4   # vertical gap between a node's icon row and its label's first line
NODE_ICON_MIN  = 12  # the smallest a node icon shrinks to on a short box before it is dropped, still legible as a vector
# Every node icon renders at this size, so the same kind of icon reads the same across a
# diagram. render_node still shrinks it (down to NODE_ICON_MIN) on a box too small to fit it.
NODE_ICON_TARGET_SIZE = 30
NODE_ICON_ROW_GAP = 6  # horizontal gap between side-by-side icons when a node has more than one

# Trust boundary corner badges match a node's icon size, so the two read at the same weight.
ICON_SIZE = NODE_ICON_TARGET_SIZE

# AWS icons, and this project's own opensource/ squares, fill their viewBox edge to edge, while
# Azure's line art leaves a margin, so at the same size a full-bleed icon reads larger. The scale
# applies only to boundary badges in render_icon(), and only to the icons listed in
# FULL_BLEED_BOUNDARY_ICONS. It is 1.0, so a badge renders at exactly ICON_SIZE, and it stays a
# named constant in case a future icon set needs a reduction.
FULL_BLEED_BOUNDARY_ICON_SCALE = 1.0
FULL_BLEED_BOUNDARY_ICONS = frozenset({
    "opensource/k8s-namespace.svg",
})

# Node label font size, shared by wrap_and_fit (which wraps to it) and render_node (which draws
# at it), since a mismatch between the two overflows a box.
NODE_FONTSIZE  = 11
# The data-asset diagram's boxes are wide for its short labels, so it can use a larger font.
NODE_FONTSIZE_DATA_ASSET = 24
EDGE_FONTSIZE       = 10  # primary (solid) edges
EDGE_FONTSIZE_MINOR = 8   # dashed background edges (such as telemetry), smaller than primary ones
CLUSTER_FONTSIZE = NODE_FONTSIZE  # trust-boundary label, the same size as node labels (the data-asset diagram has no boundaries)

# The fixed pixel sizes above are scaled per diagram. A diagram with a narrower native layout
# gets a larger px_per_in, so its boxes render larger, and fixed-size text and icons would look
# undersized in them. build_svg multiplies each size by px_per_in divided by this baseline,
# clamped so a tiny diagram cannot push sizes to extremes. The baseline is the scale the sizes
# were tuned at.
DIAGRAM_SCALE_BASELINE_PX_PER_IN = 32.0
DIAGRAM_SCALE_MIN = 0.6
DIAGRAM_SCALE_MAX = 1.8


@functools.lru_cache(maxsize=None)
def _icon_data_uri(filename: str) -> str:
    data = (ICONS_DIR / filename).read_bytes()
    b64 = base64.b64encode(data).decode("ascii")
    return f"data:image/svg+xml;base64,{b64}"


# Icons that WeasyPrint renders without their gradient background, though browsers and cairosvg
# draw them correctly, so the PDF uses a raster copy. The list holds only icons tested alone in
# WeasyPrint, since the attribute that looks responsible (a rotate() in gradientTransform) also
# appears in icons that render fine. Test a new icon the same way before adding it.
ICONS_NEEDING_PRINT_RASTER = frozenset({
    "azure/azure-app-gateway.svg",
    # Confirmed blank in an isolated WeasyPrint render, like azure-app-gateway.svg.
    "azure/azure-openai.svg",
})


def _icon_needs_print_raster(filename: str) -> bool:
    """Whether an icon needs the raster copy in the PDF (see _icon_data_uri_raster). The standalone
    SVG and HTML files never use it."""
    return filename in ICONS_NEEDING_PRINT_RASTER


@functools.lru_cache(maxsize=None)
def _icon_data_uri_raster(filename: str) -> str:
    """The raster fallback for _icon_needs_print_raster() icons, used only in the PDF copy of the
    diagram, since only WeasyPrint mishandles them. The vendored SVG is never modified.

    It reads a prebuilt <name>-print.png (256x256, larger than any size used) next to the source SVG,
    so the report needs no cairosvg at run time, which matters on an air-gapped build. Regenerate the
    PNG only when its source SVG is replaced (cairosvg.svg2png(url=..., output_width=256,
    output_height=256), see icons/NOTICE.md)."""
    svg_path = ICONS_DIR / filename
    png_path = svg_path.with_name(svg_path.stem + "-print.png")
    png_bytes = png_path.read_bytes()
    b64 = base64.b64encode(png_bytes).decode("ascii")
    return f"data:image/png;base64,{b64}"


def _resolve_icon_file(tag: str) -> str:
    """Looks up ICON_FILES[tag] and confirms the vendored SVG actually
    exists on disk. Returns "" (falsy) rather than raising for an
    unrecognized tag, since a model author can tag an asset with any
    icon: value regardless of whether this pilot set defines it yet --
    both render_icon() and render_icon_centered() treat that as "no icon"."""
    filename = ICON_FILES.get(tag)
    if not filename or not (ICONS_DIR / filename).exists():
        return ""
    return filename


def _icon_source(filename: str) -> str:
    """The first path segment of an ICON_FILES value (such as "azure" from "azure/azure-vnet.svg"),
    looked up in ICON_SOURCE_SCALE."""
    return filename.split("/", 1)[0]


# Per-source size correction for node icons. Every source renders at 1.0, since the per-diagram
# scaling (see DIAGRAM_SCALE_BASELINE_PX_PER_IN) removed the visible size difference between
# Azure's margined icons and the full-bleed ones. It stays a dict for a future icon set.
ICON_SOURCE_SCALE = {}


def _icon_href(filename: str, for_print: bool) -> str:
    """SVG data URI normally; PNG data URI when both for_print (this
    build_svg call is for the PDF-embedded diagram, not the standalone
    SVG/HTML files) and this specific icon needs the WeasyPrint workaround
    -- see _icon_needs_print_raster."""
    if for_print and _icon_needs_print_raster(filename):
        return _icon_data_uri_raster(filename)
    return _icon_data_uri(filename)


def render_icon(corner_x: float, top_y: float, tags, color: str,
                 for_print: bool = False, anchor: str = "right",
                 icon_size: float = ICON_SIZE) -> str:
    """Places a trust boundary's corner badge, one icon per tag in `tags` (a string or a list),
    inset from (corner_x, top_y). With anchor="right", the row starts at the top-right corner and
    extends left. With anchor="left", it starts at the top-left corner and extends right, which is
    used for the security-control icons (see BOUNDARY_LEFT_CORNER_ICONS). `color` is unused, since
    the vendored icons keep their official colors, and the terms of use forbid recoloring them.
    build_svg passes a per-diagram icon_size (see DIAGRAM_SCALE_BASELINE_PX_PER_IN)."""
    if isinstance(tags, str):
        tags = [tags]
    filenames = [f for f in (_resolve_icon_file(t) for t in tags) if f]
    if not filenames:
        return ""
    out = []
    cursor = corner_x + ICON_MARGIN if anchor == "left" else corner_x - ICON_MARGIN
    for filename in filenames:
        # Full-bleed icons scale per icon (see FULL_BLEED_BOUNDARY_ICON_SCALE), so one such icon
        # in a mixed row does not shrink the others.
        needs_scale = filename.startswith("aws/") or filename in FULL_BLEED_BOUNDARY_ICONS
        size = icon_size * FULL_BLEED_BOUNDARY_ICON_SCALE if needs_scale else icon_size
        x = cursor if anchor == "left" else cursor - size
        y = top_y + ICON_MARGIN
        href = _icon_href(filename, for_print)
        out.append(f'<image href="{href}" x="{x:.2f}" y="{y:.2f}" '
                    f'width="{size}" height="{size}"/>')
        cursor = (x + size + NODE_ICON_ROW_GAP) if anchor == "left" else (x - NODE_ICON_ROW_GAP)
    return "\n".join(out)


def render_icon_centered(cx: float, top_y: float, tag: str, size: float = NODE_ICON_TARGET_SIZE, for_print: bool = False) -> str:
    """Places a node's primary icon centered on cx with its top edge at top_y, as opposed to a
    boundary's corner badge (render_icon). render_node always passes the size, shrinking it on a
    short box, so the default is only a fallback."""
    filename = _resolve_icon_file(tag)
    if not filename:
        return ""
    href = _icon_href(filename, for_print)
    x = cx - size / 2
    return (f'<image href="{href}" x="{x:.2f}" y="{top_y:.2f}" '
            f'width="{size}" height="{size}"/>')


# ---------------------------------------------------------------------------
# 1. Run dot -Tplain
# ---------------------------------------------------------------------------

def run_dot_plain(dot_source: str) -> str:
    dot_bin = shutil.which("dot")
    if not dot_bin:
        sys.exit("ERROR: 'dot' (Graphviz) not found on PATH.")
    result = subprocess.run(
        [dot_bin, "-Tplain"],
        input=dot_source.encode(),
        capture_output=True,
    )
    if result.returncode != 0:
        sys.exit("ERROR: dot failed:\n" + result.stderr.decode(errors="replace"))
    return result.stdout.decode(errors="replace")


# ---------------------------------------------------------------------------
# 2. Parse plain output
# ---------------------------------------------------------------------------

def _tokenise(line: str) -> list:
    """Tokenise respecting quoted strings and HTML angle-bracket labels."""
    tokens = []
    i = 0
    while i < len(line):
        if line[i].isspace():
            i += 1
            continue
        if line[i] == '"':
            j = i + 1
            while j < len(line):
                if line[j] == '"' and line[j-1] != '\\':
                    break
                j += 1
            tokens.append(line[i+1:j].replace('\\"', '"'))
            i = j + 1
        elif line[i] == '<':
            depth = 0
            j = i
            while j < len(line):
                if line[j] == '<': depth += 1
                elif line[j] == '>':
                    depth -= 1
                    if depth == 0:
                        break
                j += 1
            tokens.append(line[i:j+1])
            i = j + 1
        else:
            j = i
            while j < len(line) and not line[j].isspace():
                j += 1
            tokens.append(line[i:j])
            i = j
    return tokens


def strip_html(s: str) -> str:
    """Extract plain text from an HTML label."""
    s = s.strip()
    # Remove outer < > wrapper
    if s.startswith('<') and s.endswith('>'):
        s = s[1:-1]
    # Strip all HTML tags
    s = re.sub(r'<[^>]+>', ' ', s)
    # Decode entities
    s = s.replace('&lt;', '<').replace('&gt;', '>').replace('&amp;', '&').replace('&quot;', '"').replace('&nbsp;', ' ')
    # Collapse whitespace
    s = re.sub(r'\s+', ' ', s).strip()
    return s


def extract_bold_text(s: str) -> str:
    """Extracts the asset name from a Threagile HTML label, <b><font color=...>Asset Name</font></b>.

    Threagile HTML-escapes the label (an "&" becomes "&amp;"), so the match is unescaped, both for
    matching against the model's asset titles and to avoid a doubled "&amp;amp;" in the SVG."""
    s = s.strip()
    if s.startswith('<') and s.endswith('>'):
        s = s[1:-1]

    # Primary: <b><font ...>TEXT</font></b>
    m = re.search(r'<b[^>]*><font[^>]*>([^<]+)</font></b>', s)
    if m:
        return html.unescape(m.group(1).strip())

    # Secondary: <b>TEXT</b> with optional nested tags
    m = re.search(r'<b[^>]*>(?:<[^>]+>)?([^<]+)(?:<[^>]+>)?</b>', s)
    if m:
        return html.unescape(m.group(1).strip())

    # Fallback: strip all tags
    text = re.sub(r'<[^>]+>', ' ', s)
    text = re.sub(r'\s+', ' ', text).strip()
    return html.unescape(text)


def parse_plain(plain: str) -> dict:
    nodes = {}
    edges = []
    graph_info = {}
    STYLES = {"solid", "dashed", "dotted", "bold", "invis", "filled"}

    for raw_line in plain.splitlines():
        t = _tokenise(raw_line)
        if not t:
            continue

        if t[0] == "graph":
            graph_info = {
                "scale":  float(t[1]),
                "width":  float(t[2]),
                "height": float(t[3]),
            }

        elif t[0] == "node":
            nid       = t[1]
            x, y      = float(t[2]), float(t[3])
            w, h      = float(t[4]), float(t[5])
            raw_label = t[6] if len(t) > 6 else nid
            style     = t[7] if len(t) > 7 else "solid"
            shape     = t[8] if len(t) > 8 else "ellipse"
            color     = t[9] if len(t) > 9 else "black"
            fillcolor = t[10] if len(t) > 10 else "white"

            # Prefer label from DOT source attrs (more reliable for HTML table labels)
            label = extract_bold_text(raw_label)
            if not label or label in (r'\N', '\\N') or label == nid:
                label = nid  # will be overridden later from dot_attrs

            nodes[nid] = dict(
                id=nid, x=x, y=y, w=w, h=h,
                label=label, style=style, shape=shape,
                color=color, fillcolor=fillcolor,
            )

        elif t[0] == "edge":
            tail = t[1]
            head = t[2]
            n    = int(t[3])
            pts  = []
            idx  = 4
            for _ in range(n):
                pts.append((float(t[idx]), float(t[idx+1])))
                idx += 2
            label = ""
            lx, ly = None, None
            if idx < len(t) and t[idx] not in STYLES:
                label = strip_html(t[idx]); idx += 1
                if idx + 1 < len(t):
                    try:
                        lx, ly = float(t[idx]), float(t[idx+1])
                        idx += 2
                    except ValueError:
                        pass
            style = t[idx]   if idx   < len(t) else "solid"
            color = t[idx+1] if idx+1 < len(t) else "#999999"
            edges.append(dict(
                tail=tail, head=head, points=pts,
                label=label, lx=lx, ly=ly,
                style=style, color=color,
            ))

    return dict(graph=graph_info, nodes=list(nodes.values()), edges=edges)


# ---------------------------------------------------------------------------
# 3. Extract node attributes from DOT source
# ---------------------------------------------------------------------------

def parse_dot_node_attrs(dot_source: str) -> dict:
    """Extract per-node attributes directly from DOT source."""
    attrs = {}
    # Node blocks, "ID [ ... ];", across lines. Anchored to the start of a line, since an
    # unanchored match also catches an edge's head id ("A -> B [ ... ];") and would overwrite that
    # node's attributes with the edge's.
    pattern = re.compile(r'^[ \t]*(\d+)\s*\[\s*\n?(.*?)\s*\]\s*;', re.DOTALL | re.MULTILINE)
    for m in pattern.finditer(dot_source):
        nid  = m.group(1)
        body = m.group(2)
        d    = {}
        # Extract key=<html_label> using depth tracking
        pos = 0
        while pos < len(body):
            km = re.search(r'(\w+)\s*=\s*', body[pos:])
            if not km: break
            kstart = pos + km.start()
            vstart = pos + km.end()
            k = km.group(1)
            pos = vstart
            if pos >= len(body): break
            if body[pos] == '<':
                # HTML label - track depth
                depth = 0
                j = pos
                while j < len(body):
                    if body[j] == '<': depth += 1
                    elif body[j] == '>':
                        depth -= 1
                        if depth == 0:
                            break
                    j += 1
                d[k] = body[pos:j+1]
                pos = j + 1
            elif body[pos] == '"':
                j = pos + 1
                while j < len(body) and not (body[j] == '"' and body[j-1] != '\\'):
                    j += 1
                d[k] = body[pos+1:j]
                pos = j + 1
            else:
                j = pos
                while j < len(body) and body[j] not in (' ', '\t', '\n', ',', ']'):
                    j += 1
                d[k] = body[pos:j]
                pos = j
        attrs[nid] = d
    return attrs


def _extract_angle_bracket(text: str, start: int):
    """Extract a full <<...>> HTML label respecting nested angle brackets."""
    if start >= len(text) or text[start] != '<':
        return None, start
    depth = 0
    i = start
    while i < len(text):
        if text[i] == '<': depth += 1
        elif text[i] == '>':
            depth -= 1
            if depth == 0:
                return text[start:i+1], i+1
        i += 1
    return None, start


def _iter_clusters(dot_source: str):
    """
    Yield (cluster_id, graph_attrs_block) for every cluster in the DOT source,
    handling arbitrary nesting depth by tracking brace depth manually.
    graph_attrs_block is the text inside the 'graph [ ... ]' statement of that cluster.
    """
    i = 0
    n = len(dot_source)
    # Find every occurrence of 'subgraph cluster_NNN {'
    header_re = re.compile(r'subgraph\s+cluster_(\d+)\s*\{', re.DOTALL)
    for hm in header_re.finditer(dot_source):
        cid = hm.group(1)
        # Find the graph [ ... ] block immediately inside this cluster
        # It starts right after the opening brace
        body_start = hm.end()
        # Extract just the graph [...] portion (first graph [...] inside)
        gm = re.search(r'\bgraph\s*\[', dot_source[body_start:body_start+2000])
        if not gm:
            continue
        bracket_start = body_start + gm.end() - 1  # position of '['
        # Find matching ']' tracking depth
        depth = 0
        j = bracket_start
        while j < n:
            if dot_source[j] == '[': depth += 1
            elif dot_source[j] == ']':
                depth -= 1
                if depth == 0:
                    break
            j += 1
        graph_block = dot_source[bracket_start+1:j]
        yield cid, graph_block


def parse_dot_cluster_attrs(dot_source: str) -> list:
    """Extract cluster subgraph labels and styles, skipping layout-only spacers."""
    clusters = []
    seen = set()
    for cid, graph_block in _iter_clusters(dot_source):
        if cid in seen:
            continue

        # Skip invisible spacer clusters
        style_m = re.search(r'\bstyle\s*=\s*"([^"]*)"', graph_block)
        style = style_m.group(1) if style_m else "dashed"
        if "invis" in style:
            continue

        # The trust-boundary type follows the closing </b> as plain text (such as
        # "<b>DMZ VNet</b> (network-cloud-security-group)"), so it is extracted separately.
        label = ""
        boundary_type = ""
        lm = re.search(r'label\s*=\s*(<)', graph_block)
        if lm:
            raw, _ = _extract_angle_bracket(graph_block, lm.start(1))
            if raw:
                type_m = re.search(r'</b>\s*\(([a-z][a-z-]*)\)', raw)
                if type_m:
                    boundary_type = type_m.group(1)
                # <b><font ...>NAME</font></b>. Threagile HTML-escapes the label, so it is unescaped
                # here, or an "&" would be escaped twice in the SVG.
                bm = re.search(r'<b[^>]*><font[^>]*>([^<]+)</font></b>', raw)
                if bm:
                    label = html.unescape(bm.group(1).strip())
                else:
                    # Fallback: any <b>TEXT</b>
                    bm2 = re.search(r'<b[^>]*>([^<]+)</b>', raw)
                    if bm2:
                        label = html.unescape(bm2.group(1).strip())
        if not label:
            lm2 = re.search(r'label\s*=\s*"([^"]*)"', graph_block)
            if lm2:
                label = html.unescape(lm2.group(1).strip())
        if not label:
            continue
        # Strip trust boundary type suffix e.g. " (network-cloud-provider)"
        # in case it ended up inside the matched label text after all.
        label = re.sub(r'\s*\([^)]+\)\s*$', '', label).strip()

        color_m    = re.search(r'\bcolor\s*=\s*"([^"]*)"',    graph_block)
        bgcolor_m  = re.search(r'\bbgcolor\s*=\s*"([^"]*)"',  graph_block)
        penwidth_m = re.search(r'\bpenwidth\s*=\s*"([^"]*)"', graph_block)

        color    = color_m.group(1)    if color_m    else "#3A52C8"
        bgcolor  = bgcolor_m.group(1)  if bgcolor_m  else "none"
        penwidth = float(penwidth_m.group(1)) if penwidth_m else 2.0

        seen.add(cid)
        clusters.append(dict(
            id=cid, label=label, color=color, boundary_type=boundary_type,
            bgcolor=bgcolor, style=style, penwidth=penwidth,
        ))
    return clusters


def parse_dot_edge_xlabels(dot_source: str) -> dict:
    """Extract xlabel attributes from edges in DOT source. Returns {(tail,head): label}."""
    xlabels = {}
    for m in re.finditer(r'(\d+)\s*->\s*(\d+)\s*\[([^\]]+)\]', dot_source, re.DOTALL):
        tail, head = m.group(1), m.group(2)
        xl = re.search(r'xlabel\s*=\s*"([^"]+)"', m.group(3))
        if xl:
            xlabels[(tail, head)] = xl.group(1)
    return xlabels


def parse_dot_cluster_bbs(dot_source: str) -> tuple:
    """
    Run dot -Tdot to get:
      - bb= bounding boxes for all clusters  → dict {cluster_id: [x0,y0,x1,y1]}
      - xlp= label positions for all edges   → dict {(tail,head): (x,y)} in points

    Returns (bbs, xlp_positions).
    """
    dot_bin = shutil.which("dot")
    if not dot_bin:
        return {}, {}
    try:
        result = subprocess.run(
            [dot_bin, "-Tdot"],
            input=dot_source.encode(),
            capture_output=True,
            timeout=30,
        )
        if result.returncode != 0:
            return {}, {}
        annotated = result.stdout.decode(errors="replace")
    except Exception:
        return {}, {}

    # Cluster bounding boxes
    bbs = {}
    for cid, graph_block in _iter_clusters(annotated):
        bb_m = re.search(r'\bbb\s*=\s*"([^"]+)"', graph_block)
        if bb_m:
            parts = [float(v) for v in bb_m.group(1).split(",")]
            if len(parts) == 4:
                bbs[cid] = parts

    # Edge xlabel positions (xlp attribute in dot -Tdot output)
    xlp = {}
    for m in re.finditer(
        r'(\d+)\s*->\s*(\d+)\s*\[([^\]]*xlp\s*=\s*"[^"]*"[^\]]*)\]',
        annotated, re.DOTALL
    ):
        tail, head, attrs = m.group(1), m.group(2), m.group(3)
        xlp_m = re.search(r'xlp\s*=\s*"([^"]+)"', attrs)
        if xlp_m:
            coords = [float(v) for v in xlp_m.group(1).split(",")]
            if len(coords) == 2:
                xlp[(tail, head)] = (coords[0], coords[1])

    return bbs, xlp


# ---------------------------------------------------------------------------
# 4. Color helpers
# ---------------------------------------------------------------------------

_NAMED = {
    "white": "#ffffff", "black": "#000000", "blue": "#0000ff",
    "red": "#ff0000", "green": "#008000", "gray": "#808080",
    "grey": "#808080", "lightgrey": "#d3d3d3", "none": "none",
}

def to_hex(c: str) -> str:
    if not c: return "#000000"
    c = c.strip().strip('"')
    if c.startswith('#'): return c
    return _NAMED.get(c.lower(), c)

def luminance(h: str) -> float:
    h = h.lstrip('#')
    if len(h) == 3: h = h[0]*2+h[1]*2+h[2]*2
    if len(h) != 6: return 0.5
    r,g,b = int(h[0:2],16),int(h[2:4],16),int(h[4:6],16)
    return (0.299*r+0.587*g+0.114*b)/255

def text_color(bg: str) -> str:
    bg = to_hex(bg)
    if bg == "none": return "#333333"
    return "#ffffff" if luminance(bg) < 0.55 else "#111111"


# ---------------------------------------------------------------------------
# 5. SVG shape renderers
# ---------------------------------------------------------------------------

def svg_rect(cx, cy, w, h, fill, stroke, sw, rx=6, dash=""):
    da = f' stroke-dasharray="{dash}"' if dash else ""
    return (f'<rect x="{cx-w/2:.2f}" y="{cy-h/2:.2f}" width="{w:.2f}" height="{h:.2f}" '
            f'rx="{rx}" fill="{fill}" stroke="{stroke}" stroke-width="{sw:.1f}"{da}/>')

def wrap_label(text: str, max_width: float, fontsize: float) -> list:
    """Greedy word wrap to fit max_width, estimating FreeSans's average character width at 0.6x
    the font size, a safe upper bound for mixed-case text. A node's native box can still be too
    narrow for an unwrapped label once the diagram is scaled to the page."""
    max_chars = max(4, int(max_width / (fontsize * 0.6)))
    words = text.split()
    lines, cur = [], ""
    for word in words:
        candidate = f"{cur} {word}".strip()
        if len(candidate) <= max_chars or not cur:
            cur = candidate
        else:
            lines.append(cur)
            cur = word
    if cur:
        lines.append(cur)
    return lines or [text]


def wrap_and_fit(label: str, native_w: float, fontsize: float) -> tuple:
    """Word-wraps label against the node's native Graphviz width. Returns (lines, native_w).

    The width is deliberately left as it is. Graphviz routed every edge against the original box,
    so shrinking the box would leave _clip_and_shift pulling endpoints to a boundary the path never
    reached, which shows as floating arrows on edges that approach from the side."""
    lines = wrap_label(label, native_w * 0.85, fontsize)
    return lines, native_w


def render_node(node: dict, cx: float, cy: float, w: float, h: float,
                dot_attrs: dict, lines: list, confidentiality: str = None, icon_tags: list = None,
                fontsize: float = NODE_FONTSIZE, for_print: bool = False,
                icon_target_size: float = NODE_ICON_TARGET_SIZE, theme: Theme = LIGHT) -> str:
    """lines is the label already wrapped by the caller against the node's native Graphviz width
    (see wrap_and_fit), so the wrapping stays stable."""
    nid   = node["id"]
    extra = dot_attrs.get(nid, {})

    shape  = extra.get("shape", node["shape"]).lower()
    style  = extra.get("style", node["style"]).lower()
    periph = int(extra.get("peripheries", "1"))

    # External and out-of-scope entities (Threagile's octagons) get an accent-colored border
    # rather than a fill, which kept their labels readable. Everything else is ink on paper.
    # On the data-asset diagram, a node's confidentiality level shows as its fill in LIGHT and as
    # a heavier border in DARK (see Theme), which replaces the accent there.
    is_accent = shape == "octagon"
    fill      = theme.confidentiality_fill.get(confidentiality) or theme.node_fill
    level_edge = theme.confidentiality_stroke.get(confidentiality)
    stroke    = level_edge or (theme.accent if is_accent else theme.ink)
    sw        = HAIRLINE * 2.0 if level_edge else HAIRLINE

    dash = "5,3" if "dotted" in style else ("8,4" if "dashed" in style else "")

    # Every node is a plain rect, whatever Threagile's shape, so a flat arrowhead meets a flat
    # edge with no overlap. `shape` still decides the external-entity accent.
    shape_svg = svg_rect(cx, cy, w, h, fill, stroke, sw, rx=RADIUS, dash=dash)

    # Double border (peripheries=2) — draw a second slightly smaller rect
    periph_svg = ""
    if periph >= 2:
        inset = sw * 2 + 2
        periph_svg = svg_rect(cx, cy, w-inset, h-inset, "none", stroke, sw*0.6, rx=RADIUS-2)

    fc       = text_color(fill)
    line_h   = fontsize * 1.4
    total_h  = line_h * len(lines)

    # A node's icons are its primary identifier, so they sit in one row above the label, centered
    # with it as one block. Nodes without an icon keep a vertically centered label.
    #
    # Graphviz sizes each box for its own larger native label, so on a short box a wrapped label
    # can leave little room. The icon row shrinks (down to NODE_ICON_MIN per icon) to fit the
    # remaining height, and the width for several icons, and is dropped if even that does not fit.
    node_icon_svg = ""
    icon_tags = [t for t in (icon_tags or []) if _resolve_icon_file(t)]
    if icon_tags:
        n           = len(icon_tags)
        available_h = max(0.0, h * 0.92 - total_h - NODE_ICON_GAP)
        icon_size   = min(icon_target_size, available_h)
        if n > 1:
            available_w = max(0.0, w * 0.92 - (n - 1) * NODE_ICON_ROW_GAP)
            icon_size   = min(icon_size, available_w / n)
        if icon_size >= NODE_ICON_MIN:
            block_h   = icon_size + NODE_ICON_GAP + total_h
            block_top = cy - block_h / 2
            row_w     = n * icon_size + (n - 1) * NODE_ICON_ROW_GAP
            row_left  = cx - row_w / 2
            for i, tag in enumerate(icon_tags):
                icon_cx    = row_left + i * (icon_size + NODE_ICON_ROW_GAP) + icon_size / 2
                # icon_size is the reserved footprint, so the layout above is unaffected, and only the
                # drawn image is scaled per ICON_SOURCE_SCALE, centered in that cell.
                scale      = ICON_SOURCE_SCALE.get(_icon_source(_resolve_icon_file(tag)), 1.0)
                drawn_size = icon_size * scale
                icon_top   = block_top + (icon_size - drawn_size) / 2
                node_icon_svg += render_icon_centered(icon_cx, icon_top, tag, size=drawn_size, for_print=for_print)
            start_y = block_top + icon_size + NODE_ICON_GAP + line_h * 0.8
        else:
            start_y = cy - total_h / 2 + line_h * 0.8
    else:
        start_y = cy - total_h / 2 + line_h * 0.8

    text_parts = []
    for i, line in enumerate(lines):
        y = start_y + i * line_h
        text_parts.append(
            f'<text x="{cx:.2f}" y="{y:.2f}" text-anchor="middle" '
            f'font-size="{fontsize}" font-weight="700" '
            f'font-family="{FONT}" fill="{fc}">'
            f'{html.escape(line)}</text>'
        )

    return shape_svg + "\n" + periph_svg + "\n" + "\n".join(text_parts) + "\n" + node_icon_svg


# ---------------------------------------------------------------------------
# 6. Edge renderer
# ---------------------------------------------------------------------------

def _pts_close(a: tuple, b: tuple, eps: float = 0.01) -> bool:
    return abs(a[0] - b[0]) < eps and abs(a[1] - b[1]) < eps


def _clip_to_box(qx: float, qy: float, px: float, py: float,
                  cx: float, cy: float, hw: float, hh: float) -> tuple:
    """Where the ray from Q=(qx,qy) through P=(px,py) crosses the boundary of the axis-aligned box
    centered at (cx,cy) with half-width and half-height hw and hh. dot -Tplain's spline endpoints
    sometimes fall visibly short of or past the node boundary, so edges are clipped here. Every node
    is a plain rect (see render_node), so this is the only clip shape needed."""
    dx, dy = px - qx, py - qy
    if dx == 0 and dy == 0:
        return px, py
    candidates = []
    if dx != 0:
        for bx in (cx - hw, cx + hw):
            t = (bx - qx) / dx
            y = qy + t * dy
            if cy - hh - 1e-6 <= y <= cy + hh + 1e-6:
                candidates.append(t)
    if dy != 0:
        for by in (cy - hh, cy + hh):
            t = (by - qy) / dy
            x = qx + t * dx
            if cx - hw - 1e-6 <= x <= cx + hw + 1e-6:
                candidates.append(t)
    if not candidates:
        return px, py
    # P is at t=1 by construction, so the crossing nearest t=1 is the one Graphviz aimed for.
    t = min(candidates, key=lambda tv: abs(tv - 1.0))
    return qx + t * dx, qy + t * dy


def _direction_ref(pts: list, from_end: bool) -> tuple:
    """Walks in from one end of an edge's point list to the first point that differs from the
    endpoint, since dot -Tplain sometimes repeats the last coordinate, which leaves no direction to
    clip against."""
    seq = list(reversed(pts)) if from_end else pts
    terminal = seq[0]
    for p in seq[1:]:
        if not _pts_close(p, terminal):
            return p
    return terminal


def bezier_path(pts: list) -> str:
    if len(pts) < 2: return ""
    cur = pts[0]
    d = f"M {cur[0]:.2f},{cur[1]:.2f}"
    i = 1
    while i + 2 < len(pts):
        c1, c2, end = pts[i], pts[i+1], pts[i+2]
        # dot -Tplain sometimes emits a final control point almost on the endpoint. The exit
        # tangent is then near zero, and the browser draws no arrowhead at all, so that segment is
        # drawn as a straight line instead. build_svg separately moves c2 with any endpoint it clips.
        if _pts_close(c2, end, eps=2.0):
            d += f" L {end[0]:.2f},{end[1]:.2f}"
        else:
            d += (f" C {c1[0]:.2f},{c1[1]:.2f}"
                  f" {c2[0]:.2f},{c2[1]:.2f}"
                  f" {end[0]:.2f},{end[1]:.2f}")
        cur = end
        i += 3
    while i < len(pts):
        d += f" L {pts[i][0]:.2f},{pts[i][1]:.2f}"
        cur = pts[i]
        i += 1
    return d


def render_edge(edge: dict, theme: Theme = LIGHT) -> str:
    pts   = edge["points"]
    if not pts: return ""
    style = edge.get("style", "solid").lower()
    dash  = ' stroke-dasharray="8,4"' if "dashed" in style else ""

    # Threagile dashes background links (such as telemetry and audit logging), so they render
    # thinner and muted, while primary links are ink.
    is_minor = "dashed" in style
    sw       = HAIRLINE * (0.7 if is_minor else 1.0)
    fontsize = EDGE_FONTSIZE_MINOR if is_minor else EDGE_FONTSIZE
    color    = theme.muted if is_minor else theme.ink
    mid      = "arr-muted" if is_minor else "arr-ink"

    path = bezier_path(pts)
    out  = [f'<path d="{path}" fill="none" stroke="{color}" stroke-width="{sw:.2f}"{dash} marker-end="url(#{mid})"/>']

    label = edge.get("label", "")
    if label and edge.get("lx") is not None:
        lx, ly = edge["lx"], edge["ly"]
        out.append(
            f'<text x="{lx:.2f}" y="{ly:.2f}" text-anchor="middle" '
            f'dominant-baseline="central" font-size="{fontsize}" '
            f'font-family="{FONT}" '
            f'fill="{color}">{html.escape(label)}</text>'
        )
    return "\n".join(out)


# ---------------------------------------------------------------------------
# 7. Cluster renderer
# ---------------------------------------------------------------------------

def render_cluster(cl: dict, bb: list, px_per_pt: float,
                   gh_pts: float, padding: float, shade_depth: int = 0,
                   icon_tags: list = None, for_print: bool = False,
                   label_fontsize: float = CLUSTER_FONTSIZE,
                   icon_size: float = ICON_SIZE, fill_type: str = None, theme: Theme = LIGHT) -> str:
    x0, y0, x1, y1 = bb
    # Convert points to SVG pixels (Y-flip)
    sx0 = x0 * px_per_pt + padding
    sy0 = (gh_pts - y1) * px_per_pt + padding
    w   = (x1 - x0) * px_per_pt
    h   = (y1 - y0) * px_per_pt

    # Boundaries recede, with a quiet fill and a hairline dashed border, while the border and
    # label share one color so a boundary reads as one unit. shade_depth steps one shade
    # darker per same-type ancestor, and fill_type selects another type's ramp for a type in
    # FOLLOWS_RAMP_OF.
    ramp_type = fill_type or cl.get("boundary_type", "")
    shades = theme.boundary_fill.get(ramp_type, [theme.paper])
    fill = shades[min(shade_depth, len(shades) - 1)]
    strokes = theme.boundary_stroke.get(ramp_type, [theme.accent])
    edge = strokes[min(shade_depth, len(strokes) - 1)]
    out = [
        f'<rect x="{sx0:.2f}" y="{sy0:.2f}" width="{w:.2f}" height="{h:.2f}" '
        f'rx="{RADIUS}" fill="{fill}" stroke="{edge}" stroke-width="{theme.boundary_stroke_width:.2f}" '
        f'stroke-dasharray="6,4"/>'
    ]

    label = cl["label"]
    if label:
        # The label is centered across the full width in the same strip as the corner icon,
        # which sits clear of it at this size.
        label_cx = sx0 + w / 2
        # The baseline offset scales with the font, so clearance is the same at every diagram
        # scale. 1.3 suits a single-line boundary label better than render_node's 1.4.
        label_y = sy0 + label_fontsize * 1.3
        out.append(
            f'<text x="{label_cx:.2f}" y="{label_y:.2f}" '
            f'text-anchor="middle" font-size="{label_fontsize:.2f}" font-weight="600" font-family="{FONT}" '
            f'fill="{edge}">{html.escape(label)}</text>'
        )
    if icon_tags:
        left_tags  = [t for t in icon_tags if t in BOUNDARY_LEFT_CORNER_ICONS]
        right_tags = [t for t in icon_tags if t not in BOUNDARY_LEFT_CORNER_ICONS]
        if right_tags:
            out.append(render_icon(sx0 + w, sy0, right_tags, edge, for_print=for_print, icon_size=icon_size))
        if left_tags:
            out.append(render_icon(sx0, sy0, left_tags, edge, for_print=for_print, anchor="left", icon_size=icon_size))
    return "\n".join(out)


# ---------------------------------------------------------------------------
# 8. Build HTML
# ---------------------------------------------------------------------------

_CSS = Template("""
* { box-sizing: border-box; margin: 0; padding: 0; }
body { font-family: Verdana, sans-serif; background: $page_bg; min-height: 100vh; }
header { padding: 14px 24px; background: $chrome_bg; border-bottom: 1px solid $chrome_border; display: flex; align-items: center; gap: 10px; }
header h1 { font-size: 16px; font-weight: 600; color: $title; }
.badge { background: $badge_bg; color: $badge_text; font-size: 11px; font-weight: 700; padding: 3px 8px; border-radius: 20px; }
.canvas-wrap { padding: 24px; overflow: hidden; cursor: grab; user-select: none; }
.canvas-wrap.grabbing { cursor: grabbing; }
svg.dfd { display: block; background: $paper; border-radius: 8px; box-shadow: 0 2px 12px $shadow; transform-origin: top left; }

/* Click-to-highlight (see _HIGHLIGHT_JS): clicking an asset dims every
   node/edge not connected to it. Only active once svg.dfd carries
   hl-active, so a plain (non-JS, e.g. the bare .svg file) render is
   never affected -- these rules and the .node/.edge classes/data-*
   attributes they key off of are otherwise inert. */
svg.dfd .node { cursor: pointer; }
svg.dfd.hl-active .node,
svg.dfd.hl-active .edge { opacity: 0.15; transition: opacity 0.12s ease-out; }
svg.dfd.hl-active .node.hl-selected,
svg.dfd.hl-active .node.hl-connected,
svg.dfd.hl-active .edge.hl-connected { opacity: 1; }
svg.dfd.hl-active .edge.hl-connected path { stroke: $highlight; stroke-width: 2.2px; marker-end: url(#arr-hl); }
svg.dfd.hl-active .node.hl-selected rect:first-of-type { stroke: $highlight; stroke-width: 2.5px; }

/* Filter-links bar (see _FILTER_JS): picking a category dims every edge
   not classified into it (see classify_edge/data-category) -- nodes are
   never dimmed by this, only links, so the asset layout stays legible
   while tracing one kind of flow. Independent of click-to-highlight
   above: .dimmed forces opacity regardless of hl-active/hl-connected. */
.filter-bar { padding: 10px 24px; background: $chrome_bg; border-bottom: 1px solid $chrome_border; display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }
.filter-label { font-size: 10px; font-weight: 700; letter-spacing: 0.08em; color: $label; margin-right: 2px; }
.filter-chip { font-family: Verdana, sans-serif; font-size: 11px; font-weight: 600; color: $chip_text; background: $chip_bg; border: 1px solid $chrome_border; border-radius: 20px; padding: 4px 12px; cursor: pointer; transition: all 0.12s ease-out; }
.filter-chip:hover { border-color: $chip_hover_border; color: $chip_hover_text; }
.filter-chip.active { color: $chip_active_text; background: $chip_active_bg; border-color: $chip_active_bg; }
svg.dfd .edge.dimmed { opacity: 0.06 !important; }
svg.dfd.filter-active .edge:not(.dimmed) path { stroke: $highlight; marker-end: url(#arr-hl); }
""")


def page_css(theme: Theme) -> str:
    """The HTML page's stylesheet in the theme's colors."""
    return _CSS.substitute(paper=theme.paper, highlight=theme.highlight, **theme.page)

# Fixed-color markers, since WeasyPrint does not support context-stroke and would paint a shared
# marker black on muted edges. arr-hl is for highlighted links (see _CSS).
_ARROW_DEFS = """<defs>
  <marker id="arr-ink" viewBox="0 0 10 10" refX="9" refY="5"
          markerWidth="6" markerHeight="6" orient="auto">
    <path d="M1,2 L9,5 L1,8" fill="none" stroke="%(ink)s"
          stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/>
  </marker>
  <marker id="arr-muted" viewBox="0 0 10 10" refX="9" refY="5"
          markerWidth="6" markerHeight="6" orient="auto">
    <path d="M1,2 L9,5 L1,8" fill="none" stroke="%(muted)s"
          stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/>
  </marker>
  <marker id="arr-hl" viewBox="0 0 10 10" refX="9" refY="5"
          markerWidth="6" markerHeight="6" orient="auto">
    <path d="M1,2 L9,5 L1,8" fill="none" stroke="%(highlight)s"
          stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/>
  </marker>
</defs>"""


def arrow_defs(theme: Theme) -> str:
    return _ARROW_DEFS % {"ink": theme.ink, "muted": theme.muted, "highlight": theme.highlight}

_JS = """
(function () {
  const wrap = document.querySelector('.canvas-wrap');
  const svg  = document.querySelector('svg.dfd');
  let scale = 1, tx = 0, ty = 0;
  let dragging = false, lastX = 0, lastY = 0;
  let downX = 0, downY = 0, dragMoved = false;

  function apply() {
    svg.style.transform = `translate(${tx}px,${ty}px) scale(${scale})`;
  }

  wrap.addEventListener('wheel', function (e) {
    e.preventDefault();
    const rect  = wrap.getBoundingClientRect();
    const mx    = e.clientX - rect.left;
    const my    = e.clientY - rect.top;
    const delta = e.deltaY < 0 ? 1.1 : 0.909;
    tx = mx - (mx - tx) * delta;
    ty = my - (my - ty) * delta;
    scale *= delta;
    scale = Math.min(Math.max(scale, 0.1), 10);
    apply();
  }, { passive: false });

  wrap.addEventListener('mousedown', function (e) {
    dragging = true; lastX = e.clientX; lastY = e.clientY;
    downX = e.clientX; downY = e.clientY; dragMoved = false;
    wrap.classList.add('grabbing');
  });
  window.addEventListener('mousemove', function (e) {
    if (!dragging) return;
    if (!dragMoved && (Math.abs(e.clientX - downX) > 4 || Math.abs(e.clientY - downY) > 4)) {
      dragMoved = true;
    }
    tx += e.clientX - lastX; ty += e.clientY - lastY;
    lastX = e.clientX; lastY = e.clientY;
    apply();
  });
  window.addEventListener('mouseup', function () {
    dragging = false; wrap.classList.remove('grabbing');
  });

  // A pan-drag ends with the mouse over whatever node/background the
  // cursor happens to land on, and the browser fires a normal 'click'
  // there regardless of the drag in between -- left unchecked, panning
  // across a node re-selects it and panning across empty canvas clears
  // the highlight mid-drag (see _HIGHLIGHT_JS). Swallow that one click in
  // the capturing phase (before it reaches any node's or the svg's own
  // click listener) whenever real movement happened between mousedown and
  // mouseup, so only a genuine, near-stationary click acts as a click.
  wrap.addEventListener('click', function (e) {
    if (dragMoved) { e.stopPropagation(); dragMoved = false; }
  }, true);
})();
"""

# Clicking an asset highlights it and its direct links and dims everything else, and clicking it
# again or the empty canvas clears it. It joins edges to nodes through the data-id, data-tail, and
# data-head attributes that build_svg sets, which hold Graphviz's ids.
_HIGHLIGHT_JS = """
(function () {
  const svg = document.querySelector('svg.dfd');
  if (!svg) return;
  const nodes = Array.from(svg.querySelectorAll('.node'));
  const edges = Array.from(svg.querySelectorAll('.edge'));
  let selectedId = null;

  function clear() {
    svg.classList.remove('hl-active');
    nodes.forEach(n => n.classList.remove('hl-selected', 'hl-connected'));
    edges.forEach(e => e.classList.remove('hl-connected'));
    selectedId = null;
  }

  function select(id) {
    clear();
    selectedId = id;
    svg.classList.add('hl-active');
    const connected = new Set([id]);
    edges.forEach(function (e) {
      const tail = e.getAttribute('data-tail'), head = e.getAttribute('data-head');
      if (tail === id || head === id) {
        e.classList.add('hl-connected');
        connected.add(tail);
        connected.add(head);
      }
    });
    nodes.forEach(function (n) {
      const nid = n.getAttribute('data-id');
      if (nid === id) n.classList.add('hl-selected');
      else if (connected.has(nid)) n.classList.add('hl-connected');
    });
  }

  nodes.forEach(function (n) {
    n.addEventListener('click', function (evt) {
      evt.stopPropagation();
      const id = n.getAttribute('data-id');
      if (id === selectedId) clear();
      else select(id);
    });
  });
  svg.addEventListener('click', clear);
})();
"""

# The filter bar dims every edge whose data-category list lacks the chosen category, and "all"
# clears it. A link can be in several categories, so this checks membership. Nodes are left
# alone, so the layout stays legible.
_FILTER_JS = """
(function () {
  const svg = document.querySelector('svg.dfd');
  if (!svg) return;
  const edges = Array.from(svg.querySelectorAll('.edge'));
  const chips = Array.from(document.querySelectorAll('.filter-chip'));

  chips.forEach(function (chip) {
    chip.addEventListener('click', function () {
      chips.forEach(c => c.classList.remove('active'));
      chip.classList.add('active');
      const filter = chip.getAttribute('data-filter');
      svg.classList.toggle('filter-active', filter !== 'all');
      edges.forEach(function (e) {
        const categories = (e.getAttribute('data-category') || '').split(' ');
        e.classList.toggle('dimmed', filter !== 'all' && !categories.includes(filter));
      });
    });
  });
})();
"""

# ---------------------------------------------------------------------------
# 6b. Edge classification for the filter-links bar
# ---------------------------------------------------------------------------

def classify_edge(tail_label: str, head_label: str,
                   vpc_by_label: dict = None,
                   devops_link_pairs: set = None,
                   path_tags_by_pair: dict = None) -> set:
    """Classifies an edge for the filter bar (see FILTER_CATEGORIES) as one or more of "mission",
    "telemetry", "identity", and "network". The checks run in priority order, and a later check is
    skipped once an earlier one matches:

    1. The link's own path: tags (see 03-tags-lib.yml, "COMMUNICATION LINK PATH-FILTER TAGS"). They
       record the author's intent, so they always win, and they are the only way an edge gets more
       than one category or becomes "identity", since no model field shows an identity path. An
       untagged identity link therefore shows as mission or network, which is visibly incomplete
       rather than confidently wrong.
    2. A usage: devops link is telemetry, since such links are log forwarding, even when an endpoint
       is network infrastructure such as a firewall.
    3. A link whose endpoints resolve to different VPC or VNet boundaries (via vpc_by_label, see
       compute_vpc_by_asset_id) is a Network Path.
    4. Anything else is "mission"."""
    if path_tags_by_pair:
        tagged = path_tags_by_pair.get((tail_label, head_label))
        if tagged:
            return set(tagged)
    if devops_link_pairs and (tail_label, head_label) in devops_link_pairs:
        return {"telemetry"}
    if vpc_by_label:
        tail_vpc, head_vpc = vpc_by_label.get(tail_label), vpc_by_label.get(head_label)
        if tail_vpc != head_vpc:
            return {"network"}
    return {"mission"}


# (CSS suffix, button label). "all" is handled in the filter bar itself, since no edge is
# classified as it.
FILTER_CATEGORIES = [
    ("mission",   "MISSION FLOWS"),
    ("telemetry", "LOG/TELEMETRY"),
    ("identity",  "IDENTITY PATH"),
    ("network",   "NETWORK PATH"),
]

# The data-asset diagram's edges are "stored by" and "processed by" relationships, not links, so
# classify_edge's categories have no signal there. Instead, its filter uses the edge's solid
# (stored) or dashed (processed) style, the distinction the report text describes.
FILTER_CATEGORIES_DATA_ASSET = [
    ("stored",    "STORED"),
    ("processed", "PROCESSED / TRANSITS"),
]


def build_svg(dot_source: str, title: str = "Data Flow Diagram",
              target_width: int = 3200, padding: int = 50,
              print_size_in: tuple = None,
              confidentiality_by_label: dict = None,
              icon_by_label: dict = None,
              vpc_by_label: dict = None,
              devops_link_pairs: set = None,
              path_tags_by_pair: dict = None,
              for_print: bool = False,
              theme: Theme = LIGHT) -> str:
    """Returns a bare <svg>...</svg> fragment (no XML declaration or HTML wrapper), laid out at
    Graphviz's own coordinates via `dot -Tplain`, with this project's shapes and palette.

    The optional arguments all come from the model YAML, since the .gv source does not carry them:
    1. print_size_in, as (max_width_in, max_height_in), gives the root <svg> a width and height in
       inches (aspect preserved) for embedding at a known print size.
    2. confidentiality_by_label maps a node's label to a confidentiality level (see
       CONFIDENTIALITY_FILL), the data-asset diagram's shading.
    3. icon_by_label maps a node's or boundary's label to its ICON_FILES keys, in tag order. A node
       shows them all in a row, while a boundary's badge shows the first.
    4. vpc_by_label, devops_link_pairs, and path_tags_by_pair feed each edge's data-category for the
       filter bar (see classify_edge()). Without them, every edge is "mission".
    5. for_print swaps in raster copies of the icons that WeasyPrint mishandles (see
       _icon_needs_print_raster). Pass it only for the PDF copy."""

    plain        = run_dot_plain(dot_source)
    layout       = parse_plain(plain)
    dot_attrs    = parse_dot_node_attrs(dot_source)
    cluster_defs = parse_dot_cluster_attrs(dot_source)
    cluster_bbs, edge_xlp = parse_dot_cluster_bbs(dot_source)
    edge_xlabels = parse_dot_edge_xlabels(dot_source)

    g = layout["graph"]
    if not g:
        sys.exit("ERROR: could not parse graph info.")

    gw_in, gh_in = g["width"], g["height"]
    available    = target_width - 2 * padding
    px_per_in    = available / gw_in if gw_in > 0 else 72.0
    px_per_pt    = px_per_in / PPI
    canvas_w     = gw_in * px_per_in + 2 * padding
    canvas_h     = gh_in * px_per_in + 2 * padding
    gh_pts       = gh_in * PPI  # graph height in points for Y-flip

    # Scales text and icons to this diagram's boxes (see DIAGRAM_SCALE_BASELINE_PX_PER_IN).
    diagram_scale = px_per_in / DIAGRAM_SCALE_BASELINE_PX_PER_IN
    diagram_scale = max(DIAGRAM_SCALE_MIN, min(DIAGRAM_SCALE_MAX, diagram_scale))
    cluster_fontsize    = CLUSTER_FONTSIZE * diagram_scale
    boundary_icon_size  = ICON_SIZE * diagram_scale
    node_icon_target    = NODE_ICON_TARGET_SIZE * diagram_scale

    def tx(x): return x * px_per_in + padding
    def ty(y): return (gh_in - y) * px_per_in + padding

    if print_size_in:
        # px_per_in user units are one inch by construction, so this is the print size in
        # inches.
        max_w_in, max_h_in = print_size_in
        native_w_in, native_h_in = canvas_w / px_per_in, canvas_h / px_per_in
        scale = min(max_w_in / native_w_in, max_h_in / native_h_in)
        size_attrs = f'width="{native_w_in*scale:.2f}in" height="{native_h_in*scale:.2f}in" '
    else:
        size_attrs = f'width="{canvas_w:.0f}" height="{canvas_h:.0f}" '

    parts = [
        f'<svg class="dfd" {size_attrs}'
        f'viewBox="0 0 {canvas_w:.2f} {canvas_h:.2f}" '
        f'xmlns="http://www.w3.org/2000/svg" role="img">',
        f'<title>{html.escape(title)}</title>',
        arrow_defs(theme),
        f'<rect width="{canvas_w:.2f}" height="{canvas_h:.2f}" fill="{theme.paper}"/>',
    ]

    # Trust boundaries, sorted by area so outer ones render first. Same-type shade depth comes
    # from geometric containment in the boundaries already placed, since DOT source order does not
    # guarantee outer before inner.
    cl_map = {cl["id"]: cl for cl in cluster_defs}
    bb_items = []
    for cid, bb in cluster_bbs.items():
        if cid in cl_map:
            area = (bb[2]-bb[0]) * (bb[3]-bb[1])
            bb_items.append((area, cid, bb))
    bb_items.sort(reverse=True)

    def _bb_contains(outer, inner, eps=0.5):
        return (outer[0] - eps <= inner[0] and outer[1] - eps <= inner[1]
                and outer[2] + eps >= inner[2] and outer[3] + eps >= inner[3])

    placed = []  # (cid, bb) already rendered, outer-to-inner so far
    for _, cid, bb in bb_items:
        cl = cl_map[cid]
        # A type in FOLLOWS_RAMP_OF counts depth among ancestors of the type it follows (see
        # FOLLOWS_RAMP_OF).
        fill_type = FOLLOWS_RAMP_OF.get(cl.get("boundary_type", ""), cl.get("boundary_type", ""))
        depth = sum(
            1 for pcid, pbb in placed
            if cl_map[pcid].get("boundary_type") == fill_type
            and _bb_contains(pbb, bb)
        )
        # A boundary's corner badge shows one icon per tag, in tag order, as a row extending left
        # from the corner.
        cl_icons = (icon_by_label.get(cl["label"]) or []) if icon_by_label else []
        parts.append(render_cluster(cl, bb, px_per_pt, gh_pts, padding, shade_depth=depth, icon_tags=cl_icons, for_print=for_print,
                                     label_fontsize=cluster_fontsize, icon_size=boundary_icon_size, fill_type=fill_type, theme=theme))
        placed.append((cid, bb))

    # confidentiality_by_label is passed only for the data-asset diagram, so it also selects that
    # diagram's larger font and its own filter categories.
    is_data_asset = confidentiality_by_label is not None
    node_fontsize = (NODE_FONTSIZE_DATA_ASSET if is_data_asset else NODE_FONTSIZE) * diagram_scale

    # Each node's label and wrapped lines, computed once so that edge clipping and the drawn boxes
    # use the same dimensions (Graphviz's own, never resized, see wrap_and_fit).
    node_render_info = {}
    for node in layout["nodes"]:
        nid = node["id"]
        extra = dot_attrs.get(nid, {})
        label = node["label"] or nid
        if extra.get("label"):
            better = extract_bold_text(extra["label"])
            if better and better != nid:
                label = better
        icon_tags = (icon_by_label.get(label) or []) if icon_by_label else []
        icon_tags = [t for t in icon_tags if _resolve_icon_file(t)]
        native_w = node["w"] * px_per_in
        lines, fitted_w = wrap_and_fit(label, native_w, fontsize=node_fontsize)
        native_h = node["h"] * px_per_in

        # Grow a short box to fit a node icon at NODE_ICON_TARGET_SIZE, before node_boxes and edge
        # clipping read its height, so they stay consistent. Otherwise render_node would shrink or
        # drop the icon. Threagile draws a machine external entity shorter than a human one, which
        # is the usual case.
        if icon_tags:
            line_h = node_fontsize * 1.4
            total_h = line_h * len(lines)
            min_h = (node_icon_target + total_h + NODE_ICON_GAP) / 0.92
            native_h = max(native_h, min_h)

        node_render_info[nid] = {
            "label": label,
            "icon_tags": icon_tags,
            "lines": lines,
            "w": fitted_w,
            "h": native_h,
        }

    # Node boxes in pixels, built before the edge loop so edges can clip their endpoints to them
    # (see _clip_to_box).
    node_boxes = {}
    for node in layout["nodes"]:
        info = node_render_info[node["id"]]
        node_boxes[node["id"]] = (tx(node["x"]), ty(node["y"]), info["w"] / 2, info["h"] / 2)

    def _clip_and_shift(pts_px, idx, ctrl_idx, box, from_end):
        """Clips pts_px[idx] onto the box boundary, then moves pts_px[ctrl_idx], that segment's
        Bezier control point, by the same delta. The drawn rect is larger than the curved shape Graphviz
        sized the node for, so a clip can move the endpoint a long way, and moving it alone would bend
        the tangent that orients the arrowhead."""
        q = _direction_ref(pts_px, from_end=from_end)
        old_pt = pts_px[idx]
        new_pt = _clip_to_box(*q, *old_pt, *box)
        pts_px[idx] = new_pt
        n = len(pts_px)
        ctrl_pos = ctrl_idx % n  # normalize negative indices before comparing
        if ctrl_pos not in (0, n - 1):
            dx, dy = new_pt[0] - old_pt[0], new_pt[1] - old_pt[1]
            cx2, cy2 = pts_px[ctrl_pos]
            pts_px[ctrl_pos] = (cx2 + dx, cy2 + dy)

    # Edges first (under nodes)
    for edge in layout["edges"]:
        pts_px = [(tx(px), ty(py)) for px, py in edge["points"]]
        if len(pts_px) >= 2:
            tail_box = node_boxes.get(edge["tail"])
            if tail_box:
                _clip_and_shift(pts_px, 0, 1, tail_box, from_end=False)
            head_box = node_boxes.get(edge["head"])
            if head_box:
                _clip_and_shift(pts_px, -1, -2, head_box, from_end=True)
        e2 = dict(edge, points=pts_px)
        key = (edge["tail"], edge["head"])

        # Use exact xlp position from dot -Tdot (Graphviz-computed, never overlaps)
        if key in edge_xlp:
            xlp_x, xlp_y = edge_xlp[key]
            e2["lx"] = xlp_x * px_per_pt + padding
            e2["ly"] = (gh_pts - xlp_y) * px_per_pt + padding
        elif edge.get("lx") is not None:
            e2["lx"] = tx(edge["lx"])
            e2["ly"] = ty(edge["ly"])

        # Attach xlabel text from DOT source
        if not e2.get("label") and key in edge_xlabels:
            e2["label"] = edge_xlabels[key]

        if is_data_asset:
            # The data-asset diagram classifies by edge style (see FILTER_CATEGORIES_DATA_ASSET).
            style = edge.get("style", "solid").lower()
            categories = {"processed"} if "dashed" in style else {"stored"}
        else:
            tail_label = node_render_info.get(edge["tail"], {}).get("label", "")
            head_label = node_render_info.get(edge["head"], {}).get("label", "")
            categories = classify_edge(tail_label, head_label, vpc_by_label,
                                        devops_link_pairs, path_tags_by_pair)
        parts.append(f'<g class="edge" data-tail="{html.escape(edge["tail"])}" '
                     f'data-head="{html.escape(edge["head"])}" data-category="{" ".join(sorted(categories))}">')
        parts.append(render_edge(e2, theme))
        parts.append('</g>')

    # Nodes on top
    for node in layout["nodes"]:
        info = node_render_info[node["id"]]
        cx = tx(node["x"])
        cy = ty(node["y"])
        node = dict(node, label=info["label"])
        level = confidentiality_by_label.get(info["label"]) if confidentiality_by_label else None
        parts.append(f'<g class="node" data-id="{html.escape(node["id"])}">')
        parts.append(render_node(node, cx, cy, info["w"], info["h"], dot_attrs,
                                  info["lines"], confidentiality=level, icon_tags=info["icon_tags"],
                                  fontsize=node_fontsize, for_print=for_print,
                                  icon_target_size=node_icon_target, theme=theme))
        parts.append('</g>')

    parts.append('</svg>')
    return "".join(parts)


def build_html(dot_source: str, title: str = "Data Flow Diagram",
               target_width: int = 3200, padding: int = 50,
               confidentiality_by_label: dict = None,
               icon_by_label: dict = None,
               vpc_by_label: dict = None,
               devops_link_pairs: set = None,
               path_tags_by_pair: dict = None,
               theme: Theme = None) -> str:
    theme = theme or DARK  # the interactive page is on-screen

    svg = build_svg(dot_source, title=title, target_width=target_width, padding=padding,
                     theme=theme,
                     confidentiality_by_label=confidentiality_by_label,
                     icon_by_label=icon_by_label,
                     vpc_by_label=vpc_by_label,
                     devops_link_pairs=devops_link_pairs,
                     path_tags_by_pair=path_tags_by_pair)

    # The data-asset diagram has its own filter set (see FILTER_CATEGORIES_DATA_ASSET).
    categories = FILTER_CATEGORIES_DATA_ASSET if confidentiality_by_label is not None else FILTER_CATEGORIES
    filter_chips = '<button class="filter-chip active" data-filter="all">ALL</button>' + "".join(
        f'<button class="filter-chip" data-filter="{value}">{label}</button>'
        for value, label in categories
    )

    return textwrap.dedent(f"""\
    <!DOCTYPE html>
    <html lang="en">
    <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width,initial-scale=1">
    <title>{html.escape(title)}</title>
    <style>{page_css(theme)}</style>
    </head>
    <body>
    <header>
      <h1>{html.escape(title)}</h1>
      <span class="badge">DFD</span>
    </header>
    <div class="filter-bar">
      <span class="filter-label">FILTER LINKS:</span>
      {filter_chips}
    </div>
    <div class="canvas-wrap">
    {svg}
    </div>
    <script>{_JS}</script>
    <script>{_HIGHLIGHT_JS}</script>
    <script>{_FILTER_JS}</script>
    </body>
    </html>
    """)


# ---------------------------------------------------------------------------
# 9. CLI
# ---------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--dot",   metavar="FILE")
    src.add_argument("--stdin", action="store_true")
    ap.add_argument("--out",     metavar="FILE", default="dfd.html")
    ap.add_argument("--title",   metavar="TEXT", default="Data Flow Diagram")
    ap.add_argument("--width",   metavar="N",    type=int, default=3200)
    ap.add_argument("--padding", metavar="N",    type=int, default=50)
    ap.add_argument("--dump-plain", action="store_true")
    args = ap.parse_args()

    dot_source = Path(args.dot).read_text() if args.dot else sys.stdin.read()

    if args.dump_plain:
        print(run_dot_plain(dot_source))
        return

    out = build_html(dot_source, title=args.title,
                     target_width=args.width, padding=args.padding)
    out_path = Path(args.out)
    out_path.write_text(out, encoding="utf-8")
    print(f"Written -> {out_path}  ({out_path.stat().st_size // 1024} KB)")


if __name__ == "__main__":
    main()