# Risk Scoring Methodology

This is the full technical reference for how a finding's Likelihood, Impact, and Severity get
computed in this repo's threat model reports. It exists because the report's own **Methodology**
section (`templates/report.html.jinja`) has to stay skimmable inside a system-specific PDF read by
a broad audience — it states *what* the two scoring paths do, not the full *why* behind each
design choice. This document is the *why*: the reasoning, the trade-offs considered and rejected,
and the exact formulas, aimed at someone doing due diligence on the methodology itself (an ISSO,
an AO, an assessor, or a new team member) independent of any one report run.

**This document is a narrative reference, not the source of truth.** The actual scoring logic
lives in code — `models/central-security-repo/core-policies/inject_risks.py` for the custom
engine, Threagile's own compiled binary for built-in categories. Every constant and threshold
quoted below is current as of this writing; if a number here ever disagrees with the code, the
code is right and this document is stale — see [Keeping this in sync](#keeping-this-in-sync).

## Contents

- [The two scoring paths, at a glance](#the-two-scoring-paths-at-a-glance)
- [Relative Attacker Attractiveness (RAA)](#relative-attacker-attractiveness-raa)
- [Threagile's built-in risk categories](#threagiles-built-in-risk-categories)
- [This repo's custom risk-injection engine](#this-repos-custom-risk-injection-engine)
  - [1. Baseline Likelihood and Impact](#1-baseline-likelihood-and-impact)
  - [2. The Likelihood adjustment: RAA and internet reachability](#2-the-likelihood-adjustment-raa-and-internet-reachability)
  - [3. The Impact adjustment: CIA rank and business criticality](#3-the-impact-adjustment-cia-rank-and-business-criticality)
  - [4. Severity: combining Likelihood and Impact](#4-severity-combining-likelihood-and-impact)
- [Why two different engines score differently](#why-two-different-engines-score-differently)
- [Could the custom engine just adopt Threagile's own formula?](#could-the-custom-engine-just-adopt-threagiles-own-formula)
- [Source of truth, by topic](#source-of-truth-by-topic)
- [Keeping this in sync](#keeping-this-in-sync)

## The two scoring paths, at a glance

Every finding in a report comes from one of two independent rule sources, and each computes
Severity its own way:

| | Threagile's built-in categories | This repo's custom categories |
|---|---|---|
| Likelihood source | Hardcoded per rule, or RAA-threshold-gated for a few rules | Category's own author-judged baseline, adjusted per-asset |
| Impact source | Asset's/link's own CIA ratings, computed per rule | Category's own author-judged baseline, adjusted per-asset |
| Combination rule | Likelihood weight (1–4) × Impact weight (1–4), product bucketed | Explicit hand-authored Likelihood × Impact lookup table |
| Where it runs | Inside the Threagile binary, undisclosed/compiled-in | `inject_risks.py`, before Threagile ever runs |
| Enrichment text | `libraries/10-threagile-builtin-risks-lib.yml` | `libraries/09-custom-risks-lib.yml` |

Both paths land on the same five-level Severity scale — Low, Medium, Elevated, High, Critical —
and both are shown through identical badges/columns in the report, but a similar-looking finding
can score differently depending on which engine produced it. See
[Why two different engines score differently](#why-two-different-engines-score-differently).

## Relative Attacker Attractiveness (RAA)

RAA is shared infrastructure, not something specific to either scoring path: two of Threagile's
own four RAA-aware built-in rules consult it directly inside the compiled binary (see
[Threagile's built-in risk categories](#threagiles-built-in-risk-categories) below), and this
repo's custom engine uses an independently-computed copy of the exact same formula as part of its
own Likelihood adjustment (see
[§2](#2-the-likelihood-adjustment-raa-and-internet-reachability)). Explained once here since both
paths depend on it, rather than duplicated under whichever path happened to be documented first.

Threagile computes RAA itself, but only *after* its own analysis runs (`technical-assets.json`,
read by `generate_report.py`'s `load_raa_by_id()`) — too late for `inject_risks.py`, which needs a
Likelihood value before Threagile ever executes. `compute_raa_by_id()` is therefore an independent
computation of *the same formula*, replicated faithfully from Threagile's own
`pkg/model/raa.go`/`pkg/types/confidentiality.go`/`criticality.go`/`quantity.go` source (read
directly against the engine this repo actually runs — a custom build from
`jessestarkey/threagile`, not the `threagile/threagile:0.9.1` image the baseline threat-modeling
repo still pins — not assumed) rather than approximated. It works in seven steps:

1. Start from the asset's own Confidentiality/Integrity/Availability ranks (0–4), each looked up
   in a weight table drawn from the Fibonacci sequence rather than a linear 0–4 scale — Threagile's
   own design choice, not this repo's invention. Fibonacci weighting makes the gap between
   adjacent tiers grow non-linearly: the jump in attractiveness from "confidential" to
   "strictly-confidential" is much larger than the jump from "public" to "internal," so the
   highest-sensitivity tier disproportionately dominates the score, rather than merely
   contributing ~20% more than the tier below it the way a flat linear scale would. Six separate
   tables exist — one Confidentiality/Criticality pair (Criticality covers both Integrity and
   Availability, since Threagile's own source doesn't distinguish the two for RAA purposes) for
   each of three contexts a CIA rating can apply in:

   | Rank → | 0 | 1 | 2 | 3 | 4 |
   |---|---|---|---|---|---|
   | `CONF_ASSET` — the asset's own Confidentiality | 8 | 13 | 21 | 34 | 55 |
   | `CRIT_ASSET` — the asset's own Integrity/Availability | 5 | 8 | 13 | 21 | 34 |
   | `CONF_PROCESSED_OR_STORED` — a data asset it processes/stores | 5 | 8 | 13 | 21 | 34 |
   | `CRIT_PROCESSED_OR_STORED` — same, Integrity/Availability | 3 | 5 | 8 | 13 | 21 |
   | `CONF_TRANSFERRED` — a data asset sent/received over a link | 2 | 3 | 5 | 8 | 13 |
   | `CRIT_TRANSFERRED` — same, Integrity/Availability | 2 | 3 | 5 | 8 | 13 |

   All six rows draw from the same underlying sequence (2, 3, 5, 8, 13, 21, 34, 55), just windowed
   differently — `CONF_ASSET` starts three steps further into the sequence than
   `CONF_TRANSFERRED`, which is what produces the "an asset's own rating counts for more than data
   it merely transits" effect independent of the rank itself. Confidentiality also consistently
   sits one step higher than Criticality for both the asset's own rating and processed/stored
   data — RAA is fundamentally about what makes an asset worth *attacking to read or steal*, not
   just disrupt — except at the transferred tier, where the two converge to identical weights:
   data merely passing through an asset is treated as equally attractive to intercept regardless
   of whether the risk is disclosure or corruption.

2. Add a weighted contribution for every data asset the technical asset processes or stores,
   scaled by that data asset's own Confidentiality/Integrity rank (via `CONF_PROCESSED_OR_STORED`/
   `CRIT_PROCESSED_OR_STORED` above) *and* its `quantity` field (`very-few`→1, `few`→2, `many`→3,
   `very-many`→5).
3. Add a smaller weighted contribution for every data asset sent or received over the asset's own
   communication links, the same way but via `CONF_TRANSFERRED`/`CRIT_TRANSFERRED`.
4. Scale the whole sum by a technology-type multiplier: a reverse proxy or load balancer is
   structurally a conduit and is scaled *down* (÷5.5) regardless of its own CIA rating; an identity
   provider, vault, or container platform is scaled *up* (2×–5×) since it's disproportionately
   attractive independent of what it's rated. A generic `datastore`-type asset with no more
   specific multiplier still gets a flat 2× floor.
5. Apply a 1.5× multiplier if the asset is `multi_tenant`.
6. **Pivot**: an asset inherits up to a third of the positive attractiveness gap to the single most
   attractive asset it can directly reach over its own communication links — value propagates
   backward from a high-value target onto whatever can reach it, so a plain-looking front-door
   asset that happens to have a path to a vault or identity provider scores higher than its own raw
   attractiveness alone would suggest.
7. Normalize every asset's score to 0–100% relative to the min/max across every asset *in this
   specific model* (floored at 1%, since 0% would imply an asset can't be attacked at all).

That last step matters: RAA is **relative to the model it's computed against**, not an absolute
scale — "at or above 40%" means a different real attack-worthiness in a 3-asset model than in a
50-asset one. This instability is inherited directly from Threagile's own real RAA design; this
repo faithfully replicates it rather than correcting it, since correcting it would mean deviating
from a faithful replication of Threagile's own formula, and doing so hasn't been validated against
whether Threagile's own built-in RAA-aware rules are actually less exposed to the same instability
in practice.

## Threagile's built-in risk categories

Threagile's own ~36 built-in rules (Missing Authentication, SQL/NoSQL Injection, Missing WAF, and
so on) score entirely inside the engine binary itself — this repo builds that binary from
`jessestarkey/threagile`, a fork of upstream Threagile, so unlike the baseline threat-modeling
repo's pinned `threagile/threagile:0.9.1` image, two of the pieces described below (the weight
table and the severity thresholds) are things this repo's own fork actually controls and has
edited. Everything else about how a built-in rule decides its own Likelihood/Impact inputs remains
upstream, closed logic this repo has no visibility into beyond what's observable from real runs and
`threagile -explain-risk-rules`, and doesn't attempt to reproduce.

What's known and confirmed by testing:

- **Impact** comes from the affected technical asset's (or communication link's) own
  Confidentiality/Integrity/Availability ratings, computed per rule.
- **Likelihood** is decided independently by each rule. Most rules simply hardcode a fixed
  Likelihood for that vulnerability class. A small number of rules instead raise Likelihood when
  the asset's RAA score (see [RAA](#relative-attacker-attractiveness-raa) above) crosses a
  threshold — two of Threagile's four RAA-aware built-in rules (`unguarded-access-from-internet`,
  `unguarded-direct-datastore-access`) use a flat 40% cutoff; the other two (`missing-hardening`,
  `missing-network-segmentation`) use a two-tier `raaLimit`/`raaLimitReduced` pair instead. This
  repo's own custom engine's RAA threshold (see
  [§2](#2-the-likelihood-adjustment-raa-and-internet-reachability)) is deliberately set to match
  that 40% value.
- **Severity** combines the two arithmetically: each Likelihood and Impact level carries a weight,
  the two weights are multiplied, and the product is bucketed into a Severity level. As of this
  fork, the weight table is Fibonacci-spaced (1, 2, 3, 5) rather than the original linear 1–4, and
  the likelihood vocabulary itself was renamed (`frequent` → `possible`, reordered to
  unlikely/possible/likely/very-likely — see
  [`pkg/types/risk_exploitation_likelihood.go`](https://github.com/jessestarkey/threagile/blob/master/pkg/types/risk_exploitation_likelihood.go)
  in the fork), the same way this repo's own custom engine's vocabulary was renamed to match (see
  [§4](#4-severity-combining-likelihood-and-impact)). The severity thresholds were recalibrated to
  `≤1 Low, ≤3 Medium, ≤6 Elevated, ≤15 High`, else Critical:

  | | Low (1) | Medium (2) | High (3) | Very-High (5) |
  |---|---|---|---|---|
  | **Unlikely (1)** | Low | Medium | Medium | Elevated |
  | **Possible (2)** | Medium | Elevated | Elevated | High |
  | **Likely (3)** | Medium | Elevated | High | High |
  | **Very-Likely (5)** | Elevated | High | High | Critical |

  Across the 16 cells this now gives Low 1/16, Medium 4/16, Elevated 5/16, High 5/16, Critical
  1/16 — Low and Critical both stay single-cell minorities (product 1, and product 25 at
  Very-Likely × Very-High, the one cell where both axes are genuinely maxed), the same shape this
  repo's own matrix targets, confirmed by a real end-to-end pipeline run against actual app data
  after making this change (see [§4](#4-severity-combining-likelihood-and-impact) for the full
  validation this shape is based on). This shape was adopted, not merely "considered," for the
  custom engine's own matrix too — see [§4](#4-severity-combining-likelihood-and-impact).

`libraries/10-threagile-builtin-risks-lib.yml` supplies the same kind of enrichment text
(description/impact/ASVS/cheat-sheet/risk-assessment/false-positives) the custom engine's library
provides for its own categories, extracted once from Threagile's own upstream output (its
`-explain-risk-rules` text and native `report.pdf`) — it doesn't feed Severity, only report
narrative.

## This repo's custom risk-injection engine

`inject_risks.py` scans every technical asset's tags against a large if-chain and injects matching
`custom_risk_categories` entries (Threagile's own field name for this; it was renamed upstream from
`individual_risk_categories`, and this repo's loader builds its internal dict keyed by title as
before but converts to the new list-of-entries shape at the final write step), each with its own
computed Severity — not a flat value copy-pasted onto every finding in a category regardless of
which asset it landed on. The computation has four steps.

### 1. Baseline Likelihood and Impact

Every one of the ~120 category definitions in `libraries/09-custom-risks-lib.yml` carries its own
`baseline_likelihood` and `baseline_impact` — an author judgment of how exploitable and how
consequential that *class* of vulnerability inherently is, independent of which asset it lands on.
Grounded in CWE's own "Likelihood of Exploit" rating or the relevant OWASP Top 10/API Security Top
10 entry where a real mapping exists; expert judgment where it doesn't.

This baseline is the majority of the signal. Everything below is a small, bounded nudge on top of
it — never a full override — so a category's own author-judged starting point still carries the
most weight for any given finding.

### 2. The Likelihood adjustment: RAA and internet reachability

Baseline Likelihood gets a **-1 / 0 / +1** delta from the asset's own RAA score (see
[RAA](#relative-attacker-attractiveness-raa) above for the full formula), plus a
**+1 (never negative)** delta if the asset is reachable from the internet:

```
raa_delta      = +1  if asset_raa >= 40.0
               = -1  if asset_raa <  15.0
               =  0  otherwise
exposed_delta  = +1  if internet_reachable else 0

Likelihood = clamp(baseline_likelihood + raa_delta + exposed_delta)
```

The **40.0** positive threshold is deliberately kept identical to the real value two of Threagile's
own four RAA-aware built-in rules use (see [Threagile's built-in risk
categories](#threagiles-built-in-risk-categories) above) — not independently tuned. The **15.0**
negative threshold is the mirror-image cutoff that lets Likelihood step *down* for a genuinely
low-value asset; this delta didn't originally exist (the RAA delta used to be 0/+1 only), which
made every category's baseline a hard floor regardless of how obscure the specific asset actually
was, biasing Likelihood to only ever escalate as a model grows. 15.0 was chosen well below 40.0
rather than as its exact mirror (e.g. 60.0), since 40.0's own value is anchored to Threagile's real
rules and isn't this repo's to move — an asset has to be genuinely low-value relative to the
model, not merely below-average, to earn the downward nudge.

RAA replaced an earlier, cruder version of this delta that used a flat max-CIA-rank comparison.
RAA already includes the asset's own CIA rating as its first term, plus the data it actually
handles, its technology role, and the pivoting effect — a strictly richer signal, not an additional
one stacked alongside the old one.

**Internet reachability.** Broader than a direct `zone:dmz` tag: `compute_internet_reachable_ids()`
walks outbound `communication_links` from every `zone:dmz`-tagged asset, since most vulnerability
classes pass straight through a WAF untouched, so an asset several hops behind one is still a
realistic target. The walk passes through anything *not* tagged as a real application tier
(`app:frontend-ui`/`app:backend-api`/`app:async-worker` — assumed to be plumbing: a firewall, a
load balancer) but stops at the first real application asset it reaches, without expanding into
*that* app's own downstream dependencies (a database, an internal service). An unbounded walk would
converge toward "everything is internet-reachable" in any architecture with enough hops, defeating
the point of the signal.

This delta is **one-directional** by design: not being reachable is simply the ordinary case the
category's own baseline already assumes, not a fact that should push Likelihood *below* baseline
the way a genuinely low-RAA asset does.

`zone:dmz` itself stays narrowly scoped to "this asset directly receives hostile traffic" (used
by the Missing WAF and Dangling DNS checks, which must not broaden to match) — the reachability
walk is a deliberately separate, broader signal built on top of it.

### 3. The Impact adjustment: CIA rank and business criticality

Baseline Impact gets a **-1 / 0 / +1** delta from the asset's own CIA rank on whichever single
dimension the finding's STRIDE category actually threatens, plus a gated **+1** if the model's
overall Business Criticality is Critical or Mission-Critical:

```
dimension          = STRIDE_TO_CIA_DIMENSION[stride]   (falls back to max(C,I,A) if unmapped)
cia_delta           = -1 if rank in {public/archive, internal/operational}
                    =  0 if rank in {restricted/important}
                    = +1 if rank in {confidential/critical, strictly-confidential/mission-critical}
criticality_delta   = +1 if business_criticality in {critical, mission-critical} AND cia_delta < 1
                    =  0 otherwise

Impact = clamp(baseline_impact + cia_delta + criticality_delta)
```

**Why a single dimension, not max(C, I, A).** A denial-of-service finding is nudged by the asset's
Availability rating alone, not a flat maximum across all three — an asset with high Confidentiality
but low Availability shouldn't have a DoS finding's Impact inflated by a CIA dimension the finding
doesn't actually threaten. The mapping:

| STRIDE category | CIA dimension |
|---|---|
| information-disclosure | confidentiality |
| spoofing | integrity |
| tampering | integrity |
| repudiation | integrity |
| denial-of-service | availability |
| elevation-of-privilege (or unmapped) | max(C, I, A) |

Spoofing maps to **integrity**, not confidentiality — Microsoft's original STRIDE mnemonic pairs
spoofing with *Authentication*, which isn't one of the three CIA fields a Threagile technical asset
actually carries. The direct consequence of a successful spoofing finding (an attacker impersonates
another identity, forges a token, bypasses an authentication check) is that the integrity of the
authentication decision itself is what broke; what the attacker does with that impersonated
identity afterward is a downstream consequence, not the finding itself. This matters most in
Identity-domain categories, where nearly every finding is tagged `spoofing`: an identity broker or
CA whose real value is its Integrity rating (not necessarily its Confidentiality rating) is now
scored off the axis that actually reflects what it is.

This mapping is one known, accepted trade-off: spoofing also covers infrastructure impersonation
(Rogue Access Point, Evil-Twin Credential Harvesting), where the actual consequence — credentials
intercepted over the air — is genuinely a confidentiality event, not an authentication-integrity
one. The mapping is a single global table, not something an individual category can override, so
this trades a worse fit for that minority case for a better fit across the majority (identity
impersonation) case the mapping was built for. Reclassifying those specific categories' own
`stride` value just to route around the table would misrepresent their actual STRIDE category, so
they're left as spoofing and documented here instead.

**Why the criticality bump is gated.** A system rated Critical/Mission-Critical is, almost by
definition, built mostly from components that themselves carry top-tier CIA ratings — applying
both bumps unconditionally would mostly double-count the same underlying fact for the same
finding. Gating the system-level bump to only fill the gap for an asset whose own CIA rating
*didn't* already earn it preserves the real justification behind the bump (a low-value component
still matters more inside an important system) without stacking it on assets that already earned
it on their own.

### 4. Severity: combining Likelihood and Impact

Likelihood and Impact combine through a weight-product-and-threshold formula, the same shape as
Threagile's own built-in `CalculateSeverity()` (see [Threagile's built-in risk
categories](#threagiles-built-in-risk-categories) above) — not the hand-authored rank-sum lookup
table an earlier version of this engine used (see git history). Each Likelihood and Impact level
carries a Fibonacci-spaced weight — 1, 2, 3, 5, not the linear 1, 2, 3, 4 a first attempt might
reach for — the two weights are multiplied, and the product is bucketed into a Severity level by
threshold: `≤1 → Low, ≤3 → Medium, ≤6 → Elevated, ≤15 → High`, else Critical.

|  | Low (1) | Medium (2) | High (3) | Very-High (5) |
|---|---|---|---|---|
| **Unlikely (1)** | Low | Medium | Medium | Elevated |
| **Possible (2)** | Medium | Elevated | Elevated | High |
| **Likely (3)** | Medium | Elevated | High | High |
| **Very-Likely (5)** | Elevated | High | High | Critical |

**Why Fibonacci, not linear.** The real-world jump in exploitability or consequence from Likely to
Very-Likely (or High to Very-High) is bigger than the jump from Unlikely to Possible (or Low to
Medium) — equal linear steps understate that. This is the same non-linear-tier-gap reasoning this
file's own RAA weight tables already use for Confidentiality/Criticality ranks (see
[RAA](#relative-attacker-attractiveness-raa) above): higher tiers should disproportionately
dominate, not merely contribute a fixed increment over the tier below.

**Why this replaced the old rank-sum-band table.** The rank-sum approach (sum the two 0–3 ranks,
bucket the sum 0–6 into five levels, with one hand-picked exception cell to keep Critical rare) was
never wrong on the data — it was deliberately tuned against real app findings and produced a
genuinely balanced spread. But it required a hand-picked exception cell to do it (Frequent × High
pinned to High rather than its literal sum-6 Critical position), and it was a second, bespoke
formula alongside Threagile's own weight-product approach rather than a shared one. Switching this
engine onto the same weight-product shape as Threagile's own built-in rules — but with Fibonacci
weights and recalibrated thresholds instead of either engine's original linear-1–4 scheme — gives
both engines the same mathematical shape without needing a hand-picked exception cell in either:
Fibonacci's own non-linear spacing keeps Critical naturally rare (1 of 16 cells, only where both
axes are genuinely maxed) on its own.

**Validated empirically before landing**, the same way every prior methodology change in this repo
has been: real (likelihood, impact) pairs were extracted from ~186 real custom-category findings
in an actual app's output, and distinct-value/percentile-calibrated distributions were compared
across a linear `[1,2,3,4]` weighting and three candidate Fibonacci windows (`[1,2,3,5]`,
`[2,3,5,8]`, `[3,5,8,13]`). All three Fibonacci windows outperformed linear identically (10 distinct
products across the 16 cells vs. linear's 9); `[1,2,3,5]` was chosen as the simplest window that
achieved this. The specific tie it breaks over linear weighting is a real one: Likely × Likely
(moderate on both axes) no longer scores identically to Unlikely × Very-High (rare but
catastrophic) — Fibonacci separates a "moderate-everywhere" risk profile from a "rare-but-severe"
one that linear weighting conflated. A full pipeline run against real confluence app data after
landing this change confirmed the shape holds in practice: across 292 combined built-in + custom
findings, Critical stayed a 5.8% minority, Low a 3.8% minority, and High the largest single tier
at 37.7% — the same right-skewed shape the old rank-sum table was tuned to produce, now reached
without an exception cell.

## Why two different engines score differently

As of the Fibonacci-weighting change (see [§4](#4-severity-combining-likelihood-and-impact)), both
paths now share the same weight-product-and-threshold *formula* — this changed from an earlier
state where the two used genuinely different mechanisms (Threagile's built-in weight product vs.
this repo's own rank-sum lookup table). But the two paths still compute their Likelihood and Impact
*inputs* to that shared formula completely independently, and still can, so a similar-looking
finding from a built-in rule and a custom category can score differently even on the same asset:

- Threagile's built-in rules decide their own Likelihood per rule (mostly hardcoded per
  vulnerability class, a few RAA-threshold-gated) and take Impact straight from the asset's/link's
  raw CIA ratings.
- This repo's custom engine starts from a category's own author-judged baseline for both axes, then
  nudges each with its own distinct per-asset deltas (RAA + internet-reachability for Likelihood;
  single-CIA-dimension + gated business-criticality for Impact — see
  [§2](#2-the-likelihood-adjustment-raa-and-internet-reachability) and
  [§3](#3-the-impact-adjustment-cia-rank-and-business-criticality)).

This is accepted, not treated as a bug to reconcile: adopting a shared formula *shape* for both was
a deliberate joint design choice applied to each independently-maintained path at once — it is not
the custom engine deferring to a pre-existing Threagile formula (see [Could the custom engine just
adopt Threagile's own
formula?](#could-the-custom-engine-just-adopt-threagiles-own-formula) below for why that
framing still doesn't apply even now that the formula shape matches). The two paths remain
structurally separate; only the mapping from (Likelihood weight × Impact weight) to a Severity
label converged, and it converged because both were independently retuned toward the same
properties (Critical and Low both genuine single-digit-percent minorities), not because one
deferred to the other.

## Could the custom engine just adopt Threagile's own formula?

This question originally got asked, and answered "no," back when this repo only ever ran the
*unmodified* pinned `threagile/threagile:0.9.1` image (see the baseline threat-modeling repo, which
still does). Since forking Threagile (`jessestarkey/threagile`) and landing the Fibonacci-weighting
change, the premise has partly changed — the formula *shape* is in fact now shared (see
[§4](#4-severity-combining-likelihood-and-impact)) — so this section now answers a narrower
question: does sharing the formula shape mean the two paths should go further and actually merge
into one engine? Still no, for reasons distinct from the original ones.

**There's still no "hand it to Threagile's engine" option.** Even with a forked, editable Threagile
binary, Threagile's built-in categories are scored by compiled Go rules this repo's Python tooling
has no access to and can't call into at the point `inject_risks.py` runs — before Threagile ever
executes. `custom_risk_categories` (what `inject_risks.py` writes, see [this repo's custom
risk-injection engine](#this-repos-custom-risk-injection-engine) above) is author-supplied data
Threagile renders as-is, not something its own engine computes for us, regardless of which fork is
running. So the two paths staying structurally separate was never really about *inability* to share
a formula — the Fibonacci change proves that part was always possible — it's about the inputs each
path feeds that formula remaining genuinely different by design (see [Why two different engines
score differently](#why-two-different-engines-score-differently) above).

**Sharing the formula shape was a deliberate, validated choice — not a step toward merging.** The
weight table and thresholds converged because both were independently retuned toward the same
target properties (Critical and Low each a genuine single-digit-percent minority, no hand-picked
exception cell needed) and that happened to be the same destination for both, not because one
engine's output was piped into or constrained by the other's. Each retains its own Likelihood/Impact
computation entirely, and either could diverge again in the future (a new Fibonacci window, a
different threshold recalibration) without requiring the other to follow, since nothing couples
them beyond both currently choosing the same constants.

**Net:** the two paths now compute Severity through the same formula shape, by coincidence of a
shared, separately-validated design choice — not because the custom engine started deferring to
Threagile's, or because the two engines merged. They remain two independently maintained codebases —
Threagile's own forked `pkg/types` vs. this repo's own `inject_risks.py` — by design, and nothing
about the Fibonacci change requires that to change going forward.

## Source of truth, by topic

| Topic | Where |
|---|---|
| Custom engine's full scoring logic | `models/central-security-repo/core-policies/inject_risks.py` — `compute_likelihood()`, `compute_impact()`, `compute_severity()`, `compute_raa_by_id()`, `compute_internet_reachable_ids()` |
| RAA formula's own weight tables | Same file — `CONF_ASSET`, `CRIT_ASSET`, `CONF_PROCESSED_OR_STORED`, `CRIT_PROCESSED_OR_STORED`, `CONF_TRANSFERRED`, `CRIT_TRANSFERRED`, `QTY_FACTOR`, `RAA_TECHNOLOGY_MULTIPLIER` |
| Current threshold/weight constants | Same file — `RAA_LIKELIHOOD_THRESHOLD`, `RAA_LIKELIHOOD_LOW_THRESHOLD`, `CIA_RANK_TO_DELTA`, `STRIDE_TO_CIA_DIMENSION`, `WEIGHT`, `SEVERITY_THRESHOLDS` |
| Per-category baseline Likelihood/Impact | `models/central-security-repo/libraries/09-custom-risks-lib.yml` — each entry's `baseline_likelihood`/`baseline_impact` |
| Threagile's own built-in categories | This repo's fork, `jessestarkey/threagile` (built via `Dockerfile.local`) — `pkg/types/risk_exploitation_likelihood.go`/`risk_exploitation_impact.go` for the weight tables, `pkg/types/model.go`'s `CalculateSeverity()` for the thresholds; everything else about a built-in rule's own Likelihood/Impact logic stays closed upstream source, cross-referenced against `threagile -explain-risk-rules` and real local runs |
| Built-in category enrichment text | `models/central-security-repo/libraries/10-threagile-builtin-risks-lib.yml` |
| The condensed, report-facing version of this document | `models/central-security-repo/core-policies/templates/report.html.jinja`'s Methodology section |
| Broader repo/pipeline architecture | `CLAUDE.md` |

## Keeping this in sync

There's no automation tying this document to the code. If a threshold, weight, or the severity
matrix itself changes in `inject_risks.py`, update the corresponding number here — and, more
importantly, update the *reasoning* if the change reflects a new trade-off rather than just a
retuned value. A stale number is a quick fix; a stale rationale silently misrepresents why the
methodology works the way it does, which matters more for a document whose whole purpose is
explaining the "why." The report's own condensed Methodology section
(`templates/report.html.jinja`) should be checked for the same drift at the same time — the two
are meant to describe the same underlying logic at two different levels of depth, not diverge from
each other.
