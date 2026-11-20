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
- [Native script rules: a third mechanism, same forked binary](#native-script-rules-a-third-mechanism-same-forked-binary)
- [This repo's custom risk-injection engine](#this-repos-custom-risk-injection-engine)
  - [1. Baseline Likelihood and Impact](#1-baseline-likelihood-and-impact)
  - [2. The Likelihood adjustment: RAA and internet reachability](#2-the-likelihood-adjustment-raa-and-internet-reachability)
  - [3. The Impact adjustment: CIA rank](#3-the-impact-adjustment-cia-rank)
  - [4. Severity: combining Likelihood and Impact](#4-severity-combining-likelihood-and-impact)
- [Why two different engines score differently](#why-two-different-engines-score-differently)
- [Could the custom engine just adopt Threagile's own formula?](#could-the-custom-engine-just-adopt-threagiles-own-formula)
- [Risk calibration](#risk-calibration)
- [Source of truth, by topic](#source-of-truth-by-topic)
- [Keeping this in sync](#keeping-this-in-sync)
- [Appendix: Calibration table](#appendix-calibration-table)

## The two scoring paths, at a glance

Every finding in a report comes from one of two independent rule sources. Severity itself is
standardized — both sources combine Likelihood and Impact into Severity through the same
Fibonacci-weighted formula and threshold bands (see [§4](#4-severity-combining-likelihood-and-impact)).
What differs between them is everything that feeds *into* that shared formula: how each source
decides a finding's Likelihood and Impact in the first place. (A third mechanism, native script
rules, shares the Threagile-binary
execution context with built-in categories but matches the custom engine's own baseline-authorship
and delta mechanism almost exactly — see [Native script rules](#native-script-rules-a-third-mechanism-same-forked-binary)
below; it's folded into the "built-in categories" column's *mechanism* description here since it
computes Likelihood/Impact the same way the custom column does, just running Threagile-side.)

| | Threagile's built-in categories | This repo's custom categories |
|---|---|---|
| Likelihood source | Each rule's own hardcoded baseline, nudged by a shared RAA + internet-reachability delta (`computeLikelihood()` in the fork) | Category's own author-judged baseline, adjusted per-asset (`compute_likelihood()`) |
| Impact source | Asset's/link's own CIA ratings (most rules narrowed to the single STRIDE-mapped dimension; some stay multi-dimensional by documented exception) | Category's own author-judged baseline, adjusted per-asset |
| Combination rule | Fibonacci weight (1,2,3,5) product, bucketed by threshold | Same Fibonacci weight-product-and-threshold formula |
| Where it runs | Inside the forked Threagile binary (`jessestarkey/threagile`) — compiled Go rules and native YAML script rules alike | `inject_risks.py`, before Threagile ever runs |
| Enrichment text | `libraries/10-threagile-builtin-risks-lib.yml` (built-in rules); inline per file (native scripts) | `libraries/09-custom-risks-lib.yml` |

As of the built-in-rule standardization project, 35 of ~42 built-in rules share this shape with the
custom engine almost exactly — a per-category/per-rule baseline, nudged by the same RAA/
reachability delta and (where it fits) the same single-STRIDE-dimension Impact narrowing. Only 7
rules stay out of scope by design: the model-authoring checks, not real vulnerabilities a per-asset
delta would mean anything for. (An earlier version of this project left 4 more rules out too — the
whole-model singleton checks, "does *any* asset have a vault" and similarly-shaped checks — on the
theory that they have no single asset to anchor a delta on; a later pass found each one already
selects a "most relevant example asset" for its own reporting, and anchored the delta on that
instead of leaving it out.) See [Threagile's built-in risk categories](#threagiles-built-in-risk-categories)
below for the full picture, and [Why two different engines score
differently](#why-two-different-engines-score-differently) for why, even with the mechanism this
aligned, the two paths still aren't one engine.

Both paths land on the same five-level Severity scale — Low, Medium, Elevated, High, Critical —
and both are shown through identical badges/columns in the report, but a similar-looking finding
can still score differently depending on which engine produced it, since each path still computes
its own baseline and reads its own inputs independently.

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
repo still pins — not assumed) rather than approximated. It works in eight steps:

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
   scaled by that data asset's own Confidentiality/Integrity/Availability rank (via
   `CONF_PROCESSED_OR_STORED`/`CRIT_PROCESSED_OR_STORED` above — Availability shares the same
   `CRIT_PROCESSED_OR_STORED` table Integrity uses, the same way it does for the asset's own rating
   in step 1). Confidentiality and Integrity are *also* scaled by the data asset's `quantity` field
   (`very-few`→1, `few`→2, `many`→3, `very-many`→5); Availability is added at its raw weight,
   un-scaled by quantity — this asymmetry is Threagile's own real formula (`raa.go`'s own comment:
   "Multiplied by the quantity values of the data asset for C and I (not A)"), faithfully
   replicated here, not an omission.
3. Add a smaller weighted contribution for every data asset sent or received over the asset's own
   communication links, the same way but via `CONF_TRANSFERRED`/`CRIT_TRANSFERRED` (same
   Confidentiality/Integrity quantity-scaling, same un-scaled Availability term).
4. Scale the whole sum by a technology-type multiplier: a reverse proxy, load balancer, or
   monitoring asset is structurally a conduit and is scaled *down* (÷5.5 for the first two, ÷5 for
   monitoring) regardless of its own CIA rating; an identity provider, vault, or container platform
   is scaled *up* (2×–5×) since it's disproportionately attractive independent of what it's rated.
   A generic `datastore`-type asset with no more specific multiplier still gets a flat 2× floor.
5. Apply a 1.5× multiplier if the asset is `multi_tenant`.
6. **Normalize once**, provisionally: every asset's raw score (steps 1–5) to 0–100% relative to the
   min/max across every asset *in this specific model* (floored at 1%, since 0% would imply an
   asset can't be attacked at all). This first pass exists only to give step 7 something
   comparable to measure a gap in — it isn't the final RAA value.
7. **Pivot**: using those normalized percentages, an asset inherits up to a third of the positive
   attractiveness gap to the single most attractive asset it can directly reach over its own
   communication links — value propagates backward from a high-value target onto whatever can
   reach it, so a plain-looking front-door asset that happens to have a path to a vault or identity
   provider scores higher than its own raw attractiveness alone would suggest. The resulting
   adjustment is added back onto each asset's *raw* (step 1–5) score, not its normalized one.
8. **Normalize again**: the adjusted raw scores (step 5 + step 7's adjustment) go through the same
   0–100%-relative-to-this-model normalization a second time — this second pass is the actual final
   RAA value, not step 6's. Two normalization passes, not one, is Threagile's own real design
   (`raa.go`'s `calculatePivotingNeighbourEffectAdjustment()` computes its delta off normalized
   values before `applyRAA()` normalizes the adjusted raw score again at the end) — faithfully
   replicated here down to the double pass, not simplified to a single final step.

That final normalization matters: RAA is **relative to the model it's computed against**, not an absolute
scale — "at or above 40%" means a different real attack-worthiness in a 3-asset model than in a
50-asset one. This instability is inherited directly from Threagile's own real RAA design; this
repo faithfully replicates it rather than correcting it, since correcting it would mean deviating
from a faithful replication of Threagile's own formula, and doing so hasn't been validated against
whether Threagile's own built-in RAA-aware rules are actually less exposed to the same instability
in practice.

## Threagile's built-in risk categories

Threagile's own ~42 built-in rules (Missing Authentication, SQL/NoSQL Injection, Missing WAF, and
so on) score entirely inside the engine binary itself — this repo builds that binary from
`jessestarkey/threagile`, a fork of upstream Threagile, so unlike the baseline threat-modeling
repo's pinned `threagile/threagile:0.9.1` image, this repo's own fork actually controls and has
edited not just the weight table and severity thresholds (below) but, as of the built-in-rule
standardization project, most individual rules' own Likelihood/Impact scoring logic too. Everything
else about a rule's *detection logic* (does this risk apply at all to this asset/link) remains
upstream, closed logic this repo treats as given rather than second-guesses.

**The standardization project.** 35 of the ~42 rules were brought onto the same per-asset-context
shape the custom engine already used for Likelihood: a shared `computeLikelihood()` helper
(`pkg/risks/builtin/helpers.go` in the fork) mirroring `inject_risks.py`'s own
`compute_likelihood()` almost exactly — same RAA delta, same internet-reachability check. Each rule
keeps its own hardcoded value as its *baseline* (exactly the role `baseline_likelihood` plays in
`09-custom-risks-lib.yml`) and calls the shared helper to nudge it per asset, rather than using the
flat value for every asset the rule fires on. Impact is a separate story — see the
`computeImpact()` note further below; there is no broadly-shared Impact helper the way there is
for Likelihood, the single-STRIDE-dimension narrowing is applied per-rule, inline.

Only 7 rules were deliberately left out of this and still use only their original, context-blind
Likelihood logic: the model-authoring-mistake checks (`ModelFailurePossibleReason: true` —
incomplete model, unnecessary assets, etc.), which aren't real vulnerabilities a per-asset delta
would mean anything for.

**The 4 whole-model singleton checks** ("does *any* asset in the model have a vault/identity
store/build pipeline," plus push-vs-pull deployment) were originally left out alongside the model-
authoring checks too, on the theory that a whole-model check has no single asset to anchor a
per-asset RAA delta on. That theory didn't hold up: every one of these rules already selects a
"most relevant example asset" to anchor its own `MostRelevantTechnicalAssetId` for reporting — the
same asset the `computeLikelihood()` delta needs. `missing_vault_rule.go` is the one exception
requiring a guard: it can legitimately fire with no technical asset at all (a true "there is no
vault anywhere, and nothing else to point to either" case), so its call into `computeLikelihood()`
is skipped when the chosen asset is `nil`, falling back to the flat baseline for that specific case
only. `missing_cloud_hardening_rule.go`'s and `mixed_targets_on_shared_runtime_rule.go`'s own
shared-runtime/trust-boundary-level risk paths are a genuinely different case from these 4 — they
score a *shared runtime or trust boundary itself*, not a single asset standing in for "no X exists
anywhere," and still keep a flat baseline Likelihood for that reason.

**Impact narrowing.** For each of the 35 in-scope rules, the existing Impact check (most originally
checked multiple CIA fields at once) was reviewed individually against its own category's STRIDE
value and Impact text — narrowed to the single STRIDE-mapped dimension where the category's own
text was genuinely single-dimension (e.g. `path-traversal` and `xml-external-entity`, both purely
about *reading* files, narrowed from a Confidentiality-or-Integrity check to Confidentiality alone),
left multi-dimensional with an inline comment explaining why where the category's own text spans
more than one dimension (e.g. `sql-nosql-injection`'s own Impact text says an attacker can "steal
*and modify*" data — the same accepted Confidentiality+Integrity pattern this file's own
`STRIDE_TO_CIA_DIMENSION` discussion documents for spoofing above), and left untouched where the
rule's own `moreRisky`/gate logic already folds in something a generic CIA check can't know about
(e.g. `dos-risky-access-across-trust-boundary`'s VPN/IP-filtering/redundancy factors). This is why
there's no broadly-shared Impact helper the way there is for Likelihood — the right Impact logic
genuinely differs per rule (which single dimension, whether a gate overrides a generic CIA check),
where Likelihood's RAA/reachability delta is identical everywhere it applies.

**A `computeImpact()` helper does exist in `helpers.go`, but it's dead code.** No built-in rule
calls it. Three rules (`cross_site_request_forgery_rule.go`,
`dos_risky_access_across_trust_boundary_rule.go`, `missing_authentication_rule.go`) mention it by
name in a comment explaining why *that specific rule* computes Impact its own way instead (a
link's own rating rather than the asset's, in CSRF's case). It used to still carry the gated
business-criticality bump that had already been removed from the Python engine and every native
script rule (see [§3](#3-the-impact-adjustment-cia-rank)) — a genuine, if inert, inconsistency,
since nothing called it so the bump was never actually live. That's since been cleaned up too, so
all three layers now agree even in code nothing currently executes — no landmine left for if a
future rule is ever wired into it.

**The 4 RAA-special-cased rules got an actual redesign, not just a wiring change.** Before this
project, none of them used RAA as a Likelihood delta the way the custom engine always has:
`missing-hardening` and `missing-network-segmentation` used RAA purely as an *existence gate*
(the risk doesn't fire at all below a `raaLimit`/`raaLimitReduced` threshold); `unguarded-access-
from-internet` and `unguarded-direct-datastore-access` used RAA as a flat *Impact* bump
(`if dataStore.RAA > 40 { impact = MediumImpact }`) layered on top of an already-maximal, RAA-blind
Likelihood. All four now run RAA through the shared `computeLikelihood()` delta like every other
rule, consistent with the custom engine's own architecture (RAA affects how *likely* exploitation
is, not how *severe* it is once it occurs):

- For the two existence-gated rules, the gate itself is kept exactly as-is (that's a genuine
  detection-logic question — "is this asset hardening-worthy/segmentation-worthy at all" — separate
  from scoring). Since both gates' thresholds (55%/40% and 50%) already sit at or above
  `computeLikelihood()`'s own 40% high threshold, every asset that reaches the gate also
  automatically earns the RAA Likelihood bump — the two roles don't conflict, they're just no
  longer the same mechanism doing both jobs at once.
- For the two Impact-bump rules, RAA was removed from Impact entirely (Impact now depends only on
  the asset's own CIA rating) and the previously-flat baseline Likelihood now goes through
  `computeLikelihood()` instead — a real behavior change, confirmed against real test fixtures
  (a genuinely low-RAA asset's Likelihood now gets pulled down a notch where it previously never
  would have, and a high-RAA asset's severity bump now shows up on the Likelihood axis instead of
  Impact).

This whole project reused the mapping/weight/threshold constants `inject_risks.py` already defines
(`RAA_LIKELIHOOD_THRESHOLD`/`RAA_LIKELIHOOD_LOW_THRESHOLD`/`STRIDE_TO_CIA_DIMENSION`/
`CIA_RANK_TO_DELTA`) rather than inventing a second, slightly-different set of numbers in Go — the
two files' own constants should be checked against each other if either is ever retuned (see
[Keeping this in sync](#keeping-this-in-sync)).

What's known and confirmed by testing, for the remaining upstream, closed detection-logic pieces
of every rule:

- **Impact** comes from the affected technical asset's (or communication link's) own
  Confidentiality/Integrity/Availability ratings — as of the standardization above, usually
  narrowed to a single dimension, computed inline per-rule rather than through a shared helper (see
  the `computeImpact()` dead-code note above).
- **Likelihood**'s baseline is still decided independently by each rule (a hardcoded constant per
  vulnerability class, or an existence-gate/RAA-dependent trigger for the 4 rules discussed above),
  then nudged by the shared RAA + reachability delta for all 35 in-scope rules. Two of Threagile's
  four originally-RAA-aware built-in rules (`unguarded-access-from-internet`,
  `unguarded-direct-datastore-access`) used a flat 40% cutoff before this project; the other two
  (`missing-hardening`, `missing-network-segmentation`) use a two-tier `raaLimit`/`raaLimitReduced`
  pair instead. This repo's own custom engine's RAA threshold (see
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
(description/impact/ASVS/cheat-sheet/risk-assessment/detection-logic/references/false-positives)
the custom engine's library provides for its own categories — it doesn't feed Severity, only
report narrative. It started as a one-time extraction of Threagile's own upstream output (its
`-explain-risk-rules` text and native `report.pdf`), but has since been rewritten with real
technical depth and is actively maintained here going forward, the same as `09-custom-risks-lib.yml`
is for the custom engine's own categories — not pass-through upstream text anymore.

## Native script rules: a third mechanism, same forked binary

Alongside the compiled Go built-in rules above, the fork has a second, independent way to add risk
categories that still runs *inside* the Threagile binary rather than as Python preprocessing:
`pkg/risks/scripts/*.yaml`, a YAML scripting DSL (match conditions, utility functions, loops,
`calculate_severity()`) loaded via `go:embed` and auto-discovered at startup — no edit to the
engine's own rule-registration code needed to add one. 66 files exist today, almost entirely
IL5-specific categories (AI/ATLAS/MAESTRO threat vectors, CDS, container/VM hardening, mission
systems) that were deliberately rolled into the fork instead of staying as `inject_risks.py`
Python categories, on the view that this fork is purpose-built for IL5+ systems and content
specific to it belongs natively in the engine rather than bolted on as a preprocessing step.

**The mechanism matches the custom engine's, not the built-in rules'.** Each script supplies its
own author-judged baseline Likelihood/Impact (the same role `baseline_likelihood`/`baseline_impact`
play in `09-custom-risks-lib.yml`, and the same role a built-in rule's hardcoded constant plays),
nudged by the identical RAA delta (`+1` at RAA ≥ 40, `-1` below 15) and the identical single-
STRIDE-dimension CIA delta described in [§2](#2-the-likelihood-adjustment-raa-and-internet-reachability)
and [§3](#3-the-impact-adjustment-cia-rank) above — same thresholds, same STRIDE-to-CIA mapping,
reused deliberately rather than independently retuned a third time. As of this writing, every one
of the 66 files applies both deltas; `accidental-secret-leak.yaml` was the one exception (a flat,
RAA-blind `unlikely` baseline) until it was brought into line with the rest.

**One deliberate difference: no internet-exposure delta.** The custom engine adds `+1` Likelihood
when an asset is internet-reachable (`exposed_delta` in [§2](#2-the-likelihood-adjustment-raa-and-internet-reachability)).
The native scripts leave it out on purpose, decided 2026-11-17. Native rules are moving toward using
exposure to decide *whether* they fire at all, rather than as a Likelihood nudge. For example, many
of the reworked AI rules fire only when an asset is reachable from outside its own trust boundary
(see `docs/ai-risk-rework-plan.md`), and adding `+1` for exposure on top of that would count the
same fact twice. So a native finding and a custom finding on the same asset can differ by one
Likelihood level when that asset is internet-reachable. That is expected, not drift.

**There's no shared helper to call, by design of the DSL.** The script language has no
cross-file sharing (`pkg/risks/script/risk-rule.go`'s `loadRiskRule()` parses each file
independently), so the RAA/CIA delta logic is written out in full inside every single file's own
`get_likelihood`/`get_impact` utility functions — 66 independent copies of the same two formulas,
not a shared library call. This is a real, accepted maintenance cost specific to this mechanism:
retuning the RAA thresholds or the STRIDE-to-CIA mapping means editing up to 66 files by hand, not
one shared helper, on top of the existing two-copy (Python/Go) sync burden described in [Keeping
this in sync](#keeping-this-in-sync).

**These files also had their own business-criticality bump, and it was removed from all of them.**
Every script's Impact calculation used to include the same gated system-wide bump the custom
engine's `compute_impact()` had — removed from both for the same reason (see
[§3](#3-the-impact-adjustment-cia-rank)): it mostly inflated assets whose own CIA rating was
genuinely lower than the system around them, not the under-rated components it was meant to
protect. Unlike the built-in Go layer's dead `computeImpact()` helper (see [Threagile's built-in
risk categories](#threagiles-built-in-risk-categories) above), this bump was live and firing in
every one of these 73 files before removal — there was no "nothing calls it" safety net here.

**Enrichment text lives inline, not in a separate library file.** Unlike built-in rules
(`10-threagile-builtin-risks-lib.yml`) or custom categories (`09-custom-risks-lib.yml`), each
script carries its own full description/impact/ASVS/cheat-sheet/action/mitigation/detection-logic/
references/risk-assessment/false-positives set directly in the file — there's nothing to look up
in a companion library for this mechanism.

## This repo's custom risk-injection engine

`inject_risks.py` scans every technical asset's tags against a large if-chain and injects matching
`custom_risk_categories` entries (Threagile's own field name for this; it was renamed upstream from
`individual_risk_categories`, and this repo's loader builds its internal dict keyed by title as
before but converts to the new list-of-entries shape at the final write step), each with its own
computed Severity — not a flat value copy-pasted onto every finding in a category regardless of
which asset it landed on. The computation has four steps.

### 1. Baseline Likelihood and Impact

Every one of the 89 category definitions in `libraries/09-custom-risks-lib.yml` carries its own
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

**Internet reachability.** `net:internet-reachable` is an explicit, author-maintained tag, checked
directly (`'net:internet-reachable' in tags`) — broader than a direct `zone:dmz` tag, since most
vulnerability classes pass straight through a WAF untouched, so the real application behind an
already-modeled gateway/ALB/WAF is still a realistic target even though it isn't the edge component
itself (which already carries its own native `internet: true` field). An author applies this tag to
whichever specific assets are actually known to be reachable — typically the real backend behind
the gateway, not the gateway itself.

This *was* a computed signal instead: `compute_internet_reachable_ids()` walked outbound
`communication_links` from every `zone:dmz`-tagged asset, stopping at the first real application
tier reached (`app:frontend-ui`/`app:backend-api`/`app:async-worker`, assumed to be plumbing
otherwise) rather than expanding unboundedly. It was removed after being confirmed to produce real
false positives in practice: a shared infrastructure hop with multiple independent inbound
paths — e.g. one Ingress Controller serving both a DMZ-rooted login flow and an entirely separate,
never-internet-facing internal flow — has no way in a plain graph walk to distinguish which of its
own outbound edges continue the DMZ-originated flow versus which belong to an unrelated caller, so
once any inbound edge marked the shared hop reachable, the walk indiscriminately marked *every* one
of its outbound targets reachable too. Fixing that properly would mean tracking path provenance
through shared nodes (per-edge tagging), which reintroduces a comparable maintenance burden to what
an explicit tag already requires, without the walk's own upside of being cheap to audit. The
explicit tag is therefore not just cheaper than the walk — it's more *correct*, not a
completeness-for-effort tradeoff.

This delta is **one-directional** by design: not being reachable is simply the ordinary case the
category's own baseline already assumes, not a fact that should push Likelihood *below* baseline
the way a genuinely low-RAA asset does.

`zone:dmz` itself stays narrowly scoped to "this asset directly receives hostile traffic" (used by
the Missing WAF and Dangling DNS checks, which must not broaden to match) — `net:internet-reachable`
is a deliberately separate, broader signal, manually applied rather than derived from it.

As of the built-in-rule standardization (see [Why two different engines score
differently](#why-two-different-engines-score-differently)), the forked engine's built-in rules
check the same two signals directly: `technicalAsset.Internet || contains(technicalAsset.Tags,
"net:internet-reachable")`, reusing a `contains()` helper already in `pkg/risks/builtin/helpers.go`.

### 3. The Impact adjustment: CIA rank

Baseline Impact gets a **-1 / 0 / +1** delta from the asset's own CIA rank on whichever single
dimension the finding's STRIDE category actually threatens:

```
dimension          = STRIDE_TO_CIA_DIMENSION[stride]   (falls back to max(C,I,A) if unmapped)
cia_delta           = -1 if rank in {public/archive, internal/operational}
                    =  0 if rank in {restricted/important}
                    = +1 if rank in {confidential/critical, strictly-confidential/mission-critical}

Impact = clamp(baseline_impact + cia_delta)
```

**This used to also get a gated +1 if the model's overall Business Criticality was Critical or
Mission-Critical** (whenever the asset's own cia_delta hadn't already earned it) — a system-wide
signal meant to catch a low-value-looking component that still matters more inside an important
system. Removed: every asset in this framework already carries an individually-justified CIA
rating (`justification_cia_rating` is a real, per-asset writeup, not a formality), so the bump's
practical effect was almost entirely to inflate assets whose *own* rating was genuinely lower than
the system around them — the same peripheral-asset-noise problem it was meant to prevent, just
pointed at a different set of assets. An asset that's genuinely more important than its own CIA
rating suggests should get that rating corrected directly, not compensated for indirectly by a
model-wide flag.

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

Two separate changes brought the engines closer together, in stages: first the Fibonacci-weighting
change made both use the same weight-product-and-threshold Severity *formula* (see
[§4](#4-severity-combining-likelihood-and-impact)); then the built-in-rule standardization project
(see [Threagile's built-in risk categories](#threagiles-built-in-risk-categories)) made 35 of ~42
built-in rules compute their Likelihood/Impact *inputs* to that formula the same *way* the custom
engine does — a per-category/per-rule baseline nudged by a shared RAA + reachability delta
(Likelihood) and, where it fits, a single-STRIDE-dimension narrowing (Impact). Despite that, a
similar-looking finding from a built-in rule and a custom category can still score differently on
the same asset, for reasons that survive both changes:

- **The baselines themselves are still independent author judgments.** A built-in rule's hardcoded
  Likelihood/Impact constant and a custom category's `baseline_likelihood`/`baseline_impact` in
  `09-custom-risks-lib.yml` were set by different authors (upstream Threagile maintainers vs. this
  repo's own) at different times, for categories that don't always map 1:1 even when they sound
  similar.
- **7 of the ~42 built-in rules stay out of the standardization entirely** (the model-authoring
  checks — see [Threagile's built-in risk categories](#threagiles-built-in-risk-categories)), so
  they never picked up the shared delta mechanism at all and still score exactly as they did
  before any of this project's changes.
- **Some in-scope rules deliberately keep a wider, multi-dimension Impact check** where their own
  category text genuinely spans more than one CIA dimension (documented inline per rule, the same
  accepted-tradeoff pattern `STRIDE_TO_CIA_DIMENSION`'s own spoofing discussion uses below) — so
  "narrowed to one dimension" isn't a blanket rule even within the 35 standardized rules.
- **Detection logic — whether a risk fires at all for a given asset — remains entirely
  rule-specific and untouched** by this project; only the scoring of a risk that already fired was
  brought into alignment.

This is accepted, not treated as a bug to reconcile: aligning the formula shape and, later, the
delta mechanism were each a deliberate joint design choice applied to each independently-maintained
path at once — not the custom engine deferring to a pre-existing Threagile formula (see [Could the
custom engine just adopt Threagile's own
formula?](#could-the-custom-engine-just-adopt-threagiles-own-formula) below for why that framing
still doesn't apply even now that both the formula shape and most of the delta mechanism match).
The two paths remain structurally separate — two different codebases, two different sets of
authored baselines, two different rule counts in scope — even though a growing share of their
*mechanism* now matches by convergent, separately-validated design rather than by one deferring to
the other.

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
engine's output was piped into or constrained by the other's. Either could diverge again in the
future (a new Fibonacci window, a different threshold recalibration) without requiring the other to
follow, since nothing couples them beyond both currently choosing the same constants.

**The later built-in-rule standardization project went further than the formula shape, but still
isn't a merge.** 35 of ~42 built-in rules now call a shared Go helper (`computeLikelihood()` in the
fork) that mirrors `inject_risks.py`'s own `compute_likelihood()` almost exactly — same RAA delta,
same reachability check. (A `computeImpact()` helper of the same shape also exists in the same
file, mirroring `compute_impact()`'s current, bump-free form — but it's dead code nothing
currently calls; see the note under [Threagile's built-in risk
categories](#threagiles-built-in-risk-categories).) This is real, intentional convergence of
*mechanism* on the Likelihood side, not just formula shape — but each rule still supplies its own
baseline (its original hardcoded constant, author-judged by upstream Threagile maintainers, not
ported from this repo's own `09-custom-risks-lib.yml`), and `inject_risks.py` still can't call into
the Go helpers or vice versa — they're the same *logic*, implemented twice, in two languages,
because there is still no runtime bridge between the Python preprocessing step and the compiled
binary it hands its output to. Keeping both copies in sync by hand (see [Keeping this in
sync](#keeping-this-in-sync)) is the real cost this convergence took on
in exchange for consistency — a cost worth re-examining if the two sets of constants ever drift.

**Net:** the two paths now compute Severity through the same formula shape, by coincidence of a
shared, separately-validated design choice — not because the custom engine started deferring to
Threagile's, or because the two engines merged. They remain two independently maintained codebases —
Threagile's own forked `pkg/types` vs. this repo's own `inject_risks.py` — by design, and nothing
about the Fibonacci change requires that to change going forward.

## Risk calibration

A single rubric for the final likelihood and impact of every rule, in all three layers, applied after each layer's adjustments. Approved 2026-11-18.

### Why this exists

The three rule layers start from very different ratings:

| Layer | Rules | Mean starting likelihood (0–3) | Mean starting impact (0–3) | Very High impact | Likely+ **and** High+ |
|---|---|---|---|---|---|
| Built-in (upstream Threagile, in the fork) | 35 | 1.11 | 0.60 | 0 | 3% |
| Extension (fork script rules) | 66 | 1.76 | 1.94 | 26 | 42% |
| Organization-specific (custom engine) | 89 | 1.58 | 1.67 | 22 | 34% |

That gap gets wider once the per-asset adjustments run, because the layers adjust impact
differently:

| Layer | Likelihood adjustment | Impact adjustment |
|---|---|---|
| Built-in | baseline, RAA ±1 (`computeLikelihood()`), +1 internet-reachable | **step up only**, set per rule; usually +1 only at the top tier (strictly-confidential / mission-critical), sometimes at confidential/critical; never down |
| Extension scripts | baseline, RAA ±1, rule-specific model-fact steps; **no** internet delta (exposure gates firing instead) | **symmetric ±1** on the STRIDE-mapped CIA dimension: −1 public/internal (archive/operational), 0 restricted/important, **+1 confidential/critical and up** |
| Custom engine | baseline, RAA ±1, +1 `net:internet-reachable`, optional branch step | same symmetric ±1 as the scripts (`compute_impact()`) |

In an IL5 model most assets are rated confidential/critical, so:
- a built-in rule with starting impact Medium ends at **Medium**;
- a script or custom rule with starting impact Medium ends at **High**.

The two columns don't mean the same thing. This rubric therefore rates **final** outcomes on
defined reference assets, and fixes the adjustment convention so starting ratings can be compared.

### The impact-adjustment convention (decided: option A)

| Option | What changes | Effect |
|---|---|---|
| **A. Symmetric everywhere (chosen)** | The built-in rules' inline impact steps are replaced with the same symmetric ±1 on the STRIDE-mapped dimension the other layers use. The fork already standardized built-in *likelihood* this way. | One convention. A starting rating means the same thing in every layer: the impact on a restricted/important asset. Built-ins gain a downward step for low-value assets and an upward step at confidential/critical. |
| B. Step-up-only everywhere | Scripts and the custom engine drop their −1 step and +1 only at the top tier, like the built-ins. | Matches upstream, but loses the low-value step-down, which was added on purpose to stop baselines acting as hard floors. |
| C. Keep both conventions | Each layer's baselines are re-rated so the final outcome on the reference assets fits the anchors. | No code change to adjustments, but the starting-rating columns stay non-comparable and every future rule needs per-layer arithmetic. |

The anchors below apply to final outcomes either way. Option A makes them map directly onto
baselines: `baseline = target on the restricted/important asset`.

### Reference assets

Each rule is rated by the final likelihood and impact it produces on these assets, after every
adjustment.

| Profile | CIA rating | RAA | Exposure | Use |
|---|---|---|---|---|
| **R — reference** | restricted / important / important (rank 2: no CIA step) | 15–40 (no RAA step) | not internet-reachable | where baselines are set |
| **T — typical IL5** | confidential / critical / important | 15–40 | not internet-reachable | the anchors' main check: what most findings will actually show |
| **H — high** | strictly-confidential / mission-critical / mission-critical | ≥ 40 | internet-reachable | must not saturate at Critical across most rules |
| **L — low** | internal / operational / operational | < 15 | not internet-reachable | should drop to Low/Medium severity |

### Impact anchors (final rating)

Rate the **typical** consequence of a successful exploit on the asset, not the worst incident on
record. The worst case belongs in the rule's `risk_assessment` ("Critical when …"), not in its
baseline.

| Impact | Anchor | Examples |
|---|---|---|
| **Very High** | Exploitation directly yields code execution, administrative or privileged control, or bulk compromise of confidential data, with no further step needed. | injection reaching an interpreter, container escape, supply-chain code that runs on load |
| **High** | Direct compromise of a meaningful part of the asset's data or function, or broad compromise that needs one further step. | IDOR / broken object authorization, stored XSS, an agent's writable tool misused |
| **Medium** | A missing or weak control whose absence enables or worsens another attack (defense in depth, detection, recovery, change control, governance), or limited direct harm. | missing WAF, missing audit logging, no kill switch, no tested rollback |
| **Low** | Hygiene, or information leakage with little standalone consequence. | verbose errors without sensitive data, model-authoring mistakes |

### Likelihood anchors (final rating, profile R)

Every rule is first classed by what its finding asserts:
- **W — weakness shown.** The model's own facts show the weakness: an unencrypted link, a
  writable tool, an outside caller, a static secret on a link.
- **G — control not evidenced.** The finding means "this control can't be seen in the model":
  it fires unconditionally, or on a tag that only says a feature exists.

| Likelihood | Anchor |
|---|---|
| **Very Likely** | Exploitation needs only access the asset already exposes and public techniques, and is routinely seen in the wild. The standard of evidence is several documented incidents, or CAPEC/OWASP rating likelihood High with widespread prevalence. |
| **Likely** | Commonly exploited when present; documented incidents exist; needs moderate skill or one ordinary precondition. |
| **Possible** | Needs a specific precondition (insider access, a prior foothold, a chained failure), or the evidence is mainly research and demonstrations. |
| **Unlikely** | Needs privileged access or rare conditions; no in-the-wild evidence. |

**G-class cap:** a control-not-evidenced finding starts at most **Likely**, and one level below the
weakness it would enable, unless there is evidence that the control is commonly absent in
practice. The finding says the control isn't visible, not that the weakness was exploited.

### Severity sanity checks (on a reference model)

After re-rating, run every rule on a reference model of T-profile assets, which is where most
real findings will sit, and check:
- **Critical** is rare on profile T and appears on profile H, where exposure and value are
  both high (about 5–15%), only where both axes are genuinely maxed.
- Most **G-class** findings land at **Medium–Elevated**, not High.
- **Built-in and extension rules covering comparable weaknesses** land within one severity level
  of each other, for example `missing-authentication` against `ai-agent-identity-privilege-abuse`.

### Decisions (2026-11-18)

- **Impact convention: option A.** Every layer uses the symmetric ±1 step on the STRIDE-mapped
  CIA dimension. The built-in rules' step-up-only impact logic is replaced.
- **G-class cap: approved.** Rules that fire because an interface exists (a database, web app,
  API, pipeline), including the injection rules, are G-class. A database existing does not show
  a SQL injection; the rule still fires on every database, but rates the surface, not a
  confirmed flaw.
- **Critical** is expected on profile H, not on profile T.
- **Overrides to the independent pass:**
  - `cicd-pipeline-tampering-outside-repo`: impact High, not Medium (a tampered pipeline ships
    attacker code).
  - `missing-build-infrastructure` and `missing-identity-store` are exempt from the CIA step
    (whole-model checks whose reported asset is only a placeholder).
  - `fips-non-compliant-cryptography` and `ai-hidden-context-exposure` accept Medium on profile
    T.

### Results (independent re-rating, checked)

An independent Opus pass applied this rubric to all 190 catalogued rules. Claude then checked it
for:
- severity arithmetic;
- baseline plus the CIA step reproducing each final rating;
- the G-cap;
- STRIDE-to-dimension consistency.

All held. The full table is in
[Appendix: Calibration table](#appendix-calibration-table).

| Layer | Rules | Baseline changes | Final rating on T changes |
|---|---|---|---|
| Built-in | 35 | 23 | 30 |
| Extension (script) | 66 | 60 | 51 |
| Organization-specific | 89 | 78 | 70 |

Severity of every rule on each reference profile:

| Profile | Low | Medium | Elevated | High | Critical |
|---|---|---|---|---|---|
| T, before | 5 | 34 | 40 | 96 | 15 |
| T, after | 2 | 37 | 97 | 54 | 0 |
| H, after | 0 | 2 | 34 | 134 | 20 |
| L, after | 109 | 68 | 13 | 0 | 0 |

Of the comparable cross-layer pairs reviewed, 11 of 23 were two or more severity levels apart
before; one is after (code-backdooring, CI/CD tampering and dependency confusion, which are a
family rather than a true pair). The rules that reach Critical on profile H are injection and
code execution, deserialization, tier-0 identity, exposed admin panels, ICS/OT, and agent code
execution.

### Status: applied to the rules (2026-11-18)

The approved ratings are now in the rules of all three layers. The threat catalogue's
Likelihood/Impact columns and justifications are updated separately.

- **Script rules:** each states its baseline once and calls the fork's shared scoring built-ins
  (`adjust_likelihood`, `adjust_impact`, `adjust_impact_rank`, `cia_rank`), keeping its own
  rule-specific steps. `pkg/risks/scripts/calibration_test.go` checks every script rule against
  this table on profile T.
- **Built-in rules:** approved baselines and the symmetric CIA step, each keeping its existing
  rating source (processed data, stored data, link data, or the asset itself). Every branch
  step is one level.
- **Custom engine:** approved baselines in `09-custom-risks-lib.yml`; the engine already used the
  symmetric step.

Decisions made while applying it:
- **Injection rules** (cross-site scripting, SQL/NoSQL, LDAP and search-query injection) take
  the CIA step from the higher of confidentiality and integrity, not the Tampering dimension
  alone: injection both reads and alters data.
- **DevOps branches** are a one-level likelihood step down. SQL/NoSQL injection and SSRF keep
  their documented rule of skipping the RAA/internet step on a DevOps link.
- **Mitigations the model can show** keep a one-level impact step down: a code-inspection
  platform (code backdooring), and a VPN-protected, IP-filtered or redundant target (DoS). SSRF
  keeps its Medium floor inside a cloud boundary.
- **Agent rules** take impact from the highest rating across the agent and every target it
  reaches, instead of jumping to Very High when any target is mid-rated.
- **AI rules that fire only with confidential data** take that data as the floor for the
  confidentiality step.
- `ai-telemetry-prompt-log-leakage` has no step for a modeled telemetry link: its baseline already
  sits at the cap for a control-not-evidenced finding.

Fixes applied with it:
- Branch steps that overshot are one level: the same-execution-environment step of
  `missing-identity-provider-isolation` and `missing-vault-isolation`, the cross-boundary step of
  `unencrypted-communication`, and the cross-boundary step of `untrusted-deserialization`.
- `accidental-secret-leak` moves from step-up-only impact to the symmetric step.
- `unencrypted-virtual-disk` fires only when the asset's `encryption` is none.
- `ai-retrieval-resilience-gap`, `ai-sensitive-information-disclosure`,
  `ai-synthetic-data-leakage` and `ai-telemetry-prompt-log-leakage` replace a hard-coded impact
  with baseline plus the symmetric step.
- `push-instead-of-pull-deployment` rates each deployment target on its own (one target's impact
  no longer carries over to the next).
- `backup-integrity-recovery-gap` changes STRIDE from information-disclosure to tampering.
- Still open: the catalogue's two Optus breach figures (9.5 million vs 9.8 million customers)
  are reconciled after verification.

On the Confluence fixture model, findings went from 384 to 383 (the dropped one is a
virtual-disk false positive on an encrypted host) and Critical from 64 to 11.

### Finding class in the output and the report

Every rule carries its approved class (the *Class* column of the appendix table), as
`finding_class`: `weakness-shown` or `control-not-evidenced`.

- **Where it is set:** in each built-in rule's category and each script rule's YAML in the fork,
  and on each entry of `09-custom-risks-lib.yml`, which the engine passes through to the model.
- **Where it appears:** on every finding in `risks.json`, and on every category in
  `risk-categories.json`, which the fork writes next to `risks.json` with each category's
  metadata (including `risk_assessment`) from all three layers.
- **In the report:** open risks are split into *Model Weaknesses* and *Control
  Verifications*. Each control verification shows its risk assessment as the severity to assign if the
  control is confirmed missing; every category's details show its class. A self-check fails the
  run if the split doesn't add up to the open-risk total. Tracking status already appears next
  to severity in every findings table.

On the Confluence fixture model, the 383 open findings split into 29 model weaknesses and 354
control verifications.

### Drift checks

A rating or class that moves away from the appendix table fails a test:

| Layer | Check |
|---|---|
| Script rules | `pkg/risks/scripts/calibration_test.go`: every rule on profile T |
| Built-in rules | `pkg/risks/scripts/builtin_calibration_test.go`: the 13 built-ins that fire on the profile-T kitchen-sink model, each named (the rest are covered by their unit tests) |
| Both fork layers | `pkg/risks/scripts/finding_class_test.go`: every rule's class |
| Custom engine | `core-policies/tests/test_calibration.py`: every category on profile T, its class, and the class reaching the injected model |
| Dimensions, fork | `pkg/risks/scripts/dimension_calibration_test.go`: every built-in and script rule the kitchen sink fires (73 of 100) on confidentiality-only, integrity-only and availability-only profiles, so a rule stepping on the wrong dimension or rating source fails (profile T rates C and I alike and can't tell) |
| Dimensions, custom | `test_calibration.py`: every custom category on the same three single-dimension profiles |
| Built-in report text | `test_calibration.py`: each built-in's `risk_assessment` in `10-threagile-builtin-risks-lib.yml` states its approved starting likelihood and impact |
| Report | `core-policies/tests/test_generate_report.py`: finding-class annotation and the weaknesses/controls split |

Changing a baseline, a step or a class therefore means changing the rule and this table
together, deliberately.

### Independent review of the applied calibration (2026-11-18)

An independent review of the code as applied (not the table) found the arithmetic sound and
every script rule on its approved baseline and dimension. It led to these changes:
- **Rating sources:** `missing-authentication` rates the target when its link carries no data
  (an empty link had stepped it down to Low); `unencrypted-communication` steps on the higher of
  the link data's confidentiality and integrity, since it fires on either.
- **Read-and-alter threats:** `untrusted-deserialization` and `code-backdooring` join the
  injection rules in stepping on the higher of confidentiality and integrity (code execution
  both reads and alters data).
- **Whole-model checks:** `missing-build-infrastructure` and `missing-identity-store` keep a flat
  Unlikely likelihood, like their flat Low impact; the asset they name is only an example.
- **Agents:** `ai-excessive-agency-tool-misuse` reaches through a tool server to what it writes,
  and suppresses the tool server's own finding only when the agent's link to it is writable.
  Custom `ai-unexpected-code-execution` takes its isolation step only on an explicitly physical
  machine (a missing machine had pushed it to Critical on profile T).
- **Alignment:** the script `missing-network-micro-segmentation` steps on the highest of C, I and
  A, like the built-in and custom segmentation rules.
- **Text:** the built-ins' scoring text in the fork and in `10-threagile-builtin-risks-lib.yml`
  describes the calibrated scoring; stale "keyed off all three dimensions" comments are gone.
- **Script built-ins:** an empty baseline, an unknown rating name, or a number passed as a rating
  is an error instead of a silent one-level drop.

Declined: counting plain datastores as indirect-injection sources (it would make nearly every
agent fire again, and the model can't tell user content from other data), and scaling the
cleartext-credential floor by asset value (cleartext credentials are a weakness at any value).

### Review of the non-AI script rules (2026-11-18)

A review of the fork's non-AI script rules, measured on the Confluence model (43 rules, 134
findings, 14 on a typical container app), found three sources of repetition and acted on them:
- **Merged:** `baseline-security-event-logging-gap` (forwarding security events to the SIEM) into
  `insufficient-audit-logging` (generating them), now "Insufficient Security Event Logging (AU-2 /
  AU-6 Gap)". They had identical triggers, STRIDE and CWE, and fired on exactly the same assets.
- **Evidence respected:** `missing-network-micro-segmentation` does not fire on a container inside a
  `network-policy-namespace-isolation` trust boundary, which is the model showing the control.
- **Once per cluster:** `cluster-control-plane-audit-gap` moved from a script to a built-in, so it
  attaches to the shared runtime (the cluster) once instead of to every container; script rules can
  only attach findings to technical assets. Its calibration is unchanged (Likely / Low).
- **Duplicate retired:** Threagile's built-in `container-baseimage-backdooring` fired on the same
  containers for the same risk as the script `untrusted-container-image`, with conflicting ratings;
  the fork retires the built-in and the script's description covers backdoored base layers.
- **Trigger narrowed:** `cui-telemetry-spillage` fires only on assets handling confidential or
  higher data.
- **STRIDE:** `missing-endpoint-security-agents` and `security-control-tamper-resistance-gap` move
  from information-disclosure to repudiation (CWE-778, insufficient logging), stepping on
  integrity; ratings on profile T are unchanged.

Kept as they are: the authorization rules (BOLA, BFLA, BOPLA), because link authentication can't
show object-level checks either way, and the per-workload container rules
(`mutable-container-filesystem`, `dangerous-container-capabilities`), which are set per pod spec.
The appendix table reflects these changes; the result tables above record the calibration as
first applied (190 rules).

### Independent reviews of the fork scripts and the custom categories (2026-11-18)

Two independent reviews covered the rules the earlier work had not examined: the 18 non-AI script
rules that never fire on the Confluence model, and duplication between the non-AI custom categories
and the fork. They led to these changes:

- **Bugs.** The script `accidental-secret-leak` failed for the whole model whenever any rating was
  "public" (a dropped zero value hit its `as:` cast), read a tag, and shadowed a built-in covering
  more technologies; the script is retired and the built-in fires again. Threagile's built-in
  `missing-network-segmentation` had its gate inverted by an upstream refactor, so it ran only on
  the assets it should skip; the gate and its tests are corrected. The merged logging rule's
  findings carried the old title. The cluster audit rule now takes the highest likelihood across
  its containers and gives its runtime finding a distinct id.
- **Duplicates retired or narrowed.** Custom `insecure-deserialization` (the built-in
  `untrusted-deserialization` reads `data_formats_accepted: serialization`); custom
  `missing-waf-internet-facing` and its `ops:waf-enabled` tag (the built-in `missing-waf` reads a
  modelled WAF; the custom one ignored it and fired on non-web services); the script
  `unencrypted-virtual-disk` (the built-in `unencrypted-asset` covers at-rest encryption with the
  right exclusions). Custom `malicious-file-parsing` is narrowed to archive extraction (zip slip,
  decompression bombs; CWE-22), which the XXE and file-validation built-ins don't cover. Custom
  self-managed segmentation leaves containers to the fork's micro-segmentation rule. The
  root-container waiver covers UID 0 only; capabilities are `dangerous-container-capabilities`.
- **Classes, STRIDE and CWEs.** `ics-controller-unauthenticated-protocol` is control-not-evidenced
  (it fires on the technology alone; rating unchanged). `network-ids-blind-spot` is repudiation;
  `air-vehicle-gps-spoofing` is spoofing. CWEs: vulnerable dependency 1395, CDS guard 693,
  dependency confusion 427, install scripts 829.
- **Scope and text.** `vulnerable-outdated-dependency` and `os-command-injection` skip external
  entities. `trusted-thin-client` no longer counts as a CDS guard. Three control-not-evidenced
  descriptions are worded as conditions to verify. Every custom `risk_assessment` opens with its
  calibrated scoring sentence, followed by the guidance for once the condition is confirmed, and
  `test_calibration.py` checks it.

Policy-exception waivers are recorded as `risk_tracking` status `accepted` on the finding the
waived condition raises (see `08-risk-tracking-lib.yml`). The cleartext-transit waiver tag and its
category are retired: the built-in `unencrypted-communication` raises the weakness per link. The
local-authentication waiver keeps its category, narrowed to the identity-provider bypass, because no
built-in raises that (on the Confluence model the break-glass account has no other finding); missing
MFA is the built-in two-factor rule's. The root-container waiver stays for the same reason.
Since done: risk triggers that restated native fields read them instead. Dangling DNS and the
IDS blind spot fire on a public endpoint -- `internet: true` and called by an out-of-scope or
external-entity asset -- instead of `zone:dmz` (IDS also on `net:internet-reachable`), so an
egress-only device such as a firewall no longer qualifies; CORS/CSP fires on an asset with a
browser caller (CORS and framing are browser mechanisms), and the `feature:browser-facing` tag is
retired; the WebSocket finding fires on an incoming `ws`/`wss`
link; search-index abuse lands on the modeled search engine, or on an app tagged
`feature:search-index` whose search is built in. `zone:dmz`, `feature:search-index` and
`feature:websocket` stay as tags, since libraries 01 and 02 use them to select requirements and
abuse cases.

Partial overlaps closed the same day: the direct-admin-access waiver raises its own finding only
where the built-in `unguarded-access-from-internet` does not (a lower-value VM, or an admin path not
drawn as a link), and is otherwise recorded as accepted on the built-in finding;
`exposed-admin-panel` covers network exposure and step-up authentication, leaving server-side role
checks to `broken-function-level-authorization`; `air-vehicle-gps-spoofing` states that its single
finding covers navigation spoofing and the capture it can lead to, rated on the hijack. Since done: the rogue access point
and route origin validation findings are raised once per network trust boundary, on its edge
asset where one is modeled, instead of on every self-managed workload; segmentation stays per
workload. Kept as a documented exception: the built-ins' internet step reads the
`net:internet-reachable` tag, which marks a backend behind a gateway as reachable (computing that
from the graph produced false positives through shared hops). The catalogue now counts 183
rules (35 built-in, 62 extension, 86 organization-specific).

### Mission criticality (2026-11-18)

The model-level rating is `mission_criticality`, on its own four-value scale: `administrative`,
`mission-support`, `mission-essential`, `mission-critical` (shown in reports as "Mission Support"
and so on). It is separate from the five-value scale that rates each asset's and data asset's
integrity and availability, which the CIA step above depends on and which is unchanged.

The rating changes no score. At `mission-essential` or above, the custom engine adds the
incident-response readiness checks (IR plan testing, DFARS breach notification, forensic chain of
custody, containment disposition). `business_criticality`, the older name, is still accepted, and
its five values map onto the four: `archive` and `operational` to `administrative`, `important` to
`mission-support`, `critical` to `mission-essential`, `mission-critical` to `mission-critical`. The
mapping keeps every existing model's findings the same. A model that sets both keys must give them
the same value.

### Unguarded access from internet narrowed (2026-11-20)

The built-in `unguarded-access-from-internet` counted a link as internet access whenever its source
was marked `internet: true`. In-scope internet-facing components carry that flag too, so everything
an application gateway or firewall talked to was raised: on Confluence, the gateways' traffic
through the firewall and the gateways' and firewall's log forwarding to Log Analytics, five of its
seven findings. The rule now needs an internet-side caller, meaning an internet-facing external
entity or out-of-scope asset. An in-scope gateway calling inward is the guarded path the rule asks
for. The custom engine's direct-admin waiver, which defers to this rule where it fires, mirrors the
same gate. The report's Communication Link column also names the link's source when it isn't the
row's asset, since link titles repeat across sources.

### Application features and requirement tailoring (2026-11-20)

The report now prints the questions first, as "Application Features and Scoping," and the security
requirements after them, because the answers decide which requirement sections apply. Applicability
works at two levels. First, a domain's tag triggers decide whether its block of questions and
requirements applies at all (02-abuse-and-reqs-lib.yml and 01-metadata-lib.yml share the same
triggers). Second, within a block, the answers decide which sections apply, since a block's triggers
are broad. For example, the Identity block fires on any OAuth or SAML feature, while password
requirements apply only where local passwords exist.

Tailoring is manual, and it rests on a feature checklist. Each domain in 01-metadata-lib.yml has a
few checklist items (25 in all), and for a new model the checklist comes first, since it records what
the application has before any tags exist. An option can name the tags it implies, such as File
uploads implying feature:file-upload-processing, and the author places each tag on the asset that has
the feature. The report lists the implied tags next to each item for a reviewer to check, and nothing
checks them automatically. Tags that record evidence of a control, topology, or a policy waiver stay
outside the checklist. Each item has a fixed list of options, and the author answers by
selecting the ones that apply. Each item also names the sections it affects and how its selections
can rule them out, and the report prints the checklist as a table with the selected options marked. The 31 questions that follow are short,
since the precise criteria live in the requirement rows. An author tailors a section out
by replacing its rows with "Not applicable: <reason>" in the model, rather than deleting it, and the
report then shows the section as not applicable with that reason. As a result, a reviewer can see
what was tailored out and why. The OWASP and NIST rows themselves are never edited, only replaced by
that note. Additionally, the report warns when an abuse case pairs with a section marked not
applicable, since the model would then state a threat without a control.

Having said that, the decision needs judgment rather than a blanket rule. On the Confluence model,
for instance, logins federate to Entra ID, but a local break-glass account still exists, so ASVS V6.2
(Password Security) remains in scope for that account.

## Source of truth, by topic

| Topic | Where |
|---|---|
| Custom engine's full scoring logic | `models/central-security-repo/core-policies/inject_risks.py` — `compute_likelihood()`, `compute_impact()`, `compute_severity()`, `compute_raa_by_id()` (the Internet-reachability signal is the manual `net:internet-reachable` tag now, not a function — `compute_internet_reachable_ids()` was removed; see git history) |
| RAA formula's own weight tables | Same file — `CONF_ASSET`, `CRIT_ASSET`, `CONF_PROCESSED_OR_STORED`, `CRIT_PROCESSED_OR_STORED`, `CONF_TRANSFERRED`, `CRIT_TRANSFERRED`, `QTY_FACTOR`, `RAA_TECHNOLOGY_MULTIPLIER` |
| Current threshold/weight constants | Same file — `RAA_LIKELIHOOD_THRESHOLD`, `RAA_LIKELIHOOD_LOW_THRESHOLD`, `CIA_RANK_TO_DELTA`, `STRIDE_TO_CIA_DIMENSION`, `WEIGHT`, `SEVERITY_THRESHOLDS` |
| Per-category baseline Likelihood/Impact | `models/central-security-repo/libraries/09-custom-risks-lib.yml` — each entry's `baseline_likelihood`/`baseline_impact` |
| Threagile's own built-in categories | This repo's fork, `jessestarkey/threagile` (built via its default `Dockerfile`) — `pkg/types/risk_exploitation_likelihood.go`/`risk_exploitation_impact.go` for the weight tables, `pkg/types/model.go`'s `CalculateSeverity()` for the thresholds, `pkg/risks/builtin/helpers.go`'s `computeLikelihood()` for the shared per-asset Likelihood delta now used by 35 of ~42 rules (`computeImpact()` in the same file is dead code, not currently called by anything — see [Threagile's built-in risk categories](#threagiles-built-in-risk-categories)), and each individual `pkg/risks/builtin/*_rule.go` file for that rule's own baseline value and detection logic (the one piece that stays closed-upstream in spirit even though this repo's fork can technically see and edit it) |
| Built-in category enrichment text | `models/central-security-repo/libraries/10-threagile-builtin-risks-lib.yml` |
| Native script rules | This repo's fork, `pkg/risks/scripts/*.yaml` (64 files) — each file's own `get_likelihood`/`get_impact` utility functions carry the RAA/CIA delta logic independently (no shared helper, no central enrichment library; see [Native script rules](#native-script-rules-a-third-mechanism-same-forked-binary)) |
| The condensed, report-facing version of this document | `models/central-security-repo/core-policies/templates/report.html.jinja`'s Methodology section |
| Broader repo/pipeline architecture | `CLAUDE.md` |

## Keeping this in sync

The calibrated ratings, classes and dimensions are now enforced by the drift checks (see
[Drift checks](#drift-checks)); a baseline, step or class change fails a test until the appendix
table and the matching test map change with it. Three texts describe the scoring in prose and must
be kept to it by hand: each built-in's `RiskAssessment` in the fork, each built-in's
`risk_assessment` in `10-threagile-builtin-risks-lib.yml` (the report prints it, and
`test_calibration.py` checks that it states the approved starting rating), and the threat
catalogue's calibration notes.

Beyond those, nothing ties this document to the code. If a threshold, weight, or the severity
matrix itself changes in `inject_risks.py`, update the corresponding number here — and, more
importantly, update the *reasoning* if the change reflects a new trade-off rather than just a
retuned value. A stale number is a quick fix; a stale rationale silently misrepresents why the
methodology works the way it does, which matters more for a document whose whole purpose is
explaining the "why." The report's own condensed Methodology section
(`templates/report.html.jinja`) should be checked for the same drift at the same time — the two
are meant to describe the same underlying logic at two different levels of depth, not diverge from
each other.

**Since the built-in-rule standardization, there's a second, cross-repo version of this problem.**
`inject_risks.py`'s `RAA_LIKELIHOOD_THRESHOLD`/`RAA_LIKELIHOOD_LOW_THRESHOLD`/
`CIA_RANK_TO_DELTA`/`STRIDE_TO_CIA_DIMENSION` and the fork's `pkg/risks/builtin/helpers.go`
constants of the same shape are two independent copies of the same logic in two different
repositories and languages, kept in sync by hand, not by either repo importing the other. If either
file's constants change, check the other and this document together — a drift here wouldn't throw
an error anywhere, it would just quietly make the two engines disagree again on something they're
currently deliberately aligned on.

**The native script rules multiply this same problem by 66.** Each of the 66 files in
`pkg/risks/scripts/` writes the RAA/CIA delta logic out independently (see [Native script
rules](#native-script-rules-a-third-mechanism-same-forked-binary)), so a threshold or mapping
retune isn't a two-place sync problem for this mechanism, it's a 75-place one (`inject_risks.py` +
`helpers.go` + every script file). There's no tooling today that checks all of them agree; a drift
here is just as silent as the two-engine case above, spread across many more files.

## Appendix: Calibration table

Every catalogued rule, rated on profile T (confidential / critical / important, mid RAA, not internet-reachable). *Class*: W = weakness shown by model facts, G = control not evidenced. *Current* is today's final rating under each layer's current logic; *new baseline* is what the rule will carry under option A; *new on T* is the resulting final rating.

| Layer | Rule | Class | Current on T | New baseline | New on T | Reason |
|---|---|---|---|---|---|---|
| Built-in | `accidental-secret-leak` | G | Likely / Medium → Elevated | Likely / Low | Likely / Medium → Elevated | G: fires on every repo/registry. Likely kept: GitGuardian 35% of private repos hold plaintext secrets = control commonly absent (G-cap exception), capped at Likely. Impact Medium anchor (missing scanning control); the secret's own consequence is scored by the W-class hardcoded-credentials rule. |
| Built-in | `cluster-control-plane-audit-gap` | G | Likely / High → High | Likely / Low | Likely / Medium → Elevated | G detection gap. Likely: Kubernetes audits nothing by default = commonly absent (cap Likely). Medium anchor: detection. Moved to a built-in on 2026-11-18 so it fires once per cluster (shared runtime). |
| Built-in | `code-backdooring` | W | Unlikely / High → Medium | Possible / Medium | Possible / High → Elevated | W: model shows an internet-reachable dev asset. Possible: needs dev-environment access/credentials (prior foothold); CAPEC-444 Medium, Codecov/SolarWinds real. High anchor: backdoored code still has to be built and shipped (one further step), so not Very High. |
| Built-in | `container-platform-escape` | G | Unlikely / High → Medium | Unlikely / High | Unlikely / Very High → Elevated | G: fires on every container platform. Unlikely: needs a compromised container first (CAPEC-480 Low), one below the Possible escape weakness. Very High anchor: platform control = privileged control of every container. |
| Built-in | `cross-site-request-forgery` | G | Likely / Low → Medium | Possible / Low | Possible / Medium → Elevated | G: fires on every web app link (anti-CSRF not modelled). Weakness ~Likely (CAPEC-62 High but CWE Medium, 6 KEV, SameSite defaults) -> one below = Possible. Medium anchor: limited direct harm (one forged action as the victim). |
| Built-in | `cross-site-scripting` | G | Very Likely / Medium → High | Likely / Medium | Likely / High → High | G: fires on every web app. Weakness Very Likely (CWE #1, CAPEC High, 30k CVEs) but G-cap = Likely. High anchor: stored XSS is the rubric's own High example. |
| Built-in | `dos-risky-access-across-trust-boundary` | W | Unlikely / Low → Low | Possible / Low | Possible / Medium → Elevated | W: cross-boundary link to an availability-critical asset. Possible: flooding source must already sit in an adjacent zone (prior foothold). Medium anchor: CAPEC-125 typical severity Medium; outage stops when the flood stops. |
| Built-in | `ldap-injection` | G | Likely / Medium → Elevated | Possible / Medium | Possible / High → Elevated | G: fires on any LDAP link. Weakness Possible-Likely (CAPEC-136 High, but 0 KEV, no CWE likelihood) -> Possible. High anchor: directory objects read/modified beyond caller's rights. |
| Built-in | `missing-authentication` | W | Likely / Medium → Elevated | Likely / Medium | Likely / High → High | W: link authentication = none to a sensitive asset. Likely: anyone with network reach (one ordinary precondition on a non-internet asset); CWE-306 in KEV. High anchor: direct read/modify of what the endpoint exposes. |
| Built-in | `missing-authentication-second-factor` | W | Likely / Medium → Elevated | Likely / Medium | Likely / High → High | W: human-accessed link without two-factor. Likely: CAPEC-600 High, DBIR stuffing 19% of auth attempts; not internet-reachable on T. High anchor: one stolen password = that account's full access (CAPEC-600 High). Current fixed Medium becomes symmetric. |
| Built-in | `missing-build-infrastructure` | G | Unlikely / Medium → Medium | Unlikely / Low | Unlikely / Low → Low | Model-completeness check. Low anchor (model-authoring mistake). Under option A a Low target is unreachable on T: Low baseline +1 = Medium. Exempt from the CIA step (user-approved): a whole-model check whose reported asset is only a placeholder. |
| Built-in | `missing-cloud-hardening` | G | Unlikely / High → Medium | Possible / Low | Possible / Medium → Elevated | G: cloud component without hardening evidence. Weakness Likely (CSA #1 misconfiguration) -> one below = Possible. Medium anchor: posture/defense-in-depth gap, not a shown exploitable path. |
| Built-in | `missing-file-validation` | G | Likely / Medium → Elevated | Possible / Medium | Possible / High → Elevated | G: fires on file-accepting assets. Weakness Likely (CWE-434, 23 KEV) -> Possible. High anchor: malicious upload becomes code execution or malware delivery only once served/executed (one further step). |
| Built-in | `missing-hardening` | G | Very Likely / Low → Elevated | Unlikely / Low | Possible / Medium → Elevated | G: fires on high-RAA assets without hardening evidence. Weakness Likely (AA23-278A defaults) -> Possible final. Medium anchor: posture gap that worsens other findings. |
| Built-in | `missing-identity-propagation` | W | Unlikely / Low → Low | Possible / Low | Possible / Medium → Elevated | W: link authorizes on service identity, not end user. Possible: needs a compromised upstream component (prior foothold). Medium anchor: defense in depth, widens a compromise that another attack causes. |
| Built-in | `missing-identity-provider-isolation` | W | Unlikely / High → Medium | Possible / Medium | Possible / High → Elevated | W: IdP shares a trust boundary. Possible: pivot needs a foothold on a co-located asset (Storm-0501). High: broad compromise (every identity) needing one further step (exploit the IdP from the foothold). |
| Built-in | `missing-identity-store` | G | Unlikely / Medium → Medium | Unlikely / Low | Unlikely / Low → Low | Model-completeness check. Low anchor; unreachable on T under option A (Low baseline +1 = Medium). Exempt from the CIA step (user-approved): a whole-model check whose reported asset is only a placeholder. |
| Built-in | `missing-network-segmentation` | W | Possible / Low → Medium | Unlikely / Low | Possible / Medium → Elevated | W: sensitive asset shares a segment with less-protected assets. Possible final: lateral move needs a foothold (Target 2013). Medium anchor: segmentation is defense in depth. |
| Built-in | `missing-vault` | G | Unlikely / Medium → Medium | Unlikely / Low | Unlikely / Medium → Medium | G: no vault in the model. Weakness Possible (needs a file-read flaw/host compromise; Uber 2022) -> Unlikely. Medium anchor: missing control enabling secret theft. |
| Built-in | `missing-vault-isolation` | W | Unlikely / Medium → Medium | Unlikely / Medium | Unlikely / High → Medium | W: vault co-located. Unlikely: shared segment still needs a foothold plus defeating vault auth (chained); no statistic. High: broad compromise (every secret) needing one further step. |
| Built-in | `missing-waf` | G | Unlikely / Low → Low | Possible / Low | Possible / Medium → Elevated | G: cross-boundary web traffic with no WAF modelled. Enabled weakness Likely (T1190) -> one below = Possible. Medium anchor: missing WAF is the rubric's own Medium example. |
| Built-in | `mixed-targets-on-shared-runtime` | W | Unlikely / Low → Low | Unlikely / Low | Unlikely / Medium → Medium | W: mixed tiers on one runtime. Unlikely: compromise + escape chain (CAPEC-480 Low). Medium anchor: compartmentalization (defense in depth). |
| Built-in | `path-traversal` | G | Very Likely / Medium → High | Likely / Medium | Likely / High → High | G: fires on file-serving assets. Weakness Very Likely (CWE-22, 81 KEV, CISA alert) but G-cap = Likely. High anchor: read of config/credential/business files. |
| Built-in | `push-instead-of-pull-deployment` | W | Unlikely / Medium → Medium | Unlikely / Low | Unlikely / Medium → Medium | W: push deployment link. Unlikely: needs pipeline/credential compromise first; no statistic. Medium anchor: added attack surface. |
| Built-in | `search-query-injection` | G | Very Likely / Medium → High | Possible / Medium | Possible / High → Elevated | G: fires on search engines. Weakness Likely at most (few KEV-listed Solr flaws; catalogue itself calls VL aggressive) -> Possible. High anchor: index disclosure, escalating to code execution in the Solr cases. |
| Built-in | `server-side-request-forgery` | G | Likely / Low → Medium | Possible / Low | Possible / Medium → Elevated | G: fires on outgoing web calls. Weakness Likely (CAPEC-664 High, 22 KEV) -> Possible. Medium anchor: API7 technical impact Moderate (internal enumeration); High only in cloud/metadata cases. |
| Built-in | `service-registry-poisoning` | G | Unlikely / Low → Low | Unlikely / Medium | Unlikely / High → Medium | G: fires on any registry. Unlikely: needs registry write access (weakness Possible) -> one below. High: redirecting service endpoints is broad compromise needing one further step (CAPEC-51 Very High). |
| Built-in | `sql-nosql-injection` | G | Very Likely / Medium → High | Likely / High | Likely / Very High → High | G: fires on every queried database. Weakness Very Likely (CWE #2, 32 KEV, MOVEit) but G-cap = Likely. Very High anchor: injection reaching an interpreter (read/modify all data). |
| Built-in | `unchecked-deployment` | G | Likely / Medium → Elevated | Likely / Low | Likely / Medium → Elevated | G: pipeline without scanning evidence. Likely: OSSRA 86% vulnerable codebases = control commonly absent (cap Likely). Medium anchor: change-control gap. |
| Built-in | `unencrypted-asset` | W | Unlikely / Medium → Medium | Unlikely / Low | Unlikely / Medium → Medium | W: encryption=none on a sensitive store. Unlikely: needs offline/privileged storage access (snapshot, media). Medium anchor: encryption at rest is defense in depth behind storage access control. |
| Built-in | `unencrypted-communication` | W | Unlikely / Medium → Medium | Possible / Medium | Possible / High → Elevated | W: unencrypted link with sensitive/auth data. Possible: sniffing needs an on-path position (prior foothold); CAPEC-94 High. High: interception of the link's sensitive data/credentials. |
| Built-in | `unguarded-access-from-internet` | W | Very Likely / Low → Elevated | Likely / Low | Likely / Medium → Elevated | W: internet caller reaches a sensitive asset with no proxy. Likely, not Very Likely: exposure is shown but exploitation still needs a flaw in the asset. Medium anchor: missing guard is defense in depth. |
| Built-in | `unguarded-direct-datastore-access` | W | Likely / Low → Medium | Possible / Low | Possible / Medium → Elevated | W: cross-boundary direct datastore link. Possible: needs a position in the adjacent zone; store's own auth still applies (Meow was internet-exposed). Medium anchor: application tier as guard is defense in depth. |
| Built-in | `untrusted-deserialization` | G | Likely / High → High | Possible / High | Possible / Very High → High | G: fires on serialization technology/protocols. Weakness Likely (CAPEC-586 Medium, 71 KEV) -> Possible. Very High anchor: RCE. |
| Built-in | `xml-external-entity` | G | Likely / Medium → Elevated | Possible / Medium | Possible / High → Elevated | G: fires on XML input. Weakness Likely at most (8 KEV) -> Possible. High anchor: local file read / internal service access. |
| Extension (script) | `ai-adversarial-evasion` | G | Likely / Very High → High | Possible / Medium | Possible / High → Elevated | G: fires on every model-serving platform. Weakness Likely (ATLAS 18 case studies) -> Possible. High: evasion lets specific inputs through the control; the downstream fraud/malware is a further step. |
| Extension (script) | `ai-agent-identity-privilege-abuse` | W | Likely / Very High → High | Likely / Medium | Likely / High → High | W: service-identity link. Likely: agents are steered via prompt injection (one ordinary precondition); LLMjacking, LiteLLM KEV. High anchor: 'an agent's writable tool misused' is the rubric's High example. |
| Extension (script) | `ai-cascading-agent-failures` | W | Possible / Medium → Elevated | Possible / Medium | Possible / Medium → Elevated | W: agent-to-agent link. Possible: needs a triggering fault plus missing containment; analyst judgment. Medium anchor: recoverable availability loss. |
| Extension (script) | `ai-content-provenance-tampering` | G | Likely / Very High → High | Likely / Medium | Likely / High → High | G: provenance service. Likely: stripping is routine (WaPo test: all 8 platforms stripped) = commonly absent, cap Likely. High: the service's trust function is defeated for that content; forged-verifies-as-genuine is the rarer CAPEC-476 path. |
| Extension (script) | `ai-cross-context-bleed` | W | Possible / High → Elevated | Possible / Medium | Possible / High → Elevated | W: context mixes sensitivities. Possible: needs an isolation defect (one ChatGPT incident). High: another user's confidential data exposed. |
| Extension (script) | `ai-excessive-agency-tool-misuse` | W | Likely / Very High → High | Likely / Medium | Likely / High → High | W: writable tool link. Likely: in-the-wild agent steering (ATLAS CS0051, CS0069, postmark-mcp). High anchor: the rubric's own example. |
| Extension (script) | `ai-hidden-context-exposure` | W | Very Likely / High → High | Very Likely / Low | Very Likely / Medium → High | W: requests from outside the boundary. Very Likely: chat access only, routine (Bing 'Sydney'). Low anchor: OWASP says the system prompt is not a secret; harm only if secrets are placed there. Low target unreachable on T (Low baseline +1 = Medium). |
| Extension (script) | `ai-improper-output-handling` | W | Likely / Very High → High | Likely / Medium | Likely / High → High | W: output reaches a consumer. Likely: production exploits (Lenovo XSS, MathGPT, CVE-2023-29374). High: the typical consumer is a browser (stored-XSS class); RCE sinks are the worst case. |
| Extension (script) | `ai-inference-data-reconstruction` | W | Very Likely / High → High | Very Likely / Low | Very Likely / Medium → High | W: outside callers. Very Likely: query access only, documented at scale (distillation campaigns). Medium: typical loss is model IP/partial membership, limited direct harm. |
| Extension (script) | `ai-insecure-inter-agent-communication` | W | Likely / Very High → High | Possible / Medium | Possible / High → Elevated | W: unauthenticated/unencrypted/boundary-crossing agent link. Possible: no public impersonation incident; evidence is structural/research (Habler 2025, CAPEC-151 Medium). High: agent acts on injected instructions (same anchor as writable tool misuse). |
| Extension (script) | `ai-model-exfiltration` | G | Likely / Very High → High | Likely / Medium | Likely / High → High | G: fires on registries/training/edge models. Likely: 41% of on-device apps unprotected (Sun 2021) = commonly absent. High: copied weights = loss of a meaningful part of the asset's data (IP), not system control. |
| Extension (script) | `ai-operational-control-gap` | G | Likely / High → High | Possible / Low | Possible / Medium → Elevated | G: fires on every AI asset. Weakness Likely (Amazon Q, Tay) -> Possible. Medium anchor: 'no kill switch, no tested rollback' are the rubric's own Medium examples. |
| Extension (script) | `ai-rag-corpus-poisoning` | W | Likely / High → High | Likely / Medium | Likely / High → High | W: content from outside the boundary. Likely: production attacks (Slack AI, EchoLeak). High: persistent answer redirection/exfiltration of retrieved data. |
| Extension (script) | `ai-retrieval-resilience-gap` | G | Possible / High → Elevated | Unlikely / Low | Unlikely / Medium → Medium | G: resilience controls not evidenced. Weakness Possible (operational failure, no prevalence data) -> Unlikely. Medium anchor: recovery/resilience gap. |
| Extension (script) | `ai-security-tooling-compromise` | G | Unlikely / Very High → Elevated | Unlikely / High | Unlikely / Very High → Elevated | G: AI security agent. Unlikely: privileged foothold required. Very High: privileged trusted position (suppress alerts, pivot). Baseline drops to High only because option A adds +1 on T; final unchanged. |
| Extension (script) | `ai-sensitive-information-disclosure` | W | Likely / High → High | Likely / Medium | Likely / High → High | W: outside callers and confidential data in reach. Likely: production leaks (Copilot Studio, EchoLeak). High: confidential data disclosed in responses. |
| Extension (script) | `ai-supply-chain-compromise` | G | Possible / Very High → High | Possible / High | Possible / Very High → High | G: fires on registries/serving/agents. Weakness Likely (JFrog ~100 malicious HF models, torchtriton) -> Possible. Very High anchor: code that runs on load. |
| Extension (script) | `ai-synthetic-data-leakage` | W | Likely / High → High | Possible / Low | Possible / Medium → Elevated | W: synthetic pipeline with confidential sources. Possible: evidence is research (Nasr 2023, Stadler 2022). Medium: leakage is partial and probabilistic (limited direct harm). |
| Extension (script) | `ai-telemetry-prompt-log-leakage` | G | Likely / High → High | Likely / Medium | Likely / High → High | G: AI asset with confidential data (tracing captures prompts by default = control commonly absent, cap Likely). High: a full, weaker-protected copy of confidential prompts/responses (DeepSeek ClickHouse). |
| Extension (script) | `ai-training-data-model-poisoning` | G | Unlikely / High → Medium | Unlikely / Medium | Unlikely / High → Medium | G: training/feature/eval stores. Unlikely: adversary write access is the constraint for curated sources. High: backdoor ships and persists (Sleeper Agents). |
| Extension (script) | `ai-unbounded-consumption` | W | Likely / Medium → Elevated | Likely / Medium | Likely / Medium → Elevated | W: outside callers reach the endpoint. Likely: API4 Widespread, CAPEC-125 High, LLMjacking. Medium: outage/spend, no data loss. |
| Extension (script) | `ai-unsafe-nl-data-gateway` | W | Likely / High → High | Possible / Medium | Possible / High → Elevated | W: AI-to-datastore link. Possible: prompt-to-SQL evidence is research (Pedro et al. 2023, DSGAI12); no incident cited. High: over-broad/injected query exposes what the connection can read, bounded by the model output channel. |
| Extension (script) | `ai-vector-store-exposure` | G | Likely / High → High | Unlikely / Medium | Unlikely / High → Medium | G in its usual state (fires on confidential content alone; unencrypted/multi-tenant are the W cases). Weakness Possible (Vec2Text research) -> Unlikely. High: corpus disclosure after inversion. |
| Extension (script) | `air-ground-station-c2-link-hijack` | G | Likely / Very High → High | Possible / Medium | Possible / High → Elevated | G: fires on every GCS. Weakness Likely for downlink interception (SkyGrabber 2009), hijack rarer -> Possible. High typical (downlink exposure); total loss of control is the worst case. |
| Extension (script) | `air-vehicle-gps-spoofing` | G | Likely / Very High → High | Likely / Medium | Likely / High → High | G: every aircraft/drone. Likely: 310k flights affected in 2024 = commonly present, cap Likely. High typical (navigation error/redirect); crash/capture is the worst case. |
| Extension (script) | `broken-function-level-authorization` | G | Very Likely / Very High → Critical | Likely / High | Likely / Very High → High | G: fires on every request-serving API. Weakness Very Likely (API5 Easy, OWASP A01 100%) but G-cap = Likely. Very High anchor: privileged/administrative functions invoked. |
| Extension (script) | `broken-object-level-authorization` | G | Very Likely / Very High → Critical | Likely / Medium | Likely / High → High | G: every request-serving API. Weakness Very Likely (API1 widespread, Optus) but G-cap = Likely. High anchor: IDOR is the rubric's own High example. |
| Extension (script) | `broken-object-property-level-authorization` | G | Likely / Very High → High | Possible / Medium | Possible / High → Elevated | G: every API. Weakness Likely (API3 Easy/Common, no KEV) -> Possible. High: writable privileged properties. |
| Extension (script) | `cds-data-diode-unidirectionality-gap` | G | Unlikely / Very High → Elevated | Unlikely / High | Unlikely / Very High → Elevated | G: diode verification not evidenced. Unlikely: physical construction; no incident data. Very High: total boundary failure. |
| Extension (script) | `cds-guard-ruleset-bypass` | G | Likely / Very High → High | Possible / Medium | Possible / High → Elevated | G: guard rule currency not evidenced. Weakness Likely (operational drift, judgment) -> Possible. High: prohibited content crosses for the stale rule's format; not a wholesale boundary collapse. |
| Extension (script) | `certificate-validation-soft-fail` | G | Likely / Very High → High | Possible / Medium | Possible / High → Elevated | G: fires on every OCSP/CRL service. Possible: needs a revoked-but-stolen credential plus on-path position; soft-fail is a common default (Langley). High: one revoked identity authenticates. |
| Extension (script) | `cicd-pipeline-tampering-outside-repo` | G | Unlikely / Very High → Elevated | Unlikely / Medium | Unlikely / High → Medium | G: console access not evidenced as restricted. Unlikely: CAPEC-511 Low (Codecov real). Medium anchor: change-control gap; the malicious change it lets through is the further attack. Reviewer override (user-approved): High, not Medium -- a tampered pipeline ships attacker code. |
| Extension (script) | `cui-telemetry-spillage` | G | Very Likely / High → High | Likely / Low | Likely / Medium → Elevated | G: fires on every non-AI app asset. Weakness commonly present (CWE-532, Meta plaintext passwords) but G-cap = Likely. Medium: incidental fragments exposed to internal staff (limited direct harm); reportable spill. |
| Extension (script) | `dangerous-container-capabilities` | G | Likely / Very High → High | Possible / Medium | Possible / High → Elevated | G: fires on every container (capability drop not evidenced). Possible: needs code execution in the container first; permissive privilege common (Sysdig 76% root). High: escape primitives = broad compromise needing one further step. |
| Extension (script) | `data-store-audit-detection-gap` | G | Likely / High → High | Likely / Low | Likely / Medium → Elevated | G detection gap. Likely: Snowflake/UNC5537 shows unmonitored bulk export as routine = commonly absent. Medium anchor: detection/attribution. |
| Extension (script) | `dependency-confusion-internal-namespace` | G | Very Likely / Very High → Critical | Likely / High | Likely / Very High → High | G: fires on every build pipeline (unclaimed namespace not shown). Likely: Birsan hit 35+ companies = commonly absent, cap Likely. Very High anchor: attacker code runs in the build. |
| Extension (script) | `endpoint-security-manager-fleet-compromise` | G | Unlikely / Very High → Elevated | Unlikely / High | Unlikely / Very High → Elevated | G: EDR console. Unlikely: console compromise required (APT32/ePO). Very High: fleet-wide code execution. |
| Extension (script) | `hardcoded-credentials-secrets-sprawl` | W | Very Likely / Very High → Critical | Likely / Medium | Likely / High → High | W: static secret on a link (the rubric's own W example). Likely, not Very Likely: extraction needs access to code/image/config (one ordinary precondition); CAPEC-37 High. High: immediate authenticated access to the target system. |
| Extension (script) | `ics-controller-unauthenticated-protocol` | G | Very Likely / Very High → Critical | Likely / High | Likely / Very High → High | W: unauthenticated-by-design protocol. Likely on T (not internet-reachable: needs network reach into the OT segment); FrostyGoop/Unitronics were internet-exposed. Very High: commands change physical processes. |
| Extension (script) | `insecure-session-management` | G | Very Likely / High → High | Likely / Medium | Likely / High → High | G: every front end. Weakness Very Likely (147k token replays) but G-cap = Likely. High: hijacked session = victim's full access. |
| Extension (script) | `insufficient-audit-logging` | G | Likely / High → High | Possible / Low | Possible / Medium → Elevated | G detection/compliance gap. Possible: no statistic on AU-2 gaps. Medium anchor: detection. |
| Extension (script) | `key-management-separation-of-duties-violation` | G | Unlikely / High → Medium | Unlikely / Low | Unlikely / Medium → Medium | G governance. Unlikely: needs a malicious/compromised key admin. Medium anchor: governance/detection (misuse can be hidden). |
| Extension (script) | `key-rotation-escrow-neglect` | G | Unlikely / High → Medium | Unlikely / Low | Unlikely / Medium → Medium | G governance. Unlikely: needs a separate key compromise (Storm-0558). Medium: compounds another attack; recovery risk. |
| Extension (script) | `key-storage-ownership-hardening-gap` | G | Unlikely / High → Medium | Unlikely / Low | Unlikely / Medium → Medium | G hardening gap. Unlikely: needs host compromise first. Medium anchor: defense in depth (HSM) behind host security. |
| Extension (script) | `malicious-install-script-execution` | G | Very Likely / Very High → Critical | Likely / High | Likely / Very High → High | G: every pipeline. Weakness Very Likely (Shai-Hulud, tj-actions KEV) but G-cap = Likely. Very High anchor: code runs on fetch. |
| Extension (script) | `media-sanitization-procedure-gap` | G | Likely / High → High | Possible / Low | Possible / Medium → Elevated | G governance. Possible: needs access to disposed equipment (CAPEC-675 Medium); residue common (42% of eBay drives). Medium anchor: governance; CAPEC-675 severity Medium. |
| Extension (script) | `mishandling-exceptional-conditions` | G | Likely / Very High → High | Possible / Low | Possible / Medium → Elevated | G: every processing asset. Weakness ~Likely (judgment) -> Possible. Medium: typical case is error leakage (CWE-209); fail-open privilege bypass is the worst case. |
| Extension (script) | `missing-data-retention-schedule` | G | Likely / Medium → Elevated | Possible / Low | Possible / Medium → Elevated | G governance. Possible: over-retention only matters once a breach occurs. Medium anchor: governance gap that worsens another attack. |
| Extension (script) | `missing-endpoint-security-agents` | G | Likely / High → High | Likely / Low | Likely / Medium → Elevated | G detection gap. Likely: insufficient monitoring is an AA23-278A top-ten misconfiguration = commonly absent. Medium anchor: detection. |
| Extension (script) | `missing-network-micro-segmentation` | G | Likely / High → High | Possible / Low | Possible / Medium → Elevated | G: every container (no default-deny evidenced; non-isolated is the K8s default). Possible: lateral move needs a container foothold. Medium anchor: segmentation is defense in depth. |
| Extension (script) | `multi-tenant-data-isolation` | G | Likely / Very High → High | Possible / High | Possible / Very High → High | G: fires on the multi_tenant flag alone. Weakness Likely (A01 prevalence; ChaosDB) -> Possible. Very High: one flaw exposes every tenant (bulk). |
| Extension (script) | `mutable-container-filesystem` | G | Likely / High → High | Possible / Low | Possible / Medium → Elevated | G: writable root fs is the default. Possible: needs code execution in the container first. Medium anchor: worsens other code-execution findings. |
| Extension (script) | `network-encryptor-common-mode-failure` | G | Unlikely / Very High → Elevated | Unlikely / High | Unlikely / Very High → Elevated | G. Unlikely: accredited two-layer design. Very High: classified plaintext crosses. |
| Extension (script) | `os-command-injection` | G | Very Likely / Very High → Critical | Likely / High | Likely / Very High → High | G: fires on custom application logic. Weakness Very Likely (110 KEV, CISA alert) but G-cap = Likely. Very High anchor: injection reaching an interpreter. |
| Extension (script) | `security-control-tamper-resistance-gap` | G | Unlikely / Very High → Elevated | Unlikely / Low | Unlikely / Medium → Medium | G. Unlikely: foothold needed (tampering common once inside, Sophos 82%). Medium anchor: tamper-evidence/detection gap; the attack it hides is scored elsewhere. |
| Extension (script) | `space-ground-station-rogue-uplink` | G | Unlikely / Very High → Elevated | Unlikely / High | Unlikely / Very High → Elevated | G. Unlikely: RF capability and protocol knowledge. Very High: loss of command authority. |
| Extension (script) | `space-vehicle-bus-segmentation-gap` | G | Unlikely / Very High → Elevated | Unlikely / High | Unlikely / Very High → Elevated | G. Unlikely: ground segment must be defeated first (Viasat). Very High: unrecoverable vehicle loss. |
| Extension (script) | `unhardened-os-missing-patch-management` | G | Very Likely / Very High → Critical | Likely / Medium | Likely / High → High | G: every VM. Weakness Very Likely (DBIR 20%, Sophos 32%, Mandiant 33%) but G-cap = Likely. High: accumulated flaws = escalation path needing exploitation (one step). |
| Extension (script) | `unscanned-data-store` | G | Likely / High → High | Possible / Low | Possible / Medium → Elevated | G governance. Possible: under-protection only matters with another failure (shadow data 35%). Medium anchor: governance. |
| Extension (script) | `untrusted-container-image` | G | Very Likely / Very High → Critical | Likely / Medium | Likely / High → High | G: every container. Likely: 87% of images carry high/critical vulns = commonly absent, cap Likely. High: typical case is a vulnerable image (needs exploitation); malicious images are the worst case. |
| Extension (script) | `vulnerability-scanner-credential-exposure` | G | Likely / Very High → High | Possible / High | Possible / Very High → High | G: fires on every credentialed scanner (the technology implies standing privileged credentials). Possible: reaching the scanner's credential store is a foothold precondition. Very High: enclave-wide privileged access. |
| Extension (script) | `vulnerable-outdated-dependency` | G | Very Likely / Very High → Critical | Likely / Medium | Likely / High → High | G: every custom-code asset. Weakness Very Likely (OSSRA 86%) but G-cap = Likely. High typical (CVE-dependent); Log4Shell-class RCE is the worst case. |
| Organization-specific | `ai-agent-memory-poisoning` | G | Likely / High → High | Possible / Medium | Possible / High → Elevated | G: memory feature. Weakness Likely (ATLAS CS0040, CS0072) -> Possible. High: persistent behavior manipulation (same as RAG poisoning). |
| Organization-specific | `ai-direct-prompt-injection` | W | Very Likely / Very High → Critical | Very Likely / Medium | Very Likely / High → High | W: free-form prompt input. Very Likely: a text box, 26-100% jailbreak success, ATLAS 11+25 case studies. High: secret leakage to unauthorized tool actions; tool RCE is the worst case. |
| Organization-specific | `ai-endpoint-assistant-overreach` | G | Possible / High → Elevated | Unlikely / Low | Unlikely / Medium → Medium | G. Unlikely: no incident found. Medium: limited, device-scoped disclosure. |
| Organization-specific | `ai-indirect-prompt-injection` | W | Very Likely / Very High → Critical | Very Likely / Medium | Very Likely / High → High | W: indirect input/RAG/agent. Very Likely: ATLAS 18 case studies incl. zero-click EchoLeak. High: acts with the user's data and tool rights. |
| Organization-specific | `ai-labeler-overexposure` | G | Possible / High → Elevated | Unlikely / Low | Unlikely / Medium → Medium | G. Weakness Possible (one iRobot case) -> Unlikely. Medium: limited exposure to uncleared reviewers. |
| Organization-specific | `ai-ot-actuation-boundary-gap` | W | Likely / Very High → High | Possible / High | Possible / Very High → High | W: tag asserts an ungated path to OT. Possible: no incident; RoboPAIR research. Very High: physical actuation. |
| Organization-specific | `ai-overreliance-trust-exploitation` | G | Likely / High → High | Likely / Low | Likely / Medium → Elevated | G. Likely: hallucination is inherent (1,600+ court filings). Medium anchor: governance/decision quality, no system compromise. |
| Organization-specific | `ai-unexpected-code-execution` | W | Likely / Very High → High | Likely / High | Likely / Very High → High | W: tag asserts model-produced code is run. Likely (MathGPT, CVE-2023-29374). Very High: RCE. Unisolated +1 step should cap at Very Likely only with in-the-wild evidence. |
| Organization-specific | `ai-unvetted-agent-skills` | G | Likely / Very High → High | Possible / Medium | Possible / High → Elevated | G. Weakness Likely (ClawdBot, postmark-mcp) -> Possible. High: acts with the agent's permissions. |
| Organization-specific | `air-gapped-model-package-integrity-gap` | G | Unlikely / Very High → Elevated | Unlikely / High | Unlikely / Very High → Elevated | G. Unlikely: insider/physical access. Very High: pickle executes on load. |
| Organization-specific | `api-abuse-enumeration-logging-gap` | G | Likely / High → High | Possible / Low | Possible / Medium → Elevated | G detection gap. Possible (Optus, T-Mobile). Medium anchor: detection. |
| Organization-specific | `background-job-security` | G | Likely / High → High | Possible / Low | Possible / Medium → Elevated | G. Weakness Likely (CWE-863) -> Possible. Medium: one job acts on stale rights. |
| Organization-specific | `backup-admin-privilege-separation-gap` | G | Likely / Very High → High | Likely / Medium | Likely / High → High | G. Likely: backups targeted in 94% of ransomware (Sophos) = commonly exploited. High: one compromise removes the recovery path. |
| Organization-specific | `backup-immutability-not-enforced` | G | Likely / Very High → High | Likely / Medium | Likely / High → High | G. Likely: T1490, Veeam 96% targeted. High: removable lock gives no protection from the privileged attacker. |
| Organization-specific | `backup-integrity-recovery-gap` | G | Possible / Very High → High | Possible / Low | Possible / Medium → Elevated | G assurance gap. Possible (Sophos 94% attempted). Medium anchor: recovery assurance; the direct backup-loss controls are scored by the immutability/separation rows. STRIDE changed from information-disclosure to tampering, so the step reads integrity (same result on profile T). |
| Organization-specific | `backup-key-rotation-retention-mismatch` | G | Unlikely / Medium → Medium | Unlikely / Low | Unlikely / Medium → Medium | G. Unlikely: managed KMS keeps old material by default. Medium anchor: recovery. |
| Organization-specific | `break-glass-circular-dependency-untested` | G | Unlikely / Medium → Medium | Unlikely / Medium | Unlikely / Medium → Medium | G. Unlikely: needs a primary-IdP outage plus a broken path. Medium anchor: recovery. |
| Organization-specific | `bulk-import-export-abuse` | G | Likely / High → High | Possible / Medium | Possible / High → Elevated | G. Weakness Likely (CWE-862 #4) -> Possible. High: volume disclosure/overwrite. |
| Organization-specific | `business-flow-abuse` | G | Likely / Medium → Elevated | Likely / Medium | Likely / Medium → Elevated | G. Likely: automated traffic >50% of web traffic = commonly unprotected. Medium: business harm, no technical impact. |
| Organization-specific | `cache-poisoning-data-persistence` | G | Likely / High → High | Possible / Medium | Possible / High → Elevated | G. Weakness Likely (CAPEC-141 High) -> Possible. High: cross-user disclosure (same as cross-context bleed). |
| Organization-specific | `cds-above-releasable-content-inclusion` | G | Very Likely / Very High → Critical | Likely / Medium | Likely / High → High | G. Weakness Very Likely (hidden metadata, TSA manual) but G-cap = Likely. High: spill of the released document's hidden content. |
| Organization-specific | `cds-broker-queue-injection` | G | Unlikely / Very High → Elevated | Unlikely / Medium | Unlikely / High → Medium | G. Unlikely: broker credentials and reach. High: prohibited content crosses without audit. |
| Organization-specific | `cds-high-side-broker-tampering` | G | Unlikely / Very High → Elevated | Unlikely / Medium | Unlikely / High → Medium | G. Unlikely: high-side enclave access. High: bypass of release approval. |
| Organization-specific | `cds-low-to-high-influence` | G | Likely / Very High → High | Possible / Medium | Possible / High → Elevated | G. Weakness Likely -> Possible. High: corrupted inputs drive high-side decisions. |
| Organization-specific | `cds-malicious-insider-release-abuse` | G | Unlikely / Very High → Elevated | Unlikely / High | Unlikely / Very High → Elevated | G. Unlikely: rare insider (Teixeira). Very High: bulk release evading every technical control. |
| Organization-specific | `cds-marking-validation-bypass` | G | Likely / Very High → High | Likely / Medium | Likely / High → High | G. Likely: marking error is pervasive (DBIR misdelivery) = commonly absent check, cap Likely. High: spill of the mismarked content. |
| Organization-specific | `cds-misclassification-audit-gap` | G | Likely / High → High | Possible / Low | Possible / Medium → Elevated | G audit gap. Possible: one below the Likely human error it fails to reconstruct. Medium anchor: detection/audit. |
| Organization-specific | `cds-release-authority-bypass` | G | Unlikely / Very High → Elevated | Unlikely / Medium | Unlikely / High → Medium | G. Unlikely: workflow flaw in an accredited CDS. High: unapproved release (spill). |
| Organization-specific | `cds-transfer-interface-covert-channel` | G | Unlikely / High → Medium | Unlikely / Low | Unlikely / Medium → Medium | G. Unlikely: cooperating sender and receiver. Medium: low-bandwidth leakage. |
| Organization-specific | `cds-unsafe-inbound-content` | G | Likely / Very High → High | Possible / Medium | Possible / High → Elevated | G. Weakness Likely (parser exploits) -> Possible. High: parser exploit to code execution on the receiver needs a working exploit for that format. |
| Organization-specific | `container-runs-as-root` | W | Likely / Very High → High | Possible / Medium | Possible / High → Elevated | W: exception asserts root. Possible: exploitation needs code execution in the container first (CWE-250). High: easier escape (one further step). Same as script dangerous-container-capabilities. |
| Organization-specific | `dangling-dns-subdomain-takeover` | G | Possible / High → Elevated | Possible / Low | Possible / Medium → Elevated | G. Possible: needs a deleted resource plus a claimable name (SubdoMailing). Medium: phishing/cookie theft under a trusted name. |
| Organization-specific | `dataset-reidentification-risk` | G | Possible / High → Elevated | Possible / Medium | Possible / High → Elevated | G. Possible: needs a motivated party with auxiliary data (Rocher 2019). High: irreversible exposure of individuals. |
| Organization-specific | `deprecated-tls-weak-ciphers` | G | Possible / High → Elevated | Unlikely / Low | Unlikely / Medium → Medium | G: fires on every TLS terminator. Weakness Possible (SWEET32/POODLE costly) -> Unlikely. Medium: practical decryption difficulty, CAT II. |
| Organization-specific | `dfars-breach-notification-gap` | G | Unlikely / Medium → Medium | Unlikely / Medium | Unlikely / Medium → Medium | G compliance. Unlikely. Medium: contractual exposure. |
| Organization-specific | `dlp-egress-blind-spot` | G | Likely / High → High | Possible / Low | Possible / Medium → Elevated | G detection gap. Possible: one below the insider/error path it misses. Medium anchor: detection. |
| Organization-specific | `dynamic-code-rce` | G | Very Likely / Very High → Critical | Likely / High | Likely / Very High → High | G: feature tag. Weakness Very Likely (71 KEV CWE-94, Confluence) but G-cap = Likely. Very High anchor: injection reaching an interpreter. |
| Organization-specific | `email-header-injection` | G | Very Likely / High → High | Unlikely / Low | Unlikely / Medium → Medium | G. Weakness Possible (1 KEV; ease, not frequency) -> Unlikely. Medium anchor: limited direct harm (spam/phishing relay). |
| Organization-specific | `eol-component-ato-boundary` | W | Very Likely / High → High | Likely / Medium | Likely / High → High | W: exception asserts EOL software. Likely, not Very Likely, on a non-internet asset (needs a disclosed flaw + reach). High: unpatchable flaws, escalation with one step (same as unhardened OS). |
| Organization-specific | `exposed-admin-panel` | G | Very Likely / Very High → Critical | Possible / High | Possible / Very High → High | G: feature tag (hardening not evidenced). Weakness Likely (CAPEC-560 High; not internet-reachable on T) -> Possible. Very High: administrative control. |
| Organization-specific | `fips-non-compliant-cryptography` | G | Unlikely / High → Medium | Unlikely / Low | Unlikely / Medium → Medium | G compliance. Unlikely. Low anchor: no security consequence with strong algorithms (authorization blocker, not exploit). Low target unreachable on T (Low +1 = Medium). |
| Organization-specific | `forensic-chain-of-custody-gap` | G | Unlikely / High → Medium | Unlikely / Low | Unlikely / Medium → Medium | G process. Unlikely. Medium anchor: response. |
| Organization-specific | `graphql-security-gaps` | G | Very Likely / High → High | Likely / Low | Likely / Medium → Elevated | G. Likely: 57% had not disabled introspection = commonly absent. Medium: reconnaissance plus resource exhaustion; field-auth leaks are the worst case. |
| Organization-specific | `improper-api-inventory-management` | G | Likely / High → High | Possible / Low | Possible / Medium → Elevated | G. Weakness Likely (API9, Optus) -> Possible. Medium anchor: governance (inventory). |
| Organization-specific | `insecure-password-reset` | G | Likely / Very High → High | Possible / Medium | Possible / High → Elevated | G: feature tag only. Weakness Likely (Scattered Spider help-desk resets) -> Possible. High: account takeover. |
| Organization-specific | `malicious-file-parsing` | G | Likely / High → High | Possible / Medium | Possible / High → Elevated | G: feature tag. Weakness Likely (8 KEV) -> Possible. High: local file disclosure/internal requests (same as built-in XXE). |
| Organization-specific | `media-downgrade-procedure-gap` | G | Unlikely / High → Medium | Unlikely / Medium | Unlikely / High → Medium | G. Unlikely: infrequent governed transfers. High: the procedure is the primary control against a downgrade spill (TSA manual). |
| Organization-specific | `missing-data-provenance-chain` | G | Likely / High → High | Possible / Low | Possible / Medium → Elevated | G. Possible: weakness evidence is research (Carlini LAION). Medium anchor: governance/detection. |
| Organization-specific | `missing-data-rights-management` | G | Likely / Medium → Elevated | Likely / Low | Likely / Medium → Elevated | G. Likely: loss of control after release near-certain. Medium anchor: governance. |
| Organization-specific | `missing-privacy-impact-assessment` | G | Likely / High → High | Possible / Low | Possible / Medium → Elevated | G compliance gap. Possible: matters only alongside a privacy failure. Medium anchor: governance. |
| Organization-specific | `missing-token-binding` | G | Likely / Very High → High | Likely / Medium | Likely / High → High | G: binding not evidenced; Likely as commonly absent (147k replays, infostealer supply), cap Likely. High: session takeover without MFA. |
| Organization-specific | `network-ids-blind-spot` | G | Likely / High → High | Possible / Low | Possible / Medium → Elevated | G detection gap. Possible. Medium anchor: detection (dwell time). |
| Organization-specific | `oauth-illicit-consent-grant` | G | Likely / Very High → High | Possible / Medium | Possible / High → Elevated | G. Weakness Likely (APT28/29, Midnight Blizzard) -> Possible. High: persistent app access to user data. |
| Organization-specific | `oauth-oidc-vulnerabilities` | G | Likely / Very High → High | Possible / Medium | Possible / High → Elevated | G: feature tag. Weakness Likely (Storm-0558) -> Possible. High: token theft/forgery for the affected users; any-account forgery is the worst case. |
| Organization-specific | `overprivileged-workload-identity` | G | Likely / Very High → High | Likely / High | Likely / Very High → High | G. Likely: workloads use <5% of granted permissions = commonly absent. Very High: control-plane administrator. |
| Organization-specific | `pdf-generation-injection` | G | Likely / High → High | Possible / Medium | Possible / High → Elevated | G. Weakness Likely (CVE-2022-35583) -> Possible. High: local file read / metadata credentials. |
| Organization-specific | `permissive-cors-framing-policy` | G | Likely / High → High | Possible / Low | Possible / Medium → Elevated | G. Weakness Likely -> Possible. Medium: needs victim interaction. |
| Organization-specific | `policy-exception-direct-admin-access` | W | Likely / Very High → High | Likely / High | Likely / Very High → High | W: exception asserts directly exposed admin ports. Likely (RDP abuse in 90% of Sophos cases; not internet-reachable on T). Very High: interactive admin control. |
| Organization-specific | `policy-exception-local-auth` | W | Likely / Very High → High | Likely / Medium | Likely / High → High | W: exception tag asserts a local store outside MFA. Likely (CAPEC-600 High, DBIR 22%; not internet-reachable on T). High: one account taken over (same as built-in 2FA). |
| Organization-specific | `privileged-session-credential-disclosure` | G | Likely / Very High → High | Likely / High | Likely / Very High → High | G. Likely: poor credential hygiene in AA23-278A top ten, infostealer dumps. Very High: revealed shared admin passwords = privileged control (same as standing access). |
| Organization-specific | `public-api-abuse` | G | Very Likely / Medium → High | Likely / Medium | Likely / Medium → Elevated | G: public API tag. Weakness Very Likely (CAPEC-125, bots 37%) but G-cap = Likely. Medium: degradation/cost. |
| Organization-specific | `recovery-objective-definition-gap` | G | Likely / Low → Medium | Possible / Medium | Possible / Medium → Elevated | G planning. Possible: one below the Likely outage. Medium anchor: recovery. |
| Organization-specific | `saml-assertion-vulnerabilities` | G | Likely / Very High → High | Unlikely / High | Unlikely / Very High → Elevated | G: feature tag. Weakness Possible (CAPEC-475 Low; CVE-2017-11427) -> Unlikely. Very High: sign in as any user including admins. |
| Organization-specific | `search-index-abuse` | G | Likely / High → High | Possible / Medium | Possible / High → Elevated | G. Weakness Likely -> Possible. High: harvest across the index (same as built-in search-query injection). |
| Organization-specific | `self-managed-bmc-compromise` | G | Likely / Very High → High | Possible / High | Possible / Very High → High | G. Weakness Likely (CAPEC-70, BMC KEV) -> Possible. Very High: invisible remote control, firmware overwrite. |
| Organization-specific | `self-managed-boot-integrity-bypass` | G | Unlikely / Very High → Elevated | Unlikely / Medium | Unlikely / High → Medium | G. Unlikely: privileged access + tooling (BlackLotus). High: neutralizes OS defenses after a prior compromise. Resolves the catalogue's Medium/High/Very High mismatch at High. |
| Organization-specific | `self-managed-ca-template-escalation` | G | Likely / Very High → High | Likely / High | Likely / Very High → High | G. Likely: ESC1 the most commonly encountered AD CS escalation (commonly absent), ordinary user + public tooling. Very High: Domain Admin certificates. |
| Organization-specific | `self-managed-directory-tier0-compromise` | G | Possible / Very High → High | Possible / High | Possible / Very High → High | G. Possible: foothold then commodity DCSync; AA23-278A #2 misconfiguration. Very High: impersonate any identity. |
| Organization-specific | `self-managed-firmware-persistence-gap` | G | Unlikely / Very High → Elevated | Unlikely / Medium | Unlikely / High → Medium | G. Unlikely: CAPEC-532 Low, few in-the-wild cases. High: persistence that survives reinstall after a separate privileged compromise. |
| Organization-specific | `self-managed-hybrid-sync-compromise` | G | Possible / Very High → High | Possible / High | Possible / Very High → High | G. Possible: prior on-prem access needed (Storm-0501, APT29). Very High: set any hybrid account's password. |
| Organization-specific | `self-managed-missing-rpki-route-validation` | G | Unlikely / High → Medium | Unlikely / Low | Unlikely / Medium → Medium | G. Unlikely: needs a BGP-speaking network. Medium: TLS mostly limits a redirect to denial of service. |
| Organization-specific | `self-managed-network-no-segmentation` | G | Likely / Very High → High | Possible / Low | Possible / Medium → Elevated | G. Possible: lateral move needs a foothold (Target). Medium anchor: segmentation is defense in depth (same as built-in network segmentation). |
| Organization-specific | `self-managed-rogue-ap-credential-harvesting` | G | Unlikely / High → Medium | Unlikely / Medium | Unlikely / High → Medium | G. Unlikely: physical proximity. High: harvested credentials, broad compromise with one further step. |
| Organization-specific | `standing-privileged-access-no-tiering` | G | Likely / Very High → High | Likely / High | Likely / Very High → High | G. Likely: AA23-278A #2, >50% super identities = commonly absent. Very High: standing admin credential. |
| Organization-specific | `unauthorized-marketplace-plugin` | G | Likely / Very High → High | Likely / Medium | Likely / High → High | G. Likely: 91% of WordPress-ecosystem vulns in plugins = commonly present. High: typical case is a vulnerable add-on needing exploitation; malicious add-ons are the worst case. |
| Organization-specific | `undocumented-containment-disposition` | G | Unlikely / Medium → Medium | Unlikely / Medium | Unlikely / Medium → Medium | G process. Unlikely. Medium anchor: response. |
| Organization-specific | `undocumented-credential-blast-radius` | G | Unlikely / High → Medium | Unlikely / Low | Unlikely / Medium → Medium | G process. Unlikely: needs an incident plus an incomplete rotation. Medium anchor: response/recovery. |
| Organization-specific | `ungoverned-third-party-model-api` | G | Likely / High → High | Likely / Low | Likely / Medium → Elevated | G. Likely: 11% of pasted data confidential (Cyberhaven), Samsung = commonly absent. Medium: data reaches a vendor, governance rather than attacker compromise. |
| Organization-specific | `unsafe-api-consumption` | G | Likely / Very High → High | Possible / Medium | Possible / High → Elevated | G. Possible: needs a compromised/faulty third party (DBIR third-party 30%). High: unchecked response drives injection or data exposure. |
| Organization-specific | `unsupported-saas-backup-gap` | G | Likely / Medium → Elevated | Unlikely / High | Unlikely / High → Medium | G. Unlikely: vendor-side deletion is rare (Atlassian, UniSuper). High: with no org-controlled export the data is permanently lost. |
| Organization-specific | `untested-incident-response-plan` | G | Likely / Medium → Elevated | Possible / Medium | Possible / Medium → Elevated | G process. Possible: one below the Likely incident (Sophos 59%). Medium anchor: response (cf. 'no tested rollback'). |
| Organization-specific | `untested-restoration-procedure` | G | Likely / Medium → Elevated | Possible / Medium | Possible / Medium → Elevated | G. Possible: one below the Likely restore need. Medium anchor: 'no tested rollback'. |
| Organization-specific | `vdi-clipboard-data-exfiltration` | G | Unlikely / High → Medium | Unlikely / Low | Unlikely / Medium → Medium | G. Unlikely: authorized malicious insider. Medium: DLP/detection bypass. |
| Organization-specific | `vendor-remote-support-access-gap` | G | Possible / Very High → High | Possible / Medium | Possible / High → Elevated | G. Possible: vendor credentials/environment must be compromised first (DBIR third-party 30%). High: standing entry point, broad compromise with one further step. |
| Organization-specific | `webhook-signature-bypass` | G | Likely / High → High | Possible / Low | Possible / Medium → Elevated | G. Weakness Likely (low bar, few KEV) -> Possible. Medium: forged event triggers one handler action. |
| Organization-specific | `websocket-security-gaps` | G | Likely / High → High | Possible / Low | Possible / Medium → Elevated | G. Weakness Likely at most (no KEV) -> Possible. Medium: CSRF-class action/read as the victim (same as built-in CSRF). |
