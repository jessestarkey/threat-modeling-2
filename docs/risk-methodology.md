# Risk Scoring Methodology

This document is the full technical reference for how each finding's Likelihood, Impact, and
Severity are computed in this repository's threat model reports. The report's own Risk Methodology
section (`templates/report.html.jinja`) states what the scoring does, in a form short enough for a
broad audience. This document gives the reasons behind each design choice, the alternatives that
were weighed, and the exact formulas. It is written for anyone reviewing the methodology itself,
such as an ISSO, an AO, an assessor, or a new team member.

Having said that, this document is a narrative reference, not the source of truth. The scoring
logic lives in code: `models/central-security-repo/core-policies/inject_risks.py` for the custom
engine, and the fork of Threagile (`jessestarkey/threagile`) for the built-in and script rules.
Where a number here disagrees with the code, the code is right and this document is stale (see
[Keeping this in sync](#keeping-this-in-sync)).

## Contents

- [The three rule layers](#the-three-rule-layers)
- [Relative Attacker Attractiveness (RAA)](#relative-attacker-attractiveness-raa)
- [Likelihood](#likelihood)
- [Impact](#impact)
- [Severity](#severity)
- [How the layers differ](#how-the-layers-differ)
- [Why the layers stay separate](#why-the-layers-stay-separate)
- [Risk calibration](#risk-calibration)
- [Mission criticality](#mission-criticality)
- [Unguarded access from internet](#unguarded-access-from-internet)
- [Application features and requirement tailoring](#application-features-and-requirement-tailoring)
- [Source of truth, by topic](#source-of-truth-by-topic)
- [Keeping this in sync](#keeping-this-in-sync)
- [Appendix: Calibration table](#appendix-calibration-table)

## The three rule layers

Every finding in a report comes from one of three rule layers. They detect risks in different
ways, but they score them the same way: each rule supplies a baseline Likelihood and Impact, the
baseline is adjusted for the asset the finding lands on, and the two results combine into
Severity through one shared formula.

| | Built-in rules | Script rules | Custom engine |
|---|---|---|---|
| What they are | Threagile's 42 compiled Go rules, in the fork. Seven are model-authoring checks, so 35 are catalogued as threats. | 62 YAML rules in the fork's scripting language, mostly IL5-specific (AI, CDS, container and VM hardening, mission systems) | 86 categories in `09-custom-risks-lib.yml`, injected by `inject_risks.py` |
| Where they run | Inside the Threagile binary | Inside the Threagile binary | Before Threagile runs, as preprocessing |
| Baseline | Set in each rule's code | Stated once in each rule's YAML | `baseline_likelihood` and `baseline_impact` on each category |
| Likelihood steps | RAA step, internet step, rule-specific steps | RAA step and rule-specific steps, with no internet step | RAA step, internet step, an optional branch step |
| Impact step | Symmetric CIA step on the STRIDE-mapped dimension | The same | The same |
| Report text | `10-threagile-builtin-risks-lib.yml` | Inline in each rule's YAML | `09-custom-risks-lib.yml` |

The shared arithmetic lives in the fork's `pkg/types/risk_scoring.go`, which both fork layers
call. Specifically, the built-in rules call it through `computeLikelihood()` and the impact helpers
in `pkg/risks/builtin/helpers.go`, and the script rules call it through the `adjust_likelihood`,
`adjust_impact`, `adjust_impact_rank`, and `cia_rank` functions of the scripting language. The
custom engine is Python and cannot call into the binary, so `inject_risks.py` mirrors the same
constants. Thus, the three layers share one scoring mechanism in two copies, kept in step by the
drift tests (see [Drift checks](#drift-checks)).

## Relative Attacker Attractiveness (RAA)

RAA estimates how appealing an asset is as a target, relative to the rest of the model, and every
layer uses it for the Likelihood step. Threagile computes RAA itself, but only after its analysis
runs (in `technical-assets.json`), which is too late for `inject_risks.py`. Thus,
`compute_raa_by_id()` computes the same formula independently, replicated from the fork's
`pkg/model/raa.go` and the rating types it reads. The formula has eight steps.

1. **The asset's own ratings.** Each of the asset's Confidentiality, Integrity, and Availability
   ranks (0 to 4) is looked up in a weight table drawn from the Fibonacci sequence. Because the
   weights grow non-linearly, the jump from confidential to strictly confidential counts for much
   more than the jump from public to internal, so the top tier dominates the score. There are six
   tables, one Confidentiality and Criticality pair for each context a rating can apply in
   (Criticality covers both Integrity and Availability, since Threagile does not separate them for
   RAA):

   | Rank | 0 | 1 | 2 | 3 | 4 |
   |---|---|---|---|---|---|
   | `CONF_ASSET`: the asset's own Confidentiality | 8 | 13 | 21 | 34 | 55 |
   | `CRIT_ASSET`: the asset's own Integrity and Availability | 5 | 8 | 13 | 21 | 34 |
   | `CONF_PROCESSED_OR_STORED`: a data asset it processes or stores | 5 | 8 | 13 | 21 | 34 |
   | `CRIT_PROCESSED_OR_STORED`: the same, Integrity and Availability | 3 | 5 | 8 | 13 | 21 |
   | `CONF_TRANSFERRED`: a data asset sent or received over a link | 2 | 3 | 5 | 8 | 13 |
   | `CRIT_TRANSFERRED`: the same, Integrity and Availability | 2 | 3 | 5 | 8 | 13 |

   All six rows are windows onto one sequence (2, 3, 5, 8, 13, 21, 34, 55). An asset's own rating
   starts three steps further in than data it only transfers, so an asset counts for more than
   the data passing through it. Additionally, Confidentiality sits one step above Criticality,
   since RAA mainly measures what makes an asset worth attacking to read or steal. The exception is
   the transferred tier, where the two are equal, so intercepting data in transit counts the same
   for disclosure and corruption.
2. **Data the asset processes or stores.** Each such data asset adds a weighted contribution from
   the processed-or-stored tables. Confidentiality and Integrity are also multiplied by the data
   asset's `quantity` (very-few 1, few 2, many 3, very-many 5), while Availability is added at its
   raw weight. This asymmetry is Threagile's own formula (`raa.go`: "Multiplied by the quantity
   values of the data asset for C and I (not A)").
3. **Data the asset transfers.** Each data asset sent or received over the asset's links adds a
   smaller contribution from the transferred tables, scaled the same way.
4. **Technology multiplier.** The sum is scaled by the asset's technology. A reverse proxy or load
   balancer is divided by 5.5 and a monitoring asset by 5, since each is a conduit. In contrast, a
   database, vault, build pipeline, source repository, or artifact registry is doubled, an
   identity provider or identity store is multiplied by 2.5, and a container platform by 5. A
   datastore with no more specific multiplier is doubled.
5. **Multi-tenancy.** A `multi_tenant` asset is multiplied by 1.5.
6. **First normalization.** Every raw score is normalized to 0 to 100% against the lowest and
   highest scores in this model, with a floor of 1%. This pass exists only to give step 7
   comparable values.
7. **Pivoting.** An asset inherits up to a third of the gap between its normalized score and that
   of the most attractive asset it can reach directly over its links. As a result, a plain-looking
   front-door asset with a path to a vault or identity provider scores higher than its own ratings
   suggest. The adjustment is added to the raw score from step 5.
8. **Second normalization.** The adjusted raw scores are normalized again, and this pass gives the
   final RAA. The double pass is Threagile's own design (`calculatePivotingNeighbourEffectAdjustment()`
   works on normalized values before `applyRAA()` normalizes again), and it is replicated as is.

**Limitation.** Because of that final normalization, RAA is relative to the model rather than an
absolute scale. For example, "40% or more" means a different absolute attack-worthiness in a
three-asset model than in a fifty-asset one. This framework keeps Threagile's formula rather than
correcting it, since a corrected formula would no longer match the binary's RAA, and the change
has not been validated against the rules that consult it.

## Likelihood

A finding's Likelihood starts from its rule's baseline and takes up to three kinds of step, each
one level, with the result clamped to the four-level scale (Unlikely, Possible, Likely, Very
Likely):

```
raa_step       = +1  if asset_raa >= 40.0
               = -1  if asset_raa <  15.0
               =  0  otherwise
internet_step  = +1  if the asset is internet-facing or internet-reachable, else 0
                     (built-in rules and the custom engine only)
rule_steps     = any steps a rule takes from model facts, such as -1 on a DevOps link

Likelihood = clamp(baseline + raa_step + internet_step + rule_steps)
```

**The RAA step.** The 40.0 threshold matches the value that Threagile's RAA-aware rules already
used, rather than being tuned separately. The 15.0 threshold lets Likelihood step down for an asset
that is clearly low-value relative to the model. Without it, every baseline would be a floor, and
Likelihood could only rise as a model grows. Additionally, 15.0 sits well below 40.0 rather than
mirroring it (at 60.0), so an asset must be clearly low-value, not merely below average, to step
down.

**The internet step.** The built-in rules read the native `internet: true` field, which marks an
internet-facing edge component, or the `net:internet-reachable` tag. The custom engine reads the
tag. The tag marks an asset that internet traffic can reach even though it is not the edge
component, typically the application behind a gateway, since most vulnerability classes pass
through a WAF untouched. The author places the tag, rather than the engine deriving it from the
graph, because a graph walk produces false positives through shared hops. For example, one
ingress controller can serve both an internet-facing login flow and a separate internal flow, and
a walk cannot tell which outbound links continue the internet-facing one. Tracking that
provenance would cost as much to maintain as the tag, so the explicit tag is both cheaper and more
correct. The step is one-directional, since an asset that is not reachable is the ordinary case
that the baseline already assumes. Finally, `zone:dmz` stays narrower, meaning an asset that
directly receives hostile traffic, and the rules that need that meaning (such as Missing WAF) read
it instead.

**The script rules take no internet step.** Script rules use exposure to decide whether they fire
at all, rather than as a Likelihood step. For example, many AI rules fire only when an asset is
reachable from outside its own trust boundary, so an internet step on top would count the same
fact twice. Thus, a script finding and a custom finding on the same internet-reachable asset can
differ by one Likelihood level, and that difference is expected rather than drift.

## Impact

A finding's Impact starts from its rule's baseline and takes one symmetric step from a CIA rank,
clamped to the four-level scale (Low, Medium, High, Very High):

```
dimension  = STRIDE_TO_CIA_DIMENSION[stride]     (the highest of C, I, and A if unmapped)
cia_step   = -1  if the rank is public / internal (archive / operational)
           =  0  if the rank is restricted / important
           = +1  if the rank is confidential / critical or higher

Impact = clamp(baseline + cia_step)
```

Thus, a baseline Impact is the impact on a restricted or important asset, in every layer.

**One dimension, not the highest of three.** The step uses the dimension that the finding's STRIDE
category threatens. For instance, a denial-of-service finding steps on Availability alone, so an
asset with high Confidentiality but low Availability does not inflate a threat to its
availability. The mapping is:

| STRIDE category | CIA dimension |
|---|---|
| information-disclosure | confidentiality |
| spoofing | integrity |
| tampering | integrity |
| repudiation | integrity |
| denial-of-service | availability |
| elevation-of-privilege (or unmapped) | the highest of C, I, and A |

Spoofing maps to Integrity rather than Confidentiality. Microsoft's STRIDE pairs spoofing with
authentication, which is not one of the three ratings a Threagile asset carries. The direct
consequence of a spoofing finding (an impersonated identity, a forged token, a bypassed
authentication check) is that the authentication decision itself lost its integrity, while what
the attacker does next is a downstream consequence. This matters most in the Identity focus area,
where nearly every finding is spoofing, since an identity broker or certificate authority is
valued mainly for its Integrity.

However, the mapping fits one minority case poorly. Spoofing also covers infrastructure
impersonation, such as a rogue access point, where the consequence (credentials intercepted over
the air) is a confidentiality event. The mapping is one global table that a category cannot
override, and changing those categories' STRIDE value to route around it would misstate them.
Thus, they stay spoofing, and the trade-off is accepted in favor of the identity cases.

**Rating sources.** A rule's rank comes from whichever ratings best describe what the finding
endangers: the asset's own ratings, the highest rating among the data it processes, or the data on
the link. The injection, deserialization, and code backdooring rules use the higher of
Confidentiality and Integrity, since those threats both read and alter data. Finally, the two
whole-model checks, `missing-build-infrastructure` and `missing-identity-store`, take no step,
since the asset they report is only an example.

**No model-wide step.** The model's mission criticality does not change Impact (see
[Mission criticality](#mission-criticality)). Every asset carries its own justified CIA rating, so
a model-wide step would mostly inflate assets rated lower than the system around them. An asset
that matters more than its rating suggests should have its rating corrected instead.

## Severity

Likelihood and Impact combine the same way in all three layers. Each level carries a
Fibonacci-spaced weight (1, 2, 3, 5), the two weights are multiplied, and the product is bucketed
by threshold: 1 or less is Low, 3 or less is Medium, 6 or less is Elevated, 15 or less is High, and
anything higher is Critical.

| | Low (1) | Medium (2) | High (3) | Very-High (5) |
|---|---|---|---|---|
| **Unlikely (1)** | Low | Medium | Medium | Elevated |
| **Possible (2)** | Medium | Elevated | Elevated | High |
| **Likely (3)** | Medium | Elevated | High | High |
| **Very-Likely (5)** | Elevated | High | High | Critical |

Across the 16 cells, this gives Low 1, Medium 4, Elevated 5, High 5, and Critical 1. Critical
appears only where both axes are at their maximum.

**Why Fibonacci weights.** The real-world jump from the third tier to the fourth (Likely to Very
Likely, or High to Very High) is larger than the jump from the first to the second, and equal
linear steps understate it. This is the same reasoning as RAA's weight tables. The weights were
validated on about 186 real custom findings, comparing linear weights (1, 2, 3, 4) against three
Fibonacci windows ([1, 2, 3, 5], [2, 3, 5, 8], and [3, 5, 8, 13]). Every Fibonacci window produced 10
distinct products across the 16 cells, against linear's 9, and 1, 2, 3, 5 is the simplest of them.
Specifically, the tie it breaks is a real one: Possible and Medium (moderate on both axes) no
longer scores the same as Unlikely and Very High (rare but catastrophic).

The alternative considered was a rank-sum table, which adds the two ranks and buckets the sum. It
can produce a balanced spread, but only with a hand-picked exception cell to keep Critical rare,
and it would have been a second formula beside Threagile's. The weight product keeps Critical rare
on its own, so one formula serves every layer.

## How the layers differ

Though the scoring mechanism is shared, each layer has its own detection logic and a few scoring
exceptions.

**Built-in rules.** Detection logic, meaning whether a rule fires on an asset or link at all,
comes from upstream Threagile. This framework treats it as given, apart from the specific fixes
recorded under [Risk calibration](#risk-calibration). On scoring, three groups of rules depart from
the usual steps:
- **The seven model-authoring checks** (an incomplete model, unnecessary assets, links, or data,
  and mismatched link or boundary content) flag mistakes in how the model was written, not
  threats. They keep flat ratings, and the report lists them as model failures.
- **Two rules gate on RAA.** `missing-hardening` fires only at an RAA of 55% (40% for high-value
  asset types), and `missing-network-segmentation` uses a similar gate. Both gates sit at or above
  the 40.0 RAA threshold, so every asset that passes the gate also takes the RAA step. The gate
  decides whether the risk applies, while the step scores it.
- **Whole-model checks.** `missing-build-infrastructure` and `missing-identity-store` keep a flat
  Unlikely Likelihood, like their flat Low Impact, since the asset they report is only an example.
  `missing-vault` takes the steps on the asset it reports, and keeps its flat baseline when it has
  no asset to report. Additionally, the shared-runtime and trust-boundary findings of
  `missing-cloud-hardening` and `mixed-targets-on-shared-runtime` score the runtime or boundary
  itself, so they keep a flat Likelihood.

**Script rules.** Each script states its baseline once and calls the shared scoring functions,
adding its own steps from model facts. Because the language has no cross-file sharing, those
functions are built into the language rather than written in each file. The scripts take no
internet step, as described under [Likelihood](#likelihood), and each carries its own report text
(description, impact, ASVS, cheat sheet, action, mitigation, detection logic, references, risk
assessment, and false positives).

**Custom engine.** `inject_risks.py` matches each technical asset's tags against its categories
and writes each match into the model's `custom_risk_categories`, with Likelihood, Impact, and
Severity computed for that asset. Each category's baseline is grounded in CWE's "Likelihood of
Exploit" or the matching OWASP Top 10 entry where a real mapping exists, and in expert judgment
where none does. The baseline carries most of the signal, while the steps are small and bounded.
Some categories also take a one-level branch step from a model fact, such as a guardrail on a
prompt-injection asset's request path.

## Why the layers stay separate

On one hand, the three layers now share their formula, their thresholds, and their step
mechanism, so merging them into one engine might seem natural. On the other hand, nothing lets
them share code. The custom engine runs before Threagile, and its output is data that Threagile
renders as given. Thus, `inject_risks.py` cannot call the Go helpers, and the binary cannot call
the Python engine.

As a result, the layers remain separate by design. The shared constants are two copies of the
same logic, in two languages and two repositories, and the drift tests keep them aligned. The
baselines also stay independent judgments, since upstream maintainers set the built-in rules'
original values and this framework calibrated all three layers against one rubric (see
[Risk calibration](#risk-calibration)). Ultimately, a similar-looking finding can still score
differently across layers, for three reasons: (1) the rules' baselines and rating sources differ,
(2) the script rules take no internet step, and (3) each layer's detection logic decides which
assets a finding lands on.

## Risk calibration

This section is a single rubric for the final Likelihood and Impact of every rule, in all three
layers, after each layer's adjustments. It was approved on 2026-11-18.

### Why this exists

When the calibration began, the three layers started from very different ratings (190 rules at
the time):

| Layer | Rules | Mean starting likelihood (0–3) | Mean starting impact (0–3) | Very High impact | Likely+ **and** High+ |
|---|---|---|---|---|---|
| Built-in (upstream Threagile, in the fork) | 35 | 1.11 | 0.60 | 0 | 3% |
| Extension (fork script rules) | 66 | 1.76 | 1.94 | 26 | 42% |
| Organization-specific (custom engine) | 89 | 1.58 | 1.67 | 22 | 34% |

Additionally, the built-in rules then stepped Impact up only, while the other two layers stepped
it both ways. In an IL5 model most assets are rated confidential or critical, so a built-in rule
with a Medium baseline ended at Medium, while a script or custom rule with the same baseline ended
at High. Thus, the starting ratings did not mean the same thing across layers, and the rubric
rates final outcomes on defined reference assets.

### The impact convention

Three conventions were weighed:

| Option | What changes | Effect |
|---|---|---|
| **A. Symmetric everywhere (chosen)** | The built-in rules' step-up-only impact logic is replaced with the symmetric step on the STRIDE-mapped dimension. | One convention, so a baseline means the same thing in every layer: the impact on a restricted or important asset. |
| B. Step-up only everywhere | The scripts and the custom engine drop their downward step and step up only at the top tier. | Matches upstream, but loses the downward step that stops baselines acting as floors. |
| C. Keep both | Each layer's baselines are re-rated so that final outcomes fit the anchors. | No code change, but the baselines stay non-comparable, and every new rule needs per-layer arithmetic. |

Option A was chosen, because it makes the anchors map directly onto baselines: a rule's baseline
is its target on the restricted or important asset.

### Reference assets

Each rule is rated by the final Likelihood and Impact it produces on these assets, after every
adjustment.

| Profile | CIA rating | RAA | Exposure | Use |
|---|---|---|---|---|
| **R, reference** | restricted / important / important (rank 2, no CIA step) | 15–40 (no RAA step) | not internet-reachable | where baselines are set |
| **T, typical IL5** | confidential / critical / important | 15–40 | not internet-reachable | the main check, since most findings will show this |
| **H, high** | strictly-confidential / mission-critical / mission-critical | 40 or more | internet-reachable | must not reach Critical on most rules |
| **L, low** | internal / operational / operational | below 15 | not internet-reachable | should drop to Low or Medium severity |

### Impact anchors (final rating)

The rating is the typical consequence of a successful exploit on the asset, not the worst
incident on record. The worst case belongs in the rule's `risk_assessment` ("Critical when ..."),
not in its baseline.

| Impact | Anchor | Examples |
|---|---|---|
| **Very High** | Exploitation directly yields code execution, administrative or privileged control, or bulk compromise of confidential data, with no further step needed. | injection reaching an interpreter, container escape, supply-chain code that runs on load |
| **High** | Direct compromise of a meaningful part of the asset's data or function, or broad compromise that needs one further step. | IDOR or broken object authorization, stored XSS, an agent's writable tool misused |
| **Medium** | A missing or weak control whose absence enables or worsens another attack (defense in depth, detection, recovery, change control, governance), or limited direct harm. | missing WAF, missing audit logging, no kill switch, no tested rollback |
| **Low** | Hygiene, or information leakage with little standalone consequence. | verbose errors without sensitive data, model-authoring mistakes |

### Likelihood anchors (final rating, profile R)

Every rule is first classed by what its finding asserts:
- **W, weakness shown.** The model's own facts show the weakness, such as an unencrypted link, a
  writable tool, an outside caller, or a static secret on a link.
- **G, control not evidenced.** The finding means that the control cannot be seen in the model,
  because the rule fires unconditionally or on a tag that only says a feature exists.

| Likelihood | Anchor |
|---|---|
| **Very Likely** | Exploitation needs only access that the asset already exposes and public techniques, and it is routinely seen in the wild. The standard of evidence is several documented incidents, or a CAPEC or OWASP likelihood of High with widespread prevalence. |
| **Likely** | Commonly exploited when present, with documented incidents, and it needs moderate skill or one ordinary precondition. |
| **Possible** | Needs a specific precondition (insider access, a prior foothold, or a chained failure), or the evidence is mainly research and demonstrations. |
| **Unlikely** | Needs privileged access or rare conditions, with no in-the-wild evidence. |

**The G-class cap.** A control-not-evidenced finding starts at most at Likely, and one level below
the weakness it would enable, unless there is evidence that the control is commonly absent in
practice. The finding says that the control is not visible, not that the weakness was exploited.

### Severity sanity checks (on a reference model)

After re-rating, every rule runs on a reference model of profile-T assets, where most real
findings sit, and three checks apply:
1. Critical is rare on profile T, and appears on profile H (about 5 to 15%) only where both axes
   are at their maximum.
2. Most G-class findings land at Medium or Elevated, not High.
3. Built-in and script rules that cover comparable weaknesses land within one severity level of
   each other, for example `missing-authentication` and `ai-agent-identity-privilege-abuse`.

### Decisions

The approval set four decisions:
- **Impact convention:** option A, so every layer uses the symmetric step on the STRIDE-mapped
  dimension.
- **G-class cap:** approved. Rules that fire because an interface exists (a database, web
  application, API, or pipeline), including the injection rules, are G-class. A database existing
  does not show a SQL injection, so the rule still fires on every database, but it rates the
  surface rather than a confirmed flaw.
- **Critical** is expected on profile H, not on profile T.
- **Overrides to the independent pass:**
  - `cicd-pipeline-tampering-outside-repo` takes High impact rather than Medium, since a tampered
    pipeline ships attacker code.
  - `missing-build-infrastructure` and `missing-identity-store` take no CIA step, since they are
    whole-model checks whose reported asset is only a placeholder.
  - `fips-non-compliant-cryptography` and `ai-hidden-context-exposure` accept Medium on profile T.

### Results (independent re-rating, checked)

An independent pass applied this rubric to all 190 rules catalogued at the time. It was then
checked for (1) the severity arithmetic, (2) each baseline and CIA step reproducing its final
rating, (3) the G-class cap, and (4) consistent STRIDE dimensions. All four held, and the full
table is in [Appendix: Calibration table](#appendix-calibration-table).

| Layer | Rules | Baseline changes | Final rating on T changes |
|---|---|---|---|
| Built-in | 35 | 23 | 30 |
| Extension (script) | 66 | 60 | 51 |
| Organization-specific | 89 | 78 | 70 |

The severity of every rule on each reference profile:

| Profile | Low | Medium | Elevated | High | Critical |
|---|---|---|---|---|---|
| T, before | 5 | 34 | 40 | 96 | 15 |
| T, after | 2 | 37 | 97 | 54 | 0 |
| H, after | 0 | 2 | 34 | 134 | 20 |
| L, after | 109 | 68 | 13 | 0 | 0 |

Of the comparable cross-layer pairs reviewed, 11 of 23 were two or more severity levels apart
before, against one after (code backdooring, CI/CD tampering, and dependency confusion, which are
a family rather than a true pair). The rules that reach Critical on profile H are injection and
code execution, deserialization, tier-0 identity, exposed admin panels, ICS and OT, and agent code
execution. On the Confluence fixture model, Critical findings fell from 64 to 11.

### How the ratings are applied

The approved ratings are in the rules of all three layers. First, each script rule states its
baseline once and calls the shared scoring functions, keeping its own rule-specific steps. Second,
each built-in rule carries its approved baseline and the symmetric CIA step, from the rating
source that fits it, and every branch step is one level. Third, the custom engine reads its
approved baselines from `09-custom-risks-lib.yml`. The rules that apply them follow:
- **Injection rules** (cross-site scripting, SQL and NoSQL, LDAP, and search-query injection), along
  with `untrusted-deserialization` and `code-backdooring`, step on the higher of Confidentiality and
  Integrity, since they both read and alter data.
- **DevOps links** take a one-level Likelihood step down. However, SQL and NoSQL injection and SSRF
  keep their documented rule of skipping the RAA and internet steps on a DevOps link.
- **Mitigations the model can show** take a one-level Impact step down, namely a code-inspection
  platform (code backdooring), and a VPN-protected, IP-filtered, or redundant target
  (denial of service). Additionally, SSRF keeps its Medium floor inside a cloud boundary.
- **Agent rules** take Impact from the highest rating across the agent and every target it
  reaches. `ai-excessive-agency-tool-misuse` reaches through a tool server to what that server
  writes, and it suppresses the tool server's own finding only when the agent's link to it is
  writable.
- **AI rules that fire only with confidential data** take that data as the floor for the
  Confidentiality step.
- `ai-telemetry-prompt-log-leakage` takes no step for a modeled telemetry link, since its baseline
  already sits at the G-class cap.
- `missing-authentication` rates the target when its link carries no data, and
  `unencrypted-communication` steps on the higher of the link data's Confidentiality and Integrity,
  since it fires on either.
- Custom `ai-unexpected-code-execution` takes its isolation step only on an explicitly physical
  machine.
- The script `missing-network-micro-segmentation` steps on the highest of C, I, and A, like the
  built-in and custom segmentation rules.
- The scoring functions treat an empty baseline, an unknown rating name, or a number passed as a
  rating as an error, so a typo fails loudly instead of rating one level low.

Two changes were declined. First, plain datastores do not count as indirect-injection sources,
since nearly every agent would then fire, and the model cannot tell user content from other data.
Second, the cleartext-credential floor does not scale with asset value, since cleartext
credentials are a weakness at any value.

### Rule fixes from the calibration reviews

Independent reviews of the applied code, of the non-AI script rules, and of the overlap between
the custom categories and the fork led to these fixes:
- **Duplicates retired or merged.**
  - `baseline-security-event-logging-gap` is merged into `insufficient-audit-logging`, now
    "Insufficient Security Event Logging (AU-2 / AU-6 Gap)", since they had identical triggers,
    STRIDE, and CWE.
  - Threagile's built-in `container-baseimage-backdooring` is retired in favor of the script
    `untrusted-container-image`, whose description covers backdoored base layers.
  - The script `accidental-secret-leak` is retired in favor of the built-in, which covers more
    technologies. The script failed for the whole model whenever any rating was public.
  - The script `unencrypted-virtual-disk` is retired, since the built-in `unencrypted-asset`
    covers encryption at rest with the right exclusions.
  - Custom `insecure-deserialization` is retired, since the built-in `untrusted-deserialization`
    reads `data_formats_accepted: serialization`.
  - Custom `missing-waf-internet-facing` and its `ops:waf-enabled` tag are retired, since the
    built-in `missing-waf` reads a modeled WAF.
- **Scope narrowed.**
  - Custom `malicious-file-parsing` covers archive extraction only (zip slip and decompression
    bombs, CWE-22), which the XXE and file-validation built-ins do not cover.
  - `missing-network-micro-segmentation` does not fire on a container inside a
    `network-policy-namespace-isolation` boundary, since the model shows the control.
  - Custom self-managed segmentation leaves containers to the fork's micro-segmentation rule.
  - `cui-telemetry-spillage` fires only on assets that handle confidential or higher data.
  - `vulnerable-outdated-dependency` and `os-command-injection` skip external entities, and
    `trusted-thin-client` no longer counts as a CDS guard.
  - `exposed-admin-panel` covers network exposure and step-up authentication, and it leaves
    server-side role checks to `broken-function-level-authorization`.
- **Raised once rather than per asset.**
  - `cluster-control-plane-audit-gap` is a built-in, so it attaches to the shared runtime (the
    cluster) once instead of to every container, which a script rule cannot do. It takes the
    highest Likelihood across the cluster's containers.
  - The rogue access point and route origin validation findings are raised once per network trust
    boundary, on its edge asset where one is modeled, while segmentation stays per workload.
  - `push-instead-of-pull-deployment` rates each deployment target on its own.
- **Triggers that read native fields.**
  - Dangling DNS and the IDS blind spot fire on a public endpoint, meaning an asset with
    `internet: true` that an out-of-scope or external-entity asset calls (the IDS rule also fires on
    `net:internet-reachable`). As a result, an egress-only device such as a firewall no longer
    qualifies.
  - CORS and CSP fire on an asset with a browser caller, so the `feature:browser-facing` tag is
    retired.
  - The WebSocket finding fires on an incoming `ws` or `wss` link, and search-index abuse lands on
    the modeled search engine, or on an application tagged `feature:search-index`. The
    `zone:dmz`, `feature:search-index`, and `feature:websocket` tags remain, since libraries 01 and
    02 use them to select requirements and abuse cases.
- **Gates and classes corrected.**
  - Threagile's built-in `missing-network-segmentation` had its gate inverted by an upstream
    refactor, so it ran only on the assets it should skip, and the gate and its tests are corrected.
  - `ics-controller-unauthenticated-protocol` is control-not-evidenced, since it fires on the
    technology alone.
  - `missing-endpoint-security-agents`, `security-control-tamper-resistance-gap`, and
    `network-ids-blind-spot` are repudiation (CWE-778), `air-vehicle-gps-spoofing` is spoofing,
    and `backup-integrity-recovery-gap` is tampering.
  - The CWEs for the vulnerable dependency, CDS guard, dependency confusion, and install script
    rules are 1395, 693, 427, and 829.
- **Text.** Every custom `risk_assessment` opens with its calibrated scoring sentence, followed by
  the guidance for once the condition is confirmed, and `test_calibration.py` checks it. The
  built-ins' scoring text in the fork and in `10-threagile-builtin-risks-lib.yml` describes the
  calibrated scoring.

Two groups were kept as they are. The authorization rules (BOLA, BFLA, and BOPLA) stay, since link
authentication cannot show object-level checks either way. The per-workload container rules
(`mutable-container-filesystem` and `dangerous-container-capabilities`) also stay, since they are
set per pod spec.

**Policy exceptions.** A policy-exception waiver is recorded as `risk_tracking` status `accepted`
on the finding that the waived condition raises (see `08-risk-tracking-lib.yml`). Thus, the
cleartext-transit waiver and its category are retired, since the built-in
`unencrypted-communication` raises that weakness per link. The local-authentication waiver keeps
its category, narrowed to the identity-provider bypass, because no built-in raises that, while
missing MFA belongs to the built-in two-factor rule. The root-container waiver also keeps its
category, and it covers UID 0 only, since capabilities belong to `dangerous-container-capabilities`.
Finally, the direct-admin-access waiver raises its own finding only where the built-in
`unguarded-access-from-internet` does not (a lower-value VM, or an admin path not drawn as a link),
and it is otherwise recorded as accepted on the built-in finding.

The catalogue now counts 183 rules (35 built-in, 62 script, and 86 custom).

### Finding class in the output and the report

Every rule carries its approved class (the *Class* column of the appendix table) as
`finding_class`, either `weakness-shown` or `control-not-evidenced`. First, the class is set on
each built-in rule's category and each script rule's YAML in the fork, and on each entry of
`09-custom-risks-lib.yml`, which the engine passes through to the model. Second, it appears on every
finding in `risks.json` and on every category in `risk-categories.json`, which the fork writes next
to `risks.json` with each category's metadata (including `risk_assessment`) from all three layers.
Third, the report splits open risks into **Model Weaknesses** and **Control Verifications**. Each
control verification shows its risk assessment as the severity to assign if the control is
confirmed missing, and every category's details show its class. A self-check fails the run if the
split does not add up to the open-risk total.

### Drift checks

A rating or class that moves away from the appendix table fails a test:

| Layer | Check |
|---|---|
| Script rules | `pkg/risks/scripts/calibration_test.go`: every rule on profile T |
| Built-in rules | `pkg/risks/scripts/builtin_calibration_test.go`: each built-in that fires on the profile-T kitchen-sink model, by name (unit tests cover the rest) |
| Both fork layers | `pkg/risks/scripts/finding_class_test.go`: every rule's class |
| Custom engine | `core-policies/tests/test_calibration.py`: every category on profile T, its class, and the class reaching the injected model |
| Dimensions, fork | `pkg/risks/scripts/dimension_calibration_test.go`: every built-in and script rule the kitchen sink fires, on confidentiality-only, integrity-only, and availability-only profiles, so a rule stepping on the wrong dimension or rating source fails (profile T rates C and I alike, so it cannot tell) |
| Dimensions, custom | `test_calibration.py`: every custom category on the same three single-dimension profiles |
| Built-in report text | `test_calibration.py`: each built-in's `risk_assessment` in `10-threagile-builtin-risks-lib.yml` states its approved starting Likelihood and Impact |
| Report | `core-policies/tests/test_generate_report.py`: the finding-class annotation and the weaknesses and controls split |

Thus, changing a baseline, a step, or a class means changing the rule and this table together,
deliberately.

## Mission criticality

The model-level rating is `mission_criticality`, on its own four-value scale: `administrative`,
`mission-support`, `mission-essential`, and `mission-critical` (shown in reports as "Mission
Support" and so on). It is separate from the five-value scale that rates each asset's and data
asset's Integrity and Availability, which the CIA step depends on.

The rating changes no score. However, at `mission-essential` or above, the custom engine adds the
incident-response readiness checks (IR plan testing, DFARS breach notification, forensic chain of
custody, and containment disposition). The older key, `business_criticality`, is still accepted,
and its five values map onto the four: `archive` and `operational` to `administrative`,
`important` to `mission-support`, `critical` to `mission-essential`, and `mission-critical` to
`mission-critical`. The mapping keeps every existing model's findings the same, and a model that
sets both keys must give them the same value.

## Unguarded access from internet

The built-in `unguarded-access-from-internet` needs an internet-side caller, meaning an
internet-facing external entity or out-of-scope asset. An in-scope component that carries
`internet: true`, such as an application gateway or firewall, does not count as a caller, since an
in-scope gateway calling inward is the guarded path the rule asks for. Without this gate, the rule
raised everything a gateway or firewall talked to (on Confluence, five of its seven findings were
the gateways' and firewall's own traffic and log forwarding). The custom engine's direct-admin
waiver, which defers to this rule where it fires, mirrors the same gate
(`is_internet_side_caller()`). Additionally, the report's Communication Link column names the
link's source when it is not the row's asset, since link titles repeat across sources.

## Application features and requirement tailoring

The report prints the application's features and questions first, as "Application Features and
Scoping," and the security requirements after them, because the answers decide which requirement
sections apply. Applicability works at two levels. First, a focus area's tag triggers decide
whether its block of questions and requirements applies at all (`01-metadata-lib.yml` and
`02-abuse-and-reqs-lib.yml` share the same triggers). Second, within a block, the answers decide
which sections apply, since a block's triggers are broad. For example, the Identity block fires on
any OAuth or SAML feature, while the password requirements apply only where local passwords exist.

Tailoring is manual, and it rests on a feature checklist. Each focus area in `01-metadata-lib.yml`
has a few checklist items (24 in all), and for a new model the checklist comes first, since it
records what the application has before any tags exist. Each item has a fixed list of options, and
the author selects the ones that apply. An option can imply tags or native model fields, such as
File uploads implying `feature:file-upload-processing`, or an internet-facing endpoint implying
`internet: true`, and the author places each one on the asset that has the feature. The report
prints the checklist as a table, with the selected options marked and the implied tags and fields
listed for a reviewer to check, since nothing checks them automatically.

The checklist covers only what the application's developers know. Thus, platform and
authorization facts (such as the hosting environment, the impact level, and self-managed identity
or network infrastructure) stay outside it, and their tags are placed per asset as the model is
built, along with the tags that record evidence of a control, topology, or a policy waiver.

The 28 questions that follow the checklist are short, since the precise criteria live in the
requirement rows. Each question has an `asked_when` list, either "always" or the checklist
selections that make it apply. The report leaves out a question that the checklist rules out,
lists one that depends on an unanswered item as pending, and warns about one that applies but has
no answer.

An author tailors a section out by replacing its rows with "Not applicable: <reason>" in the
model, rather than deleting it, and the report then shows the section as not applicable with that
reason. As a result, a reviewer can see what was tailored out and why. The OWASP and NIST rows
themselves are never edited, only replaced by that note. Additionally, the report warns when an
abuse case pairs with a section marked not applicable, since the model would then state a threat
without a control.

Having said that, the decision needs judgment rather than a blanket rule. On the Confluence model,
for instance, logins federate to Entra ID, but a local break-glass account still exists, so ASVS
V6.2 (Password Security) remains in scope for that account.

## Source of truth, by topic

| Topic | Where |
|---|---|
| The custom engine's scoring | `models/central-security-repo/core-policies/inject_risks.py`: `compute_likelihood()`, `compute_impact()`, `compute_severity()`, and `compute_raa_by_id()` |
| RAA weight tables | The same file: `CONF_ASSET`, `CRIT_ASSET`, `CONF_PROCESSED_OR_STORED`, `CRIT_PROCESSED_OR_STORED`, `CONF_TRANSFERRED`, `CRIT_TRANSFERRED`, `QTY_FACTOR`, and `RAA_TECHNOLOGY_MULTIPLIER` |
| The custom engine's thresholds and weights | The same file: `RAA_LIKELIHOOD_THRESHOLD`, `RAA_LIKELIHOOD_LOW_THRESHOLD`, `CIA_RANK_TO_DELTA`, `STRIDE_TO_CIA_DIMENSION`, `WEIGHT`, and `SEVERITY_THRESHOLDS` |
| Custom baselines | `models/central-security-repo/libraries/09-custom-risks-lib.yml`: each entry's `baseline_likelihood` and `baseline_impact` |
| The fork's shared scoring | `jessestarkey/threagile`: `pkg/types/risk_scoring.go` for the RAA thresholds, CIA steps, and clamping, `pkg/types/model.go`'s `CalculateSeverity()` for the severity thresholds, and the likelihood and impact types for the weights |
| Built-in rules | The fork's `pkg/risks/builtin/helpers.go` for `computeLikelihood()` and the impact helpers, and each `pkg/risks/builtin/*_rule.go` for that rule's baseline, steps, and detection logic |
| Built-in report text | `models/central-security-repo/libraries/10-threagile-builtin-risks-lib.yml` |
| Script rules | The fork's `pkg/risks/scripts/*.yaml` (62 files), with the scoring functions in `pkg/risks/script/common/built-in-scoring.go` |
| The condensed, report-facing version of this document | The Risk Methodology section of `models/central-security-repo/core-policies/templates/report.html.jinja` |

## Keeping this in sync

The drift checks enforce the calibrated ratings, classes, and dimensions (see
[Drift checks](#drift-checks)), so a change to a baseline, step, or class fails a test until the
appendix table and the matching test change with it. However, three texts describe the scoring
in prose, and they must be kept to it by hand: (1) each built-in's `RiskAssessment` in the fork,
(2) each built-in's `risk_assessment` in `10-threagile-builtin-risks-lib.yml` (which the report
prints, and which `test_calibration.py` checks for the approved starting rating), and (3) the
threat catalogue's calibration notes.

Beyond those, nothing ties this document to the code. Thus, when a threshold, weight, or the
severity matrix changes, update the number here, and update the reasoning if the change reflects
a new trade-off rather than a retuned value. A stale number is a quick fix, whereas a stale
rationale misrepresents why the methodology works the way it does. The report's Risk Methodology
section should be checked at the same time, since the two describe the same logic at two depths.

The shared constants also exist in two copies: `inject_risks.py` in this repository, and
`pkg/types/risk_scoring.go` with `pkg/risks/builtin/helpers.go` in the fork. Neither imports the
other, so a change to either means checking the other and this document together. The drift tests
catch a change that moves a rule's final rating, but they would not catch the two copies drifting
in a case that no test profile exercises.

## Appendix: Calibration table

Every catalogued rule, rated on profile T (confidential / critical / important, mid RAA, not internet-reachable). *Class*: W = weakness shown by model facts, G = control not evidenced. *Current on T* is the final rating before the calibration, *New baseline* is the approved baseline under option A, and *New on T* is the resulting final rating.

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
