# AI risk rework: OWASP GenAI crosswalk re-anchoring (draft)

Status: **draft for review**, 2026-11-17. Nothing here is implemented yet.

This plan replaces the current ATLAS/MAESTRO-named AI risks with categories named after OWASP GenAI
risks. It merges the 51 entries in the [OWASP GenAI Security Crosswalk](https://github.com/GenAI-Security-Project/crosswalk)
(version `2026-Q3`, read from `data/entries/*.json`). Each category keeps ATLAS technique IDs and
MAESTRO layers as references, not as its identity. ATLAS describes attacker techniques, while a
Threagile finding describes a design weakness on an asset, so ATLAS works better as a reference.

The 51 entries come from four OWASP lists:

| Prefix | List | Count |
|---|---|---|
| `LLM` | LLM Top 10 2026 (renumbered Aug 2026, see note below) | 10 |
| `ASI` | Top 10 for Agentic Applications 2026 | 10 |
| `DSGAI` | GenAI Data Security 2026 | 21 |
| `AST` | Agentic Skills Top 10 2026 (sibling project; **no framework mappings yet**, MAESTRO rows are DRAFT) | 10 |

> **2026 renumbering:** LLM03→04, 04→05, 05→10, 06→03, 07→08, 08→09, 09→07, 10→06. Old
> "System Prompt Leakage" is now **LLM08 Hidden Context Exposure** (widened to all non-user context:
> developer instructions, retrieved policy text, tool schemas). Old "Insecure Output Handling" is now
> **LLM10 Improper Output Handling** (widened to cover generated code). Always cite IDs with the list
> year.

## Ground rules

1. **Merge across lists. Don't create one rule per entry.** The four lists overlap heavily. For
   example, supply chain appears as LLM04, ASI04, AST02 and DSGAI04. Each category below lists every
   OWASP ID it covers in its `references`. 51 entries become 28 OWASP-anchored categories plus 6
   kept categories with no OWASP equivalent.
2. **Cite, don't copy.** The crosswalk is CC BY-SA 4.0. Write our own description and mitigation
   text, and cite IDs plus a link. Copying the text would bring share-alike terms into the
   MIT-licensed fork.
3. **Don't take the crosswalk's mappings at face value.** Most mapping rows are `confidence:
   unreviewed`, and the `crossrefs` field is too densely connected to drive deduplication (DSGAI21
   cross-references 27 other entries). The ATLAS, MAESTRO, CWE and FedRAMP IDs in the tables below
   come from the crosswalk. Check them before relying on them in an SSP.
4. **Fire only on model facts, wherever a model fact exists.** This addresses review point 1 for
   the AI set. Every proposed condition below uses a field the script DSL can reach today:
   - an asset's own `communication_links` (outgoing), with `readonly`, `authentication`,
     `authorization`, `protocol` and `target_id`;
   - `$model.incoming_technical_communication_links_mapped_by_target_id`;
   - `$model.direct_containing_trust_boundary_mapped_by_technical_asset_id`;
   - `multi_tenant`, `encryption`, `internet`, `machine`;
   - data-asset confidentiality via `$model.data_assets.{id}`.
   
   **Proven for links (2026-11-17):** `hardcoded-credentials-secrets-sprawl` now loops over an
   asset's `communication_links`, compares `authentication`, and follows
   `$model.technical_assets.{link.target_id}` to the target's technologies. Its Go tests cover
   all of it. Building it surfaced an engine bug, now fixed: `loop` errored on a missing list
   (an asset with no links) instead of looping zero times. Trust-boundary and incoming-link
   lookups are still unexercised.
   
   Watch the omitempty pitfall: zero-value enums like `authentication: none`,
   `authorization: none` and `readonly: false` disappear after re-serialisation. Use the "not
   equal to any other value" pattern that `on-device-model-extraction-gap` already uses.

## Where each category lives

**Placement rule: the fork reads no tags.**

- A rule that fires only on fields Threagile itself models lives in the fork as a native script.
  Those fields are technologies and their attributes, `machine`, `type`, `multi_tenant`,
  `encryption`, `internet`, communication links, trust boundaries and data-asset confidentiality.
- **Any rule that reads a tag lives in `central-security-repo`.** That's
  `09-custom-risks-lib.yml` for the text and `inject_risks.py` for the trigger, with the tag
  documented in `03-tags-lib.yml`. It goes in the central library, never copied into each app
  repo.

This keeps a tag's documentation, its rule text and the code that reads it in one repo. So nobody
has to find out about a tag that only the image knows about, and no cross-repo sync is needed.

| Code | Placement | Use it when |
|---|---|---|
| **N** | Native script rule in the fork | The trigger uses only native model fields |
| **C** | Custom category in `09-custom-risks-lib.yml` + `inject_risks.py` | The trigger reads any tag, including a rule that combines a tag with native fields. `inject_risks.py` reads the model YAML, so it can check `technology`, `machine` and the rest alongside the tag |
| **Out** | Not a per-asset risk | Belongs in ATO/SSP governance documentation, not the threat model. Matches the SABER screening already applied in `09-custom-risks-lib.yml` |

What this costs:
- More findings are scored by the Python engine, so more depends on the Python copy of the
  scoring formulas staying in step with the Go copy (see `risk-methodology.md`).
- A few lookups the script DSL gives you for free, like trust boundaries, are reimplemented in
  Python.
- The Python rules need tests too.

Benefit: custom rules already get the internet-exposure likelihood bump.

Already applied: `hardcoded-credentials-secrets-sprawl` was the one existing native rule that
read a tag (`data:credential` on the technical asset). On 2026-11-17 it was rewritten to fire on
native facts instead, so it stays in the fork:
- it fires on a non-vault asset with an outgoing link whose `authentication` is `credentials` or
  `client-certificate`, a static secret the asset must hold;
- likelihood steps down one level when the asset also links to a vault.

`token` deliberately doesn't fire. The convention "model a static API key as `credentials`" is
recorded in `00-threagile-field-reference.yml`.

## Proposed categories

New `id`s use an `ai-` prefix plus a descriptive slug. No AI risk ID appears in any
`risk_tracking` file today, so renaming breaks nothing.

### Input and instruction integrity

| # | Category | OWASP IDs | Place | Matches | Fires when (proposed) | Replaces |
|---|---|---|---|---|---|---|
| 1 | Direct Prompt Injection | LLM01 | C | assets tagged `ai:user-prompt-input` | tag present. Lower likelihood if an `ai-guardrails` asset is on the inbound path | `atlas-direct-prompt-injection-jailbreak` (C) · `ai-guardrails-bypass` (N), which becomes this mitigation signal |
| 2 | Indirect Prompt Injection & Goal Hijack | LLM01 · ASI01 · AST05 · DSGAI09 (cross-modal payloads) | C | `ai:indirect-prompt-input`, plus the auto-trigger already in `inject_risks.py` for RAG, agent and multi-agent technologies | as today, with the same guardrail mitigation signal | `atlas-indirect-prompt-injection` (C) |
| 3 | Hidden Context Exposure | LLM08 | N | `ai-llm-endpoint`, `ai-agent-orchestrator`, `ai-rag-pipeline` | asset has an incoming link from outside its own trust boundary | `system-prompt-leakage` |
| 4 | Improper Output Handling | LLM10 · DSGAI05 | N | `ai-llm-endpoint`, `ai-model-serving`, `ai-agent-orchestrator`, `ai-rag-pipeline` | asset has an outgoing link, or its output reaches a browser, datastore or interpreter. Impact from the target's CIA | `llm-improper-output-handling` |
| 5 | Unsafe Natural-Language Data Gateway (NL-to-SQL/query) | DSGAI12 | N | any `ai` asset | outgoing link whose target is `type: datastore` and is not `readonly` | **new** |

Rules 1 and 2 are custom (C) because they read tags. The auto-trigger for RAG, agent and
multi-agent technologies in #2 stays in `inject_risks.py` beside the tag check, so the category
has a single source.

### Agency, tools and agent identity

| # | Category | OWASP IDs | Place | Matches | Fires when (proposed) | Replaces |
|---|---|---|---|---|---|---|
| 6 | Excessive Agency & Tool Misuse | LLM03 · ASI02 · AST03 · DSGAI06 | N | `ai-agent-orchestrator`, `ai-tool-server` | at least one outgoing link is not `readonly`. Impact = highest CIA among link targets | `atlas-agent-orchestration-hijack` (N) · `atlas-agent-tool-plugin-compromise` (C). The `ai:plugin-tool-use` tag can retire, because tool reach is now modelled as links |
| 7 | Unexpected Code Execution & Weak Sandbox | ASI05 · AST06 | C | orchestrator / tool server tagged **`ai:code-execution`** (new) | tag present. Higher likelihood when `machine` isn't `container`/`serverless` (no runtime isolation) | **new** |
| 8 | Agent Identity & Credential Abuse | ASI03 · DSGAI02 | N | `ai-agent-orchestrator`, `ai-gateway`, `ai-multi-agent-gateway` | an outgoing link has `authorization: technical-user` (no end-user identity propagation) or static `authentication: credentials` | `ai-gateway-credential-sprawl` · identity half of `maestro-l7-agent-ecosystem-identity` |
| 9 | Insecure Inter-Agent Communication | ASI07 | N (link-level) | links where both ends are agent/multi-agent assets | link crosses a trust boundary, or `authentication` is none, or the protocol is unencrypted | communication half of `maestro-l7-agent-ecosystem-identity` |
| 10 | Cascading Agent Failures | ASI08 | N | orchestrator / multi-agent gateway | has an outgoing link to another `ai` asset (an agent chain) | **new** |
| 11 | Rogue Agent & Missing Kill Switch | ASI10 | N | orchestrator, `ai-model-serving`, `ai-llm-endpoint` | always. Higher likelihood when there's no outgoing link to an `ai-observability-stack` | kill-switch half of `missing-model-rollback-killswitch` |
| 12 | AI Change Control Gap (prompts, models, skills) | AST07 · ASI10 (partial) · LLM05 (fine-tune subversion) | N | `ai-llm-endpoint`, `ai-model-serving`, orchestrator | no model fact available, so it fires unconditionally. Adding a suppression tag would move it to C under the placement rule | `ungoverned-system-prompt-change` · `missing-canary-prompt-testing` · rollback half of `missing-model-rollback-killswitch` |
| 13 | Agent Memory & Context Poisoning | ASI06 | C | assets tagged `ai:agent-memory` (existing tag) | tag present. Higher likelihood if memory is written from outside the trust boundary (this needs a trust-boundary lookup reimplemented in Python) | `atlas-agent-memory-poisoning` (C, re-anchored) |
| 14 | Cross-Context Bleed & Over-Broad Context | DSGAI11 · DSGAI15 | N | `ai-llm-endpoint`, `ai-rag-pipeline`, orchestrator | `multi_tenant: true`, or it processes data assets at more than one confidentiality level | **new** |

### Data confidentiality and model IP

| # | Category | OWASP IDs | Place | Matches | Fires when (proposed) | Replaces |
|---|---|---|---|---|---|---|
| 15 | Sensitive Information Disclosure via Model Output | LLM02 · DSGAI01 · DSGAI09 | N | `ai-llm-endpoint`, `ai-rag-pipeline`, orchestrator | processes a data asset at `confidential` or above, and has an incoming link from outside its trust boundary | **new** (generic leak half of `atlas-inference-api-abuse`) |
| 16 | Inference & Training-Data Reconstruction | DSGAI18 | N | `ai-llm-endpoint`, `ai-model-serving` | incoming link from outside the trust boundary, or `internet: true` | `atlas-inference-api-abuse` |
| 17 | Model Exfiltration & IP Replication | DSGAI20 | N | `ai-model-registry`, `ai-training-pipeline`; `ai-model-serving`/`ai-llm-endpoint` on physical hardware | registry and pipeline: always. Serving: only when `machine` is physical | `training-script-ip-exfiltration` · `on-device-model-extraction-gap` |
| 20 | Vector Store Exposure & Embedding Inversion | LLM09 · DSGAI13 | N | `ai-vector-store` | `encryption: none`, or `multi_tenant`, or stores data at `confidential` or above | `atlas-vector-store-inversion` |
| 21 | Synthetic Data & Anonymization Pitfalls | DSGAI10 | N | `ai-synthetic-data-pipeline` | processes a data asset at `confidential` or above | `atlas-synthetic-data-memorization` |
| 22 | AI Telemetry & Prompt-Log Leakage | DSGAI14 | N | `ai-observability-stack`; any `ai` asset linking to a `monitoring` technology | the link carries a data asset at `confidential` or above | `maestro-l5-observability-compromise`. Also overlaps generic `cui-telemetry-spillage`: exclude `ai` assets there |

### Integrity: poisoning and supply chain

| # | Category | OWASP IDs | Place | Matches | Fires when (proposed) | Replaces |
|---|---|---|---|---|---|---|
| 18 | Training & Fine-Tuning Data/Model Poisoning | LLM05 · DSGAI04 · DSGAI05 · DSGAI21 | N | `ai-training-pipeline`, `ai-dataset-store`, `ai-feature-store`, `ai-eval-pipeline` | an incoming writable link (not `readonly`) from outside the trust boundary. Otherwise lower likelihood | `atlas-training-data-poisoning` · `atlas-dataset-store-attack` (confidentiality half is already covered by built-in datastore rules) · `hyperparameter-tampering-no-baseline-diff` · `maestro-l5-eval-pipeline-poisoning` · `ai-feature-store-lineage-gap` |
| 19 | RAG Corpus Poisoning | LLM09 · ASI06 (partial) · DSGAI04 | N | `ai-rag-ingest-pipeline`, `ai-rag-pipeline` | an incoming link from outside the trust boundary feeds the ingest path | `atlas-dataset-ingest-integrity` · `atlas-rag-poisoning-exfil` |
| 23 | AI Supply Chain (models, frameworks, datasets) | LLM04 · ASI04 · AST02 | N | `ai-model-registry`, `ai-model-serving`, orchestrator (framework dependencies) | always for the registry. Higher likelihood when the registry has an incoming link from outside the trust boundary (a public hub pull) | `atlas-model-supply-chain` · `atlas-model-registry-supply-chain` · `untrusted-model-registry-source` · `maestro-l3-agent-framework-supply-chain` (C). The `ai:agent-framework` tag can retire |
| 24 | Unvetted Agent Skills & Instructions | AST01 · AST04 · AST05 · AST08 · AST10 | C | assets tagged **`ai:skills-enabled`** (new) | tag present, unless a new suppression tag `ai:skills-vetted` is set | **new**. Could move native only if an `ai-skill-registry` technology replaces the tag |

### Availability

| # | Category | OWASP IDs | Place | Matches | Fires when (proposed) | Replaces |
|---|---|---|---|---|---|---|
| 25 | Unbounded Consumption | LLM06 · DSGAI17 | N | `ai-llm-endpoint`, `ai-gateway` | incoming link from outside the trust boundary. Lower likelihood when the endpoint is only reached through an `ai-gateway` | `atlas-unbounded-ai-consumption` · `atlas-chaff-data-spamming` |

### Human factors and workforce

| # | Category | OWASP IDs | Place | Matches | Fires when | Replaces |
|---|---|---|---|---|---|---|
| 26 | Overreliance & Human-Agent Trust Exploitation | LLM07 · ASI09 · DSGAI21 (partial) | C | `ai:decision-support-output` (existing) | as today, suppressed by `ai:output-confidence-disclosed` | `ai-overreliance-misinformation` (C) |
| 27 | Labeler & Human-in-the-Loop Overexposure | DSGAI19 | C | **`ai:human-labeling`** (new) | tag present. For IL5, the question is the labeler workforce's clearance and need-to-know | **new** |
| 28 | Endpoint & Browser AI Overreach | DSGAI16 | C | **`ai:endpoint-assistant`** (new) | tag present | **new**. Kept (decided 2026-11-17) so it's ready when a model includes user endpoints or desktop AI assistants; it only fires where the tag is applied |

### Kept categories with no OWASP GenAI equivalent

| # | Category | Closest refs | Place | Why keep it |
|---|---|---|---|---|
| 29 | AI Output to OT/Safety Actuation Without Human Gate | ASI09 · LLM03 (partial) | C (unchanged) | IL5/OT-specific |
| 30 | Air-Gapped Model Package Integrity | LLM04 (partial) | C (unchanged) | IL5-specific, already has a suppression tag |
| 31 | Ungoverned Third-Party Model API | DSGAI03 · LLM02 (partial) | C (unchanged) | Vendor-policy and data-classification content |
| 32 | Security-AI Compromise | ASI10 · LLM01 (partial) | N (`maestro-l6-security-ai-compromise`, renamed) | Fires on your `ai-security-agent` component type |
| 33 | Content Provenance Tampering | DSGAI21 · LLM07 (partial) | N (`ai-content-provenance-tampering`, unchanged) | Fires on your component type |
| 34 | Adversarial Evasion (classic ML) | ATLAS AML.T0015 only | N (`atlas-adversarial-evasion-attack`, renamed) | GenAI lists don't cover non-LLM models. **Narrow to `ai-model-serving` only**: today it also matches `ai-llm-endpoint` |

### Out of scope (not per-asset)

| OWASP ID | Why |
|---|---|
| DSGAI03 Shadow AI & Unsanctioned Data Flows | Organisation-level. The modelled slice is covered by #31 |
| DSGAI07 Data Governance & Lifecycle | Organisation-level. Generic `missing-data-retention-schedule` already covers the per-datastore slice |
| DSGAI08 Non-Compliance & Regulatory Violations | Compliance, not a design weakness |
| AST09 No Governance | Organisation-level |

## Coverage check

All 51 crosswalk entries are covered:

| List | Covered by |
|---|---|
| LLM | 01→#1/#2 · 02→#15 · 03→#6 · 04→#23 · 05→#18 · 06→#25 · 07→#26 · 08→#3 · 09→#19/#20 · 10→#4 |
| ASI | 01→#2 · 02→#6 · 03→#8 · 04→#23 · 05→#7 · 06→#13 (+#19) · 07→#9 · 08→#10 · 09→#26 · 10→#11 |
| DSGAI | 01→#15 · 02→#8 · 03→#31/Out · 04→#18 · 05→#18 · 06→#6 · 07→Out · 08→Out · 09→#15 (+#2) · 10→#21 · 11→#14 · 12→#5 · 13→#20 · 14→#22 · 15→#14 · 16→#28 · 17→#25 · 18→#16 · 19→#27 · 20→#17 · 21→#18 (+#26) |
| AST | 01/04/05/08/10→#24 · 02→#23 · 03→#6 · 06→#7 · 07→#12 · 09→Out |

## Net change

| | Today | Proposed |
|---|---|---|
| Native AI script rules (read no tags) | 30 | 23: #3–6, #8–12, #14–23, #25, #32–34. Of those, 4 are new (#5, #10, #14, #15), 3 are kept with no OWASP equivalent (#32–34), and 2 custom categories move in (#6, #23) because their tags are replaced by native facts. `ai-guardrails-bypass` becomes a mitigation signal |
| Custom AI categories (Python) | 9 | 11: #1, #2, #7, #13, #24, #26–31. Of those, 4 are re-anchored (#1, #2, #13, #26), 3 kept unchanged (#29–31), 4 new (#7, #24, #27, #28) |
| Firing unconditionally | 30 of 30 native | 7 of 23 native (#11, #12, the registry/pipeline branches of #17 and #23, and #32–34 as kept). The other 16 require a link, data or boundary fact. Every custom rule requires its tag |
| OWASP GenAI entries covered | partial, mostly loose matches | 47 of 51 (4 out of scope by design) |
| Tags | `ai:plugin-tool-use`, `ai:agent-framework` | retire both (#6 and #23 replace them with native facts). Add `ai:code-execution`, `ai:skills-enabled`, `ai:skills-vetted`, `ai:human-labeling` and `ai:endpoint-assistant`, all documented in `03-tags-lib.yml` |

## New technology: `ai-tool-server` (added 2026-11-17)

**`ai-tool-server`** is an MCP server or function/tool host that exposes callable actions to
agents and executes them against downstream systems. It was added to the fork's
`pkg/types/technologies.yaml`, with a matching `IsAIToolServer` constant in `technology-list.go`.

- **Aliases:** `mcp-server`, `model-context-protocol-server`, `tool-server`,
  `function-calling-server`, `agent-tool-host`. These are documentation only: a model must use the
  canonical key `ai-tool-server`.
- **Attributes:** `ai-tool-server`, `ai`, `less_protected_type`, `backend_related`,
  `request_serving_api`, `application_logic`. These are the same as `ai-gateway`.

**Model tools as links.** For #6, #7 and #10, the orchestrator links to one or more tool servers,
and each tool server links to the systems its tools act on. A tool server's reach is then its own
outgoing links. #6 matches both the orchestrator (reach through tool servers) and the tool server
itself, and #7's `ai:code-execution` tag goes on the tool server that actually runs the code.

**What it triggers today, before any AI rule uses it.** Checked on a two-asset synthetic model
with both assets as containers. The tool server picked up 15 existing findings through its
attributes:
- BOLA/BFLA/BOPLA, from `request_serving_api`;
- baseline and insufficient audit logging, CUI telemetry spillage, mishandling of exceptional
  conditions and OS command injection, from `application_logic`;
- 7 container and dependency rules, from `machine: container`.

None of these are AI-specific. Those arrive with #6, #7 and #10.

## Each rule's `references` block

Put these in the `mitigation` references sentence, or a dedicated field if one is added:

- OWASP IDs with list and year (for example `OWASP LLM Top 10 2026 LLM08`).
- The crosswalk's ATLAS technique IDs and MAESTRO layers for those IDs.
- CWE.
- FedRAMP/NIST 800-53 controls, which are most useful for the SSP.
- A link to the crosswalk entry.

Pin the version as `crosswalk 2026-Q3`.

## Decisions (2026-11-17)

No decisions are open. Settled in this round:

1. **Python tests come before the new custom rules.** Write a pytest fixture-model harness for
   `inject_risks.py` before adding the 4 new custom AI rules. Each tag-triggered rule gets four
   checks: it fires with the tag, it doesn't fire without it, its suppression tag works, and its
   exclusions hold. The fork side's first per-rule test,
   `hardcoded_credentials_secrets_sprawl_test.go`, is the pattern for the Go harness.
2. **Baselines:**
   - A category that replaces one rule keeps that rule's baseline.
   - A category that merges several rules starts at their *middle* value, never the highest. For
     example, #18 starts at Possible.
   - A new category's baseline is justified from CWE/OWASP evidence in the threat catalogue's
     justification appendix.
   - The crosswalk's list-level AIVSS severity is not used.
3. **Build order:**
   1. Commit the 2026-11-17 work.
   2. Write the Go and Python test harnesses.
   3. Build #6 Excessive Agency as the first link-reading AI rule.
   4. Build the remaining native rules in groups: agentic, data, integrity.
   5. Build the custom rules.
   
   Delete each old rule in the same commit as its replacement, and update the catalogue, the
   report's domain map and `03-tags-lib.yml` in those same commits.

   Status: steps 1 and 2 are done. The test harnesses are:
   - **Go:** `pkg/risks/scripts/all_rules_test.go` checks that every script rule loads with
     complete metadata, runs without a script error, and fires on a model containing every
     technology. It runs on every image build through the Dockerfile's `go test`.
   - **Python:** `core-policies/tests/test_inject_risks.py` checks that the engine and library
     agree, every tag the engine reads is documented, every trigger tag fires, and every
     suppression tag suppresses. It also has a per-rule behaviour table. CI runs it in
     `.github/workflows/custom-risk-engine-tests.yml`.
   
   Step 3 is done too. #6 is the fork's `ai-excessive-agency-tool-misuse` rule:
   - It fires on an `ai-agent-orchestrator` or `ai-tool-server` with at least one outgoing link
     that isn't `readonly`.
   - Likelihood starts at the shared baseline of the two rules it replaced, plus the RAA delta.
   - Impact is Very High if the agent or any target of a writable link is rated
     restricted/important or higher, otherwise High.
   - It replaced `atlas-agent-orchestration-hijack` (native) and `atlas-agent-tool-plugin-compromise`
     (custom), and `ai:plugin-tool-use` is retired.
   
   **Narrower than what it replaced:** the old custom rule also fired on read-only tool access.
   Read-only tools that reach sensitive data are left to #15 (Sensitive Information
   Disclosure) and #2 (Indirect Prompt Injection).
   
   Next is step 4, the remaining native rules in groups (agentic first).
4. **Internet exposure in native scripts:** no `+1` Likelihood delta. Exposure decides whether a
   rule fires instead, and adding the delta would count it twice. This is documented in
   `risk-methodology.md`. It closes point 5 of the 2026-11-17 review.

Also decided: #28 is kept (see its row); `ai-tool-server` is added (see above).
