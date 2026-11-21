# threatcatalog — catalog-driven, gap-based threat modeling

A threat-modeling utility that moves the exercise from *"ask an LLM to imagine
threats"* to **"compute what an application of this type should have, compare it
to what it does have, and reason over the gap."** The model still writes the
narrative — but it reasons *over a deterministic gap*; it never guesses what is
missing.

> **The one idea.** A curated catalog says what controls *should* be present for
> an application's type. Evidence (an architecture diagram + a short declaration)
> says what *is* present. The difference — computed in code, not by a model —
> drives an executive summary, the threat model, recommendations, mitigations,
> DREAD scoring, and a PCI DSS v4.0.1 compliance view. Everything hangs off that gap.

### What a run actually produces

For a given application it yields, in one pass:

- an **executive summary** (posture, one ranked list of top findings by DREAD, strengths) — for leadership;
- a **findings register** — every expected control that is not present, partial or unknown (controls confirmed in place are listed with their evidence in the appendix); a control the SAD never mentions is marked *Not present (SAD silent)*;
- a **threat model** (STRIDE) with **DREAD** scoring, **recommendations**, and **mitigations**;
- a **PCI DSS v4.0.1** exposure view, produced from the same analysis;
- **framework lineage** on every control — OWASP (Web, **LLM 2025**, **Agentic/ASI 2026**, **MCP beta**, **API 2023**, **Mobile 2024**, MASVS) and **CIS Controls v8**;
- a browsable, filterable **Control Catalog reference page** for the teams being assessed;
- the whole report as **Markdown and PDF**.

It shifts threat modeling from an ad-hoc, expert-dependent exercise to a
repeatable, standards-anchored assessment that tells you where each application
falls short of the controls expected for its type — and why.

---

## Why this exists (and what it deliberately is *not*)

1. **Every app should not get the same baseline.** A static site, a multi-tenant
   SaaS product, and an agentic system are different risk surfaces. **Facets**
   (platform × AI-capability tier) resolve a *tailored* expected control set by
   composition, not one flat checklist.
2. **The model should not decide what's missing.** That is neither auditable nor
   stable. Here the **gap is deterministic**; the model only shapes how it reads.
3. **"Not mentioned" must not silently become "not there."** That manufactures
   false findings. **Unknown ≠ missing** is a hard rule — an unmentioned control
   is a *clarification*, never a finding.

**It is not a code scanner.** It asks whether *enterprise architectural controls*
(SSO, WAF, segmentation, tenant isolation, no-retention model endpoints…) are in
place — answered from a diagram and a declaration, not by reading source. Wrong
altitude, wrong tool, and a deliberate scoping choice.

---

## Facets — how app types are differentiated

Platform facets are **composable and orthogonal**; the resolver unions the
control layers an app's facets select. AI-capability facets are **tiered** and
inherit downward (`llm ⊂ llm_tools ⊂ {mcp, agentic}`; `generative` and
`training` are side-branches that still inherit `llm`).

| You are modelling… | Facets | What that adds |
|---|---|---|
| Cloud workload (no browser surface) | `cloud` | cloud-infra controls only |
| Single-tenant web app on cloud | `web` + `cloud` | web-tier + cloud-infra |
| **Multi-tenant SaaS** | `web` + `cloud` + `multitenant` | adds the **tenant-isolation** layer |
| API service | `api` (+ `cloud`) | **OWASP API Top 10** surface |
| Mobile app | `mobile` | MASVS + **OWASP Mobile Top 10** |
| Event-driven / batch integrations | add `messaging` | broker auth, replay, schema, DLQ, file transfer |
| Runs on containers / Kubernetes | add `container` | image signing, runtime hardening, cluster RBAC |
| …with AI | add `llm` / `llm_tools` / `mcp` / `agentic` / `generative` / `training` | inherits the tiers below |

This is the SaaS differentiation made explicit: the `multitenant` facet is what
separates a true SaaS product (tenant data isolation, per-tenant authz, tenant
quotas, cross-tenant leakage testing) from a single-tenant web app.

**Facet breadth drives run size**, and it is worth knowing the scale before you
pick. Because AI tiers inherit downward, selecting the full AI stack resolves
most of the catalog at once:

| Facets | Layers | Expected controls |
| --- | --- | --- |
| `web` + `cloud` | 3 | 53 |
| `web` + `cloud` + `multitenant` | 4 | 59 |
| `web` + `cloud` + `llm` | 4 | 71 |
| `web` + `cloud` + `mcp,llm,llm_tools,agentic` | 7 | **90 of 123** |

The whole gap goes into every prompt, and the model is asked for one record per
not-present/partial control. A wide AI profile therefore needs a much larger
output-token budget than a plain web app — see
[Model output budget](#model-output-budget-read-this-before-a-wide-ai-profile).

---

## Architecture

```
  facets ─► resolve ─► expected controls ┐
                                         ├─► gap engine ─► exec summary / threats /
  diagram + description + declaration ───┘   (deterministic)  recs / mitigations / DREAD
                                                           └─► PCI DSS v4.0.1 view
              out-of-catalog controls ──► judge ──► compensating + catalog candidates
```

| Module | Role | Deterministic? |
|---|---|---|
| `models.py` | Typed Pydantic models + enums (one source of truth) | — |
| `catalog/loader.py` | YAML → validated `Control`s (the gate) | ✅ |
| `catalog/resolver.py` | facets → expected set, with AI-tier inheritance | ✅ |
| `intake.py` | declaration template, text detector, quote check, ledger merge | ✅ |
| `declaration.py` | reviewed declaration rows: AI suggestion vs reviewer edit, basis, save/load | ✅ |
| `gap.py` | **the gap engine** — expected vs implemented | ✅ |
| `pci.py` | PCI DSS v4.0.1 view (second read off the gap) | ✅ |
| `out_of_catalog.py` | judge unmatched controls, flag candidates | uses engine |
| `generators.py` | `ArtifactEngine` protocol + deterministic engine | ✅ (det. engine) |
| `llm/` | `RawLLM` + `LLMArtifactEngine` (real model path, with vision) | ❌ (validated) |
| `pipeline.py` | orchestration → `ThreatModelReport` | ✅ |
| `report.py` | Markdown rendering + shared executive-summary facts | ✅ |
| `pdf_export.py` | PDF rendering (reportlab; optional `[pdf]` extra) | ✅ |
| `app/streamlit_app.py` | UI: detect-from-diagram, declare, run, download | — |
| `app/pages/1_Control_Catalog.py` | browsable control reference (generated from the catalog) | — |
| `app/pages/2_SAD_Threat_Model.py` | SAD upload → automated threat model | — |
| `app/pages/3_Help.py` | how to use + DREAD guide with a live worked example | — |
| `help_example.py` | computes the Help page's worked DREAD example with the real scorer | ✅ |

The model lives behind one protocol (`ArtifactEngine`) with two implementations
— a real `LLMArtifactEngine` and an offline `DeterministicArtifactEngine`. The
pipeline is identical either way, which is what lets the whole thing run and be
tested **with no API key**.

---

## Install

`uv` is the recommended path:

```bash
cd stride-gpt-catalog
uv sync --all-extras                       # creates .venv, installs everything
uv run streamlit run app/streamlit_app.py  # the UI
uv run pytest -q                           # the tests
```

Or pick extras explicitly: `uv sync --extra openai --extra app --extra pdf --extra dev`.

Plain pip works too:

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[openai,app,pdf,dev]"
```

### API keys in `.env`

Copy `.env.example` to `.env` and put your key there:

```bash
cp .env.example .env          # Windows: copy .env.example .env
# then edit .env:  OPENAI_API_KEY=sk-...
```

The Streamlit app and the CLI load `.env` automatically (from the current folder,
then the project root). `.env` is git-ignored, and a variable already set in your
shell always wins over the file.

Extras: `openai` (ChatGPT engine, the default), `llm` (Anthropic engine),
`bedrock` (AWS Bedrock engine via boto3), `sad` (DOCX/PDF reading for the SAD page),
`app` (Streamlit UI), `pdf` (PDF export via reportlab), `dev` (pytest).

**AWS Bedrock.** Pick *AWS Bedrock* as the engine and enter a model or inference-profile
id from your account (or set `BEDROCK_MODEL_ID`). Credentials and region come from the
normal AWS chain (`AWS_PROFILE`, `AWS_REGION`, SSO, an instance role); the sidebar can
override region and profile.
Requires Python 3.11+ (Streamlit 1.67+ for the UI).

---

## Quickstart

### Streamlit UI

```bash
uv run streamlit run app/streamlit_app.py
```

1. Pick the engine (defaults to **OpenAI / gpt-5.2**) and paste your key, or set
   `OPENAI_API_KEY` in the environment or in `.env`. Set **API base URL** if you go through an
   org gateway or Azure, and raise **Max output tokens** for wide AI facet sets.
2. Choose facets, write the architecture description, optionally upload one or more
   architecture diagrams (up to 10, e.g. context, deployment / network, data flow).
3. Enter your name under **Reviewer** in the sidebar.
4. **Detect controls** — with an LLM engine, one call reads the description *and* every
   diagram together, citing diagram evidence as `Diagram N: <element>`; offline, keyword matching reads the description. It **pre-fills the
   declaration** with a status and an **evidence note** per control: the AI's reasoning
   plus the sentence (or diagram element) it relied on. A quoted sentence that is not
   actually in the description is flagged and its confidence capped. The AI never marks
   a control absent.
5. Review the declaration table. Change a **Status** or edit the **Note** to record your
   own assessment, or tick **Reviewed** to confirm an AI evaluation as-is. Your name and
   a UTC timestamp are recorded; the AI's original suggestion is never overwritten.
   Rows where a reviewer note is expected (an override, or partial / not present with no
   note) are flagged, but nothing blocks the run. Re-running Detect leaves rows you
   touched alone. **Save declaration (JSON)** and load it again later to carry a review
   across sessions or ARB rounds.
6. **Run**. The findings register gains a **Basis** column (AI not reviewed / AI, reviewer
   confirmed / Reviewer override / Reviewer), the executive summary counts statuses that
   rest on unreviewed AI evaluations, and an **evidence appendix** shows one card per
   control (grouped by status, gaps first) with the AI evaluation, cited evidence, AI
   rationale, reviewer note and who reviewed it when. The appendix opens with a note that
   the evaluations are automated and may need further AppSec analysis. SAD runs show the
   same cards without the review fields (nobody reviews an automated run).
   Notes on partial / not-present controls are also passed to the threat and DREAD
   prompts so findings name what is actually missing. Download as **Markdown** or **PDF**.

The left-nav **Control Catalog** page is a browsable, filterable reference of
every control with a plain-language description — useful to share with the app
team or PM you're modelling with.

### SAD threat model page (upload a solution architecture document)

The left-nav **SAD Threat Model** page produces a threat model straight from a
Solution Architecture Document:

1. **Upload** a DOCX, PDF or Markdown SAD (optionally with extra PNG/JPG diagrams).
   Text keeps its headings and tables; diagrams are taken from the document. PDF pages
   with vector drawings are rendered to images, and Visio/EMF figures that a model
   cannot read are listed so you can export them as PNG. The page shows what will be
   sent and asks you to confirm the document may go to the selected provider.
2. **Check** — one call scores the SAD against a fixed 12-item completeness rubric and
   proposes the application profile, each facet with its reason and a quote. The model
   alone decides the profile (no keyword matching, which misreads sentences such as "has no
   mobile app"); a facet it only infers is included and marked *assumed*. **If a required item is missing (purpose, an architecture diagram, or the
   components), the page stops** and offers a feedback checklist for the SAD author
   instead of a report.
3. **Confirm** the profile on one screen: tick or untick facets in the table (the white
   *Include* column is editable; blue columns are the AI's proposal), and set the data
   classification and PCI scope. Your changes are recorded in the report.
4. **Run.** Controls are detected across the text and every diagram, and the SAD rules
   apply: a control the SAD **does not mention is Not present** (the report is deliberately
   harsh: what the SAD omits is taken as accepted by the business); a control only
   **implied** by features or the tech stack is **Partial** with a note that it must be
   confirmed; a cited quote that is not really in the SAD drops the control to Partial.
   A second, cheap call on the same model then checks that each cited quote actually
   backs its control's status. Quotes that don't are **flagged** for the reviewer (in the
   evidence appendix, and as rows needing a note on the review page); statuses are never
   changed by the check.
   The report opens with an *Assessment basis* section (file hash, engine, profile
   reasons, completeness, limitations). Download it as **Markdown** or **PDF**, plus the
   **declaration JSON**, which the main page can load for a human review pass.

The output budget on this page defaults to 64,000 tokens because a large SAD on a
reasoning model spends many tokens thinking. On Bedrock, if a model's own limit is lower,
the call is retried at that limit automatically.

### CLI (offline, deterministic)

```bash
uv run threatcatalog testapp/peopledesk_intake.json --out report.md --pdf report.pdf
```

Add `--provider openai --model gpt-5.2 --llm` for a model-backed narrative. The
gap is computed identically; only the prose changes.

### As a library

```python
from threatcatalog import pipeline
from threatcatalog.models import (AppProfile, PlatformFacet, AICapability,
                                  DataClassification, LedgerEntry, ControlStatus,
                                  Provenance, Confidence, ObservedControl)
from threatcatalog.report import render_markdown
from threatcatalog.pdf_export import render_pdf

profile = AppProfile(
    name="PeopleDesk",
    platforms=[PlatformFacet.WEB, PlatformFacet.CLOUD, PlatformFacet.MULTITENANT],
    ai_capabilities=[AICapability.LLM],
    data_classification=DataClassification.RESTRICTED)

report = pipeline.run(
    profile,
    description="Okta SSO; encrypted at rest; TLS 1.3; WAF; LLM summarizes records.",
    declared=[LedgerEntry(control_id="AI-PI-001", status=ControlStatus.NOT_PRESENT,
                          provenance=Provenance.DECLARED, confidence=Confidence.HIGH)])

open("report.pdf", "wb").write(render_pdf(report))
print(render_markdown(report))
```

Swap the provider behind one seam:

```python
from threatcatalog.llm import OpenAIRawLLM, AnthropicRawLLM, LLMArtifactEngine
engine = LLMArtifactEngine(OpenAIRawLLM(model="gpt-5.2"))   # ChatGPT (default)
# engine = LLMArtifactEngine(AnthropicRawLLM())             # Claude
report = pipeline.run(profile, ..., engine=engine)
```

`OpenAIRawLLM` accepts `api_key=` and `base_url=` (for an org gateway / Azure),
`max_tokens=` (default **32000**), and tolerates either `max_tokens` or
`max_completion_tokens` automatically, so newer GPT-5/o-series models work
unchanged.

---

## Model output budget (read this before a wide AI profile)

On reasoning models — the GPT-5 and o-series families — `max_completion_tokens`
is a budget for **reasoning tokens plus visible output**, not for output alone.
A model can spend the entire allowance thinking and return an empty string, with
`finish_reason="length"` and no content at all. Non-reasoning models like gpt-4o
spend the whole budget on visible output and so tolerate a much smaller number.

That is why the default is **32000** rather than something tighter. A
`mcp + llm + llm_tools + agentic` profile puts 44 controls into every prompt and
asks for a record per gap, across four separate calls (`generate_threats`,
`generate_recommendations`, `generate_mitigations`, `score_dread`) plus one per
observed out-of-catalog control. Each call pays that cost independently.

Set it in the sidebar, or in code:

```python
engine = LLMArtifactEngine(OpenAIRawLLM(model="gpt-5.2", max_tokens=32000))
```

An empty completion is now a typed failure rather than a parse error.
`EmptyCompletionError` reports `finish_reason`, any `refusal`, and the
`reasoning_tokens` actually consumed, which is what tells the two causes apart:

* `finish_reason='length'` with high `reasoning_tokens` — budget exhausted.
  Raise `max_tokens`, or narrow the facet set.
* `finish_reason='content_filter'`, or a non-null `refusal` — a policy block.
  No budget increase will help.

Model output is also parsed defensively. Fenced blocks with any language tag
(`json`, `JSON`, `jsonc`, bare), a prose preamble before the JSON, a trailing
sign-off after it, and a leading BOM are all tolerated; genuinely empty or
prose-only output raises a message naming what came back instead.

### If your gateway clamps the budget

Some org gateways silently cap `max_completion_tokens` below what you request.
If `EmptyCompletionError` still reports `finish_reason='length'` after you raise
it, that is the signal. Batch `_gap_payload` into slices of ~15 controls and
merge the resulting lists — `_listify` in `llm/engine.py` already tolerates the
shape, since it accepts both a bare array and a `{"threats": [...]}` wrapper.

---

## The catalog

Layered YAML under `threatcatalog/catalog/data/` — **123 controls** across 15
layers (33 of them in `base`, which applies to every app). A control is tagged with **every layer it applies to**, and the resolver
unions the layers an app's facets select. Each control carries a verbose
`guidance` field (plain language, for app teams / PMs) in addition to its
one-line `intent` and the `assessment_signal` used to judge it.

```yaml
- id: SAAS-ISO-001
  title: Tenant data isolation
  intent: Every data access is scoped to the caller's tenant; identifiers can't cross tenants.
  guidance: >
    This is the control that makes a SaaS product safe: one customer must never see
    another's data. Enforce a tenant scope on every query (row-level security or a
    mandatory tenant filter) rather than trusting application code to remember it.
  layers: [platform.saas]
  stride: [InformationDisclosure, ElevationOfPrivilege]
  assessment_signal: Is every data access scoped to the caller's tenant by construction?
  threat_frameworks:
    - {framework: cis_v8, ref: "Control 3", version: "8.1"}
    - {framework: owasp_api, ref: "API1:2023", version: "2023"}
  pci: [{requirement: "7.2.1"}]
  detect_keywords: [tenant isolation, row level security, tenant id, multi-tenant]
```

The loader validates on read — a bad layer, STRIDE value, PCI ref, or unknown
key fails loudly with the file and entry number.

### Frameworks & versions (pinned, because these move)

OWASP Top 10 (web), **OWASP LLM Top 10 2025**, **OWASP Agentic/ASI Top 10 2026**,
**OWASP MCP Top 10 (BETA — version-pinned, expected to drift)**, **OWASP API
Security Top 10 2023**, **OWASP Mobile Top 10 2024**, OWASP MASVS, and **CIS
Controls v8** as a cross-cutting dimension on every control. Methodology: STRIDE
+ DREAD. Compliance: **PCI DSS v4.0.1**.

> ⚠️ **Compliance mappings are illustrative seed mappings, to be verified.** The
> PCI requirement IDs and CIS control numbers in the seed catalog are starting
> points, not audited mappings — validate them against the official PCI DSS
> v4.0.1 document and CIS Controls v8 before relying on them for an assessment.
> (The PCI mapping for secrets management was corrected to **8.6.2** — credentials
> not hard-coded — after verification; 8.3.6 is password length.)

---

## Testing

```bash
uv run pytest -q          # all tests, runs fully offline
```

The suite pins the load-bearing rules: `unknown ≠ missing`, PCI double-gating
(scope AND status), AI-tier inheritance, facet composition (incl. the SaaS/API
differentiation), compensating-controls-soften-never-erase, DREAD modulation,
the catalog's data integrity (every control framework-anchored and carrying
guidance), and the LLM engine's normalization layer (messy real-model JSON is
coerced to schema, not crashed on). The end-to-end subject is PeopleDesk in
[`testapp/`](testapp/README.md).

---

## A few honest remarks

* **Unknown is the most valuable status in the system.** Treating silence as a
  finding makes a report look thorough and trains its readers to ignore it. The
  clarifications list is where the real next questions live.
* **Compensating controls soften; they never erase.** An unverified, off-catalog
  control lowers a DREAD score and earns a footnote — it does not delete a threat.
  That asymmetry is how genuine exposure gets talked away in practice, so the
  code refuses to do it.
* **The catalog is the product.** The engine is small and stable; the catalog —
  its coverage, framework lineage, assessment signals, and guidance — is what
  makes the output trustworthy, and it is never "done." The out-of-catalog
  candidate flags are there to feed it.
* **Determinism is the feature, not the model.** Anyone can ask an LLM for a
  threat model. The value here is that the *gap* is reproducible and auditable —
  two runs of the same input give the same findings, and you can explain each one.

See [`FILES.md`](FILES.md) for a map of every file, and
[`REPLACING_THE_FORK.md`](REPLACING_THE_FORK.md) to swap this into your fork.
