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

- an **executive summary** (posture, top threats by DREAD, key gaps, strengths) — for leadership;
- a **control gap register** — every expected control marked implemented / partial / not-present / unknown / N-A;
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
inherit downward (`llm ⊂ llm_tools ⊂ {mcp, agentic}`; `generative` is a
side-branch that still inherits `llm`).

| You are modelling… | Facets | What that adds |
|---|---|---|
| Cloud workload (no browser surface) | `cloud` | cloud-infra controls only |
| Single-tenant web app on cloud | `web` + `cloud` | web-tier + cloud-infra |
| **Multi-tenant SaaS** | `web` + `cloud` + `multitenant` | adds the **tenant-isolation** layer |
| API service | `api` (+ `cloud`) | **OWASP API Top 10** surface |
| Mobile app | `mobile` | MASVS + **OWASP Mobile Top 10** |
| …with AI | add `llm` / `llm_tools` / `mcp` / `agentic` / `generative` | inherits the tiers below |

This is the SaaS differentiation made explicit: the `multitenant` facet is what
separates a true SaaS product (tenant data isolation, per-tenant authz, tenant
quotas, cross-tenant leakage testing) from a single-tenant web app.

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
| `intake.py` | declaration template, text detector, ledger merge | ✅ |
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

Extras: `openai` (ChatGPT engine, the default), `llm` (Anthropic engine),
`app` (Streamlit UI), `pdf` (PDF export via reportlab), `dev` (pytest).
Requires Python 3.10+.

---

## Quickstart

### Streamlit UI

```bash
uv run streamlit run app/streamlit_app.py
```

1. Pick the engine (defaults to **OpenAI / gpt-5.2**) and paste your key, or set
   `OPENAI_API_KEY` in the environment.
2. Choose facets, write the architecture description, optionally upload an
   architecture diagram.
3. **Detect controls** — reads the description (keywords) and the diagram (vision,
   LLM engines only) and **pre-fills the declaration** with what it found.
4. Review/adjust the declaration and **Run**. Download the report as **Markdown**
   or **PDF**.

The left-nav **Control Catalog** page is a browsable, filterable reference of
every control with a plain-language description — useful to share with the app
team or PM you're modelling with.

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
and tolerates either `max_tokens` or `max_completion_tokens` automatically, so
newer GPT-5/o-series models work unchanged.

---

## The catalog

Layered YAML under `threatcatalog/catalog/data/` — **61 controls** across 12
layers. A control is tagged with **every layer it applies to**, and the resolver
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
uv run pytest -q          # 126 tests, runs fully offline
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
