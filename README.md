# threatcatalog — catalog-driven, gap-based threat modeling

An enhancement to the STRIDE-GPT fork that moves threat modeling from "ask an
LLM to imagine threats" to **"compute what an app of this type should have,
compare it to what it does have, and reason over the gap."** The LLM still
writes the narrative — but it reasons *over a deterministic gap*, it never
guesses what is missing.

> **The one idea.** A catalog says what *should* be present for an application's
> type. Evidence says what *is* present. The difference — computed in code, not
> by a model — drives the threat model, recommendations, mitigations, DREAD, and
> a PCI DSS v4.0.1 compliance view. Everything hangs off that gap.

---

## Why this exists (and what it deliberately is *not*)

The original fork injects a single flat "org baseline" string into an LLM
prompt. That works, but it has three problems this rebuild fixes:

1. **Every app gets the same baseline.** A static website and an agentic system
   are judged against the same controls. Here, **facets** (platform × AI-capability
   tier) resolve a *tailored* expected control set by composition.
2. **The model decides what's missing.** That is neither auditable nor stable.
   Here, the **gap is deterministic**; the model only shapes how it's expressed.
3. **"Not mentioned" silently becomes "not there."** That manufactures false
   findings. Here, **unknown ≠ missing** is a hard rule — an unmentioned control
   is a *clarification*, never a finding.

**It is not a code scanner.** It asks whether *enterprise architectural
controls* (SSO, WAF, segmentation, no-retention model endpoints…) are in place.
That question is answered from an architecture diagram and a declaration, not by
reading source. Wrong altitude, wrong tool — and a deliberate scoping choice
("bias, don't blind").

---

## Architecture

```
  facets ─► resolve ─► expected controls ┐
                                         ├─► gap engine ─► threats / recs /
  diagram + description + declaration ───┘   (deterministic) mitigations / DREAD
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
| `llm/` | `RawLLM` + `LLMArtifactEngine` (real model path) | ❌ (validated) |
| `pipeline.py` | orchestration → `ThreatModelReport` | ✅ |
| `report.py` | Markdown rendering | ✅ |

The LLM lives behind one protocol (`ArtifactEngine`) with two implementations —
a real `LLMArtifactEngine` and an offline `DeterministicArtifactEngine`. The
pipeline is identical either way, which is what lets the whole thing run and be
tested **with no API key**.

---

## Install

```bash
cd stride-gpt-catalog
python -m venv .venv && source .venv/bin/activate
pip install -e .            # core (pydantic + pyyaml) — enough for offline runs + tests
pip install -e ".[llm]"     # add the Anthropic engine
pip install -e ".[openai]"  # add the OpenAI / ChatGPT engine
pip install -e ".[app]"     # add the Streamlit UI
pip install -e ".[dev]"     # add pytest
```

Requires Python 3.10+.

---

## Quickstart

### 1 · CLI (offline, deterministic)

```bash
python -m threatcatalog.cli testapp/peopledesk_intake.json --out report.md
```

Add `--llm` to use a model-backed engine (needs `ANTHROPIC_API_KEY` and the
`anthropic` extra). The gap is computed identically; only the prose changes.

### 2 · Streamlit UI

```bash
streamlit run app/streamlit_app.py
```

Pick facets, paste the architecture description, declare control statuses
(leave anything you're unsure of as *unknown*), and run.

### 3 · As a library

```python
from threatcatalog import pipeline
from threatcatalog.models import (AppProfile, PlatformFacet, AICapability,
                                  DataClassification, LedgerEntry, ControlStatus,
                                  Provenance, Confidence, ObservedControl)
from threatcatalog.report import render_markdown

profile = AppProfile(
    name="PeopleDesk", platforms=[PlatformFacet.WEB, PlatformFacet.CLOUD],
    ai_capabilities=[AICapability.LLM],
    data_classification=DataClassification.RESTRICTED)

report = pipeline.run(
    profile,
    description="Okta SSO; encrypted at rest; TLS 1.3; WAF; LLM summarizes records.",
    declared=[LedgerEntry(control_id="AI-PI-001", status=ControlStatus.NOT_PRESENT,
                          provenance=Provenance.DECLARED, confidence=Confidence.HIGH)],
    observed_unmatched=[ObservedControl(name="PII tokenization",
                                        description="masks identifiers on screen")])

print(render_markdown(report))
```

For the model-backed path:

```python
from threatcatalog.llm import AnthropicRawLLM, LLMArtifactEngine
report = pipeline.run(profile, ..., engine=LLMArtifactEngine(AnthropicRawLLM()))
```

### The model provider is swappable (Anthropic **or** OpenAI / ChatGPT)

The model lives behind one tiny seam — `RawLLM.complete_json(system, user)`. Two
providers ship in the box; pick whichever your org is standardized on:

```python
from threatcatalog.llm import AnthropicRawLLM, OpenAIRawLLM, LLMArtifactEngine

engine = LLMArtifactEngine(OpenAIRawLLM(model="gpt-4o"))   # ChatGPT
# engine = LLMArtifactEngine(AnthropicRawLLM())            # Claude
```

From the CLI: `--provider openai` (reads `OPENAI_API_KEY`) or `--provider anthropic`
(reads `ANTHROPIC_API_KEY`). `OpenAIRawLLM` also accepts `base_url=` for Azure
OpenAI. Adding a third provider is ~15 lines: implement `complete_json` and pass
it in — nothing else in the pipeline changes, and the response is still validated
against our schemas.

---

## The catalog

Layered YAML under `threatcatalog/catalog/data/`. One file per layer; a control
is tagged with **every layer it applies to**, and the resolver unions the layers
an app's facets select. To add a control, drop an entry in the right file:

```yaml
- id: AI-PI-001
  title: Prompt-injection defense
  intent: Untrusted text is treated as data, not instructions.
  layers: [ai.llm]
  stride: [Tampering]
  assessment_signal: Is untrusted text delimited/labelled as data before reaching the model?
  threat_frameworks: [{framework: owasp_llm, ref: "LLM01:2025", version: "2025"}]
  detect_keywords: [prompt injection, input labeling, delimiter]
```

The loader validates on read — a bad layer, STRIDE value, PCI ref, or unknown
key fails loudly with the file and entry number.

### AI-capability tiers inherit downward

`llm ⊂ llm_tools ⊂ {mcp, agentic}`, and `generative` is a side-branch that still
inherits `llm`. Declaring an app *agentic* automatically pulls in the LLM and
tool-use controls — because an agentic app carries all of those risks too.

### Frameworks & versions (pinned, because these move)

OWASP Top 10 2025 (web), **OWASP LLM Top 10 2025**, **OWASP Agentic/ASI Top 10
2026**, **OWASP MCP Top 10 (BETA — version-pinned and expected to drift)**,
OWASP MASVS. Methodology: STRIDE + DREAD. Compliance: **PCI DSS v4.0.1**.

> ⚠️ The PCI requirement IDs in the seed catalog are **illustrative mappings**.
> Validate them against the official PCI DSS v4.0.1 document before relying on
> the compliance view for a real assessment. The engine is honest about scope;
> the *mappings* are yours to confirm.

---

## Testing

```bash
pytest -q          # 102 tests, runs fully offline
```

The suite pins the load-bearing rules: `unknown ≠ missing`, PCI double-gating
(scope AND status), AI-tier inheritance, compensating-controls-soften-never-erase,
DREAD modulation, and the LLM engine's schema validation (out-of-enum / out-of-range
model output is *rejected*, not absorbed). The end-to-end test is the PeopleDesk
subject in [`testapp/`](testapp/README.md).

---

## A few honest remarks (wisdom, as requested)

* **Unknown is the most valuable status in the system.** The temptation is to
  treat silence as a finding so the report looks thorough. Resist it — a report
  full of manufactured findings trains its readers to ignore it. The
  clarifications list is where the real next questions live.
* **Compensating controls soften; they never erase.** An unverified, off-catalog
  control reduces a DREAD score and earns a footnote — it does not delete a
  threat. That asymmetry is deliberate. It is how genuine exposure gets talked
  away in practice, so the code refuses to do it.
* **The catalog is the product.** The engine is maybe 800 lines and will barely
  change. The catalog — its coverage, its framework lineage, its assessment
  signals — is what makes the output trustworthy, and it is never "done." Budget
  accordingly; the out-of-catalog candidate flags are there to feed it.
* **Determinism is the feature, not the LLM.** Anyone can ask a model for a
  threat model. The value here is that the *gap* is reproducible and auditable,
  so two runs of the same input give the same findings and you can explain every
  one of them.

See [`REPLACING_THE_FORK.md`](REPLACING_THE_FORK.md) to swap this into your fork.
