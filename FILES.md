# File map

Everything in this project, and what it's for. If a file isn't listed here, it
isn't part of the project — delete it.

## Run it
| Path | What it is |
|---|---|
| `README.md` | Start here — overview, install, how to run (CLI / UI / library), provider swap, wisdom notes. |
| `REPLACING_THE_FORK.md` | How to swap this in for your old fork code (what maps to what, what to retire). |
| `pyproject.toml` | Package metadata, dependencies, optional extras (`llm`, `openai`, `app`, `dev`), pytest config. |
| `requirements.txt` | Core runtime deps (pydantic, PyYAML). Optional extras are commented. |
| `.gitignore` | Keeps caches/venvs/build junk out of the repo (so the root stays clean). |
| `app/streamlit_app.py` | The UI. Engine + model picker, API-key field, diagram upload, detect-and-prefill, declaration, report. |
| `app/pages/1_Control_Catalog.py` | Reference page (sidebar nav) — browsable/filterable description of every control, generated from the catalog; exportable to Markdown. |

## The engine (`threatcatalog/`)
| Path | What it is |
|---|---|
| `models.py` | All Pydantic models + enums — the single typed source of truth. |
| `catalog/loader.py` | Loads + validates the YAML catalog (the gate; fails loud on bad data). |
| `catalog/resolver.py` | Facets → expected control set, with AI-tier inheritance. |
| `catalog/data/*.yaml` | **The catalog itself** — 12 layered files, 61 controls (incl. `platform_saas.yaml`, `platform_api.yaml`). Each control carries verbose `guidance`. This is what you grow over time. |
| `intake.py` | Declaration template, conservative text detector, ledger merge. |
| `gap.py` | The deterministic gap engine (expected vs implemented). |
| `pci.py` | PCI DSS v4.0.1 compliance view (second read off the same gap). |
| `out_of_catalog.py` | Judges controls the app has but the catalog lacks; flags candidates. |
| `generators.py` | `ArtifactEngine` protocol + the offline `DeterministicArtifactEngine`. |
| `llm/provider.py` | Model providers: `OpenAIRawLLM` (default gpt-5.2), `AnthropicRawLLM`, `StubRawLLM`. |
| `llm/prompts.py` | Prompt builders (serialize the gap; vision prompt; injection hygiene baked in). |
| `llm/engine.py` | `LLMArtifactEngine` — model path, with the normalization layer that tolerates real-model JSON drift. |
| `pipeline.py` | Orchestration: profile + evidence → `ThreatModelReport`. |
| `report.py` | Renders a report to Markdown; shared executive-summary facts. |
| `pdf_export.py` | Renders the report to a PDF (reportlab; optional `[pdf]` extra). |
| `cli.py` | `python -m threatcatalog.cli intake.json --out report.md` (`--provider`, `--model`, `--llm`). |

## Test subject (`testapp/`)
| Path | What it is |
|---|---|
| `testapp/README.md` | PeopleDesk description + what the tool should produce for it. |
| `testapp/peopledesk_architecture.png` / `.svg` | The test app's architecture diagram. |
| `testapp/peopledesk_intake.json` | Ready-to-run intake for the CLI. |
| `examples/peopledesk_report.md` | A sample generated report (offline engine). |

## Tests (`tests/`)
One file per engine area; 112 tests, all offline. Run with `pytest -q`.
