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
| `app/streamlit_app.py` | UI entry point (`streamlit run app/streamlit_app.py`): registers the four pages with their sidebar titles. |
| `app/review.py` | **Threat Model Review** page. Engine + model picker, API-key field, diagram upload, detect-and-prefill, declaration (or a SAD run's JSON), report. |
| `.streamlit/config.toml` | Streamlit settings: no usage statistics sent, no Deploy button. Read when you start the app from the repository root. |
| `.env.example` | Template for a local, git-ignored `.env` holding API keys. |
| `uv.lock` | Exact versions of every dependency, used by `uv sync`. |
| `NOTICE.md` | Where the project comes from and its relation to STRIDE-GPT. |
| `app/pages/2_SAD_Threat_Model.py` | Upload a solution architecture document (DOCX/PDF/MD) → completeness check → confirm profile → automated threat model. |
| `app/pages/1_Control_Catalog.py` | Reference page (sidebar nav) — browsable/filterable description of every control, generated from the catalog; exportable to Markdown. |
| `app/pages/3_Help.py` | Help: which page to use (SAD vs description + diagram) and the DREAD scoring guide with a worked example computed by the real scorer (`threatcatalog/help_example.py`). |

## The engine (`threatcatalog/`)
| Path | What it is |
|---|---|
| `models.py` | All Pydantic models + enums — the single typed source of truth. |
| `catalog/loader.py` | Loads + validates the YAML catalog (the gate; fails loud on bad data). |
| `catalog/resolver.py` | Facets → expected control set, with AI-tier inheritance. |
| `catalog/data/*.yaml` | **The catalog itself** — 15 layered files, 123 controls (incl. `platform_messaging.yaml`, `platform_container.yaml`, `ai_training.yaml`). Each control carries verbose `guidance`. This is what you grow over time. |
| `intake.py` | Declaration template, conservative text detector, ledger merge. |
| `gap.py` | The deterministic gap engine (expected vs implemented). |
| `pci.py` | PCI DSS v4.0.1 compliance view (second read off the same gap). |
| `out_of_catalog.py` | Judges controls the app has but the catalog lacks; flags candidates. |
| `generators.py` | `ArtifactEngine` protocol + the offline `DeterministicArtifactEngine`. |
| `llm/provider.py` | Model providers: `OpenAIRawLLM` (default gpt-5.2), `AnthropicRawLLM` (streamed), `BedrockRawLLM` (AWS Bedrock Converse), `StubRawLLM`. |
| `llm/factory.py` | Engine choice in the UI → `ArtifactEngine`, shared by both pages. |
| `sad_extract.py` | Reads a SAD (DOCX/PDF/MD) into text + diagram images, in memory. |
| `sad.py` | SAD flow: completeness rubric, profile inference, stop rule, SAD status rules (silent = not present, implied = partial), run, feedback document. |
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
| `testapp/corvane-supplier-hub/` | Sample app A, a simple Azure web app: SAD (DOCX + PDF), an insufficient draft SAD (should stop the SAD page), description + diagram for the main page, `ANSWER_KEY.md` and `expected_results.json`. |
| `testapp/halcyon-claimpilot/` | Sample app B, an agentic AI claims app on AWS (agents, tools, MCP, RAG, Kafka, EKS, fine-tuning, PCI): SAD (DOCX + PDF, 3 diagrams), description + diagrams, answer key. |
| `testapp/marlowe-shift-reporter/` | Minimal demo app C, an on-prem scheduled reporting job (37 controls, onprem only): SAD (DOCX + PDF), description + diagram, answer key. |
| `testapp/northfield-sms-reminders/` | Minimal demo app D, serverless SMS reminders on Google Cloud (42 controls, cloud only): SAD (DOCX + PDF), description + diagram, answer key. |
| `testapp/PaymentGateway*`, `testapp/BankLedgerPro_OnPrem*`, `testapp/AegisPress*` | Early sample inputs for the main page (a description and a diagram each, no answer key). |
| `testapp/sources/` | Sources and build scripts for the four samples (Markdown SADs, diagram code, answer keys). Rebuild with `build_diagrams.py`, `build_docs.py`, `build_answer_keys.py`. |
| `examples/peopledesk_report.md` | A sample generated report (offline engine). |

## Tests (`tests/`)
One file per engine area; 237 tests, all offline (`test_samples.py` checks the four sample apps and their answer keys). Run with `pytest -q`.
