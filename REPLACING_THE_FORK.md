# Replacing your fork's codebase with `threatcatalog`

This guide swaps the flat-baseline threat modeling in your `amnigam/stride-gpt`
fork for the catalog-driven engine. Nothing here touches upstream's public
contract destructively — you can land it behind the existing UI or run it
side-by-side first.

## What maps to what

| Old (fork) | New | Notes |
|---|---|---|
| `org_context.py` (flat baseline string) | `threatcatalog/catalog/` + `intake.py` | The baseline becomes a *layered catalog* + a per-app declaration. |
| Single LLM prompt that imagines threats | `threatcatalog/pipeline.py` over a computed gap | The model now reasons over the gap, not from scratch. |
| Local-directory / GitHub repo analysis | *(left dormant)* | This engine is not a code scanner; see below. |
| Streamlit `main.py` | `app/streamlit_app.py` | Thin UI; all logic is in the package. |
| Vulnerable Flask test app under `tests/` | `testapp/` (PeopleDesk diagram + description) | The tool consumes a diagram + description, not source. |

## Option A — clean drop-in (recommended)

1. **Copy the package in.** Place the `threatcatalog/` directory at your repo
   root (alongside your existing Streamlit entrypoint), and copy `app/`,
   `tests/`, `testapp/`, `pyproject.toml`, and `requirements.txt`.

2. **Install.**
   ```bash
   pip install -e ".[app,dev]"        # add ".[llm]" for the model engine
   ```

3. **Retire `org_context.py`.** Its job is now done by the catalog (what to
   expect) plus the declaration step (what's in place). If other modules import
   it, replace the import with:
   ```python
   from threatcatalog.catalog import Catalog, resolve
   from threatcatalog.intake import declaration_template
   ```

4. **Point your entrypoint at the new app.** Either run `app/streamlit_app.py`
   directly, or have your existing `main.py` import and call the pipeline:
   ```python
   from threatcatalog import pipeline
   from threatcatalog.report import render_markdown
   report = pipeline.run(profile, description=desc, declared=declared,
                         observed_unmatched=observed)
   st.markdown(render_markdown(report))
   ```

5. **Leave GitHub / local-directory analysis dormant.** Keep the code if you
   like, but don't wire it into this pipeline — feeding source here is an
   altitude mismatch. If you want diagram-vision evidence, implement
   `LLMArtifactEngine.extract_controls` with a multimodal prompt; its output is
   just more `LedgerEntry` rows with `provenance=diagram_vision`, and the rest of
   the pipeline already consumes them.

6. **Verify.**
   ```bash
   pytest -q
   python -m threatcatalog.cli testapp/peopledesk_intake.json --out /tmp/r.md
   ```

## Option B — side-by-side trial

Drop `threatcatalog/` in without removing anything. Add a second Streamlit page
(or a CLI alias) that runs the new pipeline, compare its output to the old flow
on a few real apps, then delete the old path once you're satisfied. The new
engine has no shared global state, so the two coexist cleanly.

## Hardening notes carried over from the fork review

* **No hardcoded personal paths** — the catalog loads from package data via
  `importlib`-style relative paths; there is nothing machine-specific to edit.
* **Prompt-injection hygiene is built into the prompts** (`llm/prompts.py`): all
  app/record text is framed as data-not-instructions. Keep that line if you edit
  prompts.
* **Pin your dependencies.** `pyproject.toml` sets floors; pin exact versions in
  your lockfile. The OWASP MCP list is beta — the catalog records that in the
  framework `version` field, and you should re-check it on each release.
* **Secrets**: the model engine reads `ANTHROPIC_API_KEY` from the environment.
  Don't commit it; the offline engine needs no key at all.

## Rollback

The change is additive — `git revert` the merge (or delete the `threatcatalog/`
directory and restore `org_context.py`) and you're back. Because the new engine
is self-contained, nothing else in the fork depends on it until you wire the
entrypoint.
