"""
Streamlit integration surface for the catalog-driven threat modeling engine.

Two-step evidence flow:

  1. "Detect controls" reads the description and the architecture diagram (one
     LLM call; keyword matching offline) and PRE-FILLS the declaration with a
     status AND an evidence note per control — the AI's reasoning plus the
     sentence or diagram element it relied on. The reviewer edits status/note;
     the AI's original suggestion is kept so the report shows both.
  2. "Run threat model" uses the (reviewed) declaration to compute the gap and
     render the report.

All logic lives in the `threatcatalog` package; this file is just intake + render.

Run:  streamlit run app/streamlit_app.py
"""

from __future__ import annotations

import hashlib

import pandas as pd
import streamlit as st

from threatcatalog.env import load_dotenv

load_dotenv()  # pick up OPENAI_API_KEY / ANTHROPIC_API_KEY from a local .env

from threatcatalog import pipeline  # noqa: E402
from threatcatalog.catalog import Catalog, resolve
from threatcatalog.declaration import (BASIS_LABEL, DeclarationRow,
                                       apply_detection, apply_edit, ensure_rows,
                                       evidence_basis, export_json, import_json,
                                       needs_note, to_ledger)
from threatcatalog.intake import detect_from_text
from threatcatalog.llm.factory import BEDROCK, OFFLINE, default_model
from threatcatalog.llm.factory import build_engine as _factory_build
from threatcatalog.models import (AICapability, AppProfile, ControlStatus,
                                  DataClassification, LedgerEntry,
                                  ObservedControl, PlatformFacet)
from threatcatalog.report import render_markdown

st.set_page_config(page_title="Catalog Threat Modeling", layout="wide")
st.title("Catalog-driven, gap-based threat modeling")

catalog = Catalog.load()
st.caption(f"Catalog loaded: {len(catalog)} controls across all layers.")

def build_engine(choice: str, model_id: str, api_key: str = "", base_url: str = "",
                 max_tokens: int = 32000):
    """Return an ArtifactEngine for the chosen provider, or None for offline."""
    return _factory_build(choice, model_id, api_key=api_key, base_url=base_url,
                          max_tokens=max_tokens, region=aws_region, aws_profile=aws_profile)


with st.sidebar:
    st.header("0 · Model engine")
    engine_choice = st.selectbox(
        "Generation engine",
        ["OpenAI (ChatGPT)", "Anthropic (Claude)", BEDROCK, OFFLINE],
        help="Deterministic needs no API key. The others build the narrative with "
             "the model you name below, and read the diagram.")
    model_id, api_key, base_url, aws_region, aws_profile = "", "", "", "", ""
    max_out_tokens = 32000
    if engine_choice != OFFLINE:
        model_id = st.text_input("Model id", default_model(engine_choice),
                                 help="e.g. gpt-5.2, claude-sonnet-4-6, or a Bedrock model / "
                                      "inference-profile id — whatever your org provides.")
    if engine_choice == BEDROCK:
        aws_region = st.text_input("AWS region (optional)",
                                   help="Blank = AWS_REGION from the environment.")
        aws_profile = st.text_input("AWS profile (optional)",
                                    help="Blank = default AWS credential chain.")
    elif engine_choice != OFFLINE:
        key_env = "OPENAI_API_KEY" if engine_choice.startswith("OpenAI") else "ANTHROPIC_API_KEY"
        api_key = st.text_input("API key (optional — overrides env var)", type="password",
                                help=f"Leave blank to use {key_env} from the environment.")
        if engine_choice.startswith("OpenAI"):
            base_url = st.text_input("API base URL (optional)",
                                     help="For an org gateway / Azure endpoint. Blank = default OpenAI.")
    if engine_choice != OFFLINE:
        max_out_tokens = st.number_input(
            "Max output tokens", min_value=4096, max_value=128000, value=32000, step=4096,
            help="On reasoning models (GPT-5 / o-series) this budget covers reasoning "
                 "tokens as well as visible output. Wide facet sets (mcp + agentic) need "
                 "far more than the old 4096 default or the model returns nothing.")

    st.header("Reviewer")
    st.text_input("Your name", key="reviewer",
                  help="Recorded with a timestamp against every status or note you "
                       "change in the declaration, and shown in the report.")

    st.header("1 · Application facets")
    name = st.text_input("Application name", "PeopleDesk")
    platforms = st.multiselect("Platform", [p.value for p in PlatformFacet], ["web", "cloud"])
    ai = st.multiselect("AI capability", [a.value for a in AICapability], ["llm"])
    dc = st.selectbox("Data classification", [d.value for d in DataClassification], index=3)
    pci = st.checkbox("Handles cardholder data (PCI in scope)", value=False)

profile = AppProfile(
    name=name,
    platforms=[PlatformFacet(p) for p in platforms] or [PlatformFacet.WEB],
    ai_capabilities=[AICapability(a) for a in ai] or [AICapability.NONE],
    data_classification=DataClassification(dc), handles_cardholder_data=pci)

expected = resolve(profile, catalog.controls)
STATUS_OPTIONS = ["unknown", "implemented", "partial", "not_present", "n_a"]

st.subheader(f"2 · Evidence — {len(expected)} controls expected for these facets")
description = st.text_area("Architecture description (vision text can be pasted here too)", height=120)

diagram_file = st.file_uploader("Architecture diagram (optional — PNG / JPG)",
                                type=["png", "jpg", "jpeg"])
diagram_image = diagram_file.getvalue() if diagram_file else None
diagram_media_type = diagram_file.type if diagram_file else "image/png"
if diagram_file is not None:
    st.image(diagram_file, caption="Diagram to be read by the vision extractor", width=420)


# ---- step 3a: detect controls from diagram + description, pre-fill declaration ----
st.subheader("3 · Detect & declare")
st.caption("Detect reads the description and — with an LLM engine — the diagram, then "
           "pre-fills the declaration below. Each AI suggestion comes with its reasoning "
           "and the sentence or diagram element it relied on. The AI only reports controls "
           "it finds evidence for; it never marks one absent, so unseen controls stay "
           "'unknown'. The offline engine falls back to keyword matching.")

rows: dict[str, DeclarationRow] = st.session_state.setdefault("decl_rows", {})
ensure_rows(rows, expected)
st.session_state.setdefault("decl_ver", 0)


def _keyword_detect() -> list[LedgerEntry]:
    return detect_from_text(description, expected)


if st.button("🔍 Detect controls from diagram + description"):
    detected: list[LedgerEntry] = []
    if engine_choice != "Deterministic (offline)" and (description.strip() or diagram_image):
        try:
            eng = build_engine(engine_choice, model_id, api_key=api_key, base_url=base_url,
                               max_tokens=max_out_tokens)
            with st.spinner("Reading the description and diagram…"):
                detected = eng.detect_controls(expected, description, diagram_image,
                                               diagram_media_type)
        except Exception as exc:                 # noqa: BLE001 — surface model/auth errors
            st.warning(f"AI detection failed ({exc}). Fell back to keyword matching on "
                       "the description.")
            detected = _keyword_detect()
    else:
        detected = _keyword_detect()
        if diagram_image is not None:
            st.info("Diagram uploaded but the offline engine can't read it — pick OpenAI or "
                    "Anthropic to extract controls from the image.")
    apply_detection(rows, detected, expected)    # never clobbers rows a reviewer touched
    st.session_state["_detected"] = {e.control_id: (e.detail.ai_source if e.detail else
                                                    e.provenance.value) for e in detected}
    st.session_state["_detected_done"] = True
    st.session_state["decl_ver"] += 1
    st.rerun()

_detected = st.session_state.get("_detected", {})
if st.session_state.get("_detected_done"):
    by_src = {}
    for src in _detected.values():
        by_src[src] = by_src.get(src, 0) + 1
    parts = ", ".join(f"{n} from the {k.replace('keyword', 'description (keywords)')}"
                      for k, n in sorted(by_src.items())) or "none"
    st.success(f"AI found evidence for {len(_detected)} control(s): {parts}. Review the "
               "statuses and notes below; anything you change is recorded under your name.")

# ---- step 3b: declaration table (status + evidence note per control) ----
_LAYER_OF = {c.id: c.layers[0].value for c in expected}
_CTRL = {c.id: c for c in expected}


def _ai_label(row: DeclarationRow) -> str:
    ev = row.evidence
    if ev.ai_status is None:
        return "no evidence found" if st.session_state.get("_detected_done") else "—"
    bits = [ev.ai_status.value, (ev.ai_confidence.value if ev.ai_confidence else ""),
            (ev.ai_source or "")]
    label = " · ".join(b for b in bits if b)
    if ev.quote_verified is False:
        label += "  ⚠ quote not found"
    return label


with st.expander("Control declaration", expanded=True):
    st.caption("Each control has an editable note, pre-filled with the AI's reasoning. "
               "Change the status or the note to record your own assessment; the AI's "
               "original suggestion is kept and both appear in the report. Tick "
               "'Reviewed' to confirm an AI suggestion as-is.")

    # save / load — declarations survive a page refresh and carry across ARB rounds
    c1, c2 = st.columns([1, 2])
    c1.download_button(
        "💾 Save declaration (JSON)",
        export_json(rows, meta={"application": profile.name,
                                "reviewer": st.session_state.get("reviewer") or None}),
        file_name=f"{profile.name.replace(' ', '_')}_declaration.json",
        mime="application/json")
    upload = c2.file_uploader("Load a saved declaration", type=["json"], key="decl_upload",
                              label_visibility="collapsed")
    if upload is not None:
        blob = upload.getvalue()
        digest = hashlib.sha256(blob).hexdigest()
        if digest != st.session_state.get("_decl_loaded"):
            try:
                loaded, meta = import_json(blob)
            except ValueError as exc:
                st.error(f"Could not load that file: {exc}")
            else:
                rows.update(loaded)
                ensure_rows(rows, expected)
                st.session_state["_decl_loaded"] = digest
                st.session_state["_detected_done"] = True
                st.session_state["decl_ver"] += 1
                st.rerun()
        else:
            st.caption("Declaration loaded from file.")

    layers = sorted({_LAYER_OF[c.id] for c in expected})
    f1, f2 = st.columns([3, 1])
    shown_layers = f1.multiselect("Show layers", layers, default=layers)
    only_attention = f2.checkbox("Only rows needing a note", value=False)

    visible = [c.id for c in expected if _LAYER_OF[c.id] in shown_layers
               and (not only_attention or needs_note(rows[c.id]))]
    cols = ["ID", "Control", "Status", "Note", "Reviewed", "AI suggestion", "AI cited",
            "Basis", "Question", "Layer"]
    table = pd.DataFrame([{
        "ID": cid,
        "Control": _CTRL[cid].title,
        "Status": rows[cid].status.value,
        "Note": rows[cid].evidence.note or "",
        "Reviewed": rows[cid].evidence.reviewed,
        "AI suggestion": _ai_label(rows[cid]),
        "AI cited": rows[cid].evidence.ai_quote or "",
        "Basis": BASIS_LABEL.get(evidence_basis(rows[cid].status, rows[cid].evidence), ""),
        "Question": _CTRL[cid].assessment_signal,
        "Layer": _LAYER_OF[cid],
    } for cid in visible], columns=cols)

    view_key = hashlib.sha1(("|".join(shown_layers) + str(only_attention)).encode()).hexdigest()[:8]
    edited = st.data_editor(
        table, key=f"decl_editor_{st.session_state['decl_ver']}_{view_key}",
        hide_index=True, use_container_width=True, num_rows="fixed",
        height=min(36 * (len(table) + 1) + 3, 720),
        disabled=["ID", "Layer", "Control", "Question", "AI suggestion", "AI cited", "Basis"],
        column_config={
            "Control": st.column_config.TextColumn(width="medium", pinned=True),
            "ID": st.column_config.TextColumn(pinned=True),
            "Question": st.column_config.TextColumn(width="medium"),
            "AI cited": st.column_config.TextColumn(
                width="medium", help="Sentence from the description, or diagram element, "
                                     "the AI relied on"),
            "Status": st.column_config.SelectboxColumn(options=STATUS_OPTIONS, required=True,
                                                       width="small"),
            "Note": st.column_config.TextColumn(
                width="large", max_chars=2000,
                help="Pre-filled with the AI's reasoning. Edit to add or replace with your "
                     "own assessment."),
            "Reviewed": st.column_config.CheckboxColumn(
                help="Tick to confirm the AI suggestion after checking it"),
        })

    changed = False
    who = st.session_state.get("reviewer") or ""
    for rec in edited.to_dict("records"):
        note = rec["Note"] if isinstance(rec["Note"], str) else None
        status = rec["Status"] if isinstance(rec["Status"], str) else "unknown"
        changed |= apply_edit(rows[rec["ID"]], ControlStatus(status), note,
                              bool(rec["Reviewed"]), who)
    if changed:
        st.rerun()                                # refresh Basis / attention columns

    # soft prompt (never blocks the run): rows where a reviewer note is expected
    attention = [(cid, needs_note(rows[cid])) for cid in (c.id for c in expected)]
    attention = [(cid, why) for cid, why in attention if why]
    if attention:
        st.warning(f"{len(attention)} control(s) would benefit from a reviewer note — "
                   "you can still run the threat model without them. Tick 'Only rows "
                   "needing a note' to filter to them.")
        with st.expander("Which ones and why"):
            for cid, why in attention:
                st.markdown(f"- **{cid}** {_CTRL[cid].title} — {why}")
    if not who.strip():
        st.caption("Tip: enter your name under *Reviewer* in the sidebar so changes are "
                   "attributed to you in the report.")

declared: list[LedgerEntry] = to_ledger(rows, expected)

obs_raw = st.text_area("Other controls you implement that may not be in the catalog "
                       "(one per line: name — description)", height=80)
observed = []
for line in obs_raw.splitlines():
    if "—" in line or "-" in line:
        sep = "—" if "—" in line else "-"
        n, _, d = line.partition(sep)
        if n.strip():
            observed.append(ObservedControl(name=n.strip(), description=d.strip()))

# ---- step 4: run ----
if st.button("Run threat model", type="primary"):
    if diagram_image is not None and not st.session_state.get("_detected_done"):
        st.warning("You uploaded a diagram but didn't click Detect — it won't be read. "
                   "Click Detect first to pull controls from the image.")
    if attention:
        st.toast(f"Running with {len(attention)} control(s) still missing a reviewer note.")
    try:
        engine = build_engine(engine_choice, model_id, api_key=api_key, base_url=base_url,
                              max_tokens=max_out_tokens)
    except Exception as exc:                       # noqa: BLE001
        st.error(f"Could not initialize {engine_choice}: {exc}")
        st.stop()
    try:
        # diagram already incorporated via Detect -> declaration; don't re-read it here
        report = pipeline.run(profile, description=description, declared=declared,
                              observed_unmatched=observed, engine=engine,
                              controls=catalog.controls)
    except Exception as exc:                       # noqa: BLE001
        st.error(f"Run failed with {engine_choice}: {exc}")
        st.stop()
    label = engine_choice if engine_choice == "Deterministic (offline)" else f"{engine_choice} · {model_id}"
    # stash in session_state so downloads survive Streamlit's reruns
    st.session_state["report"] = report
    st.session_state["report_label"] = label

# render the latest report (persists across download-button reruns)
report = st.session_state.get("report")
if report is not None:
    st.success(f"Engine: {st.session_state['report_label']} — {len(report.threats)} findings · "
               f"{len(report.clarifications)} clarifications · "
               f"PCI in scope: {report.pci_view.in_scope}")
    fname = report.profile.name.replace(" ", "_")
    md = render_markdown(report)
    dl1, dl2 = st.columns(2)
    dl1.download_button("⬇ Download (Markdown)", md, file_name=f"{fname}_threat_model.md",
                        mime="text/markdown")
    try:
        from threatcatalog.pdf_export import render_pdf
        dl2.download_button("⬇ Download (PDF)", render_pdf(report),
                            file_name=f"{fname}_threat_model.pdf", mime="application/pdf")
    except Exception as exc:                       # noqa: BLE001 — PDF is optional
        dl2.caption(f"PDF export needs reportlab — `pip install reportlab`. ({exc})")
    st.markdown(md)
