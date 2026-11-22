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

This is the "Threat Model Review" page; app/streamlit_app.py is the entry point
that registers it and the other pages.

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
from threatcatalog.catalog.text import control_markdown
from threatcatalog.declaration import (BASIS_LABEL, DeclarationRow,
                                       apply_detection, apply_editor_changes,
                                       ensure_rows,
                                       evidence_basis, export_json, import_json,
                                       needs_note, profile_differences,
                                       reviewed_sad_context, sad_handoff, to_ledger)
from threatcatalog.architecture import parse_architecture
from threatcatalog.intake import detect_from_text
from threatcatalog.llm.factory import BEDROCK, OFFLINE, default_model
from threatcatalog.llm.factory import build_engine as _factory_build
from threatcatalog.models import (AICapability, AppProfile, CompletenessItem,
                                  DataClassification, LedgerEntry,
                                  ObservedControl, PlatformFacet)
from threatcatalog.report import render_markdown
from threatcatalog.sad_extract import MAX_IMAGES, prepare_diagrams

st.set_page_config(page_title="Threat Model Review", layout="wide")
st.title("Threat Model Review")

catalog = Catalog.load()
st.caption("Catalog-driven, gap-based threat modeling from a description and diagrams, or a "
           f"review of a saved SAD run. Catalog loaded: {len(catalog)} controls across all layers.")

def build_engine(choice: str, model_id: str, api_key: str = "", base_url: str = "",
                 max_tokens: int = 32000):
    """Return an ArtifactEngine for the chosen provider, or None for offline."""
    return _factory_build(choice, model_id, api_key=api_key, base_url=base_url,
                          max_tokens=max_tokens, region=aws_region, aws_profile=aws_profile)


ENGINES = ["OpenAI (ChatGPT)", "Anthropic (Claude)", BEDROCK, OFFLINE]
# A declaration exported from the SAD page carries the confirmed profile and engine.
# Loading it (step 3) queues them here; they are applied before the widgets are drawn.
for _k, _v in (st.session_state.pop("_pending_widgets", None) or {}).items():
    st.session_state[_k] = _v
for _k, _v in (("engine_choice", ENGINES[0]), ("app_name", "PeopleDesk"),
               ("app_platforms", ["web", "cloud"]), ("app_ai", ["llm"]),
               ("app_dc", "Restricted"), ("app_pci", False), ("obs_raw", "")):
    st.session_state.setdefault(_k, _v)

with st.sidebar:
    st.header("0 · Model engine")
    engine_choice = st.selectbox(
        "Generation engine", ENGINES, key="engine_choice",
        help="Deterministic needs no API key. The others build the narrative with "
             "the model you name below, and read the diagram.")
    model_id, api_key, base_url, aws_region, aws_profile = "", "", "", "", ""
    max_out_tokens = 32000
    if engine_choice != OFFLINE:
        st.session_state.setdefault(f"model_id::{engine_choice}", default_model(engine_choice))
        model_id = st.text_input("Model id", key=f"model_id::{engine_choice}",
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
    name = st.text_input("Application name", key="app_name")
    platforms = st.multiselect("Platform", [p.value for p in PlatformFacet], key="app_platforms")
    ai = st.multiselect("AI capability", [a.value for a in AICapability], key="app_ai")
    dc = st.selectbox("Data classification", [d.value for d in DataClassification], key="app_dc")
    pci = st.checkbox("Handles cardholder data (PCI in scope)", key="app_pci")

profile = AppProfile(
    name=name,
    platforms=[PlatformFacet(p) for p in platforms] or [PlatformFacet.WEB],
    ai_capabilities=[AICapability(a) for a in ai] or [AICapability.NONE],
    data_classification=DataClassification(dc), handles_cardholder_data=pci)

expected = resolve(profile, catalog.controls)
STATUS_OPTIONS = ["unknown", "implemented", "partial", "not_present", "n_a"]

st.subheader(f"2 · Evidence — {len(expected)} controls expected for these facets")
description = st.text_area("Architecture description (vision text can be pasted here too)", height=120)



@st.cache_data(show_spinner=False, max_entries=8)
def _prepare(files: tuple[tuple[str, bytes], ...]):
    return prepare_diagrams(list(files), MAX_IMAGES)


diagram_files = st.file_uploader(
    f"Architecture diagrams (optional — PNG / JPG, up to {MAX_IMAGES})",
    type=["png", "jpg", "jpeg"], accept_multiple_files=True,
    help="Add every view you have (context, deployment / network, data flow, agent "
         "interaction). They are read together in one call, and each AI citation names "
         "the diagram it came from.")
diagrams, diagrams_skipped = _prepare(tuple((f.name, f.getvalue())
                                            for f in diagram_files or []))
if len(diagram_files or []) > MAX_IMAGES:
    st.warning(f"Only the first {MAX_IMAGES} diagrams will be read. Remove the extra "
               "files or combine views.")
for why in diagrams_skipped:
    st.caption(f"⚠ Not read: {why}")
if diagrams:
    cols = st.columns(min(len(diagrams), 4))
    for i, img in enumerate(diagrams):
        cols[i % len(cols)].image(img.data, caption=f"Diagram {i + 1}: {img.label}",
                                  use_container_width=True)


# ---- step 3a: detect controls from diagram + description, pre-fill declaration ----
st.subheader("3 · Detect & declare")
st.caption("Detect reads the description and — with an LLM engine — every diagram, then "
           "pre-fills the declaration below. Each AI evaluation comes with its reasoning "
           "and the sentence or diagram element it relied on. The AI only reports controls "
           "it finds evidence for; it never marks one absent, so unseen controls stay "
           "'unknown'. The offline engine falls back to keyword matching.")

# profile confirmed on the SAD page, when the loaded declaration came from there
_handoff = st.session_state.get("_handoff")
_drift = profile_differences(_handoff.profile, profile) if _handoff else []
if _drift:
    st.warning("**This profile differs from the one confirmed on the SAD page:** "
               + "; ".join(_drift) + ". Controls are expected for the profile in the sidebar, "
               "so controls added this way start as unknown and controls removed this way "
               "leave the review and the report. The change is recorded in the report.")

rows: dict[str, DeclarationRow] = st.session_state.setdefault("decl_rows", {})
ensure_rows(rows, expected)
st.session_state.setdefault("decl_ver", 0)


def _keyword_detect() -> list[LedgerEntry]:
    return detect_from_text(description, expected)


if st.button("🔍 Detect controls from diagrams + description"):
    detected: list[LedgerEntry] = []
    st.session_state["_detect_arch"] = None          # a new Detect replaces what the last one read
    st.session_state["_detect_completeness"] = []
    read: list[str] = []
    if engine_choice != "Deterministic (offline)" and (description.strip() or diagrams):
        try:
            eng = build_engine(engine_choice, model_id, api_key=api_key, base_url=base_url,
                               max_tokens=max_out_tokens)
            n = len(diagrams)
            with st.spinner("Reading the description" + (f" and {n} diagram(s)…" if n else "…")):
                detected = eng.detect_controls(
                    expected, description,
                    diagrams=[(d.data, d.media_type, d.label) for d in diagrams])
            read = [d.label for d in diagrams]
            # the same call summarised the architecture and scored the completeness
            # checklist: kept for the report (they never change a control)
            extras = getattr(eng, "last_detect_extras", None) or {}
            st.session_state["_detect_arch"] = extras.get("architecture")
            st.session_state["_detect_completeness"] = list(extras.get("completeness") or [])
        except Exception as exc:                 # noqa: BLE001 — surface model/auth errors
            st.warning(f"AI detection failed ({exc}). Fell back to keyword matching on "
                       "the description.")
            detected = _keyword_detect()
    else:
        detected = _keyword_detect()
        if diagrams:
            st.info("Diagrams uploaded but the offline engine can't read them — pick an "
                    "LLM engine to extract controls from the images.")
    st.session_state["_diagrams_read"] = read
    st.session_state["_diagrams_skipped"] = list(diagrams_skipped) + (
        [] if read or not diagrams else
        [f"{d.label}: not read (no LLM engine, or detection failed)" for d in diagrams])
    apply_detection(rows, detected, expected)    # never clobbers rows a reviewer touched
    st.session_state["_detected"] = {e.control_id: (e.detail.ai_source if e.detail else
                                                    e.provenance.value) for e in detected}
    st.session_state["_detected_done"] = True
    st.session_state["decl_ver"] += 1
    st.rerun()

_detected = st.session_state.get("_detected", {})
_loaded = st.session_state.get("_decl_loaded_info")
if _loaded and not _detected:
    st.success(f"Loaded {_loaded['rows']} control(s) from {_loaded['file']}"
               + (f", {_loaded['ai']} with an AI evaluation" if _loaded["ai"] else "")
               + (" and the profile confirmed on the SAD page" if _handoff else "")
               + ". Review the statuses and notes below; anything you change is recorded "
               "under your name.")
elif st.session_state.get("_detected_done"):
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
    if ev.quote_supports is False:
        label += "  ⚠ quote doesn't support it"
    return label


_COLS = ["ID", "Control", "Status", "Note", "Reviewed", "AI evaluation", "AI cited",
         "Basis", "Question", "Layer"]
_EDITABLE = ["Status", "Note", "Reviewed"]
_AI_COLS = ["AI evaluation", "AI cited", "Basis"]          # the AI's evidence, read-only
_REF_COLS = ["ID", "Control", "Question", "Layer"]         # what the control is, read-only
# translucent tints so they read in both the light and the dark theme
_AI_TINT = "rgba(59, 130, 246, 0.12)"
_REF_TINT = "rgba(128, 128, 128, 0.10)"
_ROW_HEIGHT = 70                                           # room for two wrapped lines


def _styled(table: pd.DataFrame):
    """Shade read-only columns so the editable ones (white, pencil icon) stand out."""
    return (table.style
            .set_properties(subset=_AI_COLS, **{"background-color": _AI_TINT})
            .set_properties(subset=_REF_COLS, **{"background-color": _REF_TINT}))


def _control_details(ids: list[str]) -> None:
    """Explain controls from the catalog: shown for the search matches, or picked."""
    with st.container(border=True):
        st.markdown("**ⓘ Control details**")
        if 1 <= len(ids) <= 3 and st.session_state.get("_decl_search"):
            for cid in ids:
                st.markdown(control_markdown(_CTRL[cid], heading="", internals=False))
            return
        pick = st.selectbox("Control details", ids, index=None,
                            format_func=lambda cid: f"{cid} — {_CTRL[cid].title}",
                            placeholder="Pick a control to see what it covers and what to check",
                            label_visibility="collapsed", key="_decl_detail_pick")
        if pick:
            st.markdown(control_markdown(_CTRL[pick], heading="", internals=False))


@st.fragment
def _declaration_table() -> None:
    """Edits rerun only this section, so the rest of the page stays put."""
    with st.expander("Control declaration", expanded=True):
        st.caption("Each control has an editable note, pre-filled with the AI's reasoning. "
                   "Change the status or the note to record your own assessment; the AI's "
                   "original suggestion is kept and both appear in the report. Tick "
                   "'Reviewed' to confirm an AI evaluation as-is.")

        # save / load — declarations survive a page refresh and carry across ARB rounds
        c1, c2 = st.columns([1, 2])
        c1.download_button(
            "💾 Save declaration (JSON)",
            export_json(rows, meta={
                "application": profile.name,
                "reviewer": st.session_state.get("reviewer") or None,
                # keep what Detect read, so a reloaded review still builds the same threats
                "architecture": (st.session_state["_detect_arch"].model_dump(mode="json")
                                 if st.session_state.get("_detect_arch") else None),
                "completeness": [c.model_dump(mode="json") for c in
                                 st.session_state.get("_detect_completeness") or []]}),
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
                    st.session_state["_decl_loaded_info"] = {
                        "file": upload.name, "rows": len(loaded),
                        "ai": sum(1 for r in loaded.values() if r.evidence.ai_status is not None)}
                    st.session_state["_detected"] = {}
                    h = sad_handoff(meta)
                    st.session_state["_handoff"] = h
                    st.session_state["_detect_arch"] = parse_architecture(meta.get("architecture"))
                    st.session_state["_detect_completeness"] = [
                        CompletenessItem.model_validate(c) for c in meta.get("completeness") or []
                        if isinstance(c, dict)]
                    if h is not None:
                        p = h.profile
                        pending = {
                            "app_name": p.name,
                            "app_platforms": [x.value for x in p.platforms],
                            "app_ai": [x.value for x in p.ai_capabilities
                                       if x != AICapability.NONE],
                            "app_dc": p.data_classification.value,
                            "app_pci": p.handles_cardholder_data,
                            "obs_raw": "\n".join(f"{o.name} — {o.description}".rstrip(" —")
                                                  for o in h.other_controls)}
                        if h.provider in ENGINES:
                            pending["engine_choice"] = h.provider
                            if h.model_id:
                                pending[f"model_id::{h.provider}"] = h.model_id
                        st.session_state["_pending_widgets"] = pending
                    st.session_state["_detected_done"] = True
                    st.session_state["decl_ver"] += 1
                    st.rerun()
            else:
                st.caption("Declaration loaded from file.")

        layers = sorted({_LAYER_OF[c.id] for c in expected})
        f1, f2, f3 = st.columns([3, 2, 1])
        shown_layers = f1.multiselect("Show layers", layers, default=layers)
        search = f2.text_input("Find control", placeholder="ID or name, e.g. CORS",
                               key="_decl_search",
                               help="Filter the table to controls whose ID or name contains "
                                    "this text.").strip()
        only_attention = f3.checkbox("Only rows needing a note", value=False)

        # The table is built from a snapshot that only changes when the view changes
        # (filter, search, Detect, load). Rebuilding it after every edit made the grid
        # remount and jump back to the first row on Streamlit < 1.67.
        view = "|".join(shown_layers) + f"|{only_attention}|{search.lower()}"
        sig = f"{st.session_state['decl_ver']}:{hashlib.sha1(view.encode()).hexdigest()[:8]}"
        snap = st.session_state.get("_decl_snapshot")
        if snap is None or snap[0] != sig:
            needle = search.lower()
            visible = [c.id for c in expected if _LAYER_OF[c.id] in shown_layers
                       and (not only_attention or needs_note(rows[c.id]))
                       and (not needle or needle in c.id.lower()
                            or needle in _CTRL[c.id].title.lower())]
            table = pd.DataFrame([{
                "ID": cid,
                "Control": _CTRL[cid].title,
                "Status": rows[cid].status.value,
                "Note": rows[cid].evidence.note or "",
                "Reviewed": rows[cid].evidence.reviewed,
                "AI evaluation": _ai_label(rows[cid]),
                "AI cited": rows[cid].evidence.ai_quote or "",
                "Basis": BASIS_LABEL.get(evidence_basis(rows[cid].status, rows[cid].evidence), ""),
                "Question": _CTRL[cid].assessment_signal,
                "Layer": _LAYER_OF[cid],
            } for cid in visible], columns=_COLS)
            snap = (sig, visible, table)
            st.session_state["_decl_snapshot"] = snap
        _, visible, table = snap

        if search and not visible:
            st.info(f"No control matches '{search}' in the layers shown.")
        editor_key = f"decl_editor_{sig}"
        st.caption("**White columns with a pencil icon are yours to edit** "
                   "(Status, Note, Reviewed). "
                   ":blue-background[Blue] columns are the AI's evidence and "
                   ":gray-background[grey] columns describe the control; both are read-only. "
                   "For what a control covers, see **Control details** below the table.")
        st.data_editor(
            _styled(table), key=editor_key, column_order=_COLS,
            hide_index=True, use_container_width=True, num_rows="fixed",
            row_height=_ROW_HEIGHT,
            height=min(_ROW_HEIGHT * len(table) + 38, 760),
            disabled=_AI_COLS + _REF_COLS,
            column_config={
                "ID": st.column_config.TextColumn(
                    "ID", width=120, pinned=True,
                    help="Catalog control ID. See Control details below the table for what "
                         "the control covers, the question to answer and its framework links."),
                "Control": st.column_config.TextColumn(width=210, pinned=True),
                "Status": st.column_config.SelectboxColumn(
                    options=STATUS_OPTIONS, required=True, width=115),
                "Note": st.column_config.TextColumn(
                    width=330, max_chars=2000,
                    help="Pre-filled with the AI's reasoning. Edit to add or replace with your "
                         "own assessment."),
                "Reviewed": st.column_config.CheckboxColumn(
                    width=95,
                    help="Tick to confirm the AI evaluation after checking it. Changing a "
                         "status or note also counts as reviewed."),
                "AI evaluation": st.column_config.TextColumn(
                    width=170, help="The AI's suggested status · confidence · source"),
                "AI cited": st.column_config.TextColumn(
                    width=280, help="Sentence from the description, or diagram element, "
                                    "the AI relied on"),
                "Basis": st.column_config.TextColumn(
                    width=150,
                    help="What the status rests on. Refreshes when you change the filter or "
                         "search, or click Refresh."),
                "Question": st.column_config.TextColumn(
                    "Assessment question", width=280,
                    help="The question a reviewer answers to judge this control"),
                "Layer": st.column_config.TextColumn(width=120),
            })
        _control_details(visible)

        who = st.session_state.get("reviewer") or ""
        edits = (st.session_state.get(editor_key) or {}).get("edited_rows", {})
        apply_editor_changes(rows, visible, edits, who)
        if edits and st.button("↻ Refresh Basis and Reviewed columns",
                               help="Your edits are already saved. This redraws the table "
                                    "so the derived columns catch up."):
            st.session_state["decl_ver"] += 1
            st.rerun(scope="fragment")

        # soft prompt (never blocks the run): rows where a reviewer note is expected
        attention = [(cid, needs_note(rows[cid])) for cid in (c.id for c in expected)]
        attention = [(cid, why) for cid, why in attention if why]
        if attention:
            st.warning(f"{len(attention)} control(s) would benefit from a reviewer note — "
                       "you can still run the threat model without them. Tick 'Only rows "
                       "needing a note' to filter to them.")
            with st.popover("Which ones and why"):  # older Streamlit cannot nest expanders
                for cid, why in attention:
                    st.markdown(f"- **{cid}** {_CTRL[cid].title} — {why}")
        if not who.strip():
            st.caption("Tip: enter your name under *Reviewer* in the sidebar so changes are "
                       "attributed to you in the report.")


_declaration_table()

# recomputed on the full rerun that Run triggers, so always current there
attention = [cid for cid in (c.id for c in expected) if needs_note(rows[cid])]

declared: list[LedgerEntry] = to_ledger(rows, expected)

obs_raw = st.text_area("Other controls you implement that may not be in the catalog "
                       "(one per line: name — description)", height=80, key="obs_raw")
observed = []
for line in obs_raw.splitlines():
    if "—" in line or "-" in line:
        sep = "—" if "—" in line else "-"
        n, _, d = line.partition(sep)
        if n.strip():
            observed.append(ObservedControl(name=n.strip(), description=d.strip()))

# ---- step 4: run ----
if st.button("Run threat model", type="primary"):
    if diagrams and not st.session_state.get("_detected_done"):
        st.warning("You uploaded diagrams but didn't click Detect — they won't be read. "
                   "Click Detect first to pull controls from the images.")
    if attention:
        st.toast(f"Running with {len(attention)} control(s) still missing a reviewer note.")
    try:
        engine = build_engine(engine_choice, model_id, api_key=api_key, base_url=base_url,
                              max_tokens=max_out_tokens)
    except Exception as exc:                       # noqa: BLE001
        st.error(f"Could not initialize {engine_choice}: {exc}")
        st.stop()
    try:
        # diagrams already incorporated via Detect -> declaration; don't re-read them here
        # threats build on the SAD's architecture (flow 2) or on what Detect read (flow 3)
        arch = ((_handoff.sad.architecture if (_handoff is not None and _handoff.sad) else None)
                or st.session_state.get("_detect_arch"))
        report = pipeline.run(profile, description=description, declared=declared,
                              observed_unmatched=observed, engine=engine,
                              controls=catalog.controls, architecture=arch)
        if _handoff is None:
            report.input_completeness = list(st.session_state.get("_detect_completeness") or [])
        if _handoff is not None:   # keep the SAD record, marked as reviewed
            report.sad = reviewed_sad_context(_handoff, profile,
                                              st.session_state.get("reviewer"))
        report.diagrams_read = list(st.session_state.get("_diagrams_read") or [])
        report.diagrams_skipped = list(st.session_state.get("_diagrams_skipped") or [])
        report.engine = (engine_choice if engine_choice == "Deterministic (offline)"
                         else f"{engine_choice} · {model_id}")
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
