"""
Streamlit integration surface for the catalog-driven threat modeling engine.

Two-step evidence flow:

  1. "Detect controls" reads the architecture diagram (vision, LLM engines only)
     and the description (keyword detector), and PRE-FILLS the declaration with
     what it found — so you review and adjust rather than declare from scratch.
  2. "Run threat model" uses the (reviewed) declaration to compute the gap and
     render the report.

All logic lives in the `threatcatalog` package; this file is just intake + render.

Run:  streamlit run app/streamlit_app.py
"""

from __future__ import annotations

import streamlit as st

from threatcatalog import pipeline
from threatcatalog.catalog import Catalog, resolve
from threatcatalog.intake import declaration_template, detect_from_text
from threatcatalog.models import (AICapability, AppProfile, Confidence,
                                  ControlStatus, DataClassification,
                                  LedgerEntry, ObservedControl, PlatformFacet,
                                  Provenance)
from threatcatalog.report import render_markdown

st.set_page_config(page_title="Catalog Threat Modeling", layout="wide")
st.title("Catalog-driven, gap-based threat modeling")

catalog = Catalog.load()
st.caption(f"Catalog loaded: {len(catalog)} controls across all layers.")

DEFAULT_MODEL = {"OpenAI (ChatGPT)": "gpt-5.2", "Anthropic (Claude)": "claude-sonnet-4-6"}


def build_engine(choice: str, model_id: str, api_key: str = "", base_url: str = ""):
    """Return an ArtifactEngine for the chosen provider, or None for offline.

    api_key (from the UI) overrides the environment variable when provided;
    leaving it blank falls back to OPENAI_API_KEY / ANTHROPIC_API_KEY.
    """
    if choice == "OpenAI (ChatGPT)":
        from threatcatalog.llm import LLMArtifactEngine, OpenAIRawLLM
        return LLMArtifactEngine(OpenAIRawLLM(model=model_id, api_key=api_key or None,
                                              base_url=base_url or None))
    if choice == "Anthropic (Claude)":
        from threatcatalog.llm import AnthropicRawLLM, LLMArtifactEngine
        return LLMArtifactEngine(AnthropicRawLLM(model=model_id, api_key=api_key or None))
    return None  # Deterministic (offline) — pipeline default


with st.sidebar:
    st.header("0 · Model engine")
    engine_choice = st.selectbox(
        "Generation engine",
        ["OpenAI (ChatGPT)", "Anthropic (Claude)", "Deterministic (offline)"],
        help="Deterministic needs no API key. OpenAI/Anthropic build the "
             "narrative with the model you name below, and read the diagram.")
    model_id, api_key, base_url = "", "", ""
    if engine_choice != "Deterministic (offline)":
        model_id = st.text_input("Model id", DEFAULT_MODEL[engine_choice],
                                 help="e.g. gpt-5.2, gpt-4o, claude-sonnet-4-6 — "
                                      "whatever your org provides.")
        key_env = "OPENAI_API_KEY" if engine_choice.startswith("OpenAI") else "ANTHROPIC_API_KEY"
        api_key = st.text_input("API key (optional — overrides env var)", type="password",
                                help=f"Leave blank to use {key_env} from the environment.")
        if engine_choice.startswith("OpenAI"):
            base_url = st.text_input("API base URL (optional)",
                                     help="For an org gateway / Azure endpoint. Blank = default OpenAI.")

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
st.caption("Detect reads the description (keyword match) and — with an LLM engine — "
           "the diagram (vision), then pre-fills the declaration below. The diagram "
           "is read here, not at run time. Vision only ever reports controls it can "
           "*see*; it never marks one absent, so unseen controls stay 'unknown'.")

if st.button("🔍 Detect controls from diagram + description"):
    detected: dict[str, tuple[str, str]] = {}   # control_id -> (status, source)
    for e in detect_from_text(description, expected):
        detected[e.control_id] = (e.status.value, "description")
    if diagram_image is not None and engine_choice != "Deterministic (offline)":
        try:
            eng = build_engine(engine_choice, model_id, api_key=api_key, base_url=base_url)
            for e in eng.extract_controls(expected, diagram_image, diagram_media_type):
                detected[e.control_id] = (e.status.value, "diagram")   # vision wins over text
        except Exception as exc:                 # noqa: BLE001 — surface vision/auth errors, keep text detection
            st.warning(f"Diagram reading skipped ({exc}). Description detection still applied.")
    elif diagram_image is not None:
        st.info("Diagram uploaded but the offline engine can't read it — pick OpenAI or "
                "Anthropic to extract controls from the image.")
    # write detected statuses into the declaration widgets' state, then rerun
    for cid, (status, _src) in detected.items():
        st.session_state[f"decl_{cid}"] = status
    st.session_state["_detected"] = detected
    st.session_state["_detected_done"] = True
    st.rerun()

_detected = st.session_state.get("_detected", {})
if _detected:
    by_diagram = sum(1 for _, s in _detected.values() if s == "diagram")
    by_desc = sum(1 for _, s in _detected.values() if s == "description")
    st.success(f"Pre-filled {len(_detected)} control(s) — {by_diagram} from the diagram, "
               f"{by_desc} from the description. Review and adjust below.")

# ---- step 3b: declaration (pre-filled from detection where available) ----
declared: list[LedgerEntry] = []
with st.expander("Control declaration", expanded=bool(_detected)):
    for q in declaration_template(expected):
        cid = q["control_id"]
        src = _detected.get(cid, (None, None))[1]
        label = f"{cid} · {q['title']}" + (f"   ⟵ from {src}" if src else "")
        # key-based default: session_state[f"decl_{cid}"] (set by Detect) pre-selects it
        status = st.selectbox(label, STATUS_OPTIONS, key=f"decl_{cid}", help=q["question"])
        if status != "unknown":
            declared.append(LedgerEntry(
                control_id=cid, status=ControlStatus(status),
                provenance=Provenance.DECLARED, confidence=Confidence.HIGH))

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
    try:
        engine = build_engine(engine_choice, model_id, api_key=api_key, base_url=base_url)
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
