"""
SAD threat model — upload a Solution Architecture Document, get a threat model.

  1. Upload the SAD (DOCX / PDF / Markdown), optionally with extra diagram images.
  2. Check: one LLM call scores the SAD against a fixed completeness rubric and
     proposes the application profile. If a hard minimum is missing the page
     STOPS and offers the SAD author a feedback checklist instead of a report.
  3. Confirm: the one human checkpoint — the proposed profile, each facet with
     its reason, pre-filled. One click to continue.
  4. Run: controls are detected in the text and every diagram; controls the SAD
     does not mention are NOT PRESENT, controls only implied are PARTIAL (to be
     confirmed). Report downloads as Word or PDF, plus the declaration JSON
     that the review page can load for a human pass.

All logic lives in `threatcatalog.sad` / `threatcatalog.sad_extract`.
"""

from __future__ import annotations

import hashlib

import pandas as pd
import streamlit as st

from threatcatalog.env import load_dotenv

load_dotenv()

from threatcatalog.catalog import Catalog, resolve  # noqa: E402
from threatcatalog.declaration import export_json  # noqa: E402
from threatcatalog.llm.factory import (ANTHROPIC, BEDROCK, OPENAI, build_engine,  # noqa: E402
                                       default_model)
from threatcatalog.models import (AICapability, AppProfile, DataClassification,  # noqa: E402
                                  FacetReason, PlatformFacet, RubricScore)
from threatcatalog.report import render_markdown  # noqa: E402

DOCX_MIME = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"


def feedback_docx() -> bytes:
    from threatcatalog.docx_export import render_feedback_docx
    return render_feedback_docx(doc, a)
from threatcatalog import sad as sadflow  # noqa: E402
from threatcatalog.sad_extract import SadExtractionError, add_images, extract  # noqa: E402

st.set_page_config(page_title="SAD Threat Model", layout="wide")
st.title("Threat model from a solution architecture document")
st.caption("Upload a SAD and get an automated threat model. The SAD is checked for "
           "completeness first; you confirm the detected application profile once; "
           "everything else is automatic. Controls the SAD does not mention are reported "
           "as **not present**, and controls it only implies are **partial** and need "
           "confirmation.")

catalog = Catalog.load()
SCORE_ICON = {RubricScore.PRESENT: "✅ present", RubricScore.THIN: "⚠️ thin",
              RubricScore.MISSING: "❌ missing"}

# ---------------------------------------------------------------- sidebar ----
with st.sidebar:
    st.header("Model engine")
    choice = st.selectbox("Provider", [BEDROCK, OPENAI, ANTHROPIC],
                          help="A SAD needs a model that reads text and images.")
    model_id = st.text_input("Model id", default_model(choice),
                             help="Bedrock: a model or inference-profile id from your account "
                                  "(BEDROCK_MODEL_ID pre-fills this). OpenAI / Anthropic: e.g. "
                                  "gpt-5.2, claude-sonnet-4-6.")
    api_key = base_url = region = aws_profile = ""
    if choice == BEDROCK:
        region = st.text_input("AWS region (optional)", help="Blank = AWS_REGION from the environment.")
        aws_profile = st.text_input("AWS profile (optional)", help="Blank = default AWS credential chain.")
        endpoint = f"AWS Bedrock in your account ({region or 'region from environment'})"
    else:
        api_key = st.text_input("API key (optional — overrides env var)", type="password")
        if choice == OPENAI:
            base_url = st.text_input("API base URL (optional)", help="Org gateway / Azure endpoint.")
        endpoint = (base_url or ("api.openai.com" if choice == OPENAI else "api.anthropic.com"))
    max_tokens = st.number_input(
        "Max output tokens", min_value=8192, max_value=128000, value=64000, step=8192,
        help="Generous by default: a large SAD on a reasoning model burns many reasoning "
             "tokens before it writes anything. On Bedrock, if a model's limit is lower the "
             "call is retried at that model's limit automatically.")
    st.header("Reviewer")
    reviewer = st.text_input("Your name", key="sad_reviewer",
                             help="Recorded as the person who confirmed the profile.")


def get_engine():
    return build_engine(choice, model_id, api_key=api_key, base_url=base_url,
                        max_tokens=int(max_tokens), region=region, aws_profile=aws_profile)


engine_label = f"{choice} · {model_id or '(no model id)'}"
ss = st.session_state

# ----------------------------------------------------------------- upload ----
st.subheader("1 · Upload the SAD")
up = st.file_uploader("Solution architecture document", type=["docx", "pdf", "md", "markdown", "txt"])
extra = st.file_uploader("Extra diagram images (optional — PNG / JPG)", type=["png", "jpg", "jpeg"],
                         accept_multiple_files=True,
                         help="Use this when diagrams are in a separate file, or embedded as "
                              "Visio/EMF figures that cannot be read from the document.")
if up is None:
    st.info("Upload a DOCX, PDF or Markdown SAD to begin.")
    st.stop()

blob = up.getvalue()
extra_key = tuple((f.name, f.size) for f in extra or [])
key = (up.name, len(blob), extra_key)
if ss.get("sad_key") != key:
    for k in [k for k in ss.keys() if k.startswith("sad_") and k != "sad_reviewer"]:
        del ss[k]
    ss["sad_key"] = key
    try:
        doc = extract(up.name, blob)
        add_images(doc, [(f.name, f.getvalue()) for f in extra or []])
    except SadExtractionError as exc:
        st.error(str(exc))
        st.stop()
    ss["sad_doc"] = doc
doc = ss["sad_doc"]

c1, c2, c3, c4 = st.columns(4)
c1.metric("Words", f"{doc.words:,}")
c2.metric("Pages", (f"~{doc.pages}" if doc.pages_estimated else doc.pages) if doc.pages else "—",
          help="Estimated for Word files: a DOCX has no fixed pages, so this is worked out "
               "from the word and figure count (Word's own figure is used when it is "
               "current)." if doc.pages_estimated else None)
c3.metric("Diagrams to read", len(doc.images))
c4.metric("Approx. input tokens", f"{doc.approx_tokens:,}")
if doc.approx_tokens > 150_000:
    st.warning("This is a very large SAD. Some models' context windows will not hold it with "
               "the control list; prefer a long-context model.")
for n in doc.notes:
    st.info(n)
if doc.skipped:
    with st.expander(f"{len(doc.skipped)} figure(s) could not be read"):
        for s_ in doc.skipped:
            st.markdown(f"- {s_}")
if doc.images:
    with st.expander("Diagrams that will be read"):
        cols = st.columns(3)
        for i, img in enumerate(doc.images):
            cols[i % 3].image(img.data, caption=f"Diagram {i + 1}: {img.label}")

st.warning(f"**Confidentiality:** the full text of `{up.name}` and its diagrams will be sent to "
           f"**{choice}** ({endpoint}). Use your organisation's approved endpoint for "
           "Confidential or Restricted documents.")
# keyed to the upload: a new file (or new extra diagrams) gets a fresh, unticked box.
# One shared key was cleared above on every new upload, which left the box drawn
# ticked while the server saw it unticked and kept the Check button disabled.
_upload_id = hashlib.sha256(repr(key).encode()).hexdigest()[:16]
consent = st.checkbox("I confirm this document may be sent to this provider",
                      key=f"sad_consent_{_upload_id}")

# ------------------------------------------------------------------ check ----
st.subheader("2 · Check the SAD")
if st.button("🔎 Check completeness and detect the application profile",
             disabled=not consent or not model_id):
    try:
        with st.spinner("Reading the SAD and its diagrams…"):
            ss["sad_check_n"] = ss.get("sad_check_n", 0) + 1   # fresh profile table
            ss["sad_assessment"] = sadflow.assess(get_engine(), doc,
                                                  fallback_name=up.name.rsplit(".", 1)[0])
    except Exception as exc:  # noqa: BLE001 — surface provider/auth errors
        st.error(f"The check failed with {engine_label}: {exc}")
        st.stop()
if not model_id:
    st.caption("Enter a model id in the sidebar.")

a: sadflow.SadAssessment | None = ss.get("sad_assessment")
if a is None:
    st.stop()


def completeness_table():
    st.dataframe(pd.DataFrame([{
        "Item": i.title, "Result": SCORE_ICON[i.score],
        "Required to proceed": "yes" if i.hard_minimum else "",
        "Evidence / what to add": (i.evidence if i.score == RubricScore.PRESENT else i.comment) or "",
    } for i in a.completeness]), hide_index=True, use_container_width=True)


fname = (a.application_name or "SAD").replace(" ", "_")
if not a.sufficient:
    st.error("**This SAD is not sufficient for a threat model, so no report was produced.**\n\n"
             + "\n".join(f"- {r}" for r in a.stop_reasons))
    completeness_table()
    st.download_button("⬇ Download SAD feedback for the author (Word)", feedback_docx(),
                       file_name=f"{fname}_SAD_feedback.docx", mime=DOCX_MIME)
    st.stop()

gaps = a.gaps
st.success(f"The SAD is sufficient to threat model"
           + (f", with {len(gaps)} gap(s) that will be listed as limitations." if gaps else "."))
with st.expander("Completeness check", expanded=bool(gaps)):
    completeness_table()

# ---------------------------------------------------------------- confirm ----
st.subheader("3 · Confirm the application profile")
st.caption("Pre-filled from the AI's reading of the SAD. Facets marked *assumed* were "
           "inferred or defaulted: check those. Changes you make are recorded in the report.")
by_key = {f.facet: f for f in a.facets}
name = st.text_input("Application name", a.application_name)

# One row per platform and AI facet, so any of them can be switched on or off here.
_FACET_ROWS = [f"platform:{p.value}" for p in PlatformFacet] + \
              [f"ai:{x.value}" for x in AICapability if x != AICapability.NONE]
_AI_TINT, _REF_TINT = "rgba(59, 130, 246, 0.12)", "rgba(128, 128, 128, 0.10)"
_FACET_AI_COLS = ["AI proposal", "Assumed", "Reason", "Quote"]


def _facet_label(k: str) -> str:
    kind, val = k.split(":", 1)
    return ("Platform: " if kind == "platform" else "AI: ") + val


facet_table = pd.DataFrame([{
    "Facet": _facet_label(k),
    "Include": bool(by_key[k].selected) if k in by_key else False,
    "AI proposal": ("yes" if by_key[k].selected else "no") if k in by_key else "not raised",
    "Assumed": "assumed" if k in by_key and by_key[k].assumed else "",
    "Reason": (by_key[k].reason or "") if k in by_key else "",
    "Quote": (by_key[k].quote or "") if k in by_key else "",
} for k in _FACET_ROWS])
st.caption("**The white column with a pencil icon is yours to edit** (Include). "
           ":blue-background[Blue] columns are the AI's proposal and its reasons and "
           ":gray-background[grey] names the facet; both are read-only.")
edited = st.data_editor(
    facet_table.style.set_properties(subset=_FACET_AI_COLS, **{"background-color": _AI_TINT})
                     .set_properties(subset=["Facet"], **{"background-color": _REF_TINT}),
    key=f"sad_facets_{_upload_id}_{ss.get('sad_check_n', 0)}", hide_index=True, use_container_width=True,
    num_rows="fixed", disabled=["Facet"] + _FACET_AI_COLS, row_height=56,
    height=56 * len(facet_table) + 38,
    column_config={
        "Facet": st.column_config.TextColumn(width=150, pinned=True),
        "Include": st.column_config.CheckboxColumn(
            width=80, help="Tick to include this facet's controls in the threat model."),
        "AI proposal": st.column_config.TextColumn(width=100),
        "Assumed": st.column_config.TextColumn(width=90),
        "Reason": st.column_config.TextColumn(width=360),
        "Quote": st.column_config.TextColumn(width=300),
    })
_included = {k for k, inc in zip(_FACET_ROWS, edited["Include"]) if inc}
platforms = [k.split(":", 1)[1] for k in _FACET_ROWS if k.startswith("platform:") and k in _included]
ai = [k.split(":", 1)[1] for k in _FACET_ROWS if k.startswith("ai:") and k in _included]

_dc_f = next((f for f in a.facets if f.facet.startswith("data:")), None)
_pci_f = by_key.get("pci")
dc = st.selectbox("Data classification", [d.value for d in DataClassification],
                  index=[d for d in DataClassification].index(a.data_classification))
if _dc_f is not None and _dc_f.reason:
    st.caption(f"AI proposal: {_dc_f.facet[5:]}{' (assumed)' if _dc_f.assumed else ''}. "
               f"{_dc_f.reason}")
pci = st.checkbox("Handles cardholder data (PCI in scope)", value=a.handles_cardholder_data)
if _pci_f is not None and _pci_f.reason:
    st.caption(f"AI proposal: PCI {'in' if _pci_f.selected else 'out of'} scope"
               f"{' (assumed)' if _pci_f.assumed else ''}. {_pci_f.reason}")
profile = AppProfile(name=name or a.application_name,
                     platforms=[PlatformFacet(p) for p in platforms] or [PlatformFacet.WEB],
                     ai_capabilities=[AICapability(x) for x in ai] or [AICapability.NONE],
                     data_classification=DataClassification(dc), handles_cardholder_data=pci)
expected = resolve(profile, catalog.controls)
st.caption(f"{len(expected)} controls are expected for this profile.")


def final_facets() -> list[FacetReason]:
    """The proposal, with every reviewer change recorded as such."""
    out: list[FacetReason] = []
    chosen = {f"platform:{p.value}" for p in profile.platforms} | \
             {f"ai:{x.value}" for x in profile.ai_capabilities if x != AICapability.NONE}
    who = reviewer.strip() or "reviewer"
    for f in a.facets:
        if f.facet.startswith(("platform:", "ai:")):
            now = f.facet in chosen
            if now != f.selected:
                f = f.model_copy(update={"selected": now, "source": "reviewer", "assumed": False,
                                         "reason": f"{'Added' if now else 'Removed'} by {who}. "
                                                   f"AI proposal: {f.reason or '—'}"})
            out.append(f)
        elif f.facet.startswith("data:"):
            if dc != a.data_classification.value:
                out.append(FacetReason(facet=f"data:{dc}", selected=True, source="reviewer",
                                       reason=f"Set by {who}; proposed {f.facet[5:]}."))
            else:
                out.append(f)
        elif f.facet == "pci":
            if pci != a.handles_cardholder_data:
                out.append(FacetReason(facet="pci", selected=pci, source="reviewer",
                                       reason=f"Set by {who}; proposed {'yes' if f.selected else 'no'}."))
            else:
                out.append(f)
    for key_ in sorted(chosen - set(by_key)):
        out.append(FacetReason(facet=key_, selected=True, source="reviewer",
                               reason=f"Added by {who}."))
    return out


# -------------------------------------------------------------------- run ----
st.subheader("4 · Run the threat model")
if st.button("✅ Looks right — run the threat model", type="primary"):
    try:
        with st.status("Running the threat model…", expanded=True) as status:
            report, ledger = sadflow.run(doc, a, profile, get_engine(), catalog.controls,
                                         engine_label=engine_label,
                                         confirmed_by=reviewer.strip() or None,
                                         facets=final_facets(), progress=status.write)
            status.update(label="Threat model ready", state="complete")
    except Exception as exc:  # noqa: BLE001
        st.error(f"The run failed with {engine_label}: {exc}")
        st.stop()
    ss["sad_report"], ss["sad_ledger"] = report, ledger

report = ss.get("sad_report")
if report is None:
    st.stop()

counts: dict[str, int] = {}
for gi in report.gap_items:
    counts[gi.status.value] = counts.get(gi.status.value, 0) + 1
st.success(f"{len(report.threats)} threats · {counts.get('implemented', 0)} implemented · "
           f"{counts.get('partial', 0)} partial · {counts.get('not_present', 0)} not present · "
           f"PCI in scope: {report.pci_view.in_scope}")
flagged = [e.control_id for e in ss["sad_ledger"] if e.detail and e.detail.quote_supports is False]
if flagged:
    st.warning(f"**{len(flagged)} control(s) cite a quote that does not clearly support their "
               "status:** " + ", ".join(flagged) + ". Statuses are unchanged; the reason is shown "
               "next to the quote in the evidence appendix, and the review page flags these rows "
               "for a reviewer note.")
md = render_markdown(report)
rname = report.profile.name.replace(" ", "_")
d1, d2, d3, d4 = st.columns(4)
try:
    from threatcatalog.docx_export import render_docx
    d1.download_button("⬇ Report (Word)", render_docx(report),
                       file_name=f"{rname}_threat_model.docx", mime=DOCX_MIME)
except Exception as exc:  # noqa: BLE001
    d1.caption(f"Word export needs python-docx — `pip install python-docx`. ({exc})")
try:
    from threatcatalog.pdf_export import render_pdf
    d2.download_button("⬇ Report (PDF)", render_pdf(report), file_name=f"{rname}_threat_model.pdf",
                       mime="application/pdf")
except Exception as exc:  # noqa: BLE001
    d2.caption(f"PDF export needs reportlab — `pip install reportlab`. ({exc})")
d3.download_button("⬇ Declaration (JSON)",
                   export_json(sadflow.declaration_rows(ss["sad_ledger"]),
                               meta=sadflow.declaration_meta(report, choice, model_id)),
                   file_name=f"{rname}_declaration.json", mime="application/json",
                   help="Load this on the main review page to confirm or correct each control. "
                        "It also carries the confirmed profile and the SAD record, "
                        "so the review page fills itself in.")
d4.download_button("⬇ SAD feedback (Word)", feedback_docx(),
                   file_name=f"{fname}_SAD_feedback.docx", mime=DOCX_MIME)
st.markdown(md)
