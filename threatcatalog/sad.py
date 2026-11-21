"""
threatcatalog.sad
=================

The SAD (solution architecture document) flow: upload a SAD, get a threat model.

    extract ─► assess (completeness rubric + profile, one LLM call)
            ─► STOP if a hard minimum is missing (feedback document instead of a report)
            ─► human confirms the profile (one screen)
            ─► resolve ─► detect controls in text + every diagram
            ─► SAD status rules ─► existing pipeline ─► report

SAD status rules (decided for this page; the review page keeps 'unknown is not
missing'):

* a control the SAD STATES is in place          → implemented (or partial if the SAD says it is limited)
* a control only IMPLIED by features / tech stack → partial, with a note that it must be confirmed
* a control the SAD says is absent                → not present
* a control the SAD does not mention at all      → NOT PRESENT. The report is
  deliberately harsh: whatever the SAD omits is taken as accepted by the business.

All of this is pure logic over the engine's output, so it is testable offline.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone

from .declaration import DeclarationRow
from .intake import quote_in_text
from .models import (AICapability, AppProfile, CompletenessItem, Confidence, Control,
                     ControlEvidence, ControlStatus, DataClassification, FacetReason,
                     LedgerEntry, ObservedControl, PlatformFacet, Provenance, RubricScore,
                     SadContext)
from .sad_extract import ExtractedSad

# --------------------------------------------------------------------------- #
# Completeness rubric
# --------------------------------------------------------------------------- #
RUBRIC: list[dict] = [
    {"id": "purpose", "title": "Purpose and business functions",
     "why": "Scopes the threats and the data at risk", "hard_minimum": True},
    {"id": "diagram", "title": "Architecture diagram",
     "why": "Shows components, trust boundaries and flows", "hard_minimum": True},
    {"id": "components", "title": "Components and technology stack",
     "why": "Drives platform facets and control detection", "hard_minimum": True},
    {"id": "data_flows", "title": "Data flows between components and external parties",
     "why": "Where tampering and disclosure happen", "hard_minimum": False},
    {"id": "data", "title": "Data handled and its classification (PII, cardholder data)",
     "why": "Sets data classification and the PCI gate", "hard_minimum": False},
    {"id": "identity", "title": "Users, roles, authentication and authorisation",
     "why": "Spoofing and elevation of privilege", "hard_minimum": False},
    {"id": "hosting", "title": "Hosting and deployment (cloud, on-prem, containers)",
     "why": "Platform facets", "hard_minimum": False},
    {"id": "network", "title": "Network zones and trust boundaries",
     "why": "Boundary-crossing threats", "hard_minimum": False},
    {"id": "integrations", "title": "Third-party and external integrations",
     "why": "Supply chain, API and messaging layers", "hard_minimum": False},
    {"id": "ai", "title": "AI / LLM usage, tools, MCP servers and agents (or a statement of none)",
     "why": "AI facets, the costliest to miss", "hard_minimum": False},
    {"id": "security_controls", "title": "Security controls",
     "why": "The evidence control detection relies on", "hard_minimum": False},
    {"id": "operations", "title": "Logging, monitoring, backup and disaster recovery",
     "why": "Repudiation and availability", "hard_minimum": False},
]
_RUBRIC_BY_ID = {r["id"]: r for r in RUBRIC}


def rubric_for_prompt() -> list[dict]:
    return [{"id": r["id"], "title": r["title"]} for r in RUBRIC]


# --------------------------------------------------------------------------- #
# Assessment (completeness + proposed profile)
# --------------------------------------------------------------------------- #
@dataclass
class SadAssessment:
    is_architecture_document: bool
    completeness: list[CompletenessItem]
    facets: list[FacetReason]
    platforms: list[PlatformFacet]
    ai_capabilities: list[AICapability]
    data_classification: DataClassification
    handles_cardholder_data: bool
    application_name: str
    document_title: str | None = None
    document_version: str | None = None
    notes: list[str] = field(default_factory=list)

    @property
    def stop_reasons(self) -> list[str]:
        """Why the SAD is insufficient for a threat model. Empty = go ahead."""
        out = []
        if not self.is_architecture_document:
            out.append("The file does not appear to be a solution architecture document.")
        for item in self.completeness:
            if item.hard_minimum and item.score == RubricScore.MISSING:
                out.append(f"Missing: {item.title}." + (f" {item.comment}" if item.comment else ""))
        return out

    @property
    def sufficient(self) -> bool:
        return not self.stop_reasons

    @property
    def gaps(self) -> list[CompletenessItem]:
        return [i for i in self.completeness if i.score != RubricScore.PRESENT]

    def profile(self) -> AppProfile:
        return AppProfile(name=self.application_name, platforms=self.platforms,
                          ai_capabilities=self.ai_capabilities or [AICapability.NONE],
                          data_classification=self.data_classification,
                          handles_cardholder_data=self.handles_cardholder_data)


def _s(v) -> str | None:
    if v is None:
        return None
    if isinstance(v, list):
        v = v[0] if v else None
        if v is None:
            return None
    s = str(v).strip()
    return s or None


def _bool(v) -> bool:
    if isinstance(v, bool):
        return v
    return str(v).strip().lower() in ("true", "yes", "y", "1", "selected")


def parse_assessment(raw: dict, sad: ExtractedSad, fallback_name: str = "Application") -> SadAssessment:
    """Normalise the model's assessment.

    The model reads the whole SAD and its diagrams, so it alone decides the
    profile: no keyword matching, which cannot tell "has no mobile app" from
    "has a mobile app". The prompt biases it towards inclusion: a facet it is
    unsure of comes back selected with basis 'inferred' and is marked `assumed`
    so it is confirmed on the profile screen."""
    raw = raw if isinstance(raw, dict) else {}
    notes: list[str] = []

    # ---- completeness ----
    scored = {}
    for r in raw.get("rubric") or []:
        if isinstance(r, dict) and _s(r.get("id")) in _RUBRIC_BY_ID:
            scored[_s(r.get("id"))] = r
    items: list[CompletenessItem] = []
    for spec in RUBRIC:
        r = scored.get(spec["id"], {})
        sc = (_s(r.get("score")) or "missing").lower()
        score = RubricScore(sc) if sc in {x.value for x in RubricScore} else RubricScore.MISSING
        comment = _s(r.get("comment"))
        if spec["id"] not in scored:
            comment = comment or "Not assessed by the model; treated as missing."
        if spec["id"] == "diagram" and not sad.has_diagram:
            score = RubricScore.MISSING          # deterministic: nothing we could read
            comment = ("No readable architecture diagram was found in the document"
                       + (f" ({len(sad.skipped)} figure(s) could not be read; export them as "
                          "PNG and upload them alongside the SAD)" if sad.skipped else "")
                       + ".")
        items.append(CompletenessItem(id=spec["id"], title=spec["title"], score=score,
                                      hard_minimum=spec["hard_minimum"],
                                      evidence=_s(r.get("evidence")), comment=comment))

    # ---- facets ----
    llm: dict[str, dict] = {}
    for group, prefix in (("platforms", "platform"), ("ai_capabilities", "ai")):
        for r in raw.get(group) or []:
            if isinstance(r, dict) and _s(r.get("facet")):
                llm[f"{prefix}:{_s(r.get('facet')).lower()}"] = r

    facets: list[FacetReason] = []

    def decide(key: str) -> bool:
        r = llm.get(key)
        if r is None:
            return False
        if _bool(r.get("selected")):
            inferred = (_s(r.get("basis")) or "stated").lower() == "inferred"
            facets.append(FacetReason(facet=key, selected=True, reason=_s(r.get("reason")) or "",
                                      quote=_s(r.get("quote")), assumed=inferred, source="llm"))
            return True
        facets.append(FacetReason(facet=key, selected=False, reason=_s(r.get("reason")) or "",
                                  quote=_s(r.get("quote")), source="llm"))
        return False

    platforms = [p for p in PlatformFacet if decide(f"platform:{p.value}")]
    if not platforms:
        platforms = [PlatformFacet.WEB]
        facets.append(FacetReason(facet="platform:web", selected=True, assumed=True,
                                  source="default",
                                  reason="No platform could be identified; web assumed. Confirm."))
    ai = [a for a in AICapability if a != AICapability.NONE and decide(f"ai:{a.value}")]

    # ---- data classification ----
    dc_raw = raw.get("data_classification") if isinstance(raw.get("data_classification"), dict) else {}
    dc_val = (_s(dc_raw.get("value")) or "").capitalize()
    if dc_val in {d.value for d in DataClassification}:
        dc = DataClassification(dc_val)
        facets.append(FacetReason(facet=f"data:{dc.value}", selected=True,
                                  reason=_s(dc_raw.get("reason")) or "", quote=_s(dc_raw.get("quote"))))
    else:
        dc = DataClassification.CONFIDENTIAL
        facets.append(FacetReason(facet="data:Confidential", selected=True, assumed=True,
                                  source="default",
                                  reason="The SAD does not state a data classification; "
                                         "Confidential assumed."))
        notes.append("Data classification not stated in the SAD; Confidential assumed.")

    # ---- PCI ----
    pci_raw = raw.get("cardholder_data") if isinstance(raw.get("cardholder_data"), dict) else {}
    pci_val = (_s(pci_raw.get("value")) or "not_stated").lower()
    if pci_val == "yes":
        pci = True
        facets.append(FacetReason(facet="pci", selected=True, reason=_s(pci_raw.get("reason")) or "",
                                  quote=_s(pci_raw.get("quote")), source="llm"))
    else:
        pci = False
        stated = pci_val == "no"
        facets.append(FacetReason(
            facet="pci", selected=False, assumed=not stated,
            reason=(_s(pci_raw.get("reason")) or "The SAD says no cardholder data is handled.")
            if stated else "PCI scope is not stated in the SAD; treated as out of scope.",
            quote=_s(pci_raw.get("quote")), source="llm" if stated else "default"))
        if not stated:
            notes.append("PCI scope not stated in the SAD; treated as out of scope.")

    name = _s(raw.get("application_name")) or _s(raw.get("document_title")) or fallback_name
    is_doc = raw.get("is_architecture_document")
    return SadAssessment(
        is_architecture_document=True if is_doc is None else _bool(is_doc),
        completeness=items, facets=facets, platforms=platforms, ai_capabilities=ai,
        data_classification=dc, handles_cardholder_data=pci, application_name=name[:120],
        document_title=_s(raw.get("document_title")),
        document_version=_s(raw.get("document_version")), notes=notes)


def assess(engine, sad: ExtractedSad, fallback_name: str = "Application") -> SadAssessment:
    """Run the one assessment call and parse it."""
    raw = engine.assess_sad(sad.text, rubric_for_prompt(),
                            images=[(i.data, i.media_type) for i in sad.images],
                            image_labels=[i.label for i in sad.images])
    return parse_assessment(raw, sad, fallback_name)


# --------------------------------------------------------------------------- #
# SAD status rules → ledger
# --------------------------------------------------------------------------- #
NOT_STATED_NOTE = ("Not stated anywhere in the SAD (text, tables or diagrams), so recorded as "
                   "not present. If this control is in place, add it to the SAD.")
INFERRED_NOTE = ("Inferred, not stated in the SAD: needs to be confirmed or validated "
                 "before it can be relied on.")
UNVERIFIED_QUOTE_NOTE = ("The text the AI cited was not found verbatim in the SAD, so this is "
                         "recorded as partial: confirm.")


def build_sad_ledger(expected: list[Control], records: list[dict],
                     text: str = "", verify_quotes: bool = True) -> list[LedgerEntry]:
    """Apply the SAD status rules: one ledger entry for EVERY expected control."""
    by_id: dict[str, dict] = {}
    for r in records:
        cid = r.get("control_id")
        if cid and cid not in by_id:
            by_id[cid] = r
    out: list[LedgerEntry] = []
    for c in expected:
        r = by_id.get(c.id)
        if r is None:
            ev = ControlEvidence(ai_status=ControlStatus.NOT_PRESENT, ai_confidence=Confidence.MEDIUM,
                                 ai_source="sad", ai_basis="silent", ai_note=NOT_STATED_NOTE,
                                 note=NOT_STATED_NOTE)
            out.append(LedgerEntry(control_id=c.id, status=ControlStatus.NOT_PRESENT,
                                   provenance=Provenance.DESCRIPTION, confidence=Confidence.MEDIUM,
                                   evidence=NOT_STATED_NOTE, detail=ev))
            continue
        source = "diagram" if r.get("source") == "diagram" else "description"
        quote = r.get("quote")
        rationale = (r.get("rationale") or "").strip()
        basis = r.get("basis") if r.get("basis") in ("stated", "inferred") else "stated"
        status = r.get("status") if r.get("status") in ("implemented", "partial", "not_present") \
            else "implemented"
        verified = quote_in_text(quote, text) if (source == "description" and verify_quotes) else None
        conf = Confidence.HIGH if verified else Confidence.MEDIUM
        if basis == "inferred":
            status, conf = "partial", Confidence.LOW
            note = (rationale + " " if rationale else "") + INFERRED_NOTE
        elif verified is False and status != "not_present":
            status, conf = "partial", Confidence.LOW
            note = (rationale + " " if rationale else "") + UNVERIFIED_QUOTE_NOTE
        else:
            note = rationale or None
        st = ControlStatus(status)
        prov = Provenance.DIAGRAM_VISION if source == "diagram" else Provenance.DESCRIPTION
        ev = ControlEvidence(ai_status=st, ai_confidence=conf, ai_source=source, ai_note=note,
                             ai_basis=basis, ai_quote=quote, quote_verified=verified, note=note)
        out.append(LedgerEntry(control_id=c.id, status=st, provenance=prov, confidence=conf,
                               evidence=note or quote, detail=ev))
    return out


UNSUPPORTED_QUOTE_FLAG = "The cited quote does not clearly support this status"


def quote_check_items(ledger: list[LedgerEntry], expected: list[Control]) -> list[dict]:
    """Rows the quote check looks at: every AI status that rests on a text quote.
    Diagram citations are not re-checked (the check is text only, to stay cheap), and
    rows with no quote (not stated in the SAD) have nothing to check."""
    by_id = {c.id: c for c in expected}
    items = []
    for e in ledger:
        ev = e.detail
        if ev is None or not ev.ai_quote or ev.ai_source != "description":
            continue
        c = by_id.get(e.control_id)
        items.append({"control_id": e.control_id, "title": c.title if c else e.control_id,
                      "intent": (c.intent if c else "") or "", "status": e.status.value,
                      "quote": ev.ai_quote, "rationale": ev.ai_note or ""})
    return items


def apply_quote_check(engine, ledger: list[LedgerEntry], expected: list[Control]) -> str | None:
    """Ask the same model, in one call, whether each cited quote backs its status.
    Flags rows for the reviewer (`quote_supports=False`); never changes a status.
    Returns a note for the report's limitations, or None when nothing to say."""
    items = quote_check_items(ledger, expected)
    if not items:
        return None
    try:
        verdicts = engine.check_quotes(items)
    except Exception as exc:  # noqa: BLE001 — a failed check must not fail the run
        return f"The quote check could not run ({type(exc).__name__}); cited quotes were not checked."
    flagged = 0
    for e in ledger:
        v = verdicts.get(e.control_id)
        if v is None or e.detail is None:
            continue
        e.detail.quote_supports, reason = v[0], (v[1] or "").strip()
        if not v[0]:
            flagged += 1
            e.detail.support_note = reason or UNSUPPORTED_QUOTE_FLAG
    unchecked = len(items) - len(verdicts)
    note = (f"Quote check: {flagged} of {len(verdicts)} cited quote(s) do not clearly support "
            f"the status given; these are flagged for the reviewer in the evidence appendix.")
    if unchecked:
        note += f" {unchecked} quote(s) were not checked."
    return note


def declaration_meta(report, provider: str = "", model_id: str = "") -> dict:
    """Everything the review page needs besides the rows, saved in the declaration
    JSON: the confirmed profile (pre-fills the review page), the engine, and the SAD
    record (completeness, facet decisions, other controls) so the reviewed report
    keeps its SAD section."""
    sc: SadContext = report.sad
    return {"application": report.profile.name, "source": "sad",
            "sad_file": sc.source_file if sc else None, "sad_sha256": sc.sha256 if sc else None,
            "profile": report.profile.model_dump(mode="json"),
            "engine": {"provider": provider, "model_id": model_id},
            "sad": sc.model_dump(mode="json") if sc else None}


def declaration_rows(ledger: list[LedgerEntry]) -> dict[str, DeclarationRow]:
    """Ledger → rows the review page can load (Save/Load declaration JSON)."""
    return {e.control_id: DeclarationRow(control_id=e.control_id, status=e.status,
                                         evidence=(e.detail or ControlEvidence()).model_copy())
            for e in ledger}


# --------------------------------------------------------------------------- #
# Run
# --------------------------------------------------------------------------- #
MAX_OTHER_CONTROLS = 10


def build_context(sad: ExtractedSad, a: SadAssessment, engine_label: str,
                  confirmed_by: str | None = None, facets: list[FacetReason] | None = None,
                  other_controls: list[ObservedControl] | None = None) -> SadContext:
    notes = list(a.notes) + list(sad.notes)
    return SadContext(
        source_file=sad.filename, sha256=sad.sha256, pages=sad.pages,
        pages_estimated=sad.pages_estimated, words=sad.words,
        diagrams_read=[i.label for i in sad.images], diagrams_skipped=list(sad.skipped),
        engine=engine_label, document_title=a.document_title,
        document_version=a.document_version, completeness=a.completeness,
        facets=facets if facets is not None else a.facets, profile_confirmed_by=confirmed_by,
        notes=notes, other_controls=list(other_controls or []),
        generated_at=datetime.now(timezone.utc).replace(microsecond=0).isoformat())


def run(sad: ExtractedSad, assessment: SadAssessment, profile: AppProfile, engine,
        controls: list[Control], engine_label: str = "", confirmed_by: str | None = None,
        facets: list[FacetReason] | None = None, progress=None):
    """Detect controls in the SAD, apply the SAD rules, run the pipeline.
    Returns (report, ledger). `progress(msg)` is called before each slow step."""
    from . import pipeline
    from .catalog import resolve

    say = progress or (lambda _m: None)
    expected = resolve(profile, controls)
    say(f"Detecting {len(expected)} expected controls in the SAD text and "
        f"{len(sad.images)} diagram(s)…")
    records, others = engine.detect_sad_controls(
        expected, sad.text, images=[(i.data, i.media_type) for i in sad.images],
        image_labels=[i.label for i in sad.images])
    verify = not any("no text layer" in n for n in sad.notes)
    ledger = build_sad_ledger(expected, records, sad.text, verify_quotes=verify)
    check_note = None
    if hasattr(engine, "check_quotes"):
        say("Checking that each cited quote supports its control's status…")
        check_note = apply_quote_check(engine, ledger, expected)
    observed = [ObservedControl(name=o["name"], description=o.get("description", ""))
                for o in others[:MAX_OTHER_CONTROLS]]
    say("Generating threats, recommendations, mitigations and DREAD scores…")
    report = pipeline.run(profile, description="", declared=ledger, observed_unmatched=observed,
                          engine=engine, controls=controls)
    report.sad = build_context(sad, assessment, engine_label, confirmed_by, facets, observed)
    if check_note:
        report.sad.notes.append(check_note)
    return report, ledger


# --------------------------------------------------------------------------- #
# Feedback document when the SAD is insufficient
# --------------------------------------------------------------------------- #
_SCORE_LABEL = {RubricScore.PRESENT: "Present", RubricScore.THIN: "Thin", RubricScore.MISSING: "Missing"}


def feedback_markdown(sad: ExtractedSad, a: SadAssessment) -> str:
    """What the SAD author must add. Produced instead of a threat model when the
    SAD fails a hard minimum, and offered alongside the report otherwise."""
    title = a.document_title or sad.filename
    out = [f"# SAD review feedback — {title}\n",
           f"*File:* {sad.filename}  ",
           f"*SHA-256:* `{sad.sha256[:16]}…`  ",
           f"*Words:* {sad.words}  ·  *Diagrams read:* {len(sad.images)}\n"]
    reasons = a.stop_reasons
    if reasons:
        out.append("## Result: not enough to threat model\n")
        out.append("No threat model was produced. Fix the following and upload the SAD again:\n")
        out += [f"- {r}" for r in reasons]
        out.append("")
    else:
        out.append("## Result: sufficient, with gaps\n")
        out.append("A threat model was produced. Closing these gaps will make it more accurate.\n")
    out.append("## Completeness checklist\n")
    out.append("| Item | Result | Required to proceed | What to add |")
    out.append("|---|---|---|---|")
    for i in a.completeness:
        out.append(f"| {i.title} | {_SCORE_LABEL[i.score]} | {'Yes' if i.hard_minimum else 'No'} "
                   f"| {(i.comment or '—').replace('|', '/') if i.score != RubricScore.PRESENT else '—'} |")
    if sad.skipped:
        out.append("\n## Figures that could not be read\n")
        out += [f"- {s}" for s in sad.skipped]
    if sad.notes:
        out.append("\n## Notes\n")
        out += [f"- {n}" for n in sad.notes]
    return "\n".join(out) + "\n"
