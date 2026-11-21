"""
threatcatalog.report
====================

Renders a `ThreatModelReport` to Markdown. Pure formatting — no logic, no model
calls. Kept deliberately separate so the same report object can be rendered to
other formats (DOCX, JSON) without touching the engine.
"""

from __future__ import annotations

from .declaration import BASIS_LABEL
from .models import ControlStatus, EvidenceBasis, GapItem, ThreatModelReport

_STATUS_LABEL = {
    ControlStatus.IMPLEMENTED: "Implemented",
    ControlStatus.PARTIAL: "Partial",
    ControlStatus.NOT_PRESENT: "Not present",
    ControlStatus.UNKNOWN: "Unknown",
    ControlStatus.NOT_APPLICABLE: "N/A",
}


_SOURCE_LABEL = {"description": "description", "diagram": "diagram", "sad": "SAD",
                 "keyword": "description keyword match", "diagram_vision": "diagram"}
# In a SAD-based report (SAD page, or its declaration loaded on the review page) the
# text and figures the AI read are the SAD's, even though the rows record them under
# the generic "description" / "diagram" sources.
_SAD_SOURCE_LABEL = {"description": "SAD text", "diagram": "SAD diagram",
                     "diagram_vision": "SAD diagram", "sad": "SAD"}

_STRIDE_LABEL = {"Spoofing": "Spoofing", "Tampering": "Tampering", "Repudiation": "Repudiation",
                 "InformationDisclosure": "Information disclosure",
                 "DenialOfService": "Denial of service",
                 "ElevationOfPrivilege": "Elevation of privilege"}

_FW_LABEL = {"cis_v8": "CIS v8", "owasp_api": "OWASP API", "owasp_asi": "OWASP Agentic",
             "owasp_llm": "OWASP LLM", "owasp_masvs": "OWASP MASVS", "owasp_mcp": "OWASP MCP",
             "owasp_mobile": "OWASP Mobile"}

# The SAD rules' note for a control the SAD never mentions (see sad.NOT_STATED_NOTE).
_SAD_SILENT_PREFIX = "Not stated anywhere in the SAD"


def stride_label(s) -> str:
    """'ElevationOfPrivilege' -> 'Elevation of privilege' (readable, wraps cleanly)."""
    v = getattr(s, "value", s)
    return _STRIDE_LABEL.get(v, v)


def fw_name(framework: str, ref: str) -> str:
    """A framework reference with its framework named: 'CIS v8 Control 3'."""
    name = _FW_LABEL.get(framework, framework.replace("_", " ").upper() if framework else "")
    return f"{name} {ref}".strip()


def fw_labels(control) -> str:
    return ", ".join(fw_name(f.framework, f.ref) for f in control.threat_frameworks) or "\u2014"


def fw_text(s: str) -> str:
    """'cis_v8:Control 6' (recommendation frameworks) -> 'CIS v8 Control 6'."""
    fw, sep, ref = str(s).partition(":")
    return fw_name(fw, ref) if sep else str(s)


def threat_fw(r: "ThreatModelReport", t) -> str | None:
    """A threat's framework reference, named via its enabling control when it matches."""
    if not t.framework_ref:
        return None
    c = next((g.control for g in r.gap_items if g.control.id == t.enabling_gap), None)
    if c is not None:
        for f in c.threat_frameworks:
            if f.ref == t.framework_ref:
                return fw_name(f.framework, f.ref)
    return fw_text(t.framework_ref)


def clean_quote(q: str | None) -> str | None:
    """A quote lifted from a SAD table arrives as '| Cell | Cell |'. Show it as
    'Cell: Cell' so it reads as a sentence (display only; verification used the raw text)."""
    if not q or q.count("|") < 2:
        return q
    cells = [c.strip() for c in q.split("|")]
    cells = [c for c in cells if c and not set(c) <= set("-: ")]
    if not cells:
        return q
    return cells[0] if len(cells) == 1 else f"{cells[0]}: " + "; ".join(cells[1:])


def _ai_kept(gi: GapItem) -> bool:
    """The final status is still the AI's own (no reviewer override)."""
    ev = gi.evidence
    return (ev is not None and ev.ai_status == gi.status
            and gi.basis != EvidenceBasis.REVIEWER_OVERRIDE)


def sad_silent(gi: GapItem) -> bool:
    """Not present only because the SAD never mentions the control (and no reviewer
    has changed that status). Declarations saved before `ai_basis` existed are
    recognised by the SAD rules' note."""
    if gi.status != ControlStatus.NOT_PRESENT or not _ai_kept(gi):
        return False
    ev = gi.evidence
    if ev.ai_basis is not None:
        return ev.ai_basis == "silent"
    return (ev.ai_note or "").startswith(_SAD_SILENT_PREFIX)


def sad_inferred(gi: GapItem) -> bool:
    """Partial because the SAD only implies the control (needs confirming)."""
    return (gi.status == ControlStatus.PARTIAL and _ai_kept(gi)
            and gi.evidence.ai_basis == "inferred")


def needs_verification(gi: GapItem, auto: bool) -> bool:
    """Counted under "To verify". In an automated SAD run: partials the SAD only
    implies, or whose cited quote could not be found or does not back the status.
    On the review page: unknowns, and statuses still resting on unreviewed AI."""
    if gi.status == ControlStatus.NOT_APPLICABLE:
        return False
    if auto:
        ev = gi.evidence
        return gi.status == ControlStatus.PARTIAL and ev is not None and (
            ev.ai_basis == "inferred" or ev.quote_verified is False or ev.quote_supports is False)
    return gi.status == ControlStatus.UNKNOWN or gi.basis == EvidenceBasis.AI_UNREVIEWED


_REVIEWED = (EvidenceBasis.AI_CONFIRMED, EvidenceBasis.REVIEWER_OVERRIDE,
             EvidenceBasis.REVIEWER_ONLY)


def reviewers(r: "ThreatModelReport") -> list[str]:
    """Everyone recorded as having reviewed a control, plus the SAD record's reviewer."""
    names: list[str] = []
    for g in r.gap_items:
        who = (g.evidence.reviewer if g.evidence else None) or ""
        if who.strip() and who.strip() not in names:
            names.append(who.strip())
    if r.sad and r.sad.reviewed_by and r.sad.reviewed_by not in names:
        names.append(r.sad.reviewed_by)
    return names


def _flat(s: str | None) -> str:
    return " ".join((s or "").split())


def basis_label(gi: GapItem) -> str:
    return BASIS_LABEL.get(gi.basis, "\u2014") if gi.basis else "\u2014"


# Order of the evidence appendix: findings first, so AppSec reads gaps before passes.
EVIDENCE_ORDER = [ControlStatus.NOT_PRESENT, ControlStatus.PARTIAL, ControlStatus.UNKNOWN,
                  ControlStatus.IMPLEMENTED, ControlStatus.NOT_APPLICABLE]

EVIDENCE_TITLE = "Appendix \u2014 control evidence"
EVIDENCE_NOTE_SAD = ("Automated assessment. Every evaluation below was produced by an automated "
                     "run against the SAD; no person has reviewed it. Treat it as a starting "
                     "point that may need further analysis by AppSec before it is relied on.")
EVIDENCE_NOTE_REVIEW = ("Automated assessment. The AI evaluations below were produced "
                        "automatically and may need further analysis by AppSec. Each AI "
                        "evaluation is kept as first written; where a reviewer changed a "
                        "status or note, their change is shown next to it.")


def automated(r: ThreatModelReport) -> bool:
    """A SAD run nobody has reviewed: the AI evaluation is every row's status."""
    return r.sad is not None and not r.sad.reviewed


def sad_banner(r: ThreatModelReport) -> tuple[str, str] | None:
    """(bold lead, text) for the banner under the title of a SAD-based report."""
    if r.sad is None:
        return None
    if not r.sad.reviewed:
        return "Automated draft from SAD.", SAD_RULES_TEXT
    who = r.sad.reviewed_by or "a reviewer"
    return ("From SAD, then reviewed.",
            f"Statuses started from an automated assessment of the SAD and were then "
            f"reviewed by {who} on the review page. Where the reviewer changed a status or "
            f"note, the change is shown next to the AI evaluation in the evidence appendix.")


def evidence_note(r: ThreatModelReport) -> str:
    return EVIDENCE_NOTE_SAD if automated(r) else EVIDENCE_NOTE_REVIEW


def evidence_records(r: ThreatModelReport) -> list[dict]:
    """One record per control that has something to show in the evidence
    appendix \u2014 shared by the Markdown and PDF renderers. Every string is
    whitespace-flattened; renderers do their own escaping.

    In an automated (SAD) run nobody can review a row, so the review-only fields
    (`final_status`, `basis`, `reviewer_note`, `reviewed_by`) are left out: the AI
    evaluation *is* the status."""
    auto = automated(r)
    recs = []
    for gi in r.gap_items:
        ev = gi.evidence
        if gi.basis is None or ev is None:
            continue
        ai = None
        if ev.ai_status is not None:
            parts = [_STATUS_LABEL[ev.ai_status]]
            if ev.ai_confidence:
                parts.append(f"{ev.ai_confidence.value} confidence")
            if ev.ai_source:
                labels = _SAD_SOURCE_LABEL if r.sad is not None else _SOURCE_LABEL
                parts.append("from " + labels.get(ev.ai_source, ev.ai_source))
            ai = " \u00b7 ".join(parts)
        when = ""
        if ev.reviewed_at:
            when = ev.reviewed_at.replace("T", " ").replace("+00:00", " UTC")
        recs.append({
            "id": gi.control.id,
            "title": gi.control.title,
            "control": f"{gi.control.id} {gi.control.title}",
            "status_enum": gi.status,
            "status": _STATUS_LABEL[gi.status],
            "basis": None if auto else basis_label(gi),
            "ai_evaluation": ai,
            "quote": clean_quote(_flat(ev.ai_quote)) or None,
            "quote_unverified": ev.quote_verified is False,
            "quote_unsupported": (_flat(ev.support_note) or "the quote does not clearly support "
                                  "this status") if ev.quote_supports is False else None,
            "ai_note": _flat(ev.ai_note) if ev.ai_status is not None else None,
            "reviewer_note": None if auto else (_flat(ev.reviewer_note) or None),
            "reviewed_by": None if auto else (
                " \u00b7 ".join(x for x in (ev.reviewer, when) if x) or None),
        })
    return recs


def evidence_groups(r: ThreatModelReport) -> list[tuple[ControlStatus, list[dict]]]:
    """Evidence records grouped by final status, findings first; empty groups dropped."""
    recs = evidence_records(r)
    return [(st, g) for st in EVIDENCE_ORDER
            if (g := [x for x in recs if x["status_enum"] == st])]


def evidence_fields(rec: dict) -> list[tuple[str, str, str]]:
    """The labelled rows of one control card, in display order, as
    (key, label, raw value). Renderers escape and style the values."""
    out = []
    if rec["basis"] is not None:
        out.append(("final", "Final status", f"{rec['status']} \u00b7 {rec['basis']}"))
    if rec["ai_evaluation"]:
        out.append(("ai", "AI evaluation", rec["ai_evaluation"]))
    if rec["quote"]:
        out.append(("quote", "Cited evidence", rec["quote"]))
    if rec["ai_note"]:
        out.append(("ai_note", "AI rationale", rec["ai_note"]))
    if rec["reviewer_note"]:
        out.append(("reviewer_note", "Reviewer note", rec["reviewer_note"]))
    if rec["reviewed_by"]:
        out.append(("reviewed_by", "Reviewed by", rec["reviewed_by"]))
    return out


# --------------------------------------------------------------------------- #
# Plain-language helpers — make the summary readable for a non-specialist
# (e.g. a project manager reading only this report).
# --------------------------------------------------------------------------- #
_FACET_LABEL = {
    "web": "web", "cloud": "cloud", "onprem": "on-premises", "mobile": "mobile",
    "multitenant": "multi-tenant SaaS", "api": "API",
    "messaging": "event-driven", "container": "containerised",
}
_AI_LABEL = {
    "llm": "an LLM integration", "llm_tools": "an LLM with tool access",
    "mcp": "an MCP tool integration", "agentic": "agentic AI",
    "generative": "generative AI", "training": "in-house model training",
}


def _join_natural(items: list[str]) -> str:
    items = [i for i in items if i]
    if not items:
        return ""
    if len(items) == 1:
        return items[0]
    if len(items) == 2:
        return f"{items[0]} and {items[1]}"
    return ", ".join(items[:-1]) + f", and {items[-1]}"


def _humanize_profile(p) -> str:
    plats = _join_natural([_FACET_LABEL.get(f.value, f.value) for f in p.platforms])
    ai = [_AI_LABEL[a.value] for a in p.ai_capabilities if a.value in _AI_LABEL]
    ai_phrase = f" with {_join_natural(ai)}" if ai else ""
    return (f"{p.name} \u2014 a {plats} application{ai_phrase}, "
            f"handling data classified as {p.data_classification.value}")


def summary_facts(r: ThreatModelReport) -> dict:
    """Compute the executive-summary facts once, so the Markdown and PDF renderers
    share identical numbers and wording. Pure data + plain-language prose — no
    model calls, so the summary stays deterministic and auditable."""
    gi = r.gap_items
    not_present = [g for g in gi if g.status == ControlStatus.NOT_PRESENT]
    partial = [g for g in gi if g.status == ControlStatus.PARTIAL]
    implemented = [g for g in gi if g.status == ControlStatus.IMPLEMENTED]
    n_unknown = sum(1 for g in gi if g.status == ControlStatus.UNKNOWN)

    dread_by_threat = {d.threat_id: d for d in r.dread}

    p = r.profile

    counts = {
        "expected": r.resolved_control_count,
        "implemented": len(implemented),
        "not_present": len(not_present),
        "partial": len(partial),
        "gaps": len(not_present) + len(partial),
        "unknown": n_unknown,
        "in_scope": r.pci_view.in_scope,
        "pci_exposed": len(r.pci_view.exposed),
        "pci_indeterminate": len(r.pci_view.indeterminate),
        "pci_covered": r.pci_view.covered_count,
    }

    # ---- the headline pick: ONE ranked list, so the summary never shows two
    # "top" lists that disagree. Ranked by DREAD; at equal scores a finding backed by
    # evidence leads one resting on SAD silence, then missing before partial, then
    # PCI-exposed first. Falls back to the gap itself when no threat was scored.
    gap_by_id = {g.control.id: g for g in gi}
    ranked = []
    for t in r.threats:
        g = gap_by_id.get(t.enabling_gap or "")
        d = dread_by_threat.get(t.id)
        ranked.append(((-(d.average if d else 0.0),
                        1 if (g and sad_silent(g)) else 0,   # evidence before SAD silence
                        0 if (g and g.status == ControlStatus.NOT_PRESENT) else 1,
                        0 if (g and g.pci_exposed) else 1),
                       t, g, d))
    ranked.sort(key=lambda x: x[0])
    top_findings = []
    seen: set[str] = set()
    for _k, t, g, d in ranked:
        if len(top_findings) == 5:
            break
        cid = g.control.id if g else (t.enabling_gap or "")
        if cid and cid in seen:
            continue
        seen.add(cid)
        tags = (["PCI"] if (g and g.pci_exposed) else []) + \
               ([fw_name(g.control.threat_frameworks[0].framework, g.control.threat_frameworks[0].ref)]
                if (g and g.control.threat_frameworks) else [])
        top_findings.append({"priority": d.priority.value if d else None,
                             "score": d.average if d else None, "title": t.title,
                             "control_id": cid, "tags": tags})
    if not top_findings:
        for g in sorted(not_present + partial,
                        key=lambda g: (0 if g.status == ControlStatus.NOT_PRESENT else 1,
                                       0 if g.pci_exposed else 1))[:5]:
            verb = "is not in place" if g.status == ControlStatus.NOT_PRESENT else "is only partial"
            tags = (["PCI"] if g.pci_exposed else []) + \
                   ([fw_name(g.control.threat_frameworks[0].framework, g.control.threat_frameworks[0].ref)]
                    if g.control.threat_frameworks else [])
            top_findings.append({"priority": None, "score": None,
                                 "title": f"{g.control.title} {verb}",
                                 "control_id": g.control.id, "tags": tags})

    # strengths: required controls first, then PCI-mapped, then framework-mapped
    # (catalog order otherwise), so the most important protections lead.
    def _strength_key(g):
        c = g.control
        return (0 if c.default_expectation.value == "required" else 1,
                0 if c.pci else 1, 0 if c.threat_frameworks else 1)
    strengths = [(g.control.id, g.control.title)
                 for g in sorted(implemented, key=_strength_key)[:5]]
    n_silent = sum(1 for g in not_present if sad_silent(g))
    counts["sad_silent"] = n_silent
    auto = automated(r)
    counts["to_verify"] = sum(1 for g in gi if needs_verification(g, auto))
    counts["reviewed"] = None if auto else sum(1 for g in gi if g.basis in _REVIEWED)

    # ---- posture: a short, plain-language narrative (list of paragraphs) ----
    para1 = (f"{_humanize_profile(p)} \u2014 was assessed against the "
             f"{counts['expected']} security controls expected for an application of this "
             f"type (the controls such a system should have in place).")

    gap_clause = (f"identified {counts['gaps']} gap(s) \u2014 {counts['not_present']} not "
                  f"implemented and {counts['partial']} only partially implemented")
    para2 = (f"The review confirmed {counts['implemented']} control(s) already in place and "
             f"{gap_clause}.")
    if n_unknown:
        para2 += (f" A further {n_unknown} control(s) could not be confirmed from the "
                  f"evidence provided and are flagged for verification \u2014 an unconfirmed "
                  f"control is treated as a question to resolve, not a failure.")
    else:
        para2 += " No control was left as unknown."
    if n_silent:
        para2 += (f" {n_silent} of the {counts['not_present']} not-implemented control(s) are "
                  f"recorded only because the SAD does not mention them; the team can close "
                  f"these by documenting the control if it exists.")

    strong = [title for _, title in strengths[:3]]
    gapt = [gap_by_id[x["control_id"]].control.title for x in top_findings[:3]
            if x["control_id"] in gap_by_id]
    strong_phr = (f"Confirmed protections include {_join_natural(strong)}" if strong else "")
    if len(gapt) == 1:
        gap_phr = f"the single most important gap to close is {gapt[0]}"
    elif gapt:
        gap_phr = f"the most important gaps to close are {_join_natural(gapt)}"
    else:
        gap_phr = ""
    if strong_phr and gap_phr:
        para3 = f"{strong_phr}; {gap_phr}."
    elif strong_phr:
        para3 = f"{strong_phr}."
    elif gap_phr:
        para3 = gap_phr[0].upper() + gap_phr[1:] + "."
    else:
        para3 = ""

    if r.pci_view.in_scope:
        extra = (f" and {counts['pci_indeterminate']} require verification"
                 if counts["pci_indeterminate"] else " and none require verification")
        para4 = (f"Because the application handles cardholder data, it is in scope for PCI DSS "
                 f"v4.0.1: {counts['pci_exposed']} requirement-mapped control(s) are currently "
                 f"exposed{extra}.")
    else:
        para4 = ("The application does not handle cardholder data, so PCI DSS v4.0.1 is out of "
                 "scope.")

    posture = [para1, para2] + ([para3] if para3 else []) + [para4]

    notes = []
    if r.compensating:
        notes.append(f"{len(r.compensating)} compensating control(s) noted "
                     f"(these soften, but do not eliminate, a finding)")
    n_ai_only = sum(1 for g in gi if g.basis == EvidenceBasis.AI_UNREVIEWED
                    and g.status != ControlStatus.UNKNOWN)
    n_override = sum(1 for g in gi if g.basis == EvidenceBasis.REVIEWER_OVERRIDE)
    if n_ai_only and not automated(r):   # automated SAD runs say so once, in the banner
        notes.append(f"{n_ai_only} control status(es) rest on AI evaluations that no "
                     f"reviewer has confirmed")
    if n_override:
        notes.append(f"{n_override} AI evaluation(s) were overridden by a reviewer "
                     f"(see the evidence appendix)")
    if n_unknown:
        notes.append(f"{n_unknown} unknown control(s) need confirmation \u2014 treated as "
                     f"clarifications, not findings (unknown \u2260 missing)")

    return {"posture": posture, "counts": counts, "top_findings": top_findings,
            "strengths": strengths, "notes": notes,
            "all_confirmed": not (not_present or partial or n_unknown)}


def _executive_summary(r: ThreatModelReport) -> list[str]:
    """Markdown executive summary, built from the shared summary_facts."""
    f = summary_facts(r)
    lines = ["## Executive summary\n"]
    for para in f["posture"]:
        lines.append(para + "\n")
    if f["top_findings"]:
        lines.append("**Top findings (ranked by DREAD):**")
        for x in f["top_findings"]:
            lead = f"[{x['priority']} · {x['score']}] " if x["priority"] else ""
            tags = ", ".join([x["control_id"]] + x["tags"]) if x["control_id"] else ", ".join(x["tags"])
            lines.append(f"- {lead}{x['title']}" + (f" ({tags})" if tags else ""))
        lines.append("")
    if f["strengths"]:
        lines.append("**Strengths (confirmed in place):**")
        for cid, title in f["strengths"]:
            lines.append(f"- {cid} {title}")
        lines.append("")
    if f["notes"]:
        lines.append("**Also note:** " + "; ".join(f["notes"]) + ".\n")
    if f["all_confirmed"]:
        lines.append("_No gaps and nothing outstanding — all expected controls are confirmed in place._\n")
    return lines


SAD_RULES_TEXT = ("Automated draft generated from the solution architecture document (SAD); "
                  "no control status has been reviewed by a person. Controls the SAD does not "
                  "mention are reported as Not present: whatever the SAD omits is taken as "
                  "accepted by the business. Controls only implied by the SAD are reported as "
                  "Partial and must be confirmed.")

_FACET_SOURCE = {"llm": "AI", "keyword": "Keyword", "llm+keyword": "AI + keyword",
                 "default": "Default", "reviewer": "Reviewer"}


def sad_facts(r: ThreatModelReport) -> dict | None:
    """The SAD assessment basis, shaped for both renderers. None for non-SAD runs."""
    sc = r.sad
    if sc is None:
        return None
    src = [("File", sc.source_file)]
    if sc.document_title:
        src.append(("Document", sc.document_title + (f" (version {sc.document_version})"
                                                     if sc.document_version else "")))
    size = f"{sc.words:,} words" + (f", {'about ' if sc.pages_estimated else ''}{sc.pages} pages"
                                    if sc.pages else "")
    src += [("Size", size), ("SHA-256", sc.sha256[:16] + "…"),
            ("Diagrams read", f"{len(sc.diagrams_read)}" + (f" ({'; '.join(sc.diagrams_read)})"
                                                         if sc.diagrams_read else "")),
            ("Engine", sc.engine or "—"),
            ("Profile confirmed by", sc.profile_confirmed_by or "not recorded"),
            ("Generated", sc.generated_at or "—")]
    if sc.reviewed:
        src += [("Reviewed on the review page by", ", ".join(reviewers(r)) or "not recorded"),
                ("Report generated after review", r.generated_at or "—")]
    facets = []
    for f in sc.facets:
        basis = _FACET_SOURCE.get(f.source, f.source) + (" (assumed)" if f.assumed else "")
        facets.append((f.facet, "yes" if f.selected else "no", basis, f.reason or "—"))
    completeness = [(c.title, c.score.value.capitalize(),
                     (c.comment or "—") if c.score.value != "present" else (c.evidence or "—"))
                    for c in sc.completeness]
    limitations = [f"{c.title}: {c.score.value}" + (f" — {c.comment}" if c.comment else "")
                   for c in sc.completeness if c.score.value != "present"]
    limitations += list(sc.notes)
    limitations += [f"Figure not read: {s}" for s in sc.diagrams_skipped]
    if r.architecture is None or r.architecture.empty:
        limitations.append(NO_ARCH_NOTE)
    return {"rules": SAD_RULES_TEXT, "source": src, "facets": facets,
            "completeness": completeness, "limitations": limitations}


def _sad_section_md(r: ThreatModelReport) -> list[str]:
    f = sad_facts(r)
    if f is None:
        return []
    out = ["## Assessment basis (SAD)\n", f"> **{f['rules']}**\n"]
    out += [f"*{k}:* {_md(v)}  " for k, v in f["source"]]
    out.append("")
    out.append("### Application profile\n")
    out.append("| Facet | Selected | Basis | Reason |")
    out.append("|---|---|---|---|")
    out += [f"| {a} | {b} | {c} | {_cell(d)} |" for a, b, c, d in f["facets"]]
    out.append("")
    out.append("### SAD completeness\n")
    out.append("| Item | Result | Evidence or what is missing |")
    out.append("|---|---|---|")
    out += [f"| {a} | {b} | {_cell(c)} |" for a, b, c in f["completeness"]]
    out.append("")
    if f["limitations"]:
        out.append("### Limitations of this assessment\n")
        out += [f"- {_md(x)}" for x in f["limitations"]]
        out.append("")
    return out


def diagrams_line(r: ThreatModelReport) -> str:
    """Which architecture diagrams the Detect step read (description + diagram runs)."""
    read = "; ".join(f"Diagram {i + 1}: {d}" for i, d in enumerate(r.diagrams_read)) or "none"
    line = f"*Diagrams read ({len(r.diagrams_read)}):* {read}"
    if r.diagrams_skipped:
        line += "  \n*Not read:* " + "; ".join(r.diagrams_skipped)
    return line


# --------------------------------------------------------------------------- #
# Key focus items (page 1): informs the ARB, never directs it
# --------------------------------------------------------------------------- #
FOCUS_NOTE = ("This page summarises the security findings to inform the Architecture Review "
              "Board. It does not decide the review outcome.")
FOCUS_LIMIT = 10
READY, READY_COND, NOT_READY = "Ready", "Ready with conditions", "Not ready"


def focus_items(r: ThreatModelReport) -> dict:
    """The Key focus items, shared by both renderers. Readiness rule (agreed
    2026-11-22): Not ready if any evidence-backed Critical finding or any PCI-mapped
    control is Not present; Ready with conditions if any High finding; else Ready.
    A Critical finding resting only on SAD silence counts as High, and Ready is
    never shown while any expected control is still Unknown (Ready with conditions)."""
    auto = automated(r)
    gap_by_id = {g.control.id: g for g in r.gap_items}
    dread_by_threat = {d.threat_id: d for d in r.dread}
    worst: dict[str, tuple] = {}            # control id -> (score, priority, gap)
    for t in r.threats:
        d = dread_by_threat.get(t.id)
        for cid in t.gaps:
            g = gap_by_id.get(cid)
            if g is None or d is None or not g.is_finding:
                continue
            if g.control.id not in worst or d.average > worst[g.control.id][0]:
                worst[g.control.id] = (d.average, d.priority.value, g)
    ranked = sorted(worst.values(), key=lambda x: (-x[0], 1 if sad_silent(x[2]) else 0))

    critical = [g for _sc, pr, g in ranked if pr == "Critical" and not sad_silent(g)]
    pci_missing = [g for g in r.gap_items
                   if g.status == ControlStatus.NOT_PRESENT and g.pci_exposed]
    high = [g for _sc, pr, g in ranked
            if pr == "High" or (pr == "Critical" and sad_silent(g))]
    findings = [g for g in r.gap_items if g.is_finding]
    unscored = [g for g in findings if g.control.id not in worst]

    reasons = []
    if critical:
        reasons.append(f"{len(critical)} evidence-backed Critical finding(s)")
    if pci_missing:
        reasons.append(f"{len(pci_missing)} PCI-mapped control(s) not present")
    unknown = [g for g in r.gap_items if g.status == ControlStatus.UNKNOWN]
    if critical or pci_missing:
        readiness = NOT_READY
    elif high or unscored or unknown:
        readiness = READY_COND
        if high:
            reasons.append(f"{len(high)} High finding(s)")
        if unscored:
            reasons.append(f"{len(unscored)} finding(s) without a DREAD score")
        if unknown:
            # "Ready" must never be shown while expected controls are unassessed
            reasons.append(f"{len(unknown)} control(s) not yet assessed")
    else:
        readiness = READY
        reasons.append("no Critical or High findings")

    def item(g, why):
        return (g.control.id, g.control.title, why)

    before, seen = [], set()
    for g in critical:
        if g.control.id not in seen:
            seen.add(g.control.id)
            before.append(item(g, f"Critical, {_STATUS_LABEL[g.status].lower()}"))
    for g in pci_missing:
        if g.control.id not in seen:
            seen.add(g.control.id)
            reqs = ", ".join(x.requirement for x in g.pci_exposed)
            before.append(item(g, f"PCI {reqs}, not present"))
    risks = []
    for g in high:
        if g.control.id not in seen:
            seen.add(g.control.id)
            why = "High" + (", SAD silent" if sad_silent(g) else "")
            risks.append(item(g, f"{why}, {_STATUS_LABEL[g.status].lower()}"))

    # SAD-silent and inferred rows keep their tag until a reviewer changes the status,
    # so in a reviewed SAD run (flow 2) the untouched ones are still open questions.
    questions = [item(g, "the SAD does not mention it") for g in r.gap_items if sad_silent(g)]
    questions += [item(g, "only implied by the SAD") for g in r.gap_items if sad_inferred(g)]
    questions += [item(g, "status unknown") for g in unknown]

    def cap(xs):
        return xs[:FOCUS_LIMIT], max(0, len(xs) - FOCUS_LIMIT)

    names = reviewers(r)
    prepared = (r.sad.profile_confirmed_by if (r.sad and r.sad.profile_confirmed_by) else "")
    return {
        "readiness": readiness, "tag": "Automated draft" if auto else None,
        "reasons": reasons, "note": FOCUS_NOTE,
        "before_go_live": cap(before), "business_risks": cap(risks),
        "open_questions": cap(questions),
        "people": [("Prepared by", prepared),
                   ("Reviewed by (AppSec / security champion)", ", ".join(names)),
                   ("Business risk owner", "")],
    }


def basis_facts(r: ThreatModelReport) -> dict | None:
    """Assessment basis for a review-page run with no SAD record (flow 3). SAD-based
    runs use sad_facts()."""
    if r.sad is not None:
        return None
    n_unknown = sum(1 for g in r.gap_items if g.status == ControlStatus.UNKNOWN)
    rows = [("Description", f"{r.description_words:,} words" if r.description_words
             else "none provided"),
            ("Diagrams read", f"{len(r.diagrams_read)}"
             + (f" ({'; '.join(r.diagrams_read)})" if r.diagrams_read else "")),
            ("Engine", r.engine or "not recorded"),
            ("Reviewed by", ", ".join(reviewers(r)) or "no reviewer recorded"),
            ("Generated", (r.generated_at or "\u2014").replace("T", " ").replace("+00:00", " UTC"))]
    limits = []
    if r.diagrams_skipped:
        limits += [f"Diagram not read: {x}" for x in r.diagrams_skipped]
    if not r.description_words:
        limits.append("No written description was provided; statuses rest on the diagrams "
                      "and the reviewer's declarations only.")
    if n_unknown:
        limits.append(f"{n_unknown} control(s) are unknown: they are open questions, not "
                      f"findings, and are not reflected in the threats or DREAD scores.")
    comp = [(c.title, c.score.value.capitalize(),
             (c.comment or "\u2014") if c.score.value != "present" else (c.evidence or "\u2014"))
            for c in r.input_completeness]
    if comp:
        limits += [f"{c.title}: {c.score.value}" + (f" \u2014 {c.comment}" if c.comment else "")
                   for c in r.input_completeness if c.score.value != "present"]
    else:
        limits.append("The description and diagrams were not checked for completeness against "
                      "the SAD checklist.")
    if r.architecture is None or r.architecture.empty:
        limits.append(NO_ARCH_NOTE)
    return {"rows": rows, "limitations": limits, "completeness": comp}




# --------------------------------------------------------------------------- #
# System context, threats and action plan (shared by both renderers)
# --------------------------------------------------------------------------- #
NO_ARCH_NOTE = ("No architecture summary was available, so threats rest on the control "
                "gaps alone and do not name this system's components.")
_ARCH_LABELS = (("components", "Components"), ("entry_points", "Entry points"),
                ("data_stores", "Data stores"), ("external_integrations", "External integrations"),
                ("data_flows", "Data flows"), ("trust_boundaries", "Trust boundaries"))


def architecture_rows(r: ThreatModelReport) -> list[tuple[str, str]]:
    a = r.architecture
    if a is None or a.empty:
        return []
    rows = [("Exposure", a.exposure)] if a.exposure else []
    rows += [(label, "; ".join(getattr(a, key))) for key, label in _ARCH_LABELS
             if getattr(a, key)]
    return rows


def threat_rows(r: ThreatModelReport) -> list[dict]:
    rows = []
    for t in r.threats:
        bits = []
        if t.actor or t.target:
            bits.append(" \u2192 ".join(x for x in (t.actor, t.target) if x))
        if t.impact:
            bits.append(f"Impact: {t.impact}")
        detail = ". ".join(bits)
        if t.actor is None and t.target is None and t.impact is None:
            detail = ""                     # offline threats: the title says it all
        rows.append({"id": t.id, "stride": stride_label(t.stride), "title": t.title,
                     "detail": detail, "gaps": ", ".join(t.gaps) or "\u2014",
                     "maps": threat_fw(r, t) or "\u2014"})
    return rows


_PRIO_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}


def action_rows(r: ThreatModelReport) -> list[dict]:
    """Action plan sorted by timing (before go-live first), then priority."""
    acts = sorted(r.actions, key=lambda a: (0 if a.timing == "Before go-live" else 1,
                                            _PRIO_ORDER.get(a.priority, 9)))
    return [{"id": a.id, "action": a.action, "closes": ", ".join(a.threat_ids) or "\u2014",
             "controls": ", ".join(a.control_ids) or "\u2014", "priority": a.priority,
             "timing": a.timing, "owner": a.owner} for a in acts]



REGISTER_NOTE = ("Controls not present, partial or unknown. Controls confirmed in place are "
                 "listed with their evidence in the appendix.")
FINDING_STATUSES = (ControlStatus.NOT_PRESENT, ControlStatus.PARTIAL, ControlStatus.UNKNOWN)


def register_rows(r: ThreatModelReport, findings_only: bool) -> list[dict]:
    """Rows of the findings register (body) or the full control list (appendix),
    shared by both renderers. Findings are ordered missing, partial, unknown."""
    items = r.gap_items
    if findings_only:
        order = {st: i for i, st in enumerate(FINDING_STATUSES)}
        items = sorted([g for g in items if g.status in order], key=lambda g: order[g.status])
    rows = []
    for g in items:
        status = _STATUS_LABEL[g.status] + (" (SAD silent)" if sad_silent(g) else
                                            " (inferred)" if sad_inferred(g) else "")
        rows.append({"control": f"{g.control.id} {g.control.title}", "status_enum": g.status,
                     "status": status, "basis": basis_label(g),
                     "frameworks": fw_labels(g.control),
                     "pci": ", ".join(x.requirement for x in g.pci_exposed) or "\u2014"})
    return rows


def register_columns(r: ThreatModelReport) -> tuple[bool, bool]:
    """(show Basis, show PCI). Basis is dropped in an automated SAD run (the AI is
    every row's basis); the PCI column only appears when PCI is in scope."""
    return (not automated(r), r.pci_view.in_scope)


def _req_key(req: str):
    return tuple(int(x) if x.isdigit() else x for x in str(req).replace("-", ".").split("."))


def pci_groups(r: ThreatModelReport) -> dict:
    """PCI view grouped by requirement number: {'counts': {...}, 'groups':
    [(requirement, [(control_id, title, status_label, kind), ...]), ...]} where kind is
    'exposed' or 'verify'."""
    v = r.pci_view
    by_req: dict[str, list] = {}
    for kind, entries in (("exposed", v.exposed), ("verify", v.indeterminate)):
        for e in entries:
            label = _STATUS_LABEL[e.status]
            for q in e.requirements:
                by_req.setdefault(q.requirement, []).append((e.control_id, e.control_title,
                                                             label, kind))
    groups = [(req, by_req[req]) for req in sorted(by_req, key=_req_key)]
    return {"counts": {"mapped": len(v.exposed) + len(v.indeterminate) + v.covered_count,
                       "exposed": len(v.exposed), "verify": len(v.indeterminate),
                       "in_place": v.covered_count},
            "groups": groups}


def tile_legend(r: ThreatModelReport) -> str:
    """One line under the summary tiles saying what To verify and Reviewed count.
    Their meaning depends on the flow, so it is spelled out on every report."""
    if automated(r):
        return ("To verify: Partial controls whose status still needs confirming, because "
                "the SAD only implies them, or the cited quote was not found in the SAD or "
                "does not support the status (already counted under Partial). "
                "Reviewed: Draft, because no person has reviewed this automated run.")
    return ("To verify: controls whose status is still Unknown, plus statuses that rest on "
            "an AI evaluation no reviewer has confirmed. "
            "Reviewed: controls whose status a reviewer has confirmed or set.")


def review_state(r: ThreatModelReport) -> str:
    if automated(r):
        return "Automated draft from the SAD; no person has reviewed the statuses yet"
    n = sum(1 for g in r.gap_items if g.basis in _REVIEWED)
    names = reviewers(r)
    who = f" ({', '.join(names)})" if names else ""
    return f"{n} of {r.resolved_control_count} control statuses confirmed by a reviewer{who}"


def document_control(r: ThreatModelReport) -> list[tuple[str, str]]:
    """Document-control rows for the top of the report."""
    rows = []
    if r.generated_at:
        rows.append(("Generated", r.generated_at.replace("T", " ").replace("+00:00", " UTC")))
    rows.append(("Review state", review_state(r)))
    if r.tool_version:
        rows.append(("Tool version", r.tool_version))
    if r.catalog_version:
        rows.append(("Catalog", r.catalog_version))
    return rows


def out_of_catalog_rows(r: ThreatModelReport) -> list[str]:
    """Plain sentences for compensating controls and catalog candidates."""
    out = []
    for a in r.compensating:
        st = ", ".join(stride_label(x) for x in a.stride)
        out.append(f"Compensating: {a.observed.name}" + (f" (addresses {st})" if st else "")
                   + f". {a.rationale} It softens, but does not close, the related findings.")
    for c in r.candidates:
        st = ", ".join(stride_label(x) for x in c.stride)
        risk = (f"addresses {st} risk" if st else
                "the risk it addresses is not mapped to STRIDE yet")
        out.append(f"Candidate: {c.title} ({risk}). Described in the evidence but not in the "
                   f"catalog; it does not offset any finding in this report.")
    return out



def _register_md(r: ThreatModelReport, rows: list[dict]) -> list[str]:
    show_basis, show_pci = register_columns(r)
    out = ["| Control | Status |" + (" Basis |" if show_basis else "") + " Frameworks |"
           + (" PCI exposed |" if show_pci else ""),
           "|---|---|" + ("---|" if show_basis else "") + "---|" + ("---|" if show_pci else "")]
    for x in rows:
        out.append(f"| {x['control']} | {x['status']} |"
                   + (f" {x['basis']} |" if show_basis else "") + f" {x['frameworks']} |"
                   + (f" {x['pci']} |" if show_pci else ""))
    return out


def _focus_md(r: ThreatModelReport) -> list[str]:
    f = focus_items(r)
    tag = f" ({f['tag']})" if f["tag"] else ""
    out = ["## Key focus items\n", f"*{f['note']}*\n",
           f"**Security readiness: {f['readiness']}**{tag} — {'; '.join(f['reasons'])}.\n"]
    for key, title in (("before_go_live", "Address before go-live"),
                       ("business_risks", "Risks for the business to consider"),
                       ("open_questions", "Open questions for the team")):
        items, more = f[key]
        if not items:
            continue
        out.append(f"**{title}:**")
        out += [f"- {cid} {_md(t)} — {_md(why)}" for cid, t, why in items]
        if more:
            out.append(f"- …and {more} more (see the findings register)")
        out.append("")
    out.append("| Role | Name | Date |")
    out.append("|---|---|---|")
    out += [f"| {role} | {_cell(name) if name else ''} | |" for role, name in f["people"]]
    out.append("")
    return out


def _basis_md(r: ThreatModelReport) -> list[str]:
    b = basis_facts(r)
    if b is None:
        return []
    out = ["## Assessment basis\n"]
    out += [f"*{k}:* {_md(v)}  " for k, v in b["rows"]]
    out.append("")
    if r.diagrams_read or r.diagrams_skipped:
        out.append(diagrams_line(r) + "\n")
    if b["completeness"]:
        out.append("### Input completeness (SAD checklist, warns only)\n")
        out.append("| Item | Result | Evidence or what is missing |")
        out.append("|---|---|---|")
        out += [f"| {a} | {c} | {_cell(d)} |" for a, c, d in b["completeness"]]
        out.append("")
    out.append("### Limitations of this assessment\n")
    out += [f"- {_md(x)}" for x in b["limitations"]]
    out.append("")
    return out


def render_markdown(r: ThreatModelReport) -> str:
    p = r.profile
    out: list[str] = []
    out.append(f"# Threat Model — {p.name}\n")
    out.append(f"*Platforms:* {', '.join(f.value for f in p.platforms)}  ")
    out.append(f"*AI capability:* {', '.join(a.value for a in p.ai_capabilities)}  ")
    out.append(f"*Data classification:* {p.data_classification.value}  ")
    out.append(f"*Expected controls:* {r.resolved_control_count}  ")
    out.append(f"*PCI in scope:* {'yes' if p.handles_cardholder_data else 'no'}\n")
    dc = document_control(r)
    if dc:
        out.append("  \n".join(f"*{k}:* {_md(v)}" for k, v in dc) + "\n")
    banner = sad_banner(r)
    if banner:
        out.append(f"> **{banner[0]}** {banner[1]}\n")

    # Headline counts (same numbers as the PDF stat strip)
    c = summary_facts(r)["counts"]
    reviewed = ("Automated draft" if c["reviewed"] is None
                else f"{c['reviewed']} of {c['expected']}")
    out.append(f"**Expected** {c['expected']} · **Confirmed in place** {c['implemented']} · "
               f"**Not present** {c['not_present']} · **Partial** {c['partial']} · "
               f"**To verify** {c['to_verify']} · **Reviewed** {reviewed}\n")
    out.append(f"*{tile_legend(r)}*\n")

    # Key focus items: page 1, informs the ARB
    out.extend(_focus_md(r))

    # Executive summary — deterministic roll-up, first thing a reader sees
    out.extend(_executive_summary(r))

    # Assessment basis: the SAD record, or what a review-page run was built from
    out.extend(_sad_section_md(r))
    out.extend(_basis_md(r))

    # Findings register: gaps and unknowns only; the full list is in the appendix
    out.append("## Findings register\n")
    out.append(f"*{REGISTER_NOTE}*\n")
    rows = register_rows(r, findings_only=True)
    if rows:
        out.extend(_register_md(r, rows))
    else:
        out.append("*No findings — every expected control is confirmed in place.*")
    out.append("")

    # System context: what the threats are built on
    arch = architecture_rows(r)
    if arch:
        out.append("## System context\n")
        out.append("| Item | Details |")
        out.append("|---|---|")
        out += [f"| {k} | {_cell(v)} |" for k, v in arch]
        out.append("")

    # Threats
    out.append("## Threat model\n")
    if r.threats:
        out.append("| ID | STRIDE | Threat | Gaps | Maps to |")
        out.append("|---|---|---|---|---|")
        for x in threat_rows(r):
            threat = _cell(x["title"]) + (f"<br>_{_cell(x['detail'])}_" if x["detail"] else "")
            out.append(f"| {x['id']} | {x['stride']} | {threat} | {x['gaps']} | {x['maps']} |")
    else:
        out.append("*No findings — all expected controls implemented or unknown.*")
    out.append("")

    # DREAD
    out.append("## DREAD scoring\n")
    if r.dread:
        out.append("| Threat | D | R | E | A | D | Avg | Priority | Why |")
        out.append("|---|---|---|---|---|---|---|---|---|")
        for sc in sorted(r.dread, key=lambda x: x.average, reverse=True):
            out.append(f"| {sc.threat_id} | {sc.damage} | {sc.reproducibility} | "
                       f"{sc.exploitability} | {sc.affected_users} | {sc.discoverability} "
                       f"| {sc.average} | {sc.priority.value} | {_cell(sc.rationale or '—')} |")
    else:
        out.append("*No scored threats.*")
    out.append("")

    # Action plan (older engines produced recommendations + mitigations instead)
    if r.actions:
        out.append("## Action plan\n")
        out.append("| # | Action | Closes | Controls | Priority | Timing | Owner |")
        out.append("|---|---|---|---|---|---|---|")
        for x in action_rows(r):
            out.append(f"| {x['id']} | {_cell(x['action'])} | {x['closes']} | {x['controls']} "
                       f"| {x['priority']} | {x['timing']} | {_cell(x['owner'])} |")
        out.append("")
    else:
        out.append("## Recommendations (gap-closing)\n")
        for rec in r.recommendations:
            fw = f"  _{', '.join(fw_text(x) for x in rec.frameworks)}_" if rec.frameworks else ""
            out.append(f"- **{rec.title}** ({rec.control_id}) — {rec.action}{fw}")
        if not r.recommendations:
            out.append("- None.")
        out.append("")
        out.append("## Mitigations (threat-specific)\n")
        for m in r.mitigations:
            note = f"  _{m.note}_" if m.note else ""
            out.append(f"- **{m.threat_id}** → {m.action}{note}")
        if not r.mitigations:
            out.append("- None.")
        out.append("")

    # Clarifications
    if r.clarifications:
        out.append("## Clarifications needed (unknown ≠ missing)\n")
        for cl in r.clarifications:
            out.append(f"- {cl}")
        out.append("")

    # PCI view, grouped by requirement
    out.append("## PCI DSS v4.0.1 compliance view\n")
    if not r.pci_view.in_scope:
        out.append("*Not in scope — the application does not handle cardholder data.*\n")
    else:
        pg = pci_groups(r)
        k = pg["counts"]
        out.append(f"In scope. {k['mapped']} PCI-mapped control(s) expected: {k['exposed']} "
                   f"exposed, {k['verify']} to verify, {k['in_place']} in place.\n")
        if pg["groups"]:
            out.append("| PCI requirement | Control | Status |")
            out.append("|---|---|---|")
            for req, items in pg["groups"]:
                for cid, title, label, kind in items:
                    st = label if kind == "exposed" else f"{label} (verify)"
                    out.append(f"| {req} | {cid} {title} | {st} |")
        out.append("")

    # Out-of-catalog
    ooc = out_of_catalog_rows(r)
    if ooc:
        out.append("## Out-of-catalog controls\n")
        out += [f"- {_md(x)}" for x in ooc]
        out.append("")

    # Evidence appendix: one card per control, so every expected control is listed there
    out.extend(_evidence_md(r))

    return "\n".join(out)


_STATUS_MARK = {ControlStatus.NOT_PRESENT: "\U0001F534", ControlStatus.PARTIAL: "\U0001F7E0",
                ControlStatus.UNKNOWN: "\u26AA", ControlStatus.IMPLEMENTED: "\U0001F7E2",
                ControlStatus.NOT_APPLICABLE: "\u26AA"}


def _evidence_md(r: ThreatModelReport) -> list[str]:
    groups = evidence_groups(r)
    if not groups:
        return []
    lead, _, rest = evidence_note(r).partition(". ")
    out = [f"## {EVIDENCE_TITLE}\n", f"> \u26A0\uFE0F **{lead}.** {rest}\n"]
    for st, recs in groups:
        out.append(f"### {_STATUS_MARK[st]} {_STATUS_LABEL[st]} ({len(recs)})\n")
        for rec in recs:
            out.append(f"| **{_ecell(rec['id'])}** | **{_ecell(rec['title'])}** |")
            out.append("|---|---|")
            for key, label, val in evidence_fields(rec):
                if key == "quote":
                    v = f"\u201c{_ecell(val)}\u201d"
                    if rec["quote_unverified"]:
                        v += " \u26A0 _not found verbatim in the source_"
                    if rec["quote_unsupported"]:
                        v += f" \u26A0 _quote check: {_ecell(rec['quote_unsupported'])}_"
                elif key == "ai":
                    v = f"**{_ecell(val)}**"
                else:
                    v = _ecell(val)
                out.append(f"| {label} | {v} |")
            out.append("")
    return out


def _ecell(s: str) -> str:
    """Free text inside an evidence card cell: pipes are escaped, not replaced,
    so quotes and reviewer notes read exactly as written."""
    return _md(" ".join(str(s).split())).replace("|", "\\|")


def _cell(s: str) -> str:
    """Free text safe inside a Markdown table cell."""
    return _md(" ".join(str(s).split())).replace("|", "/")


def _md(s: str) -> str:
    """Neutralise Markdown that would break the report layout in free text."""
    return (s.replace("\\", "\\\\").replace("*", "\\*").replace("_", "\\_")
             .replace("`", "\\`").replace("<", "&lt;").replace("[", "\\["))
