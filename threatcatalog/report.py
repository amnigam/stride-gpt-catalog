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


def evidence_note(r: ThreatModelReport) -> str:
    return EVIDENCE_NOTE_SAD if r.sad is not None else EVIDENCE_NOTE_REVIEW


def evidence_records(r: ThreatModelReport) -> list[dict]:
    """One record per control that has something to show in the evidence
    appendix \u2014 shared by the Markdown and PDF renderers. Every string is
    whitespace-flattened; renderers do their own escaping.

    In an automated (SAD) run nobody can review a row, so the review-only fields
    (`final_status`, `basis`, `reviewer_note`, `reviewed_by`) are left out: the AI
    evaluation *is* the status."""
    automated = r.sad is not None
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
                parts.append("from " + _SOURCE_LABEL.get(ev.ai_source, ev.ai_source))
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
            "basis": None if automated else basis_label(gi),
            "ai_evaluation": ai,
            "quote": _flat(ev.ai_quote) or None,
            "quote_unverified": ev.quote_verified is False,
            "ai_note": _flat(ev.ai_note) if ev.ai_status is not None else None,
            "reviewer_note": None if automated else (_flat(ev.reviewer_note) or None),
            "reviewed_by": None if automated else (
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

    threats_by_id = {t.id: t for t in r.threats}
    threat_by_control = {t.enabling_gap: t for t in r.threats if t.enabling_gap}
    dread_by_threat = {d.threat_id: d for d in r.dread}

    def sev(control_id: str) -> float:
        t = threat_by_control.get(control_id)
        return dread_by_threat[t.id].average if (t and t.id in dread_by_threat) else 0.0

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

    # ---- the headline picks (named, so the summary reads completely on its own) ----
    top_threats = []
    for d in sorted(r.dread, key=lambda d: d.average, reverse=True)[:4]:
        t = threats_by_id.get(d.threat_id)
        top_threats.append((d.priority.value, d.average,
                            t.title if t else d.threat_id, t.framework_ref if t else None))

    key_gaps = []
    for g in sorted(not_present, key=lambda g: (0 if g.pci_exposed else 1, -sev(g.control.id)))[:5]:
        tags = (["PCI"] if g.pci_exposed else []) + \
               ([g.control.threat_frameworks[0].ref] if g.control.threat_frameworks else [])
        key_gaps.append((g.control.id, g.control.title, tags))

    strengths = [(g.control.id, g.control.title) for g in sorted(
        implemented, key=lambda g: 0 if (g.control.threat_frameworks or g.control.pci) else 1)[:5]]

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
        para2 += " Every expected control could be assessed from the evidence provided."

    strong = [title for _, title in strengths[:3]]
    gapt = [title for _, title, _ in key_gaps[:3]]
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
    if n_ai_only and r.sad is None:      # SAD runs say so once, in the banner
        notes.append(f"{n_ai_only} control status(es) rest on AI evaluations that no "
                     f"reviewer has confirmed")
    if n_override:
        notes.append(f"{n_override} AI evaluation(s) were overridden by a reviewer "
                     f"(see the evidence appendix)")
    if n_unknown:
        notes.append(f"{n_unknown} unknown control(s) need confirmation \u2014 treated as "
                     f"clarifications, not findings (unknown \u2260 missing)")

    return {"posture": posture, "counts": counts, "top_threats": top_threats,
            "key_gaps": key_gaps, "strengths": strengths, "notes": notes,
            "all_confirmed": not (not_present or partial or n_unknown)}


def _executive_summary(r: ThreatModelReport) -> list[str]:
    """Markdown executive summary, built from the shared summary_facts."""
    f = summary_facts(r)
    lines = ["## Executive summary\n"]
    for para in f["posture"]:
        lines.append(para + "\n")
    if f["top_threats"]:
        lines.append("**Top threats (by DREAD):**")
        for prio, avg, title, fw in f["top_threats"]:
            lines.append(f"- [{prio} · {avg}] {title}" + (f" ({fw})" if fw else ""))
        lines.append("")
    if f["key_gaps"]:
        lines.append("**Key gaps to close:**")
        for cid, title, tags in f["key_gaps"]:
            lines.append(f"- {cid} {title}" + (f" ({', '.join(tags)})" if tags else ""))
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
    size = f"{sc.words:,} words" + (f", {sc.pages} pages" if sc.pages else "")
    src += [("Size", size), ("SHA-256", sc.sha256[:16] + "…"),
            ("Diagrams read", f"{len(sc.diagrams_read)}" + (f" ({'; '.join(sc.diagrams_read)})"
                                                         if sc.diagrams_read else "")),
            ("Engine", sc.engine or "—"),
            ("Profile confirmed by", sc.profile_confirmed_by or "not recorded"),
            ("Generated", sc.generated_at or "—")]
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


def render_markdown(r: ThreatModelReport) -> str:
    p = r.profile
    out: list[str] = []
    out.append(f"# Threat Model — {p.name}\n")
    out.append(f"*Platforms:* {', '.join(f.value for f in p.platforms)}  ")
    out.append(f"*AI capability:* {', '.join(a.value for a in p.ai_capabilities)}  ")
    out.append(f"*Data classification:* {p.data_classification.value}  ")
    out.append(f"*Resolved controls:* {r.resolved_control_count}  ")
    out.append(f"*PCI in scope:* {'yes' if p.handles_cardholder_data else 'no'}\n")
    if r.sad is not None:
        out.append(f"> **Automated draft from SAD.** {SAD_RULES_TEXT}\n")

    # Executive summary — deterministic roll-up, first thing a reader sees
    out.extend(_executive_summary(r))

    # SAD assessment basis (SAD-driven runs only)
    out.extend(_sad_section_md(r))

    # Gap register
    out.append("## Control gap register\n")
    # Basis says who stands behind a status; in an automated SAD run it is the AI
    # for every row, so the column is dropped there.
    show_basis = r.sad is None
    out.append("| Control | Status |" + (" Basis |" if show_basis else "") + " Frameworks | PCI exposed |")
    out.append("|---|---|" + ("---|" if show_basis else "") + "---|---|")
    for gi in r.gap_items:
        fws = ", ".join(f.ref for f in gi.control.threat_frameworks) or "—"
        pci = ", ".join(x.requirement for x in gi.pci_exposed) or "—"
        basis = f" {basis_label(gi)} |" if show_basis else ""
        out.append(f"| {gi.control.id} {gi.control.title} | {_STATUS_LABEL[gi.status]} |"
                   f"{basis} {fws} | {pci} |")
    out.append("")

    # Threats
    out.append("## Threat model\n")
    if r.threats:
        out.append("| ID | STRIDE | Threat | Enabling gap | Maps to |")
        out.append("|---|---|---|---|---|")
        for t in r.threats:
            out.append(f"| {t.id} | {t.stride.value} | {t.title} "
                       f"| {t.enabling_gap or '—'} | {t.framework_ref or '—'} |")
    else:
        out.append("*No findings — all expected controls implemented or unknown.*")
    out.append("")

    # Recommendations
    out.append("## Recommendations (gap-closing)\n")
    for rec in r.recommendations:
        fw = f"  _{', '.join(rec.frameworks)}_" if rec.frameworks else ""
        out.append(f"- **{rec.title}** ({rec.control_id}) — {rec.action}{fw}")
    if not r.recommendations:
        out.append("- None.")
    out.append("")

    # Mitigations
    out.append("## Mitigations (threat-specific)\n")
    for m in r.mitigations:
        note = f"  _{m.note}_" if m.note else ""
        out.append(f"- **{m.threat_id}** → {m.action}{note}")
    if not r.mitigations:
        out.append("- None.")
    out.append("")

    # DREAD
    out.append("## DREAD scoring\n")
    if r.dread:
        out.append("| Threat | D | R | E | A | D | Avg | Priority |")
        out.append("|---|---|---|---|---|---|---|---|")
        for s in sorted(r.dread, key=lambda x: x.average, reverse=True):
            out.append(f"| {s.threat_id} | {s.damage} | {s.reproducibility} | "
                       f"{s.exploitability} | {s.affected_users} | {s.discoverability} "
                       f"| {s.average} | {s.priority.value} |")
    else:
        out.append("*No scored threats.*")
    out.append("")

    # Clarifications
    if r.clarifications:
        out.append("## Clarifications needed (unknown ≠ missing)\n")
        for c in r.clarifications:
            out.append(f"- {c}")
        out.append("")

    # PCI view
    out.append("## PCI DSS v4.0.1 compliance view\n")
    if not r.pci_view.in_scope:
        out.append("*Not in scope — the application does not handle cardholder data.*\n")
    else:
        out.append(f"In scope. Covered PCI-mapped controls: {r.pci_view.covered_count}.\n")
        if r.pci_view.exposed:
            out.append("**Exposed (weak/missing):**")
            for e in r.pci_view.exposed:
                reqs = ", ".join(x.requirement for x in e.requirements)
                out.append(f"- {e.control_id} {e.control_title} "
                           f"({_STATUS_LABEL[e.status]}) → PCI {reqs}")
        if r.pci_view.indeterminate:
            out.append("\n**Indeterminate (verify):**")
            for e in r.pci_view.indeterminate:
                reqs = ", ".join(x.requirement for x in e.requirements)
                out.append(f"- {e.control_id} {e.control_title} → PCI {reqs}")
        out.append("")

    # Out-of-catalog
    if r.compensating or r.candidates:
        out.append("## Out-of-catalog controls\n")
        for a in r.compensating:
            out.append(f"- Compensating: **{a.observed.name}** — {a.rationale}")
        if r.candidates:
            out.append("\n*Catalog candidates (flagged for later promotion):*")
            for c in r.candidates:
                strides = ", ".join(s.value for s in c.stride) or "unmapped"
                out.append(f"- {c.title} — [{strides}]")
        out.append("")

    # Evidence appendix — one card per control, grouped by status, findings first
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
