"""
threatcatalog.pdf_export
========================

Renders a `ThreatModelReport` to a PDF (bytes), using reportlab — pure Python,
no system binaries, so it runs the same on Linux/macOS/Windows. Kept in its own
module so the optional `reportlab` dependency never touches the core engine; the
UI/CLI import it lazily and degrade gracefully if it isn't installed.

    pip install "threatcatalog[pdf]"     # or: pip install reportlab
"""

from __future__ import annotations

import io
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import cm
from reportlab.platypus import (HRFlowable, Paragraph, SimpleDocTemplate, Spacer,
                                Table, TableStyle)

from .models import ControlStatus, ThreatModelReport
from .report import _STATUS_LABEL, summary_facts

# palette
_NAVY = colors.HexColor("#1f2c4c")
_TEAL = colors.HexColor("#0f9d8f")
_GREY = colors.HexColor("#5b6675")
_LINE = colors.HexColor("#c7ced9")
_HEADERBG = colors.HexColor("#eef1f6")
_PRIORITY = {"Critical": colors.HexColor("#b3261e"), "High": colors.HexColor("#c2620f"),
             "Medium": colors.HexColor("#8a6d00"), "Low": colors.HexColor("#5b6675")}


def _styles():
    ss = getSampleStyleSheet()
    ss.add(ParagraphStyle("TitleX", parent=ss["Title"], fontSize=20, textColor=_NAVY,
                          spaceAfter=2))
    ss.add(ParagraphStyle("Meta", parent=ss["Normal"], fontSize=8.5, textColor=_GREY,
                          spaceAfter=2))
    ss.add(ParagraphStyle("H2", parent=ss["Heading2"], fontSize=12.5, textColor=_NAVY,
                          spaceBefore=12, spaceAfter=4))
    ss.add(ParagraphStyle("Body", parent=ss["Normal"], fontSize=9.5, leading=13,
                          alignment=TA_LEFT))
    ss.add(ParagraphStyle("Bull", parent=ss["Normal"], fontSize=9.5, leading=13,
                          leftIndent=10, bulletIndent=0))
    ss.add(ParagraphStyle("Cell", parent=ss["Normal"], fontSize=8.5, leading=11))
    ss.add(ParagraphStyle("CellHdr", parent=ss["Normal"], fontSize=8.5, leading=11,
                          textColor=_NAVY, fontName="Helvetica-Bold"))
    return ss


def _table(data, col_widths, ss):
    body = [[Paragraph(escape(str(c)), ss["CellHdr" if r == 0 else "Cell"])
             for c in row] for r, row in enumerate(data)]
    t = Table(body, colWidths=col_widths, repeatRows=1)
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), _HEADERBG),
        ("LINEBELOW", (0, 0), (-1, 0), 0.6, _LINE),
        ("LINEBELOW", (0, 1), (-1, -1), 0.3, _LINE),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ("LEFTPADDING", (0, 0), (-1, -1), 5),
        ("RIGHTPADDING", (0, 0), (-1, -1), 5),
    ]))
    return t


def render_pdf(r: ThreatModelReport) -> bytes:
    ss = _styles()
    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, topMargin=1.6 * cm, bottomMargin=1.6 * cm,
                            leftMargin=1.6 * cm, rightMargin=1.6 * cm,
                            title=f"Threat Model — {r.profile.name}")
    el = []
    p = r.profile

    el.append(Paragraph(f"Threat Model &mdash; {escape(p.name)}", ss["TitleX"]))
    el.append(Paragraph(
        f"Platforms: {', '.join(f.value for f in p.platforms)} &nbsp;|&nbsp; "
        f"AI capability: {', '.join(a.value for a in p.ai_capabilities)} &nbsp;|&nbsp; "
        f"Data: {p.data_classification.value} &nbsp;|&nbsp; "
        f"Resolved controls: {r.resolved_control_count} &nbsp;|&nbsp; "
        f"PCI in scope: {'yes' if p.handles_cardholder_data else 'no'}", ss["Meta"]))
    el.append(HRFlowable(width="100%", thickness=0.6, color=_LINE, spaceBefore=4, spaceAfter=2))

    # ---- executive summary (shared facts) ----
    f = summary_facts(r)
    el.append(Paragraph("Executive summary", ss["H2"]))
    el.append(Paragraph(escape(f["posture"]), ss["Body"]))

    if f["top_threats"]:
        el.append(Spacer(1, 4))
        el.append(Paragraph("Top threats (by DREAD)", ss["CellHdr"]))
        for prio, avg, title, fw in f["top_threats"]:
            col = _PRIORITY.get(prio, _GREY)
            tag = f" ({escape(fw)})" if fw else ""
            el.append(Paragraph(
                f'<font color="{col.hexval()}"><b>[{prio} &middot; {avg}]</b></font> '
                f'{escape(title)}{tag}', ss["Bull"], bulletText="•"))

    if f["key_gaps"]:
        el.append(Spacer(1, 4))
        el.append(Paragraph("Key gaps to close", ss["CellHdr"]))
        for cid, title, tags in f["key_gaps"]:
            tg = f" ({escape(', '.join(tags))})" if tags else ""
            el.append(Paragraph(f"{escape(cid)} {escape(title)}{tg}", ss["Bull"], bulletText="•"))

    if f["strengths"]:
        el.append(Spacer(1, 4))
        el.append(Paragraph("Strengths (confirmed in place)", ss["CellHdr"]))
        for cid, title in f["strengths"]:
            el.append(Paragraph(f"{escape(cid)} {escape(title)}", ss["Bull"], bulletText="•"))

    if f["notes"]:
        el.append(Spacer(1, 4))
        el.append(Paragraph("<b>Also note:</b> " + escape("; ".join(f["notes"])) + ".", ss["Body"]))
    if f["all_confirmed"]:
        el.append(Paragraph("No gaps and nothing outstanding — all expected controls are "
                            "confirmed in place.", ss["Body"]))

    # ---- gap register ----
    el.append(Paragraph("Control gap register", ss["H2"]))
    rows = [["Control", "Status", "Frameworks", "PCI exposed"]]
    for gi in r.gap_items:
        fws = ", ".join(x.ref for x in gi.control.threat_frameworks) or "—"
        pci = ", ".join(x.requirement for x in gi.pci_exposed) or "—"
        rows.append([f"{gi.control.id}  {gi.control.title}", _STATUS_LABEL[gi.status], fws, pci])
    el.append(_table(rows, [7.2 * cm, 2.2 * cm, 4.2 * cm, 3.0 * cm], ss))

    # ---- threats ----
    el.append(Paragraph("Threat model", ss["H2"]))
    if r.threats:
        rows = [["ID", "STRIDE", "Threat", "Gap", "Maps to"]]
        for t in r.threats:
            rows.append([t.id, t.stride.value, t.title, t.enabling_gap or "—", t.framework_ref or "—"])
        el.append(_table(rows, [1.1 * cm, 2.4 * cm, 7.6 * cm, 2.9 * cm, 2.6 * cm], ss))
    else:
        el.append(Paragraph("No findings — all expected controls implemented or unknown.", ss["Body"]))

    # ---- recommendations ----
    el.append(Paragraph("Recommendations (gap-closing)", ss["H2"]))
    for rec in r.recommendations:
        fw = f" <i>[{escape(', '.join(rec.frameworks))}]</i>" if rec.frameworks else ""
        el.append(Paragraph(f"<b>{escape(rec.title)}</b> ({escape(rec.control_id)}) — "
                            f"{escape(rec.action)}{fw}", ss["Bull"], bulletText="•"))
    if not r.recommendations:
        el.append(Paragraph("None.", ss["Body"]))

    # ---- mitigations ----
    el.append(Paragraph("Mitigations (threat-specific)", ss["H2"]))
    for m in r.mitigations:
        note = f" <i>{escape(m.note)}</i>" if m.note else ""
        el.append(Paragraph(f"<b>{escape(m.threat_id)}</b> → {escape(m.action)}{note}",
                            ss["Bull"], bulletText="•"))
    if not r.mitigations:
        el.append(Paragraph("None.", ss["Body"]))

    # ---- DREAD ----
    el.append(Paragraph("DREAD scoring", ss["H2"]))
    if r.dread:
        rows = [["Threat", "D", "R", "E", "A", "D", "Avg", "Priority"]]
        for s in sorted(r.dread, key=lambda x: x.average, reverse=True):
            rows.append([s.threat_id, s.damage, s.reproducibility, s.exploitability,
                         s.affected_users, s.discoverability, s.average, s.priority.value])
        el.append(_table(rows, [2.2 * cm, 1.0 * cm, 1.0 * cm, 1.0 * cm, 1.0 * cm,
                                1.0 * cm, 1.4 * cm, 2.6 * cm], ss))
    else:
        el.append(Paragraph("No scored threats.", ss["Body"]))

    # ---- clarifications ----
    if r.clarifications:
        el.append(Paragraph("Clarifications needed (unknown ≠ missing)", ss["H2"]))
        for c in r.clarifications:
            el.append(Paragraph(escape(c), ss["Bull"], bulletText="•"))

    # ---- PCI ----
    el.append(Paragraph("PCI DSS v4.0.1 compliance view", ss["H2"]))
    if not r.pci_view.in_scope:
        el.append(Paragraph("Not in scope — the application does not handle cardholder data.", ss["Body"]))
    else:
        el.append(Paragraph(f"In scope. Covered PCI-mapped controls: {r.pci_view.covered_count}.",
                            ss["Body"]))
        for e in r.pci_view.exposed:
            reqs = ", ".join(x.requirement for x in e.requirements)
            el.append(Paragraph(f"Exposed: {escape(e.control_id)} {escape(e.control_title)} "
                                f"({_STATUS_LABEL[e.status]}) → PCI {reqs}", ss["Bull"], bulletText="•"))
        for e in r.pci_view.indeterminate:
            reqs = ", ".join(x.requirement for x in e.requirements)
            el.append(Paragraph(f"Verify: {escape(e.control_id)} {escape(e.control_title)} → PCI {reqs}",
                                ss["Bull"], bulletText="•"))

    # ---- out-of-catalog ----
    if r.compensating or r.candidates:
        el.append(Paragraph("Out-of-catalog controls", ss["H2"]))
        for a in r.compensating:
            el.append(Paragraph(f"Compensating: <b>{escape(a.observed.name)}</b> — "
                                f"{escape(a.rationale)}", ss["Bull"], bulletText="•"))
        for c in r.candidates:
            strides = ", ".join(s.value for s in c.stride) or "unmapped"
            el.append(Paragraph(f"Candidate: {escape(c.title)} [{strides}]", ss["Bull"], bulletText="•"))

    doc.build(el)
    return buf.getvalue()
