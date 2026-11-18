"""
threatcatalog.pdf_export
========================

Renders a `ThreatModelReport` to a PDF (bytes), using reportlab — pure Python,
no system binaries, so it runs the same on Linux/macOS/Windows. Kept in its own
module so the optional `reportlab` dependency never touches the core engine; the
UI/CLI import it lazily and degrade gracefully if it isn't installed.

    pip install "threatcatalog[pdf]"     # or: pip install reportlab

Styling note: this renderer carries the *presentation* polish (colour-coded
status/priority, a summary stat strip, banded section headers, zebra tables and
generous spacing). It holds no analysis logic — every number and string comes
from `report.summary_facts` / the `ThreatModelReport`, so the PDF and the
Markdown always agree.
"""

from __future__ import annotations

import io
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import cm
from reportlab.platypus import (HRFlowable, KeepTogether, Paragraph, SimpleDocTemplate,
                                Spacer, Table, TableStyle)

from .models import ControlStatus, ThreatModelReport
from .report import (_STATUS_LABEL, EVIDENCE_TITLE, basis_label, evidence_fields,
                     automated, evidence_groups, evidence_note, sad_banner,
                     sad_facts, summary_facts)

# ---- palette ----
_NAVY = colors.HexColor("#1f2c4c")
_TEAL = colors.HexColor("#0f9d8f")
_RED = colors.HexColor("#b3261e")
_AMBER = colors.HexColor("#c2620f")
_GREEN = colors.HexColor("#0f8a5f")
_GREY = colors.HexColor("#5b6675")
_LINE = colors.HexColor("#c7ced9")
_BAND = colors.HexColor("#eef1f6")        # section-header band
_ZEBRA = colors.HexColor("#f6f8fc")       # alternate table row
_HEADERBG = colors.HexColor("#e7ecf4")    # table header

_PRIORITY = {"Critical": _RED, "High": _AMBER, "Medium": colors.HexColor("#8a6d00"),
             "Low": _GREY}
_STATUS_COLOR = {
    ControlStatus.IMPLEMENTED: _GREEN,
    ControlStatus.PARTIAL: _AMBER,
    ControlStatus.NOT_PRESENT: _RED,
    ControlStatus.UNKNOWN: _GREY,
    ControlStatus.NOT_APPLICABLE: _GREY,
}


def _styles():
    ss = getSampleStyleSheet()
    ss.add(ParagraphStyle("TitleX", parent=ss["Title"], fontSize=21, textColor=_NAVY,
                          spaceAfter=3, alignment=TA_LEFT))
    ss.add(ParagraphStyle("Meta", parent=ss["Normal"], fontSize=8.5, textColor=_GREY,
                          spaceAfter=2, leading=12))
    # banded section header — a light navy-tint band with navy bold text (adds colour
    # + makes the report scannable without looking busy)
    ss.add(ParagraphStyle("H2", parent=ss["Heading2"], fontSize=12.5, textColor=_NAVY,
                          fontName="Helvetica-Bold", spaceBefore=16, spaceAfter=8,
                          leading=16, backColor=_BAND, borderColor=_BAND, borderWidth=0,
                          borderPadding=(5, 6, 5, 6), leftIndent=0))
    ss.add(ParagraphStyle("Body", parent=ss["Normal"], fontSize=9.5, leading=14.5,
                          alignment=TA_LEFT, spaceAfter=4))
    ss.add(ParagraphStyle("Lead", parent=ss["Normal"], fontSize=9.5, leading=12,
                          textColor=_NAVY, fontName="Helvetica-Bold", spaceBefore=4,
                          spaceAfter=3))
    ss.add(ParagraphStyle("Bull", parent=ss["Normal"], fontSize=9.5, leading=14,
                          leftIndent=12, bulletIndent=2, spaceAfter=3))
    ss.add(ParagraphStyle("Cell", parent=ss["Normal"], fontSize=8.5, leading=11.5))
    ss.add(ParagraphStyle("CellHdr", parent=ss["Normal"], fontSize=8.5, leading=11.5,
                          textColor=_NAVY, fontName="Helvetica-Bold"))
    ss.add(ParagraphStyle("StatNum", parent=ss["Normal"], alignment=TA_CENTER, leading=17))
    ss.add(ParagraphStyle("StatLbl", parent=ss["Normal"], alignment=TA_CENTER, fontSize=7.5,
                          textColor=_GREY, leading=9))
    ss.add(ParagraphStyle("GroupHdr", parent=ss["Normal"], fontSize=11, leading=14,
                          fontName="Helvetica-Bold", spaceBefore=8, spaceAfter=6))
    ss.add(ParagraphStyle("CardTitle", parent=ss["Normal"], fontSize=9.5, leading=12,
                          textColor=_NAVY))
    ss.add(ParagraphStyle("CardLabel", parent=ss["Normal"], fontSize=8, leading=11.5,
                          textColor=_GREY, fontName="Helvetica-Bold"))
    ss.add(ParagraphStyle("Pill", parent=ss["Normal"], fontSize=7, leading=9,
                          alignment=TA_CENTER, textColor=colors.white))
    return ss


def _table(data, col_widths, ss):
    """Build a zebra-striped table. Cells may be strings (auto-wrapped) or ready-made
    Paragraph flowables (e.g. a colour-coded status), which are passed through."""
    def mk(c, style):
        return c if isinstance(c, Paragraph) else Paragraph(escape(str(c)), style)
    body = [[mk(c, ss["CellHdr" if r == 0 else "Cell"]) for c in row]
            for r, row in enumerate(data)]
    t = Table(body, colWidths=col_widths, repeatRows=1)
    t.setStyle(TableStyle([
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, _ZEBRA]),
        ("BACKGROUND", (0, 0), (-1, 0), _HEADERBG),
        ("LINEBELOW", (0, 0), (-1, 0), 0.8, _NAVY),
        ("LINEBELOW", (0, 1), (-1, -1), 0.25, _LINE),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
    ]))
    return t


_CARD_W = 17.0 * cm
_LABEL_W = 3.3 * cm


def _callout(text, ss):
    """Amber-edged note box for the automated-assessment notice."""
    lead, _, rest = text.partition(". ")
    t = Table([[Paragraph(f'<font color="{_AMBER.hexval()}"><b>{escape(lead)}.</b></font> '
                          f"{escape(rest)}", ss["Body"])]], colWidths=[_CARD_W])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#fdf3e7")),
        ("LINEBEFORE", (0, 0), (0, -1), 3, _AMBER),
        ("TOPPADDING", (0, 0), (-1, -1), 7), ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("LEFTPADDING", (0, 0), (-1, -1), 9), ("RIGHTPADDING", (0, 0), (-1, -1), 9),
    ]))
    return t


def _pill(text, col, ss):
    t = Table([[Paragraph(f"<b>{escape(text).upper()}</b>", ss["Pill"])]], colWidths=[2.5 * cm])
    t.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), col),
                           ("TOPPADDING", (0, 0), (-1, -1), 2), ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
                           ("LEFTPADDING", (0, 0), (-1, -1), 4), ("RIGHTPADDING", (0, 0), (-1, -1), 4)]))
    return t


def _evidence_card(rec, ss):
    """One control as a card: a header band with the control and a status pill,
    then labelled rows. A coloured left edge carries the status at a glance."""
    col = _STATUS_COLOR.get(rec["status_enum"], _GREY)
    pad = 8
    head = Table([[Paragraph(f'<b>{escape(rec["id"])}</b>&nbsp;&nbsp;{escape(rec["title"])}',
                             ss["CardTitle"]), _pill(rec["status"], col, ss)]],
                 colWidths=[_CARD_W - 2 * pad - 2.7 * cm, 2.7 * cm])
    head.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                              ("ALIGN", (1, 0), (1, 0), "RIGHT"),
                              ("LEFTPADDING", (0, 0), (-1, -1), 0),
                              ("RIGHTPADDING", (0, 0), (-1, -1), 0),
                              ("TOPPADDING", (0, 0), (-1, -1), 0),
                              ("BOTTOMPADDING", (0, 0), (-1, -1), 0)]))
    data = [[head, ""]]
    for key, label, val in evidence_fields(rec):
        v = escape(val)
        if key == "ai":
            v = f"<b>{v}</b>"
        elif key == "quote":
            v = f"<i>\u201c{v}\u201d</i>"
            if rec["quote_unverified"]:
                v += (f' <font color="{_RED.hexval()}">(not found verbatim in the source)'
                      "</font>")
            if rec["quote_unsupported"]:
                v += (f' <font color="{_RED.hexval()}">(quote check: '
                      f'{escape(rec["quote_unsupported"])})</font>')
        elif key == "reviewer_note":
            v = f'<font color="{_NAVY.hexval()}">{v}</font>'
        elif key == "reviewed_by":
            v = f'<font color="{_GREY.hexval()}">{v}</font>'
        data.append([Paragraph(label, ss["CardLabel"]), Paragraph(v, ss["Cell"])])
    t = Table(data, colWidths=[_LABEL_W, _CARD_W - _LABEL_W])
    t.setStyle(TableStyle([
        ("SPAN", (0, 0), (1, 0)),
        ("BACKGROUND", (0, 0), (-1, 0), _BAND),
        ("BOX", (0, 0), (-1, -1), 0.5, _LINE),
        ("LINEBELOW", (0, 0), (-1, 0), 0.5, _LINE),
        ("LINEBELOW", (0, 1), (-1, -2), 0.25, colors.HexColor("#e3e7ee")),
        ("LINEBEFORE", (0, 0), (0, -1), 3.5, col),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), pad), ("RIGHTPADDING", (0, 0), (-1, -1), pad),
        ("TOPPADDING", (0, 0), (-1, -1), 4), ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("TOPPADDING", (0, 0), (-1, 0), 6), ("BOTTOMPADDING", (0, 0), (-1, 0), 6),
    ]))
    return t


def _status_cell(status, ss):
    col = _STATUS_COLOR.get(status, _GREY)
    return Paragraph(f'<font color="{col.hexval()}"><b>{escape(_STATUS_LABEL[status])}</b></font>',
                     ss["Cell"])


def _priority_cell(priority, ss):
    col = _PRIORITY.get(priority, _GREY)
    return Paragraph(f'<font color="{col.hexval()}"><b>{escape(priority)}</b></font>', ss["Cell"])


def _stat_strip(counts, ss):
    """A compact, colour-coded summary band: expected / in place / gaps / to verify."""
    spec = [
        ("Expected", counts["expected"], _NAVY, _BAND),
        ("Confirmed in place", counts["implemented"], _GREEN, colors.HexColor("#e6f6ef")),
        ("Gaps", counts["gaps"], _RED, colors.HexColor("#fbeae9")),
        ("To verify", counts["unknown"], _GREY, _BAND),
    ]
    cells = []
    for label, num, col, _bg in spec:
        cells.append(Paragraph(
            f'<font size="15" color="{col.hexval()}"><b>{num}</b></font><br/>'
            f'<font size="7.5" color="{_GREY.hexval()}">{escape(label)}</font>',
            ss["StatNum"]))
    t = Table([cells], colWidths=[4.35 * cm] * 4)
    style = [("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
             ("TOPPADDING", (0, 0), (-1, -1), 6), ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
             ("LEFTPADDING", (0, 0), (-1, -1), 4), ("RIGHTPADDING", (0, 0), (-1, -1), 4),
             ("BOX", (0, 0), (-1, -1), 0.4, _LINE), ("INNERGRID", (0, 0), (-1, -1), 0.4, colors.white)]
    for i, (_l, _n, _c, bg) in enumerate(spec):
        style.append(("BACKGROUND", (i, 0), (i, 0), bg))
    t.setStyle(TableStyle(style))
    return t


def render_pdf(r: ThreatModelReport) -> bytes:
    ss = _styles()
    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, topMargin=1.7 * cm, bottomMargin=1.7 * cm,
                            leftMargin=1.7 * cm, rightMargin=1.7 * cm,
                            title=f"Threat Model — {r.profile.name}")
    el = []
    p = r.profile
    f = summary_facts(r)

    # ---- title block ----
    el.append(Paragraph(f"Threat Model &mdash; {escape(p.name)}", ss["TitleX"]))
    el.append(Paragraph(
        f"Platforms: {', '.join(x.value for x in p.platforms)} &nbsp;|&nbsp; "
        f"AI capability: {', '.join(a.value for a in p.ai_capabilities)} &nbsp;|&nbsp; "
        f"Data: {p.data_classification.value} &nbsp;|&nbsp; "
        f"Expected controls: {r.resolved_control_count} &nbsp;|&nbsp; "
        f"PCI in scope: {'yes' if p.handles_cardholder_data else 'no'}", ss["Meta"]))
    if r.sad is None and (r.diagrams_read or r.diagrams_skipped):
        read = "; ".join(f"Diagram {i + 1}: {d}" for i, d in enumerate(r.diagrams_read)) or "none"
        txt = escape(f"Diagrams read ({len(r.diagrams_read)}): {read}")
        if r.diagrams_skipped:
            txt += " &nbsp;|&nbsp; " + escape("Not read: " + "; ".join(r.diagrams_skipped))
        el.append(Paragraph(txt, ss["Meta"]))
    el.append(HRFlowable(width="100%", thickness=1.4, color=_TEAL, spaceBefore=4, spaceAfter=8))
    banner = sad_banner(r)
    if banner is not None:
        el.append(Paragraph(f'<font color="{_AMBER.hexval()}"><b>{escape(banner[0])}'
                            f'</b></font> {escape(banner[1])}', ss["Body"]))

    # ---- summary stat strip ----
    el.append(_stat_strip(f["counts"], ss))
    el.append(Spacer(1, 6))

    # ---- executive summary (narrative paragraphs) ----
    el.append(Paragraph("Executive summary", ss["H2"]))
    for para in f["posture"]:
        el.append(Paragraph(escape(para), ss["Body"]))

    if f["top_threats"]:
        el.append(Paragraph("Top threats (by DREAD)", ss["Lead"]))
        for prio, avg, title, fw in f["top_threats"]:
            col = _PRIORITY.get(prio, _GREY)
            tag = f" ({escape(fw)})" if fw else ""
            el.append(Paragraph(
                f'<font color="{col.hexval()}"><b>[{prio} &middot; {avg}]</b></font> '
                f'{escape(title)}{tag}', ss["Bull"], bulletText="\u2022"))

    if f["key_gaps"]:
        el.append(Paragraph("Key gaps to close", ss["Lead"]))
        for cid, title, tags in f["key_gaps"]:
            tg = f' <font color="{_GREY.hexval()}">({escape(", ".join(tags))})</font>' if tags else ""
            el.append(Paragraph(f'<b>{escape(cid)}</b> {escape(title)}{tg}', ss["Bull"],
                                bulletText="\u2022"))

    if f["strengths"]:
        el.append(Paragraph("Strengths (confirmed in place)", ss["Lead"]))
        for cid, title in f["strengths"]:
            el.append(Paragraph(
                f'<font color="{_GREEN.hexval()}"><b>{escape(cid)}</b></font> {escape(title)}',
                ss["Bull"], bulletText="\u2022"))

    if f["notes"]:
        el.append(Spacer(1, 2))
        el.append(Paragraph("<b>Also note:</b> " + escape("; ".join(f["notes"])) + ".", ss["Body"]))
    if f["all_confirmed"]:
        el.append(Paragraph(
            f'<font color="{_GREEN.hexval()}"><b>No gaps and nothing outstanding</b></font> '
            "— all expected controls are confirmed in place.", ss["Body"]))

    # ---- SAD assessment basis ----
    sf = sad_facts(r)
    if sf is not None:
        el.append(Paragraph("Assessment basis (SAD)", ss["H2"]))
        el.append(_table([["Item", "Value"]] + [list(x) for x in sf["source"]],
                         [4.0 * cm, 12.5 * cm], ss))
        el.append(Paragraph("Application profile", ss["Lead"]))
        el.append(_table([["Facet", "Selected", "Basis", "Reason"]] + [list(x) for x in sf["facets"]],
                         [3.2 * cm, 1.7 * cm, 3.0 * cm, 8.6 * cm], ss))
        el.append(Paragraph("SAD completeness", ss["Lead"]))
        el.append(_table([["Item", "Result", "Evidence or what is missing"]]
                         + [list(x) for x in sf["completeness"]],
                         [5.2 * cm, 1.9 * cm, 9.4 * cm], ss))
        if sf["limitations"]:
            el.append(Paragraph("Limitations of this assessment", ss["Lead"]))
            for x in sf["limitations"]:
                el.append(Paragraph(escape(x), ss["Bull"], bulletText="\u2022"))

    # ---- gap register (colour-coded status) ----
    el.append(Paragraph("Control gap register", ss["H2"]))
    show_basis = not automated(r)   # automated SAD run: the AI is the basis of every row
    rows = [["Control", "Status"] + (["Basis"] if show_basis else []) + ["Frameworks", "PCI exposed"]]
    for gi in r.gap_items:
        fws = ", ".join(x.ref for x in gi.control.threat_frameworks) or "\u2014"
        pci = ", ".join(x.requirement for x in gi.pci_exposed) or "\u2014"
        rows.append([f"{gi.control.id}  {gi.control.title}", _status_cell(gi.status, ss)]
                    + ([basis_label(gi)] if show_basis else []) + [fws, pci])
    widths = ([5.4, 2.1, 2.8, 3.6, 2.6] if show_basis else [6.6, 2.1, 4.6, 3.2])
    el.append(_table(rows, [w * cm for w in widths], ss))

    # ---- threats ----
    el.append(Paragraph("Threat model", ss["H2"]))
    if r.threats:
        rows = [["ID", "STRIDE", "Threat", "Gap", "Maps to"]]
        for t in r.threats:
            rows.append([t.id, t.stride.value, t.title, t.enabling_gap or "\u2014",
                         t.framework_ref or "\u2014"])
        el.append(_table(rows, [1.1 * cm, 2.4 * cm, 7.4 * cm, 2.9 * cm, 2.7 * cm], ss))
    else:
        el.append(Paragraph("No findings — all expected controls implemented or unknown.", ss["Body"]))

    # ---- recommendations ----
    el.append(Paragraph("Recommendations (gap-closing)", ss["H2"]))
    for rec in r.recommendations:
        fw = f' <i><font color="{_GREY.hexval()}">[{escape(", ".join(rec.frameworks))}]</font></i>' if rec.frameworks else ""
        el.append(Paragraph(f"<b>{escape(rec.title)}</b> ({escape(rec.control_id)}) — "
                            f"{escape(rec.action)}{fw}", ss["Bull"], bulletText="\u2022"))
    if not r.recommendations:
        el.append(Paragraph("None.", ss["Body"]))

    # ---- mitigations ----
    el.append(Paragraph("Mitigations (threat-specific)", ss["H2"]))
    for m in r.mitigations:
        note = f' <i><font color="{_AMBER.hexval()}">{escape(m.note)}</font></i>' if m.note else ""
        el.append(Paragraph(f"<b>{escape(m.threat_id)}</b> &rarr; {escape(m.action)}{note}",
                            ss["Bull"], bulletText="\u2022"))
    if not r.mitigations:
        el.append(Paragraph("None.", ss["Body"]))

    # ---- DREAD (colour-coded priority) ----
    el.append(Paragraph("DREAD scoring", ss["H2"]))
    if r.dread:
        rows = [["Threat", "D", "R", "E", "A", "D", "Avg", "Priority"]]
        for s in sorted(r.dread, key=lambda x: x.average, reverse=True):
            rows.append([s.threat_id, s.damage, s.reproducibility, s.exploitability,
                         s.affected_users, s.discoverability, s.average,
                         _priority_cell(s.priority.value, ss)])
        el.append(_table(rows, [2.2 * cm, 1.0 * cm, 1.0 * cm, 1.0 * cm, 1.0 * cm,
                                1.0 * cm, 1.4 * cm, 2.6 * cm], ss))
    else:
        el.append(Paragraph("No scored threats.", ss["Body"]))

    # ---- clarifications ----
    if r.clarifications:
        el.append(Paragraph("Clarifications needed (unknown \u2260 missing)", ss["H2"]))
        for c in r.clarifications:
            el.append(Paragraph(escape(c), ss["Bull"], bulletText="\u2022"))

    # ---- PCI ----
    el.append(Paragraph("PCI DSS v4.0.1 compliance view", ss["H2"]))
    if not r.pci_view.in_scope:
        el.append(Paragraph("Not in scope — the application does not handle cardholder data.", ss["Body"]))
    else:
        el.append(Paragraph(f"In scope. Covered PCI-mapped controls: {r.pci_view.covered_count}.",
                            ss["Body"]))
        for e in r.pci_view.exposed:
            reqs = ", ".join(x.requirement for x in e.requirements)
            el.append(Paragraph(
                f'<font color="{_RED.hexval()}"><b>Exposed:</b></font> {escape(e.control_id)} '
                f"{escape(e.control_title)} ({_STATUS_LABEL[e.status]}) &rarr; PCI {reqs}",
                ss["Bull"], bulletText="\u2022"))
        for e in r.pci_view.indeterminate:
            reqs = ", ".join(x.requirement for x in e.requirements)
            el.append(Paragraph(
                f'<font color="{_GREY.hexval()}"><b>Verify:</b></font> {escape(e.control_id)} '
                f"{escape(e.control_title)} &rarr; PCI {reqs}", ss["Bull"], bulletText="\u2022"))

    # ---- out-of-catalog ----
    if r.compensating or r.candidates:
        el.append(Paragraph("Out-of-catalog controls", ss["H2"]))
        for a in r.compensating:
            el.append(Paragraph(f"Compensating: <b>{escape(a.observed.name)}</b> — "
                                f"{escape(a.rationale)}", ss["Bull"], bulletText="\u2022"))
        for c in r.candidates:
            strides = ", ".join(s.value for s in c.stride) or "unmapped"
            el.append(Paragraph(f"Candidate: {escape(c.title)} [{strides}]", ss["Bull"],
                                bulletText="\u2022"))

    # ---- evidence appendix: one card per control, grouped by status ----
    groups = evidence_groups(r)
    if groups:
        el.append(Paragraph(escape(EVIDENCE_TITLE), ss["H2"]))
        el.append(_callout(evidence_note(r), ss))
        for st, recs in groups:
            col = _STATUS_COLOR.get(st, _GREY)
            el.append(Paragraph(f'<font color="{col.hexval()}">{escape(_STATUS_LABEL[st])}'
                                f'</font> <font color="{_GREY.hexval()}">({len(recs)})</font>',
                                ss["GroupHdr"]))
            for rec in recs:
                el.append(KeepTogether([_evidence_card(rec, ss), Spacer(1, 7)]))

    doc.build(el)
    return buf.getvalue()
