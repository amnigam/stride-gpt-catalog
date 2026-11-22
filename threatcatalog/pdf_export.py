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
from reportlab.platypus import (HRFlowable, KeepTogether, PageBreak, Paragraph,
                                SimpleDocTemplate, Spacer, Table, TableStyle)

from .models import ControlStatus, ThreatModelReport
from .report import (_STATUS_LABEL, EVIDENCE_TITLE, REGISTER_NOTE, action_rows, architecture_rows, basis_facts,
                     focus_items, threat_rows, tile_legend, document_control, evidence_fields, evidence_groups,
                     evidence_note, fw_text, out_of_catalog_rows, pci_groups,
                     register_columns, register_rows, sad_banner, sad_facts, stride_label,
                     summary_facts, threat_fw)

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
                          borderPadding=(5, 6, 5, 6), leftIndent=0, keepWithNext=1))
    ss.add(ParagraphStyle("Body", parent=ss["Normal"], fontSize=9.5, leading=14.5,
                          alignment=TA_LEFT, spaceAfter=4))
    ss.add(ParagraphStyle("Marker", parent=ss["Normal"], fontSize=15, leading=19))
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


def _status_cell(status, ss, label):
    col = _STATUS_COLOR.get(status, _GREY)
    return Paragraph(f'<font color="{col.hexval()}"><b>{escape(label)}</b></font>', ss["Cell"])


def _priority_cell(priority, ss):
    col = _PRIORITY.get(priority, _GREY)
    return Paragraph(f'<font color="{col.hexval()}"><b>{escape(priority)}</b></font>', ss["Cell"])


def _stat_strip(counts, ss):
    """A compact, colour-coded summary band: expected / in place / not present /
    partial / to verify."""
    spec = [
        ("Expected", counts["expected"], _NAVY, _BAND),
        ("Confirmed in place", counts["implemented"], _GREEN, colors.HexColor("#e6f6ef")),
        ("Not present", counts["not_present"], _RED, colors.HexColor("#fbeae9")),
        ("Partial", counts["partial"], _AMBER, colors.HexColor("#fdf3e7")),
        ("To verify", counts["to_verify"], _GREY, _BAND),
        ("Reviewed", "Draft" if counts["reviewed"] is None
         else f"{counts['reviewed']}/{counts['expected']}", _NAVY, _BAND),
    ]
    cells = []
    for label, num, col, _bg in spec:
        cells.append(Paragraph(
            f'<font size="15" color="{col.hexval()}"><b>{num}</b></font><br/>'
            f'<font size="7.5" color="{_GREY.hexval()}">{escape(label)}</font>',
            ss["StatNum"]))
    t = Table([cells], colWidths=[2.9 * cm] * len(spec))
    style = [("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
             ("TOPPADDING", (0, 0), (-1, -1), 6), ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
             ("LEFTPADDING", (0, 0), (-1, -1), 4), ("RIGHTPADDING", (0, 0), (-1, -1), 4),
             ("BOX", (0, 0), (-1, -1), 0.4, _LINE), ("INNERGRID", (0, 0), (-1, -1), 0.4, colors.white)]
    for i, (_l, _n, _c, bg) in enumerate(spec):
        style.append(("BACKGROUND", (i, 0), (i, 0), bg))
    t.setStyle(TableStyle(style))
    return t


_READY_COLOR = {"Ready": _GREEN, "Ready with conditions": _AMBER, "Not ready": _RED}


def _focus_block(r, ss):
    f = focus_items(r)
    col = _READY_COLOR.get(f["readiness"], _GREY)
    el = [Paragraph("Key focus items", ss["H2"]),
          Paragraph(f'<font color="{_GREY.hexval()}">{escape(f["note"])}</font>', ss["Body"])]
    tag = (f' &nbsp;<font color="{_AMBER.hexval()}"><b>{escape(f["tag"])}</b></font>'
           if f["tag"] else "")
    marker = Table([[Paragraph(
        f'<font size="15" color="{col.hexval()}"><b>Security readiness: '
        f'{escape(f["readiness"])}</b></font>{tag}', ss["Marker"])],
        [Paragraph(f'<font size="9" color="{_GREY.hexval()}">'
                   f'{escape(f["reason_line"])}</font>', ss["Body"])]],
        colWidths=[_CARD_W])
    marker.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), _BAND), ("LINEBEFORE", (0, 0), (0, -1), 4.5, col),
        ("TOPPADDING", (0, 0), (-1, 0), 9), ("BOTTOMPADDING", (0, -1), (-1, -1), 8),
        ("TOPPADDING", (0, 1), (-1, 1), 2), ("BOTTOMPADDING", (0, 0), (-1, 0), 2),
        ("LEFTPADDING", (0, 0), (-1, -1), 11)]))
    el.append(marker)
    el.append(Spacer(1, 3))
    el.append(Paragraph(escape(f["legend"]), ss["Meta"]))
    for key, title in (("before_go_live", "Address before go-live"),
                       ("business_risks", "Risks for the business to consider"),
                       ("open_questions", "Open questions for the team")):
        items, more = f[key]
        if not items:
            continue
        el.append(Paragraph(title, ss["Lead"]))
        for cid, t, why in items:
            el.append(Paragraph(f"<b>{escape(cid)}</b> {escape(t)} "
                                f'<font color="{_GREY.hexval()}">({escape(why)})</font>',
                                ss["Bull"], bulletText="\u2022"))
        if more:
            el.append(Paragraph(f"…and {more} more (see the findings register)", ss["Bull"],
                                bulletText="\u2022"))
    el.append(Spacer(1, 6))
    el.append(KeepTogether([_table([["Role", "Name", "Date"]]
                                   + [[role, name, ""] for role, name in f["people"]],
                                   [6.0 * cm, 7.5 * cm, 3.0 * cm], ss)]))
    return el


def _register_table(r, rows, ss):
    show_basis, show_pci = register_columns(r)
    head = (["Control", "Status"] + (["Basis"] if show_basis else []) + ["Frameworks"]
            + (["PCI exposed"] if show_pci else []))
    data = [head]
    for x in rows:
        data.append([x["control"], _status_cell(x["status_enum"], ss, x["status"])]
                    + ([x["basis"]] if show_basis else []) + [x["frameworks"]]
                    + ([x["pci"]] if show_pci else []))
    widths = {(True, True): [5.0, 2.5, 2.8, 3.6, 2.6], (True, False): [6.2, 2.5, 3.2, 4.6],
              (False, True): [6.2, 2.5, 4.6, 3.2], (False, False): [7.6, 2.5, 6.4]}
    return _table(data, [w * cm for w in widths[(show_basis, show_pci)]], ss)


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
    dc = document_control(r)
    if dc:
        el.append(Paragraph(" &nbsp;|&nbsp; ".join(f"{escape(k)}: {escape(v)}" for k, v in dc),
                            ss["Meta"]))
    el.append(HRFlowable(width="100%", thickness=1.4, color=_TEAL, spaceBefore=4, spaceAfter=8))
    banner = sad_banner(r)
    if banner is not None:
        el.append(Paragraph(f'<font color="{_AMBER.hexval()}"><b>{escape(banner[0])}'
                            f'</b></font> {escape(banner[1])}', ss["Body"]))

    # ---- cover: key focus items (informs the ARB, never directs it) + sign-off ----
    el.extend(_focus_block(r, ss))
    el.append(PageBreak())

    # ---- executive summary: stat strip, then the narrative ----
    el.append(Paragraph("Executive summary", ss["H2"]))
    el.append(_stat_strip(f["counts"], ss))
    el.append(Spacer(1, 3))
    el.append(Paragraph(escape(tile_legend(r)), ss["Meta"]))
    el.append(Spacer(1, 6))
    for para in f["posture"]:
        el.append(Paragraph(escape(para), ss["Body"]))

    if f["top_findings"]:
        el.append(Paragraph("Top findings (ranked by DREAD)", ss["Lead"]))
        for x in f["top_findings"]:
            lead = ""
            if x["priority"]:
                col = _PRIORITY.get(x["priority"], _GREY)
                lead = (f'<font color="{col.hexval()}"><b>[{escape(x["priority"])} &middot; '
                        f'{x["score"]}]</b></font> ')
            tags = [x["control_id"]] if x["control_id"] else []
            tags += x["tags"]
            tg = f' <font color="{_GREY.hexval()}">({escape(", ".join(tags))})</font>' if tags else ""
            el.append(Paragraph(f"{lead}{escape(x['title'])}{tg}", ss["Bull"], bulletText="\u2022"))

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
        el.append(Paragraph(escape(sf["rules"]), ss["Body"]))
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

    # ---- assessment basis for a review-page run with no SAD ----
    bf = basis_facts(r)
    if bf is not None:
        el.append(Paragraph("Assessment basis", ss["H2"]))
        el.append(_table([["Item", "Value"]] + [list(x) for x in bf["rows"]],
                         [4.0 * cm, 12.5 * cm], ss))
        if r.diagrams_skipped:
            el.append(Paragraph(escape("Not read: " + "; ".join(r.diagrams_skipped)), ss["Meta"]))
        if bf["completeness"]:
            el.append(Paragraph("Input completeness (SAD checklist, warns only)", ss["Lead"]))
            el.append(_table([["Item", "Result", "Evidence or what is missing"]]
                             + [list(x) for x in bf["completeness"]],
                             [5.2 * cm, 1.9 * cm, 9.4 * cm], ss))
        el.append(Paragraph("Limitations of this assessment", ss["Lead"]))
        for x in bf["limitations"]:
            el.append(Paragraph(escape(x), ss["Bull"], bulletText="\u2022"))

    # ---- findings register (gaps + unknowns; the full list is in the appendix) ----
    el.append(Paragraph("Findings register", ss["H2"]))
    el.append(Paragraph(f'<font color="{_GREY.hexval()}">{escape(REGISTER_NOTE)}</font>', ss["Body"]))
    rows = register_rows(r, findings_only=True)
    if rows:
        el.append(_register_table(r, rows, ss))
    else:
        el.append(Paragraph("No findings — every expected control is confirmed in place.",
                            ss["Body"]))

    # ---- system context: what the threats are built on ----
    arch = architecture_rows(r)
    if arch:
        el.append(Paragraph("System context", ss["H2"]))
        el.append(_table([["Item", "Details"]] + [list(x) for x in arch],
                         [4.0 * cm, 12.5 * cm], ss))

    # ---- threats ----
    el.append(Paragraph("Threat model", ss["H2"]))
    if r.threats:
        rows = [["ID", "STRIDE", "Threat", "Gaps", "Maps to"]]
        for x in threat_rows(r):
            cell = escape(x["title"])
            if x["detail"]:
                cell += f'<br/><font size="7.5" color="{_GREY.hexval()}">{escape(x["detail"])}</font>'
            rows.append([x["id"], x["stride"], Paragraph(cell, ss["Cell"]), x["gaps"], x["maps"]])
        el.append(_table(rows, [1.1 * cm, 2.3 * cm, 6.3 * cm, 3.9 * cm, 2.9 * cm], ss))
    else:
        el.append(Paragraph("No findings — all expected controls implemented or unknown.", ss["Body"]))

    # ---- DREAD (colour-coded priority, with the reason) ----
    el.append(Paragraph("DREAD scoring", ss["H2"]))
    if r.dread:
        rows = [["Threat", "D", "R", "E", "A", "D", "Avg", "Priority", "Why"]]
        for sc in sorted(r.dread, key=lambda x: x.average, reverse=True):
            rows.append([sc.threat_id, sc.damage, sc.reproducibility, sc.exploitability,
                         sc.affected_users, sc.discoverability, sc.average,
                         _priority_cell(sc.priority.value, ss),
                         Paragraph(f'<font size="7.5">{escape(sc.rationale or "—")}</font>',
                                   ss["Cell"])])
        el.append(_table(rows, [1.55 * cm] + [0.85 * cm] * 5 + [1.1 * cm, 2.0 * cm, 7.6 * cm], ss))
    else:
        el.append(Paragraph("No scored threats.", ss["Body"]))

    # ---- action plan (older engines: recommendations + mitigations) ----
    if r.actions:
        el.append(Paragraph("Action plan", ss["H2"]))
        rows = [["#", "Action", "Closes", "Controls", "Priority", "Timing", "Owner"]]
        for x in action_rows(r):
            rows.append([x["id"], x["action"], x["closes"], x["controls"],
                         _priority_cell(x["priority"], ss), x["timing"], x["owner"]])
        el.append(_table(rows, [1.1 * cm, 5.3 * cm, 1.6 * cm, 3.5 * cm, 1.7 * cm, 1.9 * cm,
                                1.4 * cm], ss))
    else:
        el.append(Paragraph("Recommendations (gap-closing)", ss["H2"]))
        for rec in r.recommendations:
            fw = (f' <i><font color="{_GREY.hexval()}">[{escape(", ".join(fw_text(x) for x in rec.frameworks))}]'
                  "</font></i>") if rec.frameworks else ""
            el.append(Paragraph(f"<b>{escape(rec.title)}</b> ({escape(rec.control_id)}) — "
                                f"{escape(rec.action)}{fw}", ss["Bull"], bulletText="\u2022"))
        if not r.recommendations:
            el.append(Paragraph("None.", ss["Body"]))
        el.append(Paragraph("Mitigations (threat-specific)", ss["H2"]))
        for m in r.mitigations:
            note = f' <i><font color="{_AMBER.hexval()}">{escape(m.note)}</font></i>' if m.note else ""
            el.append(Paragraph(f"<b>{escape(m.threat_id)}</b> &rarr; {escape(m.action)}{note}",
                                ss["Bull"], bulletText="\u2022"))
        if not r.mitigations:
            el.append(Paragraph("None.", ss["Body"]))

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
        pg = pci_groups(r)
        k = pg["counts"]
        el.append(Paragraph(
            f"In scope. {k['mapped']} PCI-mapped control(s) expected: {k['exposed']} exposed, "
            f"{k['verify']} to verify, {k['in_place']} in place.", ss["Body"]))
        if pg["groups"]:
            prow = [["PCI requirement", "Control", "Status"]]
            for req, items in pg["groups"]:
                for cid, title, label, kind in items:
                    col = _RED if kind == "exposed" else _GREY
                    st = label if kind == "exposed" else f"{label} (verify)"
                    prow.append([req, f"{cid}  {title}",
                                 Paragraph(f'<font color="{col.hexval()}"><b>{escape(st)}</b></font>',
                                           ss["Cell"])])
            el.append(_table(prow, [3.0 * cm, 10.5 * cm, 3.0 * cm], ss))

    # ---- out-of-catalog ----
    ooc = out_of_catalog_rows(r)
    if ooc:
        el.append(Paragraph("Out-of-catalog controls", ss["H2"]))
        for x in ooc:
            el.append(Paragraph(escape(x), ss["Bull"], bulletText="\u2022"))

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
