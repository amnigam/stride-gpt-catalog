"""
threatcatalog.docx_export
=========================

Renders a `ThreatModelReport` to a Word document (bytes) with python-docx, so
business teams and the ARB can read, comment on and edit the report in Word.
The section order and every number and string match the PDF: both read the
same shared facts from `report.py`, and this module holds no analysis logic.

    pip install "threatcatalog[app]"     # or: pip install python-docx
"""

from __future__ import annotations

import io

from docx import Document
from docx.enum.section import WD_ORIENT
from docx.enum.table import WD_TABLE_ALIGNMENT
from docx.enum.text import WD_BREAK
from docx.oxml import OxmlElement
from docx.oxml.ns import qn
from docx.shared import Cm, Pt, RGBColor

from .models import ControlStatus, ThreatModelReport
from .report import (_STATUS_LABEL, EVIDENCE_TITLE, REGISTER_NOTE, action_rows,
                     architecture_rows, basis_facts, document_control, evidence_fields,
                     evidence_groups, evidence_note, focus_items, fw_text, out_of_catalog_rows,
                     pci_groups, register_columns, register_rows, sad_banner, sad_facts,
                     summary_facts, threat_rows, tile_legend)

# ---- palette (same as the PDF) ----
NAVY, TEAL, RED, AMBER = "1f2c4c", "0f9d8f", "b3261e", "c2620f"
GREEN, GREY, LINE, BAND = "0f8a5f", "5b6675", "c7ced9", "eef1f6"
ZEBRA, HEADERBG, OLIVE = "f6f8fc", "e7ecf4", "8a6d00"
PRIORITY = {"Critical": RED, "High": AMBER, "Medium": OLIVE, "Low": GREY}
STATUS = {ControlStatus.IMPLEMENTED: GREEN, ControlStatus.PARTIAL: AMBER,
          ControlStatus.NOT_PRESENT: RED, ControlStatus.UNKNOWN: GREY,
          ControlStatus.NOT_APPLICABLE: GREY}
READY = {"Ready": GREEN, "Ready with conditions": AMBER, "Not ready": RED}
TILE_BG = {"Confirmed in place": "e6f6ef", "Not present": "fbeae9", "Partial": "fdf3e7"}

FONT = "Calibri"
BODY_PT = 10
CELL_PT = 8.5
TEXT_W = 17.6          # cm between the margins on A4 portrait


# --------------------------------------------------------------------------- #
# Low-level helpers
# --------------------------------------------------------------------------- #
def _rgb(hexs: str) -> RGBColor:
    return RGBColor.from_string(hexs.upper())


def _shade(el, fill: str) -> None:
    """Background fill for a table cell (w:tcPr) or a paragraph (w:pPr)."""
    pr = el._tc.get_or_add_tcPr() if hasattr(el, "_tc") else el._p.get_or_add_pPr()
    shd = OxmlElement("w:shd")
    shd.set(qn("w:val"), "clear")
    shd.set(qn("w:color"), "auto")
    shd.set(qn("w:fill"), fill)
    pr.append(shd)


def _cell_borders(cell, **edges) -> None:
    """edges: left/right/top/bottom = (size in eighths of a point, hex colour) or None."""
    tcPr = cell._tc.get_or_add_tcPr()
    b = OxmlElement("w:tcBorders")
    for edge in ("top", "left", "bottom", "right"):
        spec = edges.get(edge)
        e = OxmlElement(f"w:{edge}")
        if spec is None:
            e.set(qn("w:val"), "nil")
        else:
            e.set(qn("w:val"), "single")
            e.set(qn("w:sz"), str(spec[0]))
            e.set(qn("w:color"), spec[1])
        b.append(e)
    tcPr.append(b)


def _table_borders(table, inner: str = LINE, outer: str | None = LINE) -> None:
    tblPr = table._tbl.tblPr
    b = OxmlElement("w:tblBorders")
    for edge in ("top", "left", "bottom", "right", "insideH", "insideV"):
        e = OxmlElement(f"w:{edge}")
        colour = inner if edge.startswith("inside") else outer
        if colour is None or edge == "insideV":
            e.set(qn("w:val"), "nil")
        else:
            e.set(qn("w:val"), "single")
            e.set(qn("w:sz"), "4")
            e.set(qn("w:color"), colour)
        b.append(e)
    tblPr.append(b)


def _cell_margins(table, top=60, bottom=60, left=100, right=100) -> None:
    tblPr = table._tbl.tblPr
    m = OxmlElement("w:tblCellMar")
    for k, v in (("top", top), ("left", left), ("bottom", bottom), ("right", right)):
        e = OxmlElement(f"w:{k}")
        e.set(qn("w:w"), str(v))
        e.set(qn("w:type"), "dxa")
        m.append(e)
    tblPr.append(m)


def _repeat_header(row) -> None:
    trPr = row._tr.get_or_add_trPr()
    e = OxmlElement("w:tblHeader")
    e.set(qn("w:val"), "true")
    trPr.append(e)


def _keep_row_together(row) -> None:
    trPr = row._tr.get_or_add_trPr()
    e = OxmlElement("w:cantSplit")
    e.set(qn("w:val"), "true")
    trPr.append(e)


def _widths(table, cms: list[float]) -> None:
    """Fixed column widths that Word and LibreOffice both honour: the table grid,
    the table width and every cell width have to agree."""
    table.autofit = False
    tbl = table._tbl
    tblPr = tbl.tblPr
    layout = OxmlElement("w:tblLayout")
    layout.set(qn("w:type"), "fixed")
    tblPr.append(layout)
    for old in tblPr.findall(qn("w:tblW")):
        tblPr.remove(old)
    tw = OxmlElement("w:tblW")
    tw.set(qn("w:w"), str(int(sum(cms) * 567)))
    tw.set(qn("w:type"), "dxa")
    tblPr.append(tw)
    for gc, w in zip(tbl.tblGrid.findall(qn("w:gridCol")), cms):
        gc.set(qn("w:w"), str(int(w * 567)))
    for row in table.rows:
        for cell, w in zip(row.cells, cms):
            cell.width = Cm(w)


def _run(p, text: str, bold=False, italic=False, colour: str | None = None,
         size: float | None = None):
    r = p.add_run(text)
    r.bold, r.italic = bold, italic
    if colour:
        r.font.color.rgb = _rgb(colour)
    if size:
        r.font.size = Pt(size)
    return r


def _para(doc_or_cell, text: str = "", size: float | None = None, colour: str | None = None,
          bold=False, italic=False, after: float = 4, style: str | None = None):
    p = doc_or_cell.add_paragraph(style=style) if style else doc_or_cell.add_paragraph()
    p.paragraph_format.space_after = Pt(after)
    if text:
        _run(p, text, bold=bold, italic=italic, colour=colour, size=size)
    return p


def _cell_text(cell, text: str, bold=False, colour: str | None = None, size=CELL_PT,
               italic=False):
    cell.text = ""
    p = cell.paragraphs[0]
    p.paragraph_format.space_after = Pt(0)
    _run(p, str(text), bold=bold, colour=colour, size=size, italic=italic)
    return p


def _h2(doc, text: str) -> None:
    p = doc.add_paragraph(style="Heading 1")
    p.paragraph_format.space_before = Pt(16)
    p.paragraph_format.space_after = Pt(8)
    p.paragraph_format.keep_with_next = True
    _shade(p, BAND)
    _run(p, " " + text, bold=True, colour=NAVY, size=13)


def _lead(doc, text: str) -> None:
    p = _para(doc, text, size=10, colour=NAVY, bold=True, after=3)
    p.paragraph_format.space_before = Pt(6)
    p.paragraph_format.keep_with_next = True


def _bullet(doc, parts: list[tuple[str, dict]]) -> None:
    """parts: [(text, run kwargs)]"""
    p = doc.add_paragraph(style="List Bullet")
    p.paragraph_format.space_after = Pt(2)
    for text, kw in parts:
        _run(p, text, **kw)


def _grid(doc, header: list[str], rows: list[list], cms: list[float]):
    """A zebra-striped table like the PDF's. A row cell may be a plain value or a
    (text, colour, bold) tuple for a colour-coded status or priority."""
    t = doc.add_table(rows=1, cols=len(header))
    t.alignment = WD_TABLE_ALIGNMENT.CENTER
    _table_borders(t, inner=LINE, outer=None)
    _cell_margins(t)
    hdr = t.rows[0]
    _repeat_header(hdr)
    for c, h in zip(hdr.cells, header):
        _cell_text(c, h, bold=True, colour=NAVY)
        _shade(c, HEADERBG)
        _cell_borders(c, bottom=(8, NAVY))
    for i, row in enumerate(rows):
        r = t.add_row()
        _keep_row_together(r)
        for c, v in zip(r.cells, row):
            if isinstance(v, tuple):
                _cell_text(c, v[0], colour=v[1], bold=v[2] if len(v) > 2 else True)
            else:
                _cell_text(c, "" if v is None else v)
            if i % 2:
                _shade(c, ZEBRA)
    _widths(t, cms)
    doc.add_paragraph().paragraph_format.space_after = Pt(2)
    return t


def _box(doc, edge: str, fill: str, lines: list[list[tuple[str, dict]]], width=TEXT_W):
    """A one-cell box with a coloured left edge (readiness marker, callouts)."""
    t = doc.add_table(rows=1, cols=1)
    _table_borders(t, inner=fill, outer=None)
    _cell_margins(t, top=120, bottom=120, left=200, right=160)
    c = t.rows[0].cells[0]
    _shade(c, fill)
    _cell_borders(c, left=(36, edge))
    c.text = ""
    for i, parts in enumerate(lines):
        p = c.paragraphs[0] if i == 0 else c.add_paragraph()
        p.paragraph_format.space_after = Pt(2)
        for text, kw in parts:
            _run(p, text, **kw)
    _widths(t, [width])
    return t


# --------------------------------------------------------------------------- #
# Sections
# --------------------------------------------------------------------------- #
def _setup(doc, r: ThreatModelReport) -> None:
    sec = doc.sections[0]
    sec.orientation = WD_ORIENT.PORTRAIT
    sec.page_width, sec.page_height = Cm(21.0), Cm(29.7)
    for side in ("left_margin", "right_margin"):
        setattr(sec, side, Cm(1.7))
    sec.top_margin = sec.bottom_margin = Cm(1.7)
    normal = doc.styles["Normal"]
    normal.font.name = FONT
    normal.font.size = Pt(BODY_PT)
    normal.element.rPr.rFonts.set(qn("w:eastAsia"), FONT)
    doc.core_properties.title = f"Threat Model — {r.profile.name}"
    doc.core_properties.subject = "Threat model"
    # footer: report name and page number
    fp = sec.footer.paragraphs[0]
    _run(fp, f"Threat Model — {r.profile.name}    ·    Page ", colour=GREY, size=8)
    for kind, text in (("begin", None), (None, "PAGE"), ("end", None)):
        run = fp.add_run()
        run.font.size, run.font.color.rgb = Pt(8), _rgb(GREY)
        if kind:
            f = OxmlElement("w:fldChar")
            f.set(qn("w:fldCharType"), kind)
            run._r.append(f)
        else:
            it = OxmlElement("w:instrText")
            it.set(qn("xml:space"), "preserve")
            it.text = text
            run._r.append(it)


def _cover(doc, r: ThreatModelReport) -> None:
    p = r.profile
    t = _para(doc, f"Threat Model — {p.name}", size=24, colour=NAVY, bold=True, after=2)
    t.paragraph_format.space_before = Pt(0)
    _para(doc, f"Platforms: {', '.join(x.value for x in p.platforms)}  |  "
               f"AI capability: {', '.join(a.value for a in p.ai_capabilities)}  |  "
               f"Data: {p.data_classification.value}  |  "
               f"Expected controls: {r.resolved_control_count}  |  "
               f"PCI in scope: {'yes' if p.handles_cardholder_data else 'no'}",
          size=8.5, colour=GREY, after=1)
    dc = document_control(r)
    if dc:
        _para(doc, "  |  ".join(f"{k}: {v}" for k, v in dc), size=8.5, colour=GREY, after=6)
    rule = doc.add_paragraph()
    pPr = rule._p.get_or_add_pPr()
    bdr = OxmlElement("w:pBdr")
    bottom = OxmlElement("w:bottom")
    for k, v in (("w:val", "single"), ("w:sz", "12"), ("w:color", TEAL), ("w:space", "1")):
        bottom.set(qn(k), v)
    bdr.append(bottom)
    pPr.append(bdr)
    rule.paragraph_format.space_after = Pt(6)
    banner = sad_banner(r)
    if banner:
        bp = _para(doc, after=6)
        _run(bp, banner[0] + " ", bold=True, colour=AMBER)
        _run(bp, banner[1])

    f = focus_items(r)
    _h2(doc, "Key focus items")
    _para(doc, f["note"], colour=GREY, after=6)
    col = READY.get(f["readiness"], GREY)
    head = [("Security readiness: " + f["readiness"], {"bold": True, "colour": col, "size": 16})]
    if f["tag"]:
        head.append(("   " + f["tag"], {"bold": True, "colour": AMBER, "size": 12}))
    _box(doc, col, BAND, [head, [(f["reason_line"], {"colour": GREY, "size": 9.5})]])
    _para(doc, f["legend"], size=8, colour=GREY, after=6)
    for key, title in (("before_go_live", "Address before go-live"),
                       ("business_risks", "Risks for the business to consider"),
                       ("open_questions", "Open questions for the team")):
        items, more = f[key]
        if not items:
            continue
        _lead(doc, title)
        for cid, title_, why in items:
            _bullet(doc, [(cid + " ", {"bold": True}), (title_ + " ", {}),
                          (f"({why})", {"colour": GREY})])
        if more:
            _bullet(doc, [(f"…and {more} more (see the findings register)", {"colour": GREY})])
    _para(doc, after=2)
    _grid(doc, ["Role", "Name", "Date"], [[role, name, ""] for role, name in f["people"]],
          [6.3, 7.8, 3.5])


def _executive_summary(doc, r: ThreatModelReport) -> None:
    f = summary_facts(r)
    c = f["counts"]
    _h2(doc, "Executive summary")
    tiles = [("Expected", c["expected"], NAVY), ("Confirmed in place", c["implemented"], GREEN),
             ("Not present", c["not_present"], RED), ("Partial", c["partial"], AMBER),
             ("To verify", c["to_verify"], GREY),
             ("Reviewed", "Draft" if c["reviewed"] is None
              else f"{c['reviewed']}/{c['expected']}", NAVY)]
    t = doc.add_table(rows=1, cols=len(tiles))
    _table_borders(t, inner="ffffff", outer=LINE)
    _cell_margins(t, top=100, bottom=100, left=60, right=60)
    for cell, (label, num, col) in zip(t.rows[0].cells, tiles):
        _shade(cell, TILE_BG.get(label, BAND))
        cell.text = ""
        p1 = cell.paragraphs[0]
        p1.alignment = 1
        p1.paragraph_format.space_after = Pt(0)
        _run(p1, str(num), bold=True, colour=col, size=17)
        p2 = cell.add_paragraph()
        p2.alignment = 1
        p2.paragraph_format.space_after = Pt(0)
        _run(p2, label, colour=GREY, size=7.5)
    _widths(t, [TEXT_W / len(tiles)] * len(tiles))
    _para(doc, tile_legend(r), size=8, colour=GREY, after=8)

    for para in f["posture"]:
        _para(doc, para, after=5)
    if f["top_findings"]:
        _lead(doc, "Top findings (ranked by DREAD)")
        for x in f["top_findings"]:
            parts = []
            if x["priority"]:
                parts.append((f"[{x['priority']} · {x['score']}] ",
                              {"bold": True, "colour": PRIORITY.get(x["priority"], GREY)}))
            parts.append((x["title"] + " ", {}))
            tags = ([x["control_id"]] if x["control_id"] else []) + x["tags"]
            if tags:
                parts.append((f"({', '.join(tags)})", {"colour": GREY}))
            _bullet(doc, parts)
    if f["strengths"]:
        _lead(doc, "Strengths (confirmed in place)")
        for cid, title in f["strengths"]:
            _bullet(doc, [(cid + " ", {"bold": True, "colour": GREEN}), (title, {})])
    if f["notes"]:
        p = _para(doc, after=4)
        _run(p, "Also note: ", bold=True)
        _run(p, "; ".join(f["notes"]) + ".")
    if f["all_confirmed"]:
        p = _para(doc, after=4)
        _run(p, "No gaps and nothing outstanding ", bold=True, colour=GREEN)
        _run(p, "— all expected controls are confirmed in place.")


def _basis(doc, r: ThreatModelReport) -> None:
    sf = sad_facts(r)
    if sf is not None:
        _h2(doc, "Assessment basis (SAD)")
        _para(doc, sf["rules"], after=6)
        _grid(doc, ["Item", "Value"], [list(x) for x in sf["source"]], [4.2, 13.4])
        _lead(doc, "Application profile")
        _grid(doc, ["Facet", "Selected", "Basis", "Reason"], [list(x) for x in sf["facets"]],
              [3.4, 1.8, 3.0, 9.4])
        _lead(doc, "SAD completeness")
        _grid(doc, ["Item", "Result", "Evidence or what is missing"],
              [list(x) for x in sf["completeness"]], [5.4, 2.0, 10.2])
        if sf["limitations"]:
            _lead(doc, "Limitations of this assessment")
            for x in sf["limitations"]:
                _bullet(doc, [(x, {})])
    bf = basis_facts(r)
    if bf is not None:
        _h2(doc, "Assessment basis")
        _grid(doc, ["Item", "Value"], [list(x) for x in bf["rows"]], [4.2, 13.4])
        if r.diagrams_skipped:
            _para(doc, "Not read: " + "; ".join(r.diagrams_skipped), size=8.5, colour=GREY)
        if bf["completeness"]:
            _lead(doc, "Input completeness (SAD checklist, warns only)")
            _grid(doc, ["Item", "Result", "Evidence or what is missing"],
                  [list(x) for x in bf["completeness"]], [5.4, 2.0, 10.2])
        _lead(doc, "Limitations of this assessment")
        for x in bf["limitations"]:
            _bullet(doc, [(x, {})])


def _register(doc, r: ThreatModelReport) -> None:
    _h2(doc, "Findings register")
    _para(doc, REGISTER_NOTE, colour=GREY, after=6)
    rows = register_rows(r, findings_only=True)
    if not rows:
        _para(doc, "No findings — every expected control is confirmed in place.")
        return
    show_basis, show_pci = register_columns(r)
    head = (["Control", "Status"] + (["Basis"] if show_basis else []) + ["Frameworks"]
            + (["PCI exposed"] if show_pci else []))
    data = []
    for x in rows:
        data.append([x["control"], (x["status"], STATUS.get(x["status_enum"], GREY))]
                    + ([x["basis"]] if show_basis else []) + [x["frameworks"]]
                    + ([x["pci"]] if show_pci else []))
    widths = {(True, True): [5.4, 2.6, 3.0, 3.8, 2.8], (True, False): [6.6, 2.6, 3.4, 5.0],
              (False, True): [6.6, 2.6, 5.0, 3.4], (False, False): [8.0, 2.8, 6.8]}
    _grid(doc, head, data, widths[(show_basis, show_pci)])


def _threats(doc, r: ThreatModelReport) -> None:
    arch = architecture_rows(r)
    if arch:
        _h2(doc, "System context")
        _grid(doc, ["Item", "Details"], [list(x) for x in arch], [4.2, 13.4])

    _h2(doc, "Threat model")
    if r.threats:
        t = _grid(doc, ["ID", "STRIDE", "Threat", "Gaps", "Maps to"],
                  [[x["id"], x["stride"], x["title"], x["gaps"], x["maps"]]
                   for x in threat_rows(r)], [1.2, 2.4, 7.0, 3.9, 3.1])
        for row, x in zip(t.rows[1:], threat_rows(r)):
            if x["detail"]:
                p = row.cells[2].add_paragraph()
                p.paragraph_format.space_after = Pt(0)
                _run(p, x["detail"], colour=GREY, size=7.5, italic=True)
    else:
        _para(doc, "No findings — all expected controls implemented or unknown.")

    _h2(doc, "DREAD scoring")
    if r.dread:
        data = []
        for sc in sorted(r.dread, key=lambda x: x.average, reverse=True):
            data.append([sc.threat_id, sc.damage, sc.reproducibility, sc.exploitability,
                         sc.affected_users, sc.discoverability, sc.average,
                         (sc.priority.value, PRIORITY.get(sc.priority.value, GREY)),
                         sc.rationale or "—"])
        _grid(doc, ["Threat", "D", "R", "E", "A", "D", "Avg", "Priority", "Why"], data,
              [1.6, 0.8, 0.8, 0.8, 0.8, 0.8, 1.1, 1.9, 9.0])
    else:
        _para(doc, "No scored threats.")

    if r.actions:
        _h2(doc, "Action plan")
        _grid(doc, ["#", "Action", "Closes", "Controls", "Priority", "Timing", "Owner"],
              [[x["id"], x["action"], x["closes"], x["controls"],
                (x["priority"], PRIORITY.get(x["priority"], GREY)), x["timing"], x["owner"]]
               for x in action_rows(r)], [1.0, 6.4, 1.6, 3.4, 1.7, 2.0, 1.5])
    else:   # reports from older engines: recommendations + mitigations
        _h2(doc, "Recommendations (gap-closing)")
        for rec in r.recommendations:
            fw = f" [{', '.join(fw_text(x) for x in rec.frameworks)}]" if rec.frameworks else ""
            _bullet(doc, [(rec.title, {"bold": True}),
                          (f" ({rec.control_id}) — {rec.action}", {}),
                          (fw, {"colour": GREY, "italic": True})])
        if not r.recommendations:
            _para(doc, "None.")
        _h2(doc, "Mitigations (threat-specific)")
        for m in r.mitigations:
            _bullet(doc, [(m.threat_id, {"bold": True}), (f" → {m.action}", {}),
                          ((" " + m.note) if m.note else "", {"colour": AMBER, "italic": True})])
        if not r.mitigations:
            _para(doc, "None.")


def _pci_and_more(doc, r: ThreatModelReport) -> None:
    if r.clarifications:
        _h2(doc, "Clarifications needed (unknown ≠ missing)")
        for c in r.clarifications:
            _bullet(doc, [(c, {})])

    _h2(doc, "PCI DSS v4.0.1 compliance view")
    if not r.pci_view.in_scope:
        _para(doc, "Not in scope — the application does not handle cardholder data.")
    else:
        pg = pci_groups(r)
        k = pg["counts"]
        _para(doc, f"In scope. {k['mapped']} PCI-mapped control(s) expected: {k['exposed']} "
                   f"exposed, {k['verify']} to verify, {k['in_place']} in place.")
        if pg["groups"]:
            data = []
            for req, items in pg["groups"]:
                for cid, title, label, kind in items:
                    data.append([req, f"{cid}  {title}",
                                 (label if kind == "exposed" else f"{label} (verify)",
                                  RED if kind == "exposed" else GREY)])
            _grid(doc, ["PCI requirement", "Control", "Status"], data, [3.2, 11.0, 3.4])

    ooc = out_of_catalog_rows(r)
    if ooc:
        _h2(doc, "Out-of-catalog controls")
        for x in ooc:
            _bullet(doc, [(x, {})])


def _appendix(doc, r: ThreatModelReport) -> None:
    groups = evidence_groups(r)
    if not groups:
        return
    _h2(doc, EVIDENCE_TITLE)
    note = evidence_note(r)
    lead, _, rest = note.partition(". ")
    _box(doc, AMBER, "fdf3e7", [[(lead + ". ", {"bold": True, "colour": AMBER}), (rest, {})]])
    _para(doc, after=4)
    for st, recs in groups:
        col = STATUS.get(st, GREY)
        p = _para(doc, after=4)
        p.paragraph_format.space_before = Pt(8)
        p.paragraph_format.keep_with_next = True
        _run(p, _STATUS_LABEL[st], bold=True, colour=col, size=12)
        _run(p, f"  ({len(recs)})", colour=GREY, size=10)
        for rec in recs:
            _card(doc, rec, col)


def _card(doc, rec: dict, col: str) -> None:
    """One control as a card: header row with the control and status, then labelled rows."""
    fields = evidence_fields(rec)
    t = doc.add_table(rows=1 + len(fields), cols=2)
    _table_borders(t, inner="e3e7ee", outer=LINE)
    _cell_margins(t, top=50, bottom=50, left=120, right=120)
    head = t.rows[0].cells
    m = head[0].merge(head[1])
    _shade(m, BAND)
    m.text = ""
    hp = m.paragraphs[0]
    hp.paragraph_format.space_after = Pt(0)
    _run(hp, rec["id"] + "  ", bold=True, size=9.5)
    _run(hp, rec["title"] + "   ", size=9.5)
    _run(hp, rec["status"].upper(), bold=True, colour=col, size=8.5)
    for row, (key, label, val) in zip(t.rows[1:], fields):
        _cell_text(row.cells[0], label, bold=True, colour=GREY, size=8)
        c = row.cells[1]
        if key == "ai":
            _cell_text(c, val, bold=True)
        elif key == "quote":
            p = _cell_text(c, f"“{val}”", italic=True)
            if rec["quote_unverified"]:
                _run(p, " (not found verbatim in the source)", colour=RED, size=CELL_PT)
            if rec["quote_unsupported"]:
                _run(p, f" (quote check: {rec['quote_unsupported']})", colour=RED, size=CELL_PT)
        elif key == "reviewer_note":
            _cell_text(c, val, colour=NAVY)
        elif key == "reviewed_by":
            _cell_text(c, val, colour=GREY)
        else:
            _cell_text(c, val)
    for row in t.rows:
        _keep_row_together(row)
        _cell_borders(row.cells[0], left=(28, col), top=(4, "e3e7ee"), bottom=(4, "e3e7ee"))
    # keep the card on one page where it fits
    for row in t.rows[:-1]:
        for p in row.cells[0].paragraphs + row.cells[-1].paragraphs:
            p.paragraph_format.keep_with_next = True
    _widths(t, [3.4, TEXT_W - 3.4])
    _para(doc, after=4)


# --------------------------------------------------------------------------- #
def render_docx(r: ThreatModelReport) -> bytes:
    doc = Document()
    _setup(doc, r)
    _cover(doc, r)
    doc.add_paragraph().add_run().add_break(WD_BREAK.PAGE)
    _executive_summary(doc, r)
    _basis(doc, r)
    _register(doc, r)
    _threats(doc, r)
    _pci_and_more(doc, r)
    _appendix(doc, r)
    buf = io.BytesIO()
    doc.save(buf)
    return buf.getvalue()


def render_feedback_docx(sad, a) -> bytes:
    """The SAD feedback checklist for the document's author, as Word. Same content
    as `sad.feedback_markdown`."""
    from .models import RubricScore
    from .sad import _SCORE_LABEL
    doc = Document()
    sec = doc.sections[0]
    sec.page_width, sec.page_height = Cm(21.0), Cm(29.7)
    sec.left_margin = sec.right_margin = sec.top_margin = sec.bottom_margin = Cm(1.7)
    doc.styles["Normal"].font.name = FONT
    doc.styles["Normal"].font.size = Pt(BODY_PT)
    title = a.document_title or sad.filename
    doc.core_properties.title = f"SAD review feedback — {title}"
    _para(doc, f"SAD review feedback — {title}", size=20, colour=NAVY, bold=True, after=2)
    _para(doc, f"File: {sad.filename}  |  SHA-256: {sad.sha256[:16]}…  |  Words: {sad.words}"
               f"  |  Diagrams read: {len(sad.images)}", size=8.5, colour=GREY, after=8)
    if a.stop_reasons:
        _h2(doc, "Result: not enough to threat model")
        _para(doc, "No threat model was produced. Fix the following and upload the SAD again:")
        for r in a.stop_reasons:
            _bullet(doc, [(r, {})])
    else:
        _h2(doc, "Result: sufficient, with gaps")
        _para(doc, "A threat model was produced. Closing these gaps will make it more accurate.")
    _h2(doc, "Completeness checklist")
    colour = {RubricScore.PRESENT: GREEN, RubricScore.THIN: AMBER, RubricScore.MISSING: RED}
    _grid(doc, ["Item", "Result", "Required to proceed", "What to add"],
          [[i.title, (_SCORE_LABEL[i.score], colour[i.score]), "Yes" if i.hard_minimum else "No",
            (i.comment or "—") if i.score != RubricScore.PRESENT else "—"]
           for i in a.completeness], [5.0, 2.0, 2.6, 8.0])
    if sad.skipped:
        _h2(doc, "Figures that could not be read")
        for s in sad.skipped:
            _bullet(doc, [(s, {})])
    if sad.notes:
        _h2(doc, "Notes")
        for n in sad.notes:
            _bullet(doc, [(n, {})])
    buf = io.BytesIO()
    doc.save(buf)
    return buf.getvalue()
