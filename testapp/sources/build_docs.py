"""Build the sample SADs: Markdown source -> DOCX (python-docx) -> PDF (LibreOffice).

Usage: python build_docs.py   (run build_diagrams.py first; diagrams are embedded)
"""
from __future__ import annotations

import pathlib
import re
import subprocess

from docx import Document
from docx.enum.table import WD_TABLE_ALIGNMENT
from docx.oxml import OxmlElement
from docx.oxml.ns import qn
from docx.shared import Cm, Pt, RGBColor

HERE = pathlib.Path(__file__).parent
JOBS = [
    # (markdown source, output docx, footer text, make_pdf)
    ("corvane_sad.md", "../corvane-supplier-hub/Corvane_SupplierHub_SAD_v1.2.docx",
     "Corvane Logistics · CONFIDENTIAL · Supplier Hub SAD v1.2", True),
    ("corvane_sad_draft.md", "../corvane-supplier-hub/Corvane_SupplierHub_SAD_v0.1_DRAFT_incomplete.docx",
     "Corvane Logistics · DRAFT", False),
    ("halcyon_sad.md", "../halcyon-claimpilot/Halcyon_ClaimPilot_SAD_v2.0.docx",
     "Halcyon Mutual · RESTRICTED · ClaimPilot SAD v2.0", True),
    ("marlowe_sad.md", "../marlowe-shift-reporter/Marlowe_ShiftReporter_SAD_v1.0.docx",
     "Marlowe Foods · INTERNAL · Shift Reporter SAD v1.0", True),
    ("northfield_sad.md", "../northfield-sms-reminders/Northfield_SMSReminders_SAD_v1.0.docx",
     "Northfield Physiotherapy Group · CONFIDENTIAL · SMS Reminders SAD v1.0", True),
]

INLINE = re.compile(r"(\*\*[^*]+\*\*|`[^`]+`)")


def add_runs(par, text):
    for part in INLINE.split(text):
        if not part:
            continue
        if part.startswith("**"):
            par.add_run(part[2:-2]).bold = True
        elif part.startswith("`"):
            r = par.add_run(part[1:-1])
            r.font.name = "Consolas"
            r.font.size = Pt(9.5)
        else:
            par.add_run(part)


def shade(cell, hex_fill):
    tcPr = cell._tc.get_or_add_tcPr()
    shd = OxmlElement("w:shd")
    shd.set(qn("w:val"), "clear")
    shd.set(qn("w:color"), "auto")
    shd.set(qn("w:fill"), hex_fill)
    tcPr.append(shd)


def add_table(doc, rows):
    rows = [r for r in rows if not re.match(r"^\s*\|?\s*:?-{3,}", r)]
    cells = [[c.strip() for c in r.strip().strip("|").split("|")] for r in rows]
    ncol = max(len(r) for r in cells)
    t = doc.add_table(rows=len(cells), cols=ncol)
    t.style = "Table Grid"
    t.alignment = WD_TABLE_ALIGNMENT.CENTER
    for i, r in enumerate(cells):
        for j in range(ncol):
            cell = t.cell(i, j)
            cell.text = ""
            p = cell.paragraphs[0]
            add_runs(p, r[j] if j < len(r) else "")
            for run in p.runs:
                run.font.size = Pt(9)
                if i == 0:
                    run.bold = True
            if i == 0:
                shade(cell, "DCE6F2")
    doc.add_paragraph()


def footer(doc, text):
    for s in doc.sections:
        p = s.footer.paragraphs[0]
        p.text = text
        p.runs[0].font.size = Pt(8)
        p.runs[0].font.color.rgb = RGBColor(0x66, 0x66, 0x66)


def build(md_path: pathlib.Path, out: pathlib.Path, foot: str):
    doc = Document()
    for s in doc.sections:
        s.left_margin = s.right_margin = Cm(2)
        s.top_margin = s.bottom_margin = Cm(2)
    st = doc.styles["Normal"]
    st.font.name = "Calibri"
    st.font.size = Pt(10.5)
    lines = md_path.read_text().splitlines()
    i = 0
    para: list[str] = []

    def flush():
        if para:
            add_runs(doc.add_paragraph(), " ".join(para))
            para.clear()

    while i < len(lines):
        line = lines[i].rstrip()
        if not line.strip():
            flush()
        elif line.startswith("|"):
            flush()
            rows = []
            while i < len(lines) and lines[i].startswith("|"):
                rows.append(lines[i])
                i += 1
            add_table(doc, rows)
            continue
        elif m := re.match(r"^!\[(.*)\]\((.*)\)$", line):
            flush()
            img = (md_path.parent / m.group(2)).resolve()
            doc.add_picture(str(img), width=Cm(17))
            cap = doc.add_paragraph()
            r = cap.add_run(m.group(1))
            r.italic = True
            r.font.size = Pt(9)
        elif line.startswith("# "):
            flush()
            doc.add_paragraph(line[2:], style="Title")
        elif m := re.match(r"^(#{2,4}) (.*)", line):
            flush()
            doc.add_heading(m.group(2), level=len(m.group(1)) - 1)
        elif line.startswith("- "):
            flush()
            add_runs(doc.add_paragraph(style="List Bullet"), line[2:])
        elif m := re.match(r"^\d+\. (.*)", line):
            flush()
            add_runs(doc.add_paragraph(style="List Number"), m.group(1))
        elif line.strip() == "---pagebreak---":
            flush()
            doc.add_page_break()
        else:
            para.append(line.strip())
        i += 1
    flush()
    footer(doc, foot)
    out.parent.mkdir(parents=True, exist_ok=True)
    doc.save(out)
    print("wrote", out)


if __name__ == "__main__":
    import sys
    want = sys.argv[1:]          # optional filter, e.g. `python build_docs.py marlowe northfield`
    for src, out, foot, pdf in JOBS:
        if want and not any(w in src for w in want):
            continue
        src_p = HERE / src
        if not src_p.exists():
            continue
        out_p = (HERE / out).resolve()
        build(src_p, out_p, foot)
        if pdf:
            subprocess.run(["soffice", "--headless", "--convert-to", "pdf", "--outdir",
                            str(out_p.parent), str(out_p)], check=True, capture_output=True)
            print("wrote", out_p.with_suffix(".pdf"))
