"""
threatcatalog.sad_extract
=========================

Turns an uploaded Solution Architecture Document (SAD) into what the models can
read: the text (with section headings and tables kept as Markdown, so quotes can
cite "section 4.2" and control matrices keep their meaning) and the diagrams as
PNG/JPEG images.

Supported: DOCX, PDF, Markdown / plain text. Everything happens in memory; the
upload is never written to disk.

* DOCX — body paragraphs and tables in document order; images taken from the
  file itself. Visio / draw.io figures embedded as EMF/WMF cannot be read by a
  vision model, so they are listed in `skipped` for the user to export as PNG.
* PDF — text per page. Diagrams in PDFs are often vector drawings rather than
  embedded images, so any page that carries a sizeable image or a lot of vector
  drawing is RENDERED to a PNG. A PDF with no text layer (a scan) is read from
  page images only.
* MD / TXT — text only; a ```mermaid / PlantUML block counts as a diagram.

Optional libraries (imported lazily): python-docx, PyMuPDF (`fitz`), Pillow.
"""

from __future__ import annotations

import hashlib
import io
import re
from dataclasses import dataclass, field

MAX_UPLOAD_BYTES = 25 * 1024 * 1024
MAX_PDF_PAGES = 300
MAX_IMAGES = 10                 # per model call; Bedrock Converse allows 20
MAX_EDGE = 1568                 # long edge sent to vision models
MIN_EDGE = 160                  # smaller images are icons / logos, not diagrams
PDF_DRAWINGS_FOR_FIGURE = 40    # vector paths on a page that suggest a diagram

_READABLE = {"image/png", "image/jpeg", "image/gif", "image/webp"}
_CONVERTIBLE = {"image/bmp", "image/tiff", "image/x-ms-bmp"}


class SadExtractionError(ValueError):
    """The file cannot be read as a SAD (wrong type, too large, corrupt)."""


@dataclass
class DiagramImage:
    data: bytes
    media_type: str
    label: str                  # where it came from, e.g. "Page 4" or "Figure after '3.1 Context'"


@dataclass
class ExtractedSad:
    filename: str
    sha256: str
    text: str
    images: list[DiagramImage] = field(default_factory=list)
    pages: int | None = None
    pages_estimated: bool = False                      # DOCX: no fixed pages, so estimated
    skipped: list[str] = field(default_factory=list)   # figures we could not use, and why
    notes: list[str] = field(default_factory=list)     # e.g. "no text layer"
    has_text_diagram: bool = False                     # mermaid / PlantUML in the text

    @property
    def words(self) -> int:
        return len(self.text.split())

    @property
    def approx_tokens(self) -> int:
        """Rough input size: ~1.35 tokens per English word, ~1,600 per image."""
        return int(self.words * 1.35) + 1600 * len(self.images)

    @property
    def has_diagram(self) -> bool:
        return bool(self.images) or self.has_text_diagram


def kind_of(filename: str) -> str:
    ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
    if ext in ("docx",):
        return "docx"
    if ext in ("pdf",):
        return "pdf"
    if ext in ("md", "markdown", "txt", "text"):
        return "text"
    raise SadExtractionError(f"Unsupported file type '.{ext}'. Upload a DOCX, PDF or Markdown SAD.")


def extract(filename: str, data: bytes, max_images: int = MAX_IMAGES) -> ExtractedSad:
    if not data:
        raise SadExtractionError("The uploaded file is empty.")
    if len(data) > MAX_UPLOAD_BYTES:
        raise SadExtractionError(f"The file is {len(data) // (1024 * 1024)} MB; the limit is "
                                 f"{MAX_UPLOAD_BYTES // (1024 * 1024)} MB.")
    kind = kind_of(filename)
    digest = hashlib.sha256(data).hexdigest()
    if kind == "docx":
        out = _extract_docx(filename, data, max_images)
    elif kind == "pdf":
        out = _extract_pdf(filename, data, max_images)
    else:
        text = data.decode("utf-8", errors="replace")
        out = ExtractedSad(filename=filename, sha256="", text=text.strip())
    out.sha256 = digest
    out.has_text_diagram = out.has_text_diagram or _has_text_diagram(out.text)
    return out


def add_images(sad: ExtractedSad, files: list[tuple[str, bytes]],
               max_images: int = MAX_IMAGES) -> None:
    """Add separately uploaded diagram files (PNG/JPG) to an extracted SAD."""
    for name, blob in files:
        if len(sad.images) >= max_images:
            sad.skipped.append(f"{name}: over the {max_images}-diagram limit")
            continue
        img = _prepare_image(blob, _guess_media_type(name), f"Uploaded diagram '{name}'", sad.skipped)
        if img is not None:
            sad.images.append(img)


def prepare_diagrams(files: list[tuple[str, bytes]], max_images: int = MAX_IMAGES
                     ) -> tuple[list[DiagramImage], list[str]]:
    """Validate, convert and downscale uploaded diagram files for a vision call.

    Returns (diagrams in upload order, labelled by file name; reasons for any
    file that was not used). Unlike figures pulled out of a SAD, a file the user
    chose is never dropped silently: a tiny image is reported as skipped."""
    images: list[DiagramImage] = []
    skipped: list[str] = []
    for name, blob in files:
        if len(images) >= max_images:
            skipped.append(f"{name}: over the {max_images}-diagram limit")
            continue
        before = len(skipped)
        img = _prepare_image(blob, _guess_media_type(name), name, skipped)
        if img is not None:
            images.append(img)
        elif len(skipped) == before:
            skipped.append(f"{name}: too small to be a diagram (under {MIN_EDGE}px)")
    return images, skipped


# --------------------------------------------------------------------------- #
# DOCX
# --------------------------------------------------------------------------- #
_NS_A = "http://schemas.openxmlformats.org/drawingml/2006/main"
_NS_R = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"
_NS_V = "urn:schemas-microsoft-com:vml"


def _extract_docx(filename: str, data: bytes, max_images: int) -> ExtractedSad:
    try:
        import docx  # python-docx
        from docx.table import Table
        from docx.text.paragraph import Paragraph
    except ImportError as exc:  # pragma: no cover - dependency guard
        raise SadExtractionError("Reading DOCX needs python-docx (pip install python-docx).") from exc
    try:
        document = docx.Document(io.BytesIO(data))
    except Exception as exc:  # noqa: BLE001
        raise SadExtractionError(f"Could not open the DOCX: {exc}") from exc

    out = ExtractedSad(filename=filename, sha256="", text="")
    lines: list[str] = []
    heading = "start of document"
    seen: set[str] = set()
    part = document.part

    def take_images(element) -> None:
        rids = [b.get(f"{{{_NS_R}}}embed") for b in element.iter(f"{{{_NS_A}}}blip")]
        rids += [d.get(f"{{{_NS_R}}}id") for d in element.iter(f"{{{_NS_V}}}imagedata")]
        for rid in filter(None, rids):
            img_part = part.related_parts.get(rid)
            if img_part is None:
                continue
            blob = img_part.blob
            h = hashlib.sha1(blob).hexdigest()
            if h in seen:
                continue
            seen.add(h)
            label = f"Figure after '{heading}'"
            if len(out.images) >= max_images:
                out.skipped.append(f"{label}: over the {max_images}-diagram limit")
                continue
            img = _prepare_image(blob, img_part.content_type, label, out.skipped)
            if img is not None:
                out.images.append(img)
                lines.append(f"[Diagram {len(out.images)}: {label}]")

    for child in document.element.body.iterchildren():
        tag = child.tag.rsplit("}", 1)[-1]
        if tag == "p":
            p = Paragraph(child, document)
            text = p.text.strip()
            style = (p.style.name if p.style is not None else "") or ""
            m = re.match(r"Heading\s*(\d)", style)
            if text:
                if m:
                    heading = text
                    lines.append("#" * min(int(m.group(1)) + 1, 6) + " " + text)
                elif style == "Title":
                    lines.append("# " + text)
                elif "List" in style:
                    lines.append("- " + text)
                else:
                    lines.append(text)
            take_images(child)
        elif tag == "tbl":
            lines.append(_table_markdown(Table(child, document)))
            take_images(child)
    out.text = "\n\n".join(x for x in lines if x).strip()
    out.pages, out.pages_estimated = docx_page_count(data, out.words, len(out.images))
    return out


# Calibrated on the sample SADs (Word -> PDF): about 400 words a page, a figure
# takes about three quarters of a page.
_WORDS_PER_PAGE = 400
_PAGES_PER_FIGURE = 0.75


def docx_page_count(data: bytes, words: int, figures: int) -> tuple[int, bool]:
    """(pages, estimated). A DOCX has no fixed pages: Word records its last layout
    in docProps/app.xml, but generators and templates often leave a stale value
    there. Use it only when that file's word count matches the document; otherwise
    estimate from words and figures."""
    import math
    import zipfile
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as z:
            app = z.read("docProps/app.xml").decode("utf-8", "replace")
        pages = int(re.search(r"<Pages>(\d+)</Pages>", app).group(1))
        app_words = int(re.search(r"<Words>(\d+)</Words>", app).group(1))
        if pages > 0 and words and abs(app_words - words) <= 0.25 * words:
            return pages, False
    except (KeyError, AttributeError, ValueError, zipfile.BadZipFile):
        pass
    return max(1, math.ceil(words / _WORDS_PER_PAGE + figures * _PAGES_PER_FIGURE)), True


def _table_markdown(table) -> str:
    rows = []
    for r in table.rows:
        cells = []
        for c in r.cells:
            cells.append(" ".join(c.text.split()).replace("|", "/"))
        rows.append(cells)
    if not rows:
        return ""
    width = max(len(r) for r in rows)
    rows = [r + [""] * (width - len(r)) for r in rows]
    md = ["| " + " | ".join(rows[0]) + " |", "|" + "---|" * width]
    md += ["| " + " | ".join(r) + " |" for r in rows[1:]]
    return "\n".join(md)


# --------------------------------------------------------------------------- #
# PDF
# --------------------------------------------------------------------------- #
# A PDF bullet is extracted as a lone glyph line (often U+F0B7 from the Symbol
# font) before its text; turn it into a Markdown "- " so the model and the
# quote check both see ordinary text.
_PDF_BULLET_LINE = re.compile(r"^[ \t]*[\ue000-\uf8ff\u2022\u2023\u2043\u25aa\u25cf\u25e6\u25a0][ \t]*\n",
                              re.M)


def _extract_pdf(filename: str, data: bytes, max_images: int) -> ExtractedSad:
    try:
        import pymupdf as fitz  # PyMuPDF
    except ImportError:
        try:
            import fitz  # older PyMuPDF
        except ImportError as exc:  # pragma: no cover - dependency guard
            raise SadExtractionError("Reading PDF needs PyMuPDF (pip install pymupdf).") from exc
    try:
        pdf = fitz.open(stream=data, filetype="pdf")
    except Exception as exc:  # noqa: BLE001
        raise SadExtractionError(f"Could not open the PDF: {exc}") from exc
    if pdf.needs_pass:
        raise SadExtractionError("The PDF is password-protected. Upload an unprotected copy.")
    if pdf.page_count > MAX_PDF_PAGES:
        raise SadExtractionError(f"The PDF has {pdf.page_count} pages; the limit is {MAX_PDF_PAGES}.")

    out = ExtractedSad(filename=filename, sha256="", text="", pages=pdf.page_count)
    parts: list[str] = []
    figure_pages: list[int] = []
    for i, page in enumerate(pdf):
        text = _PDF_BULLET_LINE.sub("- ", page.get_text("text")).strip()
        parts.append(f"--- Page {i + 1} ---\n{text}" if text else f"--- Page {i + 1} ---")
        if _pdf_page_has_figure(page):
            figure_pages.append(i)
    text_words = sum(len(p.split()) for p in parts) - 4 * len(parts)   # minus page markers
    scanned = text_words < max(50, 10 * pdf.page_count)
    if scanned:
        out.notes.append("The PDF has little or no text layer (likely scanned): it is read from "
                         "page images, and quotes cannot be checked against the text.")
        figure_pages = list(range(pdf.page_count))
    for i in figure_pages:
        label = f"Page {i + 1}"
        if len(out.images) >= max_images:
            out.skipped.append(f"{label}: over the {max_images}-diagram limit")
            continue
        page = pdf[i]
        long_edge = max(page.rect.width, page.rect.height) or 1
        zoom = min(MAX_EDGE / long_edge, 200 / 72)
        pix = page.get_pixmap(matrix=fitz.Matrix(zoom, zoom), alpha=False)
        out.images.append(DiagramImage(pix.tobytes("png"), "image/png", label))
        parts[i] += f"\n[Diagram {len(out.images)}: rendered {label}]"
    out.text = "\n\n".join(parts).strip()
    return out


def _pdf_page_has_figure(page) -> bool:
    area = page.rect.width * page.rect.height or 1
    try:
        for info in page.get_image_info():
            x0, y0, x1, y1 = info.get("bbox", (0, 0, 0, 0))
            if (x1 - x0) * (y1 - y0) > 0.08 * area and min(x1 - x0, y1 - y0) > 80:
                return True
    except Exception:  # noqa: BLE001 — older PyMuPDF
        pass
    try:
        return len(page.get_drawings()) >= PDF_DRAWINGS_FOR_FIGURE
    except Exception:  # noqa: BLE001
        return False


# --------------------------------------------------------------------------- #
# images
# --------------------------------------------------------------------------- #
def _guess_media_type(name: str) -> str:
    ext = name.rsplit(".", 1)[-1].lower()
    return {"png": "image/png", "jpg": "image/jpeg", "jpeg": "image/jpeg", "gif": "image/gif",
            "webp": "image/webp", "bmp": "image/bmp", "tif": "image/tiff",
            "tiff": "image/tiff"}.get(ext, "application/octet-stream")


def _prepare_image(blob: bytes, media_type: str, label: str,
                   skipped: list[str]) -> DiagramImage | None:
    """Validate, convert and downscale one image. Returns None (and records why)
    when it is not usable as a diagram."""
    media_type = (media_type or "").lower()
    if media_type not in _READABLE | _CONVERTIBLE:
        kind = media_type.split("/")[-1] or "unknown"
        skipped.append(f"{label}: {kind} format cannot be read by vision models "
                       "(export the figure as PNG and upload it separately)")
        return None
    try:
        from PIL import Image
    except ImportError:
        if media_type in _READABLE:
            return DiagramImage(blob, media_type, label)
        skipped.append(f"{label}: {media_type} needs Pillow to convert")
        return None
    try:
        im = Image.open(io.BytesIO(blob))
        im.load()
    except Exception:  # noqa: BLE001
        skipped.append(f"{label}: image could not be decoded")
        return None
    w, h = im.size
    if max(w, h) < MIN_EDGE:
        return None                         # an icon or logo, silently ignored
    changed = media_type in _CONVERTIBLE or media_type == "image/gif"
    if max(w, h) > MAX_EDGE:
        scale = MAX_EDGE / max(w, h)
        im = im.resize((max(1, int(w * scale)), max(1, int(h * scale))))
        changed = True
    if not changed:
        return DiagramImage(blob, media_type, label)
    if im.mode not in ("RGB", "L"):
        im = im.convert("RGB")
    buf = io.BytesIO()
    im.save(buf, format="PNG", optimize=True)
    return DiagramImage(buf.getvalue(), "image/png", label)


_TEXT_DIAGRAM = re.compile(r"```\s*(mermaid|plantuml)|@startuml", re.IGNORECASE)


def _has_text_diagram(text: str) -> bool:
    return bool(_TEXT_DIAGRAM.search(text or ""))
