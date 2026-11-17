"""Several architecture diagrams on the description + diagram page."""
from __future__ import annotations

from threatcatalog import pipeline
from threatcatalog.llm import LLMArtifactEngine
from threatcatalog.llm.prompts import detect_prompt
from threatcatalog.llm.provider import StubRawLLM

DESC = "All traffic goes through a WAF at the edge. Data is encrypted at rest with KMS."


def test_detect_sends_all_diagrams_in_one_call_with_labels(tiny_controls):
    cid = tiny_controls[0].id
    raw = StubRawLLM([{"control_id": cid, "status": "implemented", "confidence": "high",
                       "source": "diagram", "quote": "Diagram 2: WAF in front of ALB",
                       "rationale": "WAF shown on the network view."}])
    entries = LLMArtifactEngine(raw).detect_controls(
        tiny_controls, DESC,
        diagrams=[(b"a", "image/png", "Overview.png"), (b"b", "image/png", "Network.png"),
                  (b"c", "image/jpeg", "Agents.jpg")])
    assert len(raw.multi_image_calls) == 1
    _system, user, n = raw.multi_image_calls[0]
    assert n == 3
    assert "Diagram 1 = Overview.png" in user and "Diagram 3 = Agents.jpg" in user
    assert "SAME system" in user and "'Diagram N:" in user
    assert entries[0].detail.ai_quote == "Diagram 2: WAF in front of ALB"
    assert entries[0].detail.ai_source == "diagram"


def test_single_diagram_prompt_unchanged():
    _s, user = detect_prompt([], "desc", has_diagram=True)
    assert "the attached architecture DIAGRAM" in user and "Diagram 1 =" not in user


def test_prepare_diagrams_labels_downscales_and_reports_skips():
    import io

    from PIL import Image

    from threatcatalog.sad_extract import MAX_EDGE, prepare_diagrams

    def png(w, h):
        buf = io.BytesIO()
        Image.new("RGB", (w, h), "white").save(buf, format="PNG")
        return buf.getvalue()

    files = [("big.png", png(3000, 1500)), ("ok.png", png(800, 600)),
             ("icon.png", png(64, 64)), ("notes.pdf", b"%PDF")]
    images, skipped = prepare_diagrams(files, max_images=10)
    assert [i.label for i in images] == ["big.png", "ok.png"]
    assert MAX_EDGE - 2 <= max(Image.open(io.BytesIO(images[0].data)).size) <= MAX_EDGE
    assert any(s.startswith("icon.png: too small") for s in skipped)
    assert any(s.startswith("notes.pdf") for s in skipped)
    images, skipped = prepare_diagrams(files[:2], max_images=1)
    assert len(images) == 1 and "over the 1-diagram limit" in skipped[0]


def test_report_lists_diagrams_read(tiny_controls, web_llm_profile):
    from threatcatalog.report import render_markdown
    report = pipeline.run(web_llm_profile, description=DESC, controls=tiny_controls)
    report.diagrams_read = ["Overview.png", "Network.png"]
    report.diagrams_skipped = ["icon.png: too small to be a diagram (under 160px)"]
    md = render_markdown(report)
    assert "Diagrams read (2):* Diagram 1: Overview.png; Diagram 2: Network.png" in md
    assert "Not read:* icon.png" in md
