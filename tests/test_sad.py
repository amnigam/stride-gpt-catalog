"""SAD upload flow: extraction, completeness gate, profile inference, SAD status
rules, the Bedrock provider, and an end-to-end run on a stubbed model."""

from __future__ import annotations

import io
import sys
import types

import pytest

from threatcatalog import sad as sadflow
from threatcatalog.catalog import resolve
from threatcatalog.llm import BedrockRawLLM, LLMArtifactEngine, StubRawLLM
from threatcatalog.llm.provider import EmptyCompletionError
from threatcatalog.models import (AICapability, AppProfile, ControlStatus, DataClassification,
                                  EvidenceBasis, PlatformFacet, RubricScore)
from threatcatalog.sad_extract import ExtractedSad, SadExtractionError, extract

docx = pytest.importorskip("docx")
PIL = pytest.importorskip("PIL")
from PIL import Image  # noqa: E402


def _png(w=1200, h=800) -> bytes:
    b = io.BytesIO()
    Image.new("RGB", (w, h), "white").save(b, "PNG")
    return b.getvalue()


def _docx_bytes(with_image=True) -> bytes:
    d = docx.Document()
    d.add_heading("PayFlow Solution Architecture", 0)
    d.add_heading("1 Purpose", 1)
    d.add_paragraph("PayFlow lets merchants accept card payments through a web portal.")
    d.add_heading("3.1 Context", 1)
    d.add_paragraph("All traffic uses TLS 1.2 and users sign in with SSO and MFA.")
    t = d.add_table(rows=2, cols=2)
    t.cell(0, 0).text, t.cell(0, 1).text = "Control", "Status"
    t.cell(1, 0).text, t.cell(1, 1).text = "WAF", "In place"
    if with_image:
        d.add_picture(io.BytesIO(_png()))
    out = io.BytesIO()
    d.save(out)
    return out.getvalue()


def _sad(text="A web portal on AWS.", images=1) -> ExtractedSad:
    from threatcatalog.sad_extract import DiagramImage
    return ExtractedSad(filename="x.docx", sha256="ab" * 32, text=text,
                        images=[DiagramImage(_png(), "image/png", f"Page {i + 1}")
                                for i in range(images)])


# --------------------------------------------------------------- extraction --
def test_docx_extraction_keeps_headings_tables_and_diagrams():
    sad = extract("payflow.docx", _docx_bytes())
    assert "## 3.1 Context" in sad.text
    assert "| WAF | In place |" in sad.text
    assert len(sad.images) == 1 and sad.images[0].label == "Figure after '3.1 Context'"
    assert "[Diagram 1:" in sad.text
    assert len(sad.sha256) == 64 and sad.has_diagram
    assert sad.pages >= 1 and sad.pages_estimated          # python-docx leaves a stale app.xml


def test_docx_page_count_uses_word_figure_only_when_current():
    import zipfile
    from threatcatalog.sad_extract import docx_page_count

    def with_app(pages, words):
        b = io.BytesIO()
        with zipfile.ZipFile(b, "w") as z:
            z.writestr("docProps/app.xml", f"<Properties><Pages>{pages}</Pages>"
                                           f"<Words>{words}</Words></Properties>")
        return b.getvalue()
    assert docx_page_count(with_app(9, 2500), 2568, 1) == (9, False)   # Word's figure is current
    assert docx_page_count(with_app(1, 0), 2568, 1) == (8, True)       # stale: estimate
    assert docx_page_count(b"not a zip", 100, 0) == (1, True)


def test_pdf_vector_diagram_page_is_rendered():
    fitz = pytest.importorskip("pymupdf")
    pdf = fitz.open()
    page = pdf.new_page()
    for k in range(30):
        page.insert_text((72, 72 + k * 14), f"Architecture overview line {k} with several words")
    for k in range(50):
        page.draw_rect(fitz.Rect(50 + k * 5, 600, 80 + k * 5, 640))
    plain = pdf.new_page()
    for k in range(30):
        plain.insert_text((72, 72 + k * 14), f"Plain text page line {k} and more words")
    sad = extract("sad.pdf", pdf.tobytes())
    assert sad.pages == 2
    assert [i.label for i in sad.images] == ["Page 1"]
    assert sad.images[0].media_type == "image/png"
    assert not sad.notes                      # has a text layer


def test_markdown_mermaid_counts_as_diagram_and_bad_types_rejected():
    sad = extract("sad.md", b"# App\n\n```mermaid\ngraph TD; A-->B\n```\n")
    assert sad.has_diagram and not sad.images
    with pytest.raises(SadExtractionError):
        extract("sad.xlsx", b"x")
    with pytest.raises(SadExtractionError):
        extract("sad.md", b"")


def test_unreadable_figure_formats_are_reported_not_sent():
    from threatcatalog.sad_extract import _prepare_image
    skipped: list[str] = []
    assert _prepare_image(b"\x01\x00", "image/x-emf", "Figure 2", skipped) is None
    assert "cannot be read" in skipped[0]
    big = _prepare_image(_png(4000, 1000), "image/png", "big", skipped)
    assert max(Image.open(io.BytesIO(big.data)).size) == 1568


# --------------------------------------------------------------- assessment --
def _raw_assessment(**over):
    raw = {
        "is_architecture_document": True, "document_title": "PayFlow SAD",
        "document_version": "1.3", "application_name": "PayFlow",
        "rubric": [{"id": r["id"], "score": "present", "evidence": "s1"} for r in sadflow.RUBRIC],
        "platforms": [{"facet": "web", "selected": True, "basis": "stated", "reason": "portal",
                       "quote": "web portal"},
                      {"facet": "cloud", "selected": False, "reason": "not stated"}],
        "ai_capabilities": [{"facet": "llm", "selected": True, "basis": "inferred",
                             "reason": "chat assistant"}],
        "data_classification": {"value": "Restricted", "reason": "card data"},
        "cardholder_data": {"value": "yes", "reason": "card payments"},
    }
    raw.update(over)
    return raw


def test_assessment_follows_the_model_only():
    a = sadflow.parse_assessment(_raw_assessment(), _sad("A web portal hosted on AWS using Kafka."))
    by = {f.facet: f for f in a.facets}
    assert a.platforms == [PlatformFacet.WEB]                # AI said no to cloud; AWS in text ignored
    assert not by["platform:cloud"].selected and by["platform:cloud"].source == "llm"
    assert "platform:messaging" not in by                   # not raised by the model at all
    assert by["ai:llm"].assumed                              # inferred → assumed
    assert a.data_classification == DataClassification.RESTRICTED
    assert a.handles_cardholder_data and a.sufficient
    assert a.document_version == "1.3" and a.application_name == "PayFlow"


def test_negated_mentions_do_not_select_facets():
    """The Corvane case: words like 'mobile app', 'SaaS', 'at rest', 'blob container'
    and 'payment card' appear in negated or unrelated sentences."""
    text = ("It has no mobile application. BankVerify API (third-party SaaS). Encryption at "
            "rest. Documents go to a blob container. The application does not store, process "
            "or transmit payment card data; PCI DSS is not applicable.")
    raw = _raw_assessment(
        platforms=[{"facet": f, "selected": f == "web", "basis": "stated", "reason": "r"}
                   for f in ("web", "mobile", "multitenant", "api", "container")],
        cardholder_data={"value": "no", "reason": "PCI DSS is not applicable"})
    a = sadflow.parse_assessment(raw, _sad(text))
    assert a.platforms == [PlatformFacet.WEB]
    assert not a.handles_cardholder_data
    assert not {f.facet: f for f in a.facets}["pci"].assumed


def test_assessment_defaults_when_silent():
    raw = _raw_assessment(data_classification={"value": "not_stated"},
                          cardholder_data={"value": "not_stated"}, platforms=[])
    a = sadflow.parse_assessment(raw, _sad("Internal tool."))
    assert a.data_classification == DataClassification.CONFIDENTIAL
    assert not a.handles_cardholder_data
    assert a.platforms == [PlatformFacet.WEB]
    assert any("PCI scope not stated" in n for n in a.notes)


def test_pci_silence_is_out_of_scope_and_flagged():
    raw = _raw_assessment(cardholder_data={"value": "not_stated"})
    a = sadflow.parse_assessment(raw, _sad("We store the PAN in a vault."))
    assert not a.handles_cardholder_data                   # keywords no longer decide
    assert {f.facet: f for f in a.facets}["pci"].assumed
    assert any("PCI scope not stated" in n for n in a.notes)


def test_stop_when_hard_minimum_missing_or_not_a_sad():
    rubric = [{"id": r["id"], "score": "missing" if r["id"] == "components" else "present"}
              for r in sadflow.RUBRIC]
    a = sadflow.parse_assessment(_raw_assessment(rubric=rubric), _sad())
    assert not a.sufficient and any("Components" in r for r in a.stop_reasons)
    # no readable diagram at all → diagram is missing regardless of what the model said
    a = sadflow.parse_assessment(_raw_assessment(), _sad(images=0))
    assert not a.sufficient
    assert {i.id: i for i in a.completeness}["diagram"].score == RubricScore.MISSING
    a = sadflow.parse_assessment(_raw_assessment(is_architecture_document=False), _sad())
    assert not a.sufficient
    fb = sadflow.feedback_markdown(_sad(), a)
    assert "not enough to threat model" in fb


def test_thin_items_do_not_stop_but_are_gaps():
    rubric = [{"id": r["id"], "score": "thin" if r["id"] in ("purpose", "network") else "present",
               "comment": "add more"} for r in sadflow.RUBRIC]
    a = sadflow.parse_assessment(_raw_assessment(rubric=rubric), _sad())
    assert a.sufficient and len(a.gaps) == 2


# ---------------------------------------------------------- SAD status rules --
def test_sad_ledger_rules(catalog, web_llm_profile):
    expected = resolve(web_llm_profile, catalog.controls)
    ids = [c.id for c in expected]
    text = "All traffic uses TLS 1.2 everywhere. There is no WAF in front of the portal."
    records = [
        {"control_id": ids[0], "status": "implemented", "basis": "stated", "source": "text",
         "quote": "All traffic uses TLS 1.2 everywhere.", "rationale": "TLS stated"},
        {"control_id": ids[1], "status": "implemented", "basis": "inferred", "source": "text",
         "quote": None, "rationale": "Managed gateway implies it"},
        {"control_id": ids[2], "status": "implemented", "basis": "stated", "source": "text",
         "quote": "Invented sentence not in the SAD at all", "rationale": "x"},
        {"control_id": ids[3], "status": "not_present", "basis": "stated", "source": "text",
         "quote": "There is no WAF in front of the portal.", "rationale": "explicit"},
        {"control_id": ids[4], "status": "partial", "basis": "stated", "source": "diagram",
         "quote": "Diagram 1: WAF on public API only", "rationale": "limited"},
    ]
    led = {e.control_id: e for e in sadflow.build_sad_ledger(expected, records, text)}
    assert len(led) == len(expected)                       # every control gets a status
    assert led[ids[0]].status == ControlStatus.IMPLEMENTED and led[ids[0]].detail.quote_verified
    assert led[ids[1]].status == ControlStatus.PARTIAL
    assert sadflow.INFERRED_NOTE in led[ids[1]].detail.note
    assert led[ids[2]].status == ControlStatus.PARTIAL      # unverifiable citation
    assert led[ids[3]].status == ControlStatus.NOT_PRESENT
    assert led[ids[4]].status == ControlStatus.PARTIAL and led[ids[4]].detail.ai_source == "diagram"
    silent = led[ids[5]]
    assert silent.status == ControlStatus.NOT_PRESENT
    assert silent.detail.note == sadflow.NOT_STATED_NOTE


# ------------------------------------------------------------ end-to-end run --
def _stub_sad_run(catalog):
    sad = _sad("PayFlow is a web portal. All traffic uses TLS 1.2 everywhere.")
    profile = AppProfile(name="PayFlow", platforms=[PlatformFacet.WEB],
                         ai_capabilities=[AICapability.NONE],
                         data_classification=DataClassification.CONFIDENTIAL)
    expected = resolve(profile, catalog.controls)
    first = expected[0].id
    stub = StubRawLLM([
        _raw_assessment(ai_capabilities=[], cardholder_data={"value": "no"}),
        {"controls": [{"control_id": first, "status": "implemented", "basis": "stated",
                       "source": "text", "quote": "All traffic uses TLS 1.2 everywhere.",
                       "rationale": "stated"}],
         "other_controls": [{"name": "Quarterly pen test", "description": "External test"}]},
        {"checks": [{"control_id": first, "supports": "no",
                     "reason": "Covers transport only"}]},                    # quote check
        {"relevant": True, "stride": ["Tampering"], "compensating": False,
         "rationale": "useful"},                                             # out-of-catalog
        [{"id": "T1", "stride": "Spoofing", "title": "Session hijack",
          "enabling_gap": expected[1].id}],                                   # threats
        [{"control_id": expected[1].id, "title": "Add it", "action": "Do it"}],  # recs
        [{"threat_id": "T1", "action": "Rotate sessions"}],                  # mitigations
        [{"threat_id": "T1", "damage": 8, "reproducibility": 6, "exploitability": 6,
          "affected_users": 7, "discoverability": 5}],                       # DREAD
    ])
    eng = LLMArtifactEngine(stub)
    a = sadflow.assess(eng, sad)
    assert a.sufficient
    assert stub.multi_image_calls and stub.multi_image_calls[0][2] == 1
    report, ledger = sadflow.run(sad, a, profile, eng, catalog.controls, engine_label="stub",
                                 confirmed_by="Amit")
    return sad, profile, expected, report, ledger


def test_end_to_end_run_on_stub(catalog):
    sad, profile, expected, report, ledger = _stub_sad_run(catalog)
    first = expected[0].id
    status = {gi.control.id: gi for gi in report.gap_items}
    assert status[first].status == ControlStatus.IMPLEMENTED       # the check never changes it
    assert status[first].evidence.quote_supports is False
    assert status[first].evidence.support_note == "Covers transport only"
    assert any("Quote check: 1 of 1" in n for n in report.sad.notes)
    others = [gi for cid, gi in status.items() if cid != first]
    assert all(gi.status == ControlStatus.NOT_PRESENT for gi in others)
    assert all(gi.basis == EvidenceBasis.AI_UNREVIEWED for gi in report.gap_items)
    assert report.clarifications == []                      # nothing left 'unknown'
    assert report.sad.profile_confirmed_by == "Amit"
    assert [t.id for t in report.threats] == ["T1"] and len(report.dread) == 1
    assert report.candidates and report.candidates[0].title == "Quarterly pen test"

    from threatcatalog.report import render_markdown
    md = render_markdown(report)
    assert "Assessment basis (SAD)" in md and "Automated draft from SAD" in md
    # automated run: no review fields, no Basis column, AppSec note on top of the cards
    assert "not reviewed" not in md and "Reviewer" not in md and "| Control | Status | Frameworks |" in md
    assert "no person has reviewed it" in md
    assert "| AI evaluation | **Implemented · " in md and "from SAD" in md
    assert "### 🔴 Not present" in md
    assert "quote check: Covers transport only" in md
    rows = sadflow.declaration_rows(ledger)
    assert rows[first].status == ControlStatus.IMPLEMENTED
    pytest.importorskip("reportlab")
    from threatcatalog.pdf_export import render_pdf
    assert render_pdf(report)[:4] == b"%PDF"


def test_sad_declaration_hands_profile_and_record_to_review_page(catalog):
    from threatcatalog import pipeline
    from threatcatalog.declaration import (apply_edit, export_json, import_json,
                                           profile_differences, reviewed_sad_context,
                                           sad_handoff, to_ledger)
    from threatcatalog.report import render_markdown
    sad, profile, expected, report, ledger = _stub_sad_run(catalog)
    blob = export_json(sadflow.declaration_rows(ledger),
                       meta=sadflow.declaration_meta(report, "AWS Bedrock", "model-x"))
    rows, meta = import_json(blob)
    h = sad_handoff(meta)
    assert h.profile == report.profile and h.provider == "AWS Bedrock" and h.model_id == "model-x"
    assert [o.name for o in h.other_controls] == ["Quarterly pen test"]
    assert h.sad.sha256 == sad.sha256 and h.sad.completeness

    # the reviewer changes one status and widens the profile on the review page
    apply_edit(rows[expected[1].id], ControlStatus.IMPLEMENTED, "Seen in the runbook",
               False, "Priya")
    wider = profile.model_copy(update={"platforms": [PlatformFacet.WEB, PlatformFacet.API]})
    assert profile_differences(h.profile, wider) == ["Platform added: api"]
    assert profile_differences(h.profile, h.profile) == []
    reviewed = pipeline.run(profile, declared=to_ledger(rows, expected), controls=catalog.controls)
    reviewed.sad = reviewed_sad_context(h, wider, "Priya")
    md = render_markdown(reviewed)
    assert "From SAD, then reviewed." in md and "Automated draft from SAD" not in md
    assert "Assessment basis (SAD)" in md                  # SAD record kept
    assert "Profile changed on the review page by Priya" in md
    assert "| Control | Status | Basis |" in md              # review columns are back
    assert "no person has reviewed it" not in md
    pytest.importorskip("reportlab")
    from threatcatalog.pdf_export import render_pdf
    assert render_pdf(reviewed)[:4] == b"%PDF"


def test_plain_declaration_has_no_sad_handoff():
    from threatcatalog.declaration import sad_handoff
    assert sad_handoff({"application": "X"}) is None
    assert sad_handoff({"profile": {"name": 1, "platforms": "bad"}}) is None


# ------------------------------------------------------------------ Bedrock --
class _FakeBedrock:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    def converse(self, **kw):
        self.calls.append(kw)
        r = self.responses.pop(0)
        if isinstance(r, Exception):
            raise r
        return r


class ValidationException(Exception):
    pass


def _ok(text, stop="end_turn"):
    return {"output": {"message": {"content": [{"text": text}]}}, "stopReason": stop,
            "usage": {"outputTokens": 10}}


def test_bedrock_sends_images_and_parses_json():
    fake = _FakeBedrock([_ok('[{"a": 1}]')])
    llm = BedrockRawLLM(model="m", client=fake)
    import base64
    out = llm.complete_json_images("sys", "user", [(base64.b64encode(b"img").decode(), "image/jpeg")])
    assert out == [{"a": 1}]
    call = fake.calls[0]
    assert call["inferenceConfig"]["maxTokens"] == 64000
    assert call["system"] == [{"text": "sys"}]
    content = call["messages"][0]["content"]
    assert content[0]["image"]["format"] == "jpeg" and content[0]["image"]["source"]["bytes"] == b"img"
    assert content[-1] == {"text": "user"}


def test_bedrock_retries_at_model_token_limit_and_remembers_it():
    err = ValidationException("ValidationException: The maximum tokens you requested exceeds "
                              "the model limit of 8192.")
    fake = _FakeBedrock([err, _ok("{}"), _ok("{}")])
    llm = BedrockRawLLM(model="m", client=fake)
    llm.complete_json("s", "u")
    llm.complete_json("s", "u")
    assert [c["inferenceConfig"]["maxTokens"] for c in fake.calls] == [64000, 8192, 8192]


def test_bedrock_truncation_is_reported():
    fake = _FakeBedrock([_ok('{"partial": ', stop="max_tokens")])
    with pytest.raises(EmptyCompletionError, match="max_tokens"):
        BedrockRawLLM(model="m", client=fake).complete_json("s", "u")
    with pytest.raises(ValueError):
        BedrockRawLLM(model="")


def test_factory_builds_bedrock(monkeypatch):
    from threatcatalog.llm.factory import BEDROCK, build_engine, default_model
    monkeypatch.setenv("BEDROCK_MODEL_ID", "my-model")
    monkeypatch.setenv("AWS_REGION", "ap-south-1")
    assert default_model(BEDROCK) == "my-model"
    eng = build_engine(BEDROCK, "my-model", max_tokens=100000)
    assert eng.raw.model == "my-model" and eng.raw.max_tokens == 100000
    assert eng.raw._region == "ap-south-1"


def test_anthropic_provider_streams(monkeypatch):
    """Large budgets need streaming; the provider must use messages.stream."""
    seen = {}

    class _Msg:
        content = [types.SimpleNamespace(type="text", text='{"ok": true}')]
        stop_reason = "end_turn"
        usage = types.SimpleNamespace(output_tokens=5)

    class _Stream:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def get_final_message(self):
            return _Msg()

    class _Messages:
        def stream(self, **kw):
            seen.update(kw)
            return _Stream()

    class _Client:
        def __init__(self, **kw):
            self.messages = _Messages()

    monkeypatch.setitem(sys.modules, "anthropic", types.SimpleNamespace(Anthropic=_Client))
    from threatcatalog.llm import AnthropicRawLLM
    llm = AnthropicRawLLM(api_key="k", max_tokens=64000)
    assert llm.complete_json("s", "u") == {"ok": True}
    assert seen["max_tokens"] == 64000


def test_quote_check_failure_does_not_fail_the_run(catalog):
    profile = AppProfile(name="P", platforms=[PlatformFacet.WEB],
                         ai_capabilities=[AICapability.NONE],
                         data_classification=DataClassification.CONFIDENTIAL)
    expected = resolve(profile, catalog.controls)
    ledger = sadflow.build_sad_ledger(expected, [{"control_id": expected[0].id, "status": "implemented",
                                                  "basis": "stated", "source": "text",
                                                  "quote": "TLS 1.2 everywhere.", "rationale": "r"}],
                                      "TLS 1.2 everywhere.")

    class Boom:
        def check_quotes(self, items):
            raise RuntimeError("throttled")
    note = sadflow.apply_quote_check(Boom(), ledger, expected)
    assert "could not run" in note
    assert ledger[0].detail.quote_supports is None and ledger[0].status == ControlStatus.IMPLEMENTED
    # not-stated rows carry no quote, so they are never sent
    assert [i["control_id"] for i in sadflow.quote_check_items(ledger, expected)] == [expected[0].id]


def test_unsupported_quote_asks_for_a_reviewer_note():
    from threatcatalog.declaration import DeclarationRow, needs_note
    from threatcatalog.models import ControlEvidence
    row = DeclarationRow(control_id="X", status=ControlStatus.IMPLEMENTED,
                         evidence=ControlEvidence(ai_status=ControlStatus.IMPLEMENTED,
                                                  ai_note="n", note="n", quote_supports=False))
    assert "does not clearly support" in needs_note(row)
    row.evidence.reviewed = True
    assert needs_note(row) is None
