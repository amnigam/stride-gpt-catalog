"""LLM engine: verify the prompt-build -> call -> validate path, and that
malformed / out-of-enum model output is rejected (validation, not trust)."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from threatcatalog.gap import build_gap
from threatcatalog.llm.engine import LLMArtifactEngine
from threatcatalog.llm.provider import StubRawLLM, _parse_json
from threatcatalog.models import (ControlStatus, ImplementedLedger, LedgerEntry,
                                  ObservedControl, Provenance, Confidence)


def _gap(tiny_controls, profile):
    ledger = ImplementedLedger(entries=[LedgerEntry(
        control_id="X-AI-1", status=ControlStatus.NOT_PRESENT,
        provenance=Provenance.DECLARED, confidence=Confidence.HIGH)])
    return build_gap(tiny_controls, ledger, profile)


def test_parse_json_strips_fences():
    assert _parse_json('```json\n{"a":1}\n```') == {"a": 1}
    assert _parse_json('{"a":1}') == {"a": 1}


def test_threats_validated_from_stub(tiny_controls, web_llm_profile):
    raw = StubRawLLM([[{"id": "T1", "stride": "Tampering", "title": "x",
                        "description": "d", "enabling_gap": "X-AI-1",
                        "framework_ref": "LLM01:2025"}]])
    eng = LLMArtifactEngine(raw)
    threats = eng.generate_threats(_gap(tiny_controls, web_llm_profile), web_llm_profile)
    assert threats[0].id == "T1"
    # the prompt actually included the gap payload
    assert "X-AI-1" in raw.calls[0][1]


def test_unknown_stride_coerced_to_default(tiny_controls, web_llm_profile):
    # unknown STRIDE no longer crashes the run; it falls back to a safe default
    raw = StubRawLLM([[{"id": "T1", "stride": "NotAStride", "title": "x",
                        "description": "d"}]])
    eng = LLMArtifactEngine(raw)
    t = eng.generate_threats(_gap(tiny_controls, web_llm_profile), web_llm_profile)[0]
    assert t.stride.value == "Tampering"


def test_recommendations_validated(tiny_controls, web_llm_profile):
    raw = StubRawLLM([[{"control_id": "X-AI-1", "title": "Adopt", "action": "do it",
                        "frameworks": ["owasp_llm:LLM01:2025"]}]])
    eng = LLMArtifactEngine(raw)
    recs = eng.generate_recommendations(_gap(tiny_controls, web_llm_profile), web_llm_profile)
    assert recs[0].control_id == "X-AI-1"


def test_ooc_assessment_validated(web_llm_profile):
    raw = StubRawLLM({"relevant": True, "stride": ["InformationDisclosure"],
                      "compensating": True, "suggested_framework": None,
                      "suggested_layer": None, "rationale": "masks data"})
    eng = LLMArtifactEngine(raw)
    obs = ObservedControl(name="tokenization", description="masks pii")
    a = eng.judge_out_of_catalog(obs, web_llm_profile)
    assert a.relevant and a.compensating
    assert a.observed.name == "tokenization"


def test_malformed_json_raises(tiny_controls, web_llm_profile):
    class BadRaw:
        def complete_json(self, system, user):
            return _parse_json("this is not json")
    with pytest.raises(Exception):
        LLMArtifactEngine(BadRaw()).generate_threats(
            _gap(tiny_controls, web_llm_profile), web_llm_profile)


# --- provider independence: the engine works with ANY RawLLM (e.g. OpenAI) ---
def test_openai_provider_is_importable_and_constructs():
    from threatcatalog.llm import OpenAIRawLLM
    raw = OpenAIRawLLM(model="gpt-4o")          # no network call here
    assert raw.model == "gpt-4o"
    assert hasattr(raw, "complete_json")


def test_engine_runs_with_a_non_anthropic_raw(tiny_controls, web_llm_profile):
    # A stand-in that mimics any provider returning schema-valid JSON.
    class FakeOpenAI:
        def complete_json(self, system, user):
            return [{"id": "T1", "stride": "Tampering", "title": "x",
                     "description": "d", "enabling_gap": "X-AI-1"}]
    eng = LLMArtifactEngine(FakeOpenAI())
    threats = eng.generate_threats(_gap(tiny_controls, web_llm_profile), web_llm_profile)
    assert threats[0].id == "T1"


# --- diagram vision extraction ---
def test_vision_extracts_only_valid_controls(tiny_controls, web_llm_profile):
    raw = StubRawLLM([[
        {"control_id": "X-WEB-1", "status": "implemented", "confidence": "high", "evidence": "WAF box"},
        {"control_id": "NOT-IN-CATALOG", "status": "implemented", "confidence": "high"},
    ]])
    eng = LLMArtifactEngine(raw)
    entries = eng.extract_controls(tiny_controls, diagram_image=b"\x89PNG fake bytes")
    ids = {e.control_id for e in entries}
    assert ids == {"X-WEB-1"}                       # bogus id dropped
    assert entries[0].provenance.value == "diagram_vision"
    assert raw.image_calls and raw.image_calls[0][2] == "image/png"


def test_vision_never_marks_absent(tiny_controls, web_llm_profile):
    # even if the model returns an out-of-range status, it is coerced to a
    # present-state, never not_present (vision must not assert absence)
    raw = StubRawLLM([[{"control_id": "X-WEB-1", "status": "not_present"}]])
    eng = LLMArtifactEngine(raw)
    entries = eng.extract_controls(tiny_controls, diagram_image=b"img")
    assert entries[0].status.value in ("implemented", "partial")


def test_vision_no_image_returns_empty(tiny_controls):
    eng = LLMArtifactEngine(StubRawLLM([[]]))
    assert eng.extract_controls(tiny_controls, diagram_image=None) == []


# --- normalization: real models drift from the schema; we coerce, then validate ---
def test_threat_enabling_gap_dict_and_framework_list_coerced(tiny_controls, web_llm_profile):
    # this is the exact shape GPT-5.2 returned in the field
    raw = StubRawLLM([[{
        "id": "T1", "stride": "Information Disclosure", "title": "x", "description": "d",
        "enabling_gap": {"control_id": "WEB-SESS-001", "title": "Secure session management"},
        "framework_ref": [],
    }]])
    t = LLMArtifactEngine(raw).generate_threats(_gap(tiny_controls, web_llm_profile), web_llm_profile)[0]
    assert t.enabling_gap == "WEB-SESS-001"      # dict -> control_id string
    assert t.framework_ref is None               # [] -> None
    assert t.stride.value == "InformationDisclosure"  # spaced label -> enum


def test_threats_wrapped_in_object_are_unwrapped(tiny_controls, web_llm_profile):
    raw = StubRawLLM({"threats": [{"id": "T1", "stride": "Tampering",
                                   "title": "x", "description": "d"}]})
    out = LLMArtifactEngine(raw).generate_threats(_gap(tiny_controls, web_llm_profile), web_llm_profile)
    assert out[0].id == "T1"


def test_dread_as_strings_coerced(tiny_controls, web_llm_profile):
    raw = StubRawLLM([[{"threat_id": "T1", "damage": "9", "reproducibility": "8",
                        "exploitability": "8", "affected_users": "7", "discoverability": "6"}]])
    s = LLMArtifactEngine(raw).score_dread([], _gap(tiny_controls, web_llm_profile), web_llm_profile)[0]
    assert s.damage == 9 and s.priority.value in ("Critical", "High")


def test_dread_out_of_range_clamped(tiny_controls, web_llm_profile):
    raw = StubRawLLM([[{"threat_id": "T1", "damage": 99, "reproducibility": 8,
                        "exploitability": 8, "affected_users": 7, "discoverability": 6}]])
    s = LLMArtifactEngine(raw).score_dread([], _gap(tiny_controls, web_llm_profile), web_llm_profile)[0]
    assert s.damage == 10                         # clamped, not rejected


def test_recommendation_frameworks_string_to_list(tiny_controls, web_llm_profile):
    raw = StubRawLLM([[{"control_id": "X-AI-1", "title": "Adopt", "action": "do",
                        "frameworks": "owasp_llm:LLM01:2025"}]])
    r = LLMArtifactEngine(raw).generate_recommendations(_gap(tiny_controls, web_llm_profile), web_llm_profile)[0]
    assert r.frameworks == ["owasp_llm:LLM01:2025"]


def test_ooc_bad_layer_becomes_none(web_llm_profile):
    raw = StubRawLLM({"relevant": True, "stride": ["Information Disclosure"],
                      "compensating": True, "suggested_layer": "not-a-real-layer",
                      "rationale": "masks"})
    a = LLMArtifactEngine(raw).judge_out_of_catalog(
        ObservedControl(name="tok", description="masks pii"), web_llm_profile)
    assert a.suggested_layer is None
    assert a.stride[0].value == "InformationDisclosure"
