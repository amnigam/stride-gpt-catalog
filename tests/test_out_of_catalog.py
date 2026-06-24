"""Out-of-catalog: nothing dropped, compensating softens but never erases."""

from __future__ import annotations

from threatcatalog.gap import build_gap
from threatcatalog.models import (ControlStatus, ImplementedLedger, LedgerEntry,
                                  ObservedControl, Provenance, Confidence,
                                  Stride)
from threatcatalog.out_of_catalog import attach_compensating, process_observed


def test_relevant_observed_becomes_compensating(engine, web_llm_profile):
    obs = [ObservedControl(name="PII tokenization", description="masks identifiers on screen")]
    assessments, candidates = process_observed(obs, engine, web_llm_profile)
    assert assessments[0].relevant is True
    assert assessments[0].compensating is True
    assert Stride.INFO_DISCLOSURE in assessments[0].stride


def test_irrelevant_observed_still_flagged_as_candidate(engine, web_llm_profile):
    obs = [ObservedControl(name="Quarterly bake sale", description="team morale event")]
    assessments, candidates = process_observed(obs, engine, web_llm_profile)
    assert assessments[0].relevant is False
    # nothing is dropped — it is still kept as a catalog candidate
    assert len(candidates) == 1
    assert candidates[0].title == "Quarterly bake sale"


def test_every_observed_yields_one_candidate(engine, web_llm_profile):
    obs = [ObservedControl(name="a", description="rate limiting at gateway"),
           ObservedControl(name="b", description="audit logging to siem")]
    assessments, candidates = process_observed(obs, engine, web_llm_profile)
    assert len(candidates) == 2


def test_attach_compensating_annotates_matching_stride(engine, web_llm_profile, tiny_controls):
    # X-BASE-1 is InformationDisclosure; tokenization compensating is InfoDisclosure
    gap = build_gap(tiny_controls,
                    ImplementedLedger(entries=[LedgerEntry(
                        control_id="X-BASE-1", status=ControlStatus.NOT_PRESENT,
                        provenance=Provenance.DECLARED, confidence=Confidence.HIGH)]),
                    web_llm_profile)
    obs = [ObservedControl(name="tokenization", description="masks pii")]
    assessments, _ = process_observed(obs, engine, web_llm_profile)
    attach_compensating(gap, assessments)
    base = next(gi for gi in gap if gi.control.id == "X-BASE-1")
    assert base.compensating_notes  # annotated


def test_compensating_does_not_touch_unrelated_stride(engine, web_llm_profile, tiny_controls):
    # X-WEB-1 is Tampering; tokenization (InfoDisclosure) must not annotate it
    gap = build_gap(tiny_controls,
                    ImplementedLedger(entries=[LedgerEntry(
                        control_id="X-WEB-1", status=ControlStatus.NOT_PRESENT,
                        provenance=Provenance.DECLARED, confidence=Confidence.HIGH)]),
                    web_llm_profile)
    obs = [ObservedControl(name="tokenization", description="masks pii")]
    assessments, _ = process_observed(obs, engine, web_llm_profile)
    attach_compensating(gap, assessments)
    web = next(gi for gi in gap if gi.control.id == "X-WEB-1")
    assert web.compensating_notes == []
