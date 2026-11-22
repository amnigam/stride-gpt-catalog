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


def test_covered_observed_is_neither_compensating_nor_candidate(web_llm_profile, tiny_controls):
    """One line per item in the report; a control the catalog already covers is listed
    as covered, never compensating or a candidate (it would double-count)."""
    from threatcatalog.generators import DeterministicArtifactEngine
    from threatcatalog.models import OutOfCatalogAssessment, ThreatModelReport
    from threatcatalog.report import out_of_catalog_rows

    class Judge(DeterministicArtifactEngine):
        def judge_out_of_catalog(self, observed, profile, expected=None):
            covered = tiny_controls[0].id if observed.name == "Idempotent sending" else None
            return OutOfCatalogAssessment(observed=observed, relevant=True,
                                          stride=[Stride.DOS], compensating=True,
                                          covered_by=covered, rationale="caps volume.")
    obs = [ObservedControl(name="Idempotent sending", description="one SMS per id"),
           ObservedControl(name="Daily send cap", description="3,000 a day")]
    assessments, candidates = process_observed(obs, Judge(), web_llm_profile, tiny_controls)
    assert [c.title for c in candidates] == ["Daily send cap"]
    r = ThreatModelReport(profile=web_llm_profile, resolved_control_count=0, gap_items=[],
                          threats=[], dread=[], candidates=candidates,
                          compensating=[a for a in assessments if a.compensating and not a.covered_by],
                          covered_elsewhere=[a for a in assessments if a.covered_by])
    rows = out_of_catalog_rows(r)
    assert len(rows) == 2
    assert rows[0].startswith("Compensating: Daily send cap") and "catalog candidate" in rows[0]
    assert rows[1].startswith("Covered by the catalog: Idempotent sending")
