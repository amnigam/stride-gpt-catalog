"""Deterministic engine: outputs are derived from the gap and must be stable
and well-ordered. The DREAD modulation rules are pinned here."""

from __future__ import annotations

from threatcatalog.gap import build_gap
from threatcatalog.generators import DeterministicArtifactEngine
from threatcatalog.models import (AppProfile, Confidence, ControlStatus,
                                  DataClassification, GapItem, ImplementedLedger,
                                  LedgerEntry, ObservedControl, PlatformFacet,
                                  Provenance, Stride)


def _gap(tiny_controls, profile, *pairs):
    ledger = ImplementedLedger(entries=[
        LedgerEntry(control_id=c, status=s, provenance=Provenance.DECLARED,
                    confidence=Confidence.HIGH) for c, s in pairs])
    return build_gap(tiny_controls, ledger, profile)


def test_threats_only_from_findings(engine, tiny_controls, web_llm_profile):
    gap = _gap(tiny_controls, web_llm_profile,
               ("X-WEB-1", ControlStatus.NOT_PRESENT),
               ("X-BASE-1", ControlStatus.IMPLEMENTED))  # implemented -> no threat
    threats = engine.generate_threats(gap, web_llm_profile)
    enabling = {t.enabling_gap for t in threats}
    assert "X-WEB-1" in enabling
    assert "X-BASE-1" not in enabling


def test_threats_unknown_excluded(engine, tiny_controls, web_llm_profile):
    gap = _gap(tiny_controls, web_llm_profile)  # all unknown
    assert engine.generate_threats(gap, web_llm_profile) == []


def test_threats_ordered_not_present_before_partial(engine, tiny_controls, web_llm_profile):
    gap = _gap(tiny_controls, web_llm_profile,
               ("X-WEB-1", ControlStatus.PARTIAL),
               ("X-BASE-1", ControlStatus.NOT_PRESENT))
    threats = engine.generate_threats(gap, web_llm_profile)
    assert threats[0].enabling_gap == "X-BASE-1"  # worst first


def test_threat_carries_framework_ref(engine, tiny_controls, web_llm_profile):
    gap = _gap(tiny_controls, web_llm_profile, ("X-AI-1", ControlStatus.NOT_PRESENT))
    t = engine.generate_threats(gap, web_llm_profile)[0]
    assert t.framework_ref == "LLM01:2025"


def test_recommendations_target_findings(engine, tiny_controls, web_llm_profile):
    gap = _gap(tiny_controls, web_llm_profile, ("X-WEB-1", ControlStatus.NOT_PRESENT))
    recs = engine.generate_recommendations(gap, web_llm_profile)
    assert [r.control_id for r in recs] == ["X-WEB-1"]
    assert recs[0].title.startswith("Adopt")


def test_recommendations_strengthen_partial(engine, tiny_controls, web_llm_profile):
    gap = _gap(tiny_controls, web_llm_profile, ("X-WEB-1", ControlStatus.PARTIAL))
    recs = engine.generate_recommendations(gap, web_llm_profile)
    assert recs[0].title.startswith("Strengthen")


def test_mitigations_one_per_threat(engine, tiny_controls, web_llm_profile):
    gap = _gap(tiny_controls, web_llm_profile,
               ("X-WEB-1", ControlStatus.NOT_PRESENT),
               ("X-AI-1", ControlStatus.NOT_PRESENT))
    threats = engine.generate_threats(gap, web_llm_profile)
    mitigations = engine.generate_mitigations(threats, gap, web_llm_profile, [])
    assert len(mitigations) == len(threats)
    assert {m.threat_id for m in mitigations} == {t.id for t in threats}


def test_dread_missing_scores_higher_than_partial(engine, tiny_controls, web_llm_profile):
    gap_missing = _gap(tiny_controls, web_llm_profile, ("X-BASE-1", ControlStatus.NOT_PRESENT))
    gap_partial = _gap(tiny_controls, web_llm_profile, ("X-BASE-1", ControlStatus.PARTIAL))
    tm = engine.generate_threats(gap_missing, web_llm_profile)
    tp = engine.generate_threats(gap_partial, web_llm_profile)
    sm = engine.score_dread(tm, gap_missing, web_llm_profile)[0]
    sp = engine.score_dread(tp, gap_partial, web_llm_profile)[0]
    assert sm.average > sp.average


def test_dread_restricted_data_raises_damage(engine, tiny_controls):
    restricted = AppProfile(name="r", platforms=[PlatformFacet.WEB],
                            data_classification=DataClassification.RESTRICTED)
    internal = AppProfile(name="i", platforms=[PlatformFacet.WEB],
                          data_classification=DataClassification.INTERNAL)
    g_r = _gap(tiny_controls, restricted, ("X-BASE-1", ControlStatus.NOT_PRESENT))
    g_i = _gap(tiny_controls, internal, ("X-BASE-1", ControlStatus.NOT_PRESENT))
    s_r = engine.score_dread(engine.generate_threats(g_r, restricted), g_r, restricted)[0]
    s_i = engine.score_dread(engine.generate_threats(g_i, internal), g_i, internal)[0]
    assert s_r.damage > s_i.damage


def test_compensating_note_lowers_dread(engine, tiny_controls, web_llm_profile):
    gap = _gap(tiny_controls, web_llm_profile, ("X-BASE-1", ControlStatus.NOT_PRESENT))
    threats = engine.generate_threats(gap, web_llm_profile)
    base_score = engine.score_dread(threats, gap, web_llm_profile)[0]
    # now annotate a compensating note and re-score
    for gi in gap:
        if gi.control.id == "X-BASE-1":
            gi.compensating_notes.append("offset by tokenization")
    softened = engine.score_dread(threats, gap, web_llm_profile)[0]
    assert softened.exploitability < base_score.exploitability
    assert softened.average < base_score.average


def test_judge_out_of_catalog_maps_stride(engine, web_llm_profile):
    a = engine.judge_out_of_catalog(
        ObservedControl(name="rate limiter", description="throttle requests"), web_llm_profile)
    assert a.stride == [Stride.DOS]
