"""Intake: the evidence path's deterministic plumbing."""

from __future__ import annotations

from threatcatalog.intake import (declaration_template, detect_from_text,
                                  merge_ledger)
from threatcatalog.models import (Confidence, ControlStatus, LedgerEntry,
                                  ObservedControl, Provenance)


def test_declaration_template_one_question_per_control(tiny_controls):
    t = declaration_template(tiny_controls)
    assert len(t) == 3
    assert t[0]["question"]  # carries the assessment_signal


def test_detector_only_proposes_implemented(tiny_controls):
    entries = detect_from_text("we have a waf and prompt injection defenses", tiny_controls)
    statuses = {e.status for e in entries}
    assert statuses == {ControlStatus.IMPLEMENTED}
    assert all(e.confidence == Confidence.LOW for e in entries)
    assert all(e.provenance == Provenance.DESCRIPTION for e in entries)


def test_detector_matches_expected_controls(tiny_controls):
    ids = {e.control_id for e in detect_from_text("encrypted at rest, waf", tiny_controls)}
    assert ids == {"X-BASE-1", "X-WEB-1"}


def test_detector_empty_text_returns_nothing(tiny_controls):
    assert detect_from_text("", tiny_controls) == []


def test_detector_never_asserts_absence(tiny_controls):
    # text mentioning nothing yields no entries -> those controls stay UNKNOWN later
    assert detect_from_text("the app is blue", tiny_controls) == []


def test_merge_precedence_declared_beats_detected():
    detected = [LedgerEntry(control_id="X", status=ControlStatus.IMPLEMENTED,
                            provenance=Provenance.DESCRIPTION, confidence=Confidence.LOW)]
    declared = [LedgerEntry(control_id="X", status=ControlStatus.NOT_PRESENT,
                            provenance=Provenance.DECLARED, confidence=Confidence.HIGH)]
    ledger = merge_ledger(detected, declared)
    assert ledger.by_control()["X"].status == ControlStatus.NOT_PRESENT


def test_merge_keeps_observed_unmatched():
    obs = [ObservedControl(name="tokenization", description="masks pii")]
    ledger = merge_ledger([], observed_unmatched=obs)
    assert len(ledger.observed_unmatched) == 1


def test_merge_verified_beats_declared():
    declared = [LedgerEntry(control_id="X", status=ControlStatus.PARTIAL,
                            provenance=Provenance.DECLARED, confidence=Confidence.HIGH)]
    verified = [LedgerEntry(control_id="X", status=ControlStatus.IMPLEMENTED,
                            provenance=Provenance.VERIFIED, confidence=Confidence.HIGH)]
    ledger = merge_ledger(declared, verified)
    assert ledger.by_control()["X"].status == ControlStatus.IMPLEMENTED
