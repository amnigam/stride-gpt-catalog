"""
threatcatalog.pipeline
======================

End-to-end orchestration. Wires the two paths together:

    facets ─► resolve ─► expected controls ┐
                                           ├─► gap engine ─► artifacts + PCI ─► report
    diagram + description + declaration ───┘            (out-of-catalog feeds in)

The pipeline is engine-agnostic: pass `DeterministicArtifactEngine()` for an
offline run or `LLMArtifactEngine(...)` for a model-backed one. The gap is
computed deterministically either way.
"""

from __future__ import annotations

from .catalog import Catalog, resolve
from .gap import build_gap
from .generators import ArtifactEngine, DeterministicArtifactEngine
from .intake import detect_from_text, merge_ledger
from .models import (AppProfile, Control, ControlStatus, LedgerEntry,
                     ObservedControl, ThreatModelReport)
from .out_of_catalog import attach_compensating, process_observed
from .pci import build_pci_view


def _clarifications(gap) -> list[str]:
    """UNKNOWN controls become clarifications, not findings. Required and
    PCI-mapped unknowns are listed first — those are the ones worth chasing."""
    unknowns = [gi for gi in gap if gi.status == ControlStatus.UNKNOWN]
    unknowns.sort(key=lambda gi: (0 if gi.control.pci else 1,
                                  0 if gi.control.default_expectation.value == "required" else 1))
    return [f"Confirm whether '{gi.control.title}' is implemented "
            f"({gi.control.assessment_signal})" for gi in unknowns]


def run(profile: AppProfile,
        description: str = "",
        declared: list[LedgerEntry] | None = None,
        observed_unmatched: list[ObservedControl] | None = None,
        engine: ArtifactEngine | None = None,
        controls: list[Control] | None = None,
        diagram_image: bytes | None = None,
        diagram_media_type: str = "image/png") -> ThreatModelReport:
    engine = engine or DeterministicArtifactEngine()
    controls = controls if controls is not None else Catalog.load().controls

    # 1. expected control set
    expected = resolve(profile, controls)

    # 2. implemented ledger (evidence path): text detection + optional vision + declaration
    detected = detect_from_text(description, expected)
    vision = engine.extract_controls(expected, diagram_image, diagram_media_type)
    ledger = merge_ledger(detected, vision, declared or [],
                          observed_unmatched=observed_unmatched or [])

    # 3. deterministic gap
    gap = build_gap(expected, ledger, profile)

    # 4. out-of-catalog: judge, flag candidates, attach compensating notes
    assessments, candidates = process_observed(ledger.observed_unmatched, engine, profile)
    attach_compensating(gap, assessments)

    # 5. artifacts driven by the gap
    threats = engine.generate_threats(gap, profile)
    recommendations = engine.generate_recommendations(gap, profile)
    mitigations = engine.generate_mitigations(threats, gap, profile, assessments)
    dread = engine.score_dread(threats, gap, profile)

    # 6. compliance pass (deterministic second read off the same gap)
    pci_view = build_pci_view(gap, profile)

    return ThreatModelReport(
        profile=profile, resolved_control_count=len(expected), gap_items=gap,
        clarifications=_clarifications(gap), threats=threats,
        recommendations=recommendations, mitigations=mitigations, dread=dread,
        pci_view=pci_view, candidates=candidates,
        compensating=[a for a in assessments if a.relevant and a.compensating])
