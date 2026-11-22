"""
threatcatalog.out_of_catalog
============================

Handles controls the app implements that match NO catalog control. Per the
design: the engine judges each one's relevance *in the context of this model*,
relevant ones act as compensating controls (softening, never erasing), and
every one is flagged as a catalog candidate so a human can promote it later.

Nothing is dropped — that is the whole point. A catalog that silently discards
what it does not recognise calcifies its own blind spots.
"""

from __future__ import annotations

from .generators import ArtifactEngine
from .models import (AppProfile, CatalogCandidate, GapItem,
                     OutOfCatalogAssessment)


def process_observed(observed_list, engine: ArtifactEngine, profile: AppProfile,
                     expected=None
                     ) -> tuple[list[OutOfCatalogAssessment], list[CatalogCandidate]]:
    """Judge each observed control. One that a catalog control already covers is
    returned with `covered_by` set and is neither compensating nor a candidate,
    so it never double-counts that control (it is still listed in the report)."""
    assessments: list[OutOfCatalogAssessment] = []
    candidates: list[CatalogCandidate] = []
    for obs in observed_list:
        a = engine.judge_out_of_catalog(obs, profile, expected=expected)
        assessments.append(a)
        if a.covered_by:
            continue
        # Always keep for later — the flag plus context IS the mechanism.
        candidates.append(CatalogCandidate(
            title=obs.name, description=obs.description, stride=a.stride,
            suggested_framework=a.suggested_framework,
            suggested_layer=a.suggested_layer, source_evidence=obs.evidence))
    return assessments, candidates


def attach_compensating(gap: list[GapItem],
                        assessments: list[OutOfCatalogAssessment]) -> None:
    """Annotate gap items whose STRIDE a relevant compensating control touches.
    The annotation is what `score_dread` later reads to soften the score."""
    comp = [a for a in assessments if a.relevant and a.compensating and not a.covered_by]
    if not comp:
        return
    for gi in gap:
        if not gi.is_finding:
            continue
        control_strides = set(gi.control.stride)
        for a in comp:
            if control_strides & set(a.stride):
                gi.compensating_notes.append(
                    f"'{a.observed.name}' may partially offset this "
                    f"(unverified, not in baseline).")
