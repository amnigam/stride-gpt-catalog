"""
Worked DREAD example for the Help page.

The Help page walks a reader through scoring one threat. Rather than hard-code
numbers that could drift from the engine, the example is computed here with the
real catalog control and the real offline (deterministic) scorer, so the page
always shows exactly what the app would produce for the same inputs.
"""

from __future__ import annotations

from .catalog import Catalog
from .generators import DeterministicArtifactEngine
from .models import (AppProfile, ControlStatus, DataClassification, DreadScore,
                     GapItem, PlatformFacet, Threat)

EXAMPLE_CONTROL_ID = "IAM-MFA-001"   # base layer: applies to every application


def dread_example(status: ControlStatus = ControlStatus.NOT_PRESENT,
                  classification: DataClassification = DataClassification.CONFIDENTIAL,
                  compensating: bool = False,
                  catalog: Catalog | None = None) -> tuple[Threat, DreadScore]:
    """Score the 'MFA missing' threat for a web app, as the offline engine would."""
    catalog = catalog or Catalog.load()
    control = next(c for c in catalog.controls if c.id == EXAMPLE_CONTROL_ID)
    profile = AppProfile(name="Example HR portal", platforms=[PlatformFacet.WEB],
                         data_classification=classification)
    gi = GapItem(control=control, status=status)
    if compensating:
        gi.compensating_notes.append("'Conditional access by device posture' may partially "
                                     "offset this (unverified, not in baseline).")
    engine = DeterministicArtifactEngine()
    threats = engine.generate_threats([gi], profile)
    score = engine.score_dread(threats, [gi], profile)[0]
    return threats[0], score
