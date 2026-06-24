"""
threatcatalog.pci
=================

The compliance pass. PCI DSS v4.0.1 is the only regime wired in for now, so the
in-scope decision is a single boolean on the profile (`handles_cardholder_data`)
rather than the multi-regime resolver the design leaves room for.

This is a *second deterministic read* off the same gap that drives the threat
model — no extra model run. It splits PCI-mapped controls three ways:

* **exposed**       — weak/missing PCI-mapped controls (the real findings)
* **indeterminate** — UNKNOWN PCI-mapped controls (verify, don't assume breach)
* **covered**       — implemented PCI-mapped controls (counted, not listed)
"""

from __future__ import annotations

from .models import (AppProfile, ControlStatus, GapItem, PciComplianceView,
                     PciExposure)

_WEAK = (ControlStatus.NOT_PRESENT, ControlStatus.PARTIAL)


def build_pci_view(gap_items: list[GapItem], profile: AppProfile) -> PciComplianceView:
    if not profile.handles_cardholder_data:
        # Out of scope: we still record that fact rather than silently omitting it.
        return PciComplianceView(in_scope=False)

    exposed: list[PciExposure] = []
    indeterminate: list[PciExposure] = []
    covered = 0

    for gi in gap_items:
        if not gi.control.pci:
            continue
        ref = PciExposure(control_id=gi.control.id, control_title=gi.control.title,
                          status=gi.status, requirements=list(gi.control.pci))
        if gi.status in _WEAK:
            exposed.append(ref)
        elif gi.status == ControlStatus.UNKNOWN:
            indeterminate.append(ref)
        elif gi.status == ControlStatus.IMPLEMENTED:
            covered += 1

    return PciComplianceView(in_scope=True, exposed=exposed,
                             indeterminate=indeterminate, covered_count=covered)
