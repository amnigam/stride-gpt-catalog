"""
threatcatalog.gap
=================

The deterministic core. Given the expected control set and the implemented
ledger, compute one `GapItem` per expected control. This is *code*, not an LLM
call — which is exactly what makes the whole tool auditable. Everything
downstream (threats, DREAD, the action plan, PCI) reasons *over*
this computed gap; nothing guesses what is missing.

Two rules are load-bearing here:

* **unknown != missing.** A control with no ledger entry is `UNKNOWN`, never
  `NOT_PRESENT`. `UNKNOWN` becomes a clarification, not a finding.
* **PCI exposure is gated twice** — by scope (does the app handle cardholder
  data) AND by status (only weak/missing controls are *exposed*; unknown
  PCI-mapped controls are reported separately as indeterminate by `pci.py`).
"""

from __future__ import annotations

from .declaration import evidence_basis
from .models import (AppProfile, Control, ControlEvidence, ControlStatus,
                     EvidenceBasis, GapItem, ImplementedLedger, Provenance)

_WEAK = (ControlStatus.NOT_PRESENT, ControlStatus.PARTIAL)


def build_gap(expected: list[Control], ledger: ImplementedLedger,
              profile: AppProfile) -> list[GapItem]:
    status_by_id = ledger.by_control()
    items: list[GapItem] = []
    for control in expected:
        entry = status_by_id.get(control.id)
        status = entry.status if entry else ControlStatus.UNKNOWN

        pci_exposed = []
        if profile.handles_cardholder_data and control.pci and status in _WEAK:
            pci_exposed = list(control.pci)

        detail, basis = (entry.detail if entry else None), None
        if entry is not None:
            human = entry.provenance in (Provenance.DECLARED, Provenance.VERIFIED)
            if detail is None and human:
                # bare declaration (e.g. CLI / API caller) — a human said so
                detail = ControlEvidence(note=entry.evidence, reviewed=True) if entry.evidence else None
                basis = EvidenceBasis.REVIEWER_ONLY
            else:
                if detail is None and entry.evidence:
                    # bare detector / vision entry: its evidence string is the AI note
                    detail = ControlEvidence(ai_status=entry.status, ai_confidence=entry.confidence,
                                             ai_source=entry.provenance.value,
                                             ai_note=entry.evidence, note=entry.evidence)
                basis = evidence_basis(status, detail) if detail else EvidenceBasis.AI_UNREVIEWED

        items.append(GapItem(control=control, status=status, pci_exposed=pci_exposed,
                             evidence=detail, basis=basis))
    return items
