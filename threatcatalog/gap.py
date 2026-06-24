"""
threatcatalog.gap
=================

The deterministic core. Given the expected control set and the implemented
ledger, compute one `GapItem` per expected control. This is *code*, not an LLM
call — which is exactly what makes the whole tool auditable. Everything
downstream (threats, recommendations, mitigations, DREAD, PCI) reasons *over*
this computed gap; nothing guesses what is missing.

Two rules are load-bearing here:

* **unknown != missing.** A control with no ledger entry is `UNKNOWN`, never
  `NOT_PRESENT`. `UNKNOWN` becomes a clarification, not a finding.
* **PCI exposure is gated twice** — by scope (does the app handle cardholder
  data) AND by status (only weak/missing controls are *exposed*; unknown
  PCI-mapped controls are reported separately as indeterminate by `pci.py`).
"""

from __future__ import annotations

from .models import (AppProfile, Control, ControlStatus, GapItem,
                     ImplementedLedger)

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

        items.append(GapItem(control=control, status=status, pci_exposed=pci_exposed))
    return items
