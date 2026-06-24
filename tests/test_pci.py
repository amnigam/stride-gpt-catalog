"""PCI pass: a second deterministic read off the same gap."""

from __future__ import annotations

from threatcatalog.gap import build_gap
from threatcatalog.models import (AppProfile, Confidence, ControlStatus,
                                  DataClassification, ImplementedLedger,
                                  LedgerEntry, PlatformFacet, Provenance)
from threatcatalog.pci import build_pci_view


def _scope(handles):
    return AppProfile(name="x", platforms=[PlatformFacet.WEB],
                      data_classification=DataClassification.RESTRICTED,
                      handles_cardholder_data=handles)


def _entry(cid, st):
    return LedgerEntry(control_id=cid, status=st, provenance=Provenance.DECLARED,
                       confidence=Confidence.HIGH)


def test_out_of_scope_returns_empty_view(tiny_controls):
    gap = build_gap(tiny_controls, ImplementedLedger(), _scope(False))
    view = build_pci_view(gap, _scope(False))
    assert view.in_scope is False
    assert view.exposed == [] and view.indeterminate == []


def test_exposed_lists_weak_pci_controls(tiny_controls):
    profile = _scope(True)
    gap = build_gap(tiny_controls,
                    ImplementedLedger(entries=[_entry("X-BASE-1", ControlStatus.NOT_PRESENT)]),
                    profile)
    view = build_pci_view(gap, profile)
    assert view.in_scope is True
    assert [e.control_id for e in view.exposed] == ["X-BASE-1"]


def test_unknown_pci_control_is_indeterminate(tiny_controls):
    profile = _scope(True)
    gap = build_gap(tiny_controls, ImplementedLedger(), profile)  # all unknown
    view = build_pci_view(gap, profile)
    assert [e.control_id for e in view.indeterminate] == ["X-BASE-1"]
    assert view.exposed == []


def test_implemented_pci_control_counts_as_covered(tiny_controls):
    profile = _scope(True)
    gap = build_gap(tiny_controls,
                    ImplementedLedger(entries=[_entry("X-BASE-1", ControlStatus.IMPLEMENTED)]),
                    profile)
    view = build_pci_view(gap, profile)
    assert view.covered_count == 1
    assert view.exposed == [] and view.indeterminate == []


def test_non_pci_controls_ignored(tiny_controls):
    # X-WEB-1 and X-AI-1 have no pci refs; they must not appear in any bucket
    profile = _scope(True)
    gap = build_gap(tiny_controls,
                    ImplementedLedger(entries=[_entry("X-WEB-1", ControlStatus.NOT_PRESENT)]),
                    profile)
    view = build_pci_view(gap, profile)
    assert view.exposed == []  # X-WEB-1 is not PCI-mapped
