"""Gap engine: the deterministic spine. These tests pin the two load-bearing
rules — unknown is not a finding, and PCI exposure is gated by scope AND status."""

from __future__ import annotations

from threatcatalog.gap import build_gap
from threatcatalog.models import (AppProfile, ControlStatus, DataClassification,
                                  ImplementedLedger, LedgerEntry, PlatformFacet,
                                  Provenance, Confidence)


def _ledger(*pairs):
    return ImplementedLedger(entries=[
        LedgerEntry(control_id=cid, status=st, provenance=Provenance.DECLARED,
                    confidence=Confidence.HIGH) for cid, st in pairs])


def test_missing_ledger_entry_is_unknown(tiny_controls, web_llm_profile):
    gap = build_gap(tiny_controls, ImplementedLedger(), web_llm_profile)
    assert all(gi.status == ControlStatus.UNKNOWN for gi in gap)
    assert not any(gi.is_finding for gi in gap)   # unknown != finding


def test_declared_status_flows_through(tiny_controls, web_llm_profile):
    gap = build_gap(tiny_controls, _ledger(("X-WEB-1", ControlStatus.NOT_PRESENT)),
                    web_llm_profile)
    waf = next(gi for gi in gap if gi.control.id == "X-WEB-1")
    assert waf.status == ControlStatus.NOT_PRESENT and waf.is_finding


def test_one_gap_item_per_expected_control(tiny_controls, web_llm_profile):
    gap = build_gap(tiny_controls, ImplementedLedger(), web_llm_profile)
    assert len(gap) == len(tiny_controls)


def test_pci_not_exposed_when_out_of_scope(tiny_controls):
    out_of_scope = AppProfile(name="x", platforms=[PlatformFacet.WEB],
                              data_classification=DataClassification.RESTRICTED,
                              handles_cardholder_data=False)
    gap = build_gap(tiny_controls, _ledger(("X-BASE-1", ControlStatus.NOT_PRESENT)),
                    out_of_scope)
    base = next(gi for gi in gap if gi.control.id == "X-BASE-1")
    assert base.pci_exposed == []


def test_pci_exposed_when_in_scope_and_weak(tiny_controls):
    in_scope = AppProfile(name="x", platforms=[PlatformFacet.WEB],
                          data_classification=DataClassification.RESTRICTED,
                          handles_cardholder_data=True)
    gap = build_gap(tiny_controls, _ledger(("X-BASE-1", ControlStatus.NOT_PRESENT)),
                    in_scope)
    base = next(gi for gi in gap if gi.control.id == "X-BASE-1")
    assert [r.requirement for r in base.pci_exposed] == ["3.5.1"]


def test_pci_not_exposed_when_unknown_even_in_scope(tiny_controls):
    # unknown PCI control is indeterminate, not exposed (handled by pci.py)
    in_scope = AppProfile(name="x", platforms=[PlatformFacet.WEB],
                          data_classification=DataClassification.RESTRICTED,
                          handles_cardholder_data=True)
    gap = build_gap(tiny_controls, ImplementedLedger(), in_scope)
    base = next(gi for gi in gap if gi.control.id == "X-BASE-1")
    assert base.status == ControlStatus.UNKNOWN
    assert base.pci_exposed == []


def test_implemented_control_not_exposed(tiny_controls):
    in_scope = AppProfile(name="x", platforms=[PlatformFacet.WEB],
                          data_classification=DataClassification.RESTRICTED,
                          handles_cardholder_data=True)
    gap = build_gap(tiny_controls, _ledger(("X-BASE-1", ControlStatus.IMPLEMENTED)),
                    in_scope)
    base = next(gi for gi in gap if gi.control.id == "X-BASE-1")
    assert base.pci_exposed == []
