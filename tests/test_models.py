"""Model-level validation: the guarantees every downstream stage relies on."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from threatcatalog.models import (Control, ControlStatus, DreadScore, GapItem,
                                  Layer, PciRef, Priority, Stride)


# ---- PciRef validator ----
@pytest.mark.parametrize("req", ["8.3.6", "1.4.1", "10", "3.5.1.2"])
def test_pci_ref_accepts_dotted_numerics(req):
    assert PciRef(requirement=req).requirement == req


@pytest.mark.parametrize("bad", ["8.3.x", "PCI-8", "", "8..3", "eight"])
def test_pci_ref_rejects_non_numeric(bad):
    with pytest.raises(ValidationError):
        PciRef(requirement=bad)


def test_pci_ref_default_version():
    assert PciRef(requirement="1.1").version == "4.0.1"


# ---- Control ----
def test_control_requires_layer_and_stride():
    with pytest.raises(ValidationError):
        Control(id="c", title="t", intent="i", layers=[], stride=[Stride.SPOOFING],
                assessment_signal="?")
    with pytest.raises(ValidationError):
        Control(id="c", title="t", intent="i", layers=[Layer.BASE], stride=[],
                assessment_signal="?")


def test_control_forbids_unknown_keys():
    with pytest.raises(ValidationError):
        Control(id="c", title="t", intent="i", layers=[Layer.BASE],
                stride=[Stride.SPOOFING], assessment_signal="?", typo_field=1)


def test_control_rejects_bad_enum():
    with pytest.raises(ValidationError):
        Control(id="c", title="t", intent="i", layers=["not-a-layer"],
                stride=[Stride.SPOOFING], assessment_signal="?")


# ---- DreadScore computed fields ----
def test_dread_average_and_priority_critical():
    s = DreadScore(threat_id="T1", damage=9, reproducibility=8, exploitability=8,
                   affected_users=7, discoverability=6)
    assert s.average == 7.6
    assert s.priority == Priority.CRITICAL


def test_dread_priority_bands():
    low = DreadScore(threat_id="T", damage=2, reproducibility=2, exploitability=2,
                     affected_users=2, discoverability=2)
    assert low.priority == Priority.LOW
    med = DreadScore(threat_id="T", damage=5, reproducibility=5, exploitability=5,
                     affected_users=5, discoverability=4)
    assert med.priority == Priority.MEDIUM


@pytest.mark.parametrize("val", [0, 11])
def test_dread_rejects_out_of_range(val):
    with pytest.raises(ValidationError):
        DreadScore(threat_id="T", damage=val, reproducibility=5, exploitability=5,
                   affected_users=5, discoverability=5)


# ---- GapItem.is_finding ----
@pytest.mark.parametrize("status,expected", [
    (ControlStatus.NOT_PRESENT, True),
    (ControlStatus.PARTIAL, True),
    (ControlStatus.UNKNOWN, False),       # the load-bearing rule
    (ControlStatus.IMPLEMENTED, False),
    (ControlStatus.NOT_APPLICABLE, False),
])
def test_is_finding(status, expected):
    c = Control(id="c", title="t", intent="i", layers=[Layer.BASE],
                stride=[Stride.SPOOFING], assessment_signal="?")
    assert GapItem(control=c, status=status).is_finding is expected
