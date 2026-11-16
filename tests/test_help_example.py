"""The Help page's worked DREAD example is computed by the real engine; pin the
numbers the page's explanatory text relies on."""

from __future__ import annotations

from threatcatalog.help_example import dread_example
from threatcatalog.models import ControlStatus, DataClassification, Priority, Stride


def test_base_example_matches_help_text():
    threat, s = dread_example()
    assert threat.stride == Stride.SPOOFING
    assert threat.enabling_gap == "IAM-MFA-001"
    assert (s.damage, s.reproducibility, s.exploitability,
            s.affected_users, s.discoverability) == (8, 8, 8, 7, 6)
    assert s.average == 7.4 and s.priority == Priority.HIGH


def test_variants_tell_the_story():
    assert dread_example(classification=DataClassification.RESTRICTED)[1].priority == Priority.CRITICAL
    assert dread_example(status=ControlStatus.PARTIAL)[1].priority == Priority.MEDIUM
    comp = dread_example(compensating=True)[1]
    assert (comp.damage, comp.exploitability) == (6, 6)
