"""Report rendering: structure and the key sections render correctly."""

from __future__ import annotations

from threatcatalog import pipeline
from threatcatalog.models import (AICapability, AppProfile, ControlStatus,
                                  DataClassification, ObservedControl,
                                  PlatformFacet)
from threatcatalog.report import render_markdown


def _report(declared_missing_ai):
    profile = AppProfile(name="PeopleDesk", platforms=[PlatformFacet.WEB, PlatformFacet.CLOUD],
                         ai_capabilities=[AICapability.LLM],
                         data_classification=DataClassification.RESTRICTED)
    return pipeline.run(profile, description="Okta SSO; encrypted at rest; TLS 1.3; WAF.",
                        declared=declared_missing_ai,
                        observed_unmatched=[ObservedControl(name="tokenization",
                                                            description="masks pii")])


def test_report_has_core_sections(declared_missing_ai):
    md = render_markdown(_report(declared_missing_ai))
    for heading in ["# Threat Model", "## Control gap register", "## Threat model",
                    "## Recommendations", "## Mitigations", "## DREAD scoring",
                    "## PCI DSS"]:
        assert heading in md


def test_report_shows_pci_out_of_scope(declared_missing_ai):
    md = render_markdown(_report(declared_missing_ai))
    assert "Not in scope" in md


def test_report_lists_clarifications(declared_missing_ai):
    md = render_markdown(_report(declared_missing_ai))
    assert "Clarifications needed" in md


def test_report_is_nonempty_string(declared_missing_ai):
    md = render_markdown(_report(declared_missing_ai))
    assert isinstance(md, str) and len(md) > 200


def test_report_has_executive_summary(declared_missing_ai):
    md = render_markdown(_report(declared_missing_ai))
    assert "## Executive summary" in md
    # summary appears before the gap register
    assert md.index("## Executive summary") < md.index("## Control gap register")


def test_exec_summary_reports_gaps_and_strengths(declared_missing_ai):
    md = render_markdown(_report(declared_missing_ai))
    assert "Key gaps to close" in md          # AI controls declared not_present
    assert "Strengths (confirmed in place)" in md  # SSO/encryption/TLS/WAF detected
    assert "Top threats (by DREAD)" in md


def test_exec_summary_clean_when_all_confirmed(catalog):
    # an app where every expected control is declared implemented -> no gaps, no unknowns
    from threatcatalog import pipeline
    from threatcatalog.catalog import resolve
    from threatcatalog.models import (AICapability, AppProfile, ControlStatus,
                                      DataClassification, LedgerEntry, PlatformFacet,
                                      Provenance, Confidence)
    profile = AppProfile(name="Solid", platforms=[PlatformFacet.WEB],
                         ai_capabilities=[AICapability.NONE],
                         data_classification=DataClassification.INTERNAL)
    expected = resolve(profile, catalog.controls)
    declared = [LedgerEntry(control_id=c.id, status=ControlStatus.IMPLEMENTED,
                            provenance=Provenance.DECLARED, confidence=Confidence.HIGH)
                for c in expected]
    md = render_markdown(pipeline.run(profile, declared=declared, controls=catalog.controls))
    assert "all expected controls are confirmed in place" in md
