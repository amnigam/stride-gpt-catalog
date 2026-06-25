"""End-to-end pipeline — the PeopleDesk worked example.

Internal HR web app on cloud; an LLM summarizes employee records (Restricted
PII); no cardholder data. The architect declares the AI controls absent. We
assert the system produces the right *shape* of result: AI-layer findings,
no PCI section, unknowns routed to clarifications, tokenization flagged
out-of-catalog."""

from __future__ import annotations

from threatcatalog import pipeline
from threatcatalog.models import (AICapability, AppProfile, ControlStatus,
                                  DataClassification, ObservedControl,
                                  PlatformFacet)

DESCRIPTION = (
    "PeopleDesk is an internal HR web application deployed on AWS. Staff sign in "
    "through Okta SSO. The employee database is encrypted at rest and all traffic "
    "uses TLS 1.3. A WAF fronts the application. An LLM feature summarizes an "
    "employee's records on request.")


def _run(declared_missing_ai):
    profile = AppProfile(
        name="PeopleDesk", platforms=[PlatformFacet.WEB, PlatformFacet.CLOUD],
        ai_capabilities=[AICapability.LLM],
        data_classification=DataClassification.RESTRICTED,
        handles_cardholder_data=False)
    observed = [ObservedControl(name="PII display tokenization",
                                description="masks identifiers on screen after the model call",
                                evidence="declared by architect")]
    return pipeline.run(profile, description=DESCRIPTION,
                        declared=declared_missing_ai, observed_unmatched=observed)


def test_ai_layer_findings_surface(declared_missing_ai):
    report = _run(declared_missing_ai)
    finding_ids = {gi.control.id for gi in report.gap_items if gi.is_finding}
    # the declared-absent AI controls must appear as findings
    assert {"AI-PI-001", "AI-ENDP-001", "AI-OUT-001", "AI-RATE-001"} <= finding_ids


def test_threats_generated_for_ai_gaps(declared_missing_ai):
    report = _run(declared_missing_ai)
    enabling = {t.enabling_gap for t in report.threats}
    assert "AI-PI-001" in enabling and "AI-ENDP-001" in enabling


def test_detected_controls_are_not_findings(declared_missing_ai):
    # SSO, encryption, TLS, WAF are described -> detected implemented -> not findings
    report = _run(declared_missing_ai)
    finding_ids = {gi.control.id for gi in report.gap_items if gi.is_finding}
    assert "IAM-SSO-001" not in finding_ids
    assert "DATA-ENC-001" not in finding_ids
    assert "WEB-WAF-001" not in finding_ids


def test_unmentioned_controls_become_clarifications(declared_missing_ai):
    report = _run(declared_missing_ai)
    # e.g. CSRF/session/headers were neither described nor declared -> unknown
    assert report.clarifications
    joined = " ".join(report.clarifications).lower()
    assert "csrf" in joined or "session" in joined or "secrets" in joined


def test_pci_out_of_scope(declared_missing_ai):
    report = _run(declared_missing_ai)
    assert report.pci_view.in_scope is False
    assert report.pci_view.exposed == []


def test_tokenization_flagged_out_of_catalog(declared_missing_ai):
    report = _run(declared_missing_ai)
    titles = {c.title for c in report.candidates}
    assert "PII display tokenization" in titles
    # and it should be recognised as a compensating (InfoDisclosure) control
    assert any(a.observed.name == "PII display tokenization" for a in report.compensating)


def test_dread_present_and_prioritized(declared_missing_ai):
    report = _run(declared_missing_ai)
    assert len(report.dread) == len(report.threats)
    # Restricted data + missing controls should yield at least one Critical/High
    priorities = {s.priority.value for s in report.dread}
    assert priorities & {"Critical", "High"}


def test_resolved_count_matches_web_cloud_llm(declared_missing_ai):
    report = _run(declared_missing_ai)
    assert report.resolved_control_count == 29  # pinned for these facets (web+cloud+llm)


def test_pipeline_runs_with_no_evidence_at_all():
    # an empty intake must not crash; everything becomes a clarification
    profile = AppProfile(name="bare", platforms=[PlatformFacet.WEB],
                         ai_capabilities=[AICapability.NONE])
    report = pipeline.run(profile)
    assert report.threats == []
    assert report.clarifications  # all unknown
