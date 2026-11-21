"""Step 2 of the report work: evidence type per control (carried in the
declaration JSON), To verify / Reviewed counts, Key focus items with the readiness
marker, and the assessment basis for review-page runs. Shared by all three flows."""

from __future__ import annotations

import json

import pytest

from threatcatalog import pipeline
from threatcatalog import sad as sadflow
from threatcatalog.catalog import resolve
from threatcatalog.declaration import (apply_detection, apply_edit, export_json, import_json,
                                       reviewed_sad_context, sad_handoff, to_ledger)
from threatcatalog.models import (Confidence, ControlEvidence, ControlStatus, DreadScore,
                                  LedgerEntry, Provenance, Threat)
from threatcatalog.report import (NOT_READY, READY, READY_COND, focus_items, render_markdown,
                                  sad_silent, summary_facts)
from test_sad import _stub_sad_run


def _flow2(catalog, edit=None, strip_basis=False):
    _sad, profile, expected, report, ledger = _stub_sad_run(catalog)
    blob = export_json(sadflow.declaration_rows(ledger), meta=sadflow.declaration_meta(report))
    if strip_basis:                      # a declaration saved before ai_basis existed
        d = json.loads(blob)
        for row in d["rows"].values() if isinstance(d["rows"], dict) else d["rows"]:
            row["evidence"].pop("ai_basis", None)
        blob = json.dumps(d)
    rows, meta = import_json(blob)
    if edit:
        edit(rows, expected)
    r2 = pipeline.run(profile, declared=to_ledger(rows, expected), controls=catalog.controls)
    r2.sad = reviewed_sad_context(sad_handoff(meta), profile, "Priya")
    return report, r2, expected


# ------------------------------------------------------------- R4 evidence --
def test_sad_rules_record_the_evidence_type(catalog, web_llm_profile):
    expected = resolve(web_llm_profile, catalog.controls)
    ids = [c.id for c in expected]
    led = {e.control_id: e for e in sadflow.build_sad_ledger(expected, [
        {"control_id": ids[0], "status": "implemented", "basis": "stated", "source": "diagram"},
        {"control_id": ids[1], "status": "implemented", "basis": "inferred", "source": "text"},
    ], "")}
    assert led[ids[0]].detail.ai_basis == "stated"
    assert led[ids[1]].detail.ai_basis == "inferred" and led[ids[1]].status == ControlStatus.PARTIAL
    assert led[ids[2]].detail.ai_basis == "silent"


def test_round_trip_keeps_evidence_type_and_statuses(catalog):
    report, r2, _e = _flow2(catalog)
    assert {g.control.id: g.status for g in report.gap_items} == \
           {g.control.id: g.status for g in r2.gap_items}
    assert [g.control.id for g in report.gap_items if sad_silent(g)] == \
           [g.control.id for g in r2.gap_items if sad_silent(g)]
    assert all(g.evidence.ai_basis == "silent" for g in r2.gap_items if sad_silent(g))


def test_old_declaration_without_evidence_type_still_works(catalog):
    report, r2, _e = _flow2(catalog, strip_basis=True)
    assert all(g.evidence.ai_basis is None for g in r2.gap_items)
    n = sum(1 for g in report.gap_items if sad_silent(g))
    assert n and sum(1 for g in r2.gap_items if sad_silent(g)) == n   # from the note
    assert "(SAD silent)" in render_markdown(r2)


def test_detect_on_review_page_replaces_evidence_type(catalog, web_llm_profile):
    from threatcatalog.declaration import DeclarationRow
    expected = resolve(web_llm_profile, catalog.controls)
    c = expected[0].id
    rows = {c: DeclarationRow(control_id=c, status=ControlStatus.NOT_PRESENT,
                              evidence=ControlEvidence(ai_status=ControlStatus.NOT_PRESENT,
                                                       ai_basis="silent"))}
    det = [LedgerEntry(control_id=c, status=ControlStatus.IMPLEMENTED,
                       provenance=Provenance.DESCRIPTION, confidence=Confidence.HIGH,
                       detail=ControlEvidence(ai_source="description"))]
    apply_detection(rows, det, expected)
    assert rows[c].evidence.ai_basis is None and rows[c].status == ControlStatus.IMPLEMENTED


# ------------------------------------------------------- R5 counts per flow --
def test_to_verify_and_reviewed_counts(catalog):
    _s, _p, _e, report, _l = _stub_sad_run(catalog)
    c1 = summary_facts(report)["counts"]
    assert c1["reviewed"] is None                       # automated draft
    assert c1["to_verify"] == 0                         # stub has no inferred / failed quotes

    def edit(rows, expected):
        apply_edit(rows[expected[1].id], ControlStatus.UNKNOWN, "Asked the team", False, "Priya")
    _r, r2, _e2 = _flow2(catalog, edit)
    c2 = summary_facts(r2)["counts"]
    assert c2["reviewed"] == 1
    # every row not touched by the reviewer still rests on the AI, plus the unknown
    assert c2["to_verify"] == c2["expected"]
    md = render_markdown(r2)
    assert f"**Reviewed** 1 of {c2['expected']}" in md


# ------------------------------------------------- R6 Key focus items rule --
def _scored(report, control_id, scores):
    report.threats = [Threat(id="T1", stride="Tampering", title="x", description="",
                             enabling_gap=control_id)]
    d, r, e, a, disc = scores
    report.dread = [DreadScore(threat_id="T1", damage=d, reproducibility=r, exploitability=e,
                               affected_users=a, discoverability=disc)]


def test_readiness_rule(catalog):
    _s, _p, expected, report, _l = _stub_sad_run(catalog)
    silent = next(g for g in report.gap_items if sad_silent(g))
    _scored(report, silent.control.id, (9, 8, 8, 7, 6))        # Critical, but SAD silent
    f = focus_items(report)
    assert f["readiness"] == READY_COND and f["tag"] == "Automated draft"
    assert silent.control.id in [x[0] for x in f["business_risks"][0]]

    silent.evidence = ControlEvidence(ai_status=ControlStatus.NOT_PRESENT, ai_basis="stated",
                                      ai_note="Outbound internet is not restricted.")
    f = focus_items(report)
    assert f["readiness"] == NOT_READY
    assert [x[0] for x in f["before_go_live"][0]] == [silent.control.id]


def test_ready_only_when_nothing_is_open(catalog, web_llm_profile, declared_missing_ai):
    expected = resolve(web_llm_profile, catalog.controls)
    all_in = [LedgerEntry(control_id=c.id, status=ControlStatus.IMPLEMENTED,
                          provenance=Provenance.DECLARED, confidence=Confidence.HIGH)
              for c in expected]
    r = pipeline.run(web_llm_profile, declared=all_in, controls=catalog.controls)
    assert focus_items(r)["readiness"] == READY
    r = pipeline.run(web_llm_profile, declared=all_in[:-1], controls=catalog.controls)
    f = focus_items(r)
    assert f["readiness"] == READY_COND and "1 control(s) not yet assessed" in f["reasons"]
    assert f["tag"] is None


def test_pci_control_missing_is_not_ready(catalog, pci_profile):
    expected = resolve(pci_profile, catalog.controls)
    pci = next(c for c in expected if c.pci)
    led = [LedgerEntry(control_id=c.id, status=(ControlStatus.NOT_PRESENT if c.id == pci.id
                                                 else ControlStatus.IMPLEMENTED),
                       provenance=Provenance.DECLARED, confidence=Confidence.HIGH)
           for c in expected]
    r = pipeline.run(pci_profile, declared=led, controls=catalog.controls)
    r.dread = []                                          # no scores needed for this rule
    f = focus_items(r)
    assert f["readiness"] == NOT_READY and pci.id in [x[0] for x in f["before_go_live"][0]]


def test_focus_page_leads_every_flow(catalog, declared_missing_ai, web_llm_profile):
    _s, _p, _e, report, _l = _stub_sad_run(catalog)
    _r, r2, _e2 = _flow2(catalog)
    r3 = pipeline.run(web_llm_profile, description="Okta SSO and a WAF.",
                      declared=declared_missing_ai)
    for r in (report, r2, r3):
        md = render_markdown(r)
        assert md.index("## Key focus items") < md.index("## Executive summary")
        assert "It does not decide the review outcome." in md
        assert "| Business risk owner |" in md
    assert "(Automated draft)" in render_markdown(report)
    assert "(Automated draft)" not in render_markdown(r2)
    # flow 2: untouched SAD-silent controls are still open questions
    assert "the SAD does not mention it" in render_markdown(r2)


# ---------------------------------------------- R9 basis for review page --
def test_review_page_basis(declared_missing_ai, web_llm_profile):
    r = pipeline.run(web_llm_profile, description="Okta SSO and a WAF in front.",
                     declared=declared_missing_ai)
    r.engine = "Deterministic (offline)"
    r.diagrams_read = ["Overview.png"]
    md = render_markdown(r)
    basis = md[md.index("## Assessment basis"):md.index("## Findings register")]
    assert "*Description:* 7 words" in basis and "Deterministic (offline)" in basis
    assert "Diagrams read (1):* Diagram 1: Overview.png" in basis
    assert "not checked for completeness" in basis
    assert "Assessment basis (SAD)" not in md


def test_pdf_renders_focus_page_for_every_flow(catalog, declared_missing_ai, web_llm_profile):
    pytest.importorskip("reportlab")
    from threatcatalog.pdf_export import render_pdf
    _s, _p, _e, report, _l = _stub_sad_run(catalog)
    _r, r2, _e2 = _flow2(catalog)
    r3 = pipeline.run(web_llm_profile, description="x", declared=declared_missing_ai)
    for r in (report, r2, r3):
        assert render_pdf(r)[:4] == b"%PDF"
