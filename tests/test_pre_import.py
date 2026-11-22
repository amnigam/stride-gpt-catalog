"""Pre-import fixes (2026-11-22): framework references follow the published OWASP
lists, the report cover explains the readiness marker, and the profile sentence
uses the right article."""

import re

import pytest

from threatcatalog.catalog.loader import load_controls
from threatcatalog.models import (AICapability, AppProfile, DataClassification, LedgerEntry,
                                  ControlStatus, PlatformFacet, Provenance, Confidence)

# OWASP Top 10 for Agentic Applications (2026) and OWASP MCP Top 10 (2025, beta).
ASI = {"ASI-MEM-001": "ASI06:2026", "ASI-HITL-001": "ASI09:2026", "ASI-LOOP-001": "ASI08:2026",
       "ASI-MULTI-001": "ASI08:2026", "ASI-AUTH-001": "ASI07:2026", "ASI-NHI-001": "ASI03:2026",
       "ASI-KILL-001": "ASI10:2026", "AI-TOOL-001": "ASI02:2026", "AI-SANDBOX-001": "ASI05:2026",
       "AI-PI-001": "ASI01:2026"}
MCP = {"MCP-TRUST-001": "MCP04:2025", "MCP-TOKEN-001": "MCP01:2025", "MCP-DESC-001": "MCP03:2025",
       "MCP-PIN-001": "MCP03:2025", "MCP-LOG-001": "MCP08:2025"}


def _refs(c, fw):
    return [f.ref for f in c.threat_frameworks if getattr(f.framework, "value", f.framework) == fw]


def test_agentic_and_mcp_references_follow_published_lists():
    by_id = {c.id: c for c in load_controls()}
    for cid, ref in ASI.items():
        assert _refs(by_id[cid], "owasp_asi") == [ref], cid
    for cid, ref in MCP.items():
        assert _refs(by_id[cid], "owasp_mcp") == [ref], cid
    for c in by_id.values():
        for r in _refs(c, "owasp_asi"):
            assert re.fullmatch(r"ASI(0[1-9]|10):2026", r), (c.id, r)
        for r in _refs(c, "owasp_mcp"):
            assert re.fullmatch(r"MCP(0[1-9]|10):2025", r), (c.id, r)


def _ready_report(partial: str | None = None):
    from threatcatalog import pipeline
    from threatcatalog.catalog.resolver import resolve
    controls = load_controls()
    prof = AppProfile(name="Onprem Job", platforms=[PlatformFacet.ONPREM],
                      ai_capabilities=[AICapability.NONE],
                      data_classification=DataClassification.INTERNAL)
    exp = resolve(prof, controls)
    declared = [LedgerEntry(control_id=c.id,
                            status=ControlStatus.PARTIAL if c.id == partial
                            else ControlStatus.IMPLEMENTED,
                            provenance=Provenance.DECLARED, confidence=Confidence.HIGH)
                for c in exp]
    return pipeline.run(prof, declared=declared, controls=controls)


def test_cover_explains_readiness_and_counts_follow_summary():
    from threatcatalog.report import READINESS_LEGEND, render_markdown
    r = _ready_report()
    md = render_markdown(r)
    assert "an on-premises application" in md
    assert READINESS_LEGEND in md
    assert md.index("### Security readiness") < md.index("## Executive summary") \
        < md.index("**Expected**")
    # tool and catalog versions sit under Assessment basis, not on the cover
    assert md.index("*Tool version:*") > md.index("## Assessment basis")
    assert md.index("*Catalog:*") > md.index("## Assessment basis")


def test_ready_reason_names_remaining_gaps():
    from threatcatalog.report import focus_items
    assert focus_items(_ready_report())["reasons"] == ["no Critical or High findings"]
    f = focus_items(_ready_report(partial="DATA-CLS-001"))
    assert f["readiness"] == "Ready", f
    assert f["reasons"] == ["no Critical or High findings",
                            "1 Medium/Low gap(s) in the action plan"]


def test_pdf_cover_has_legend_and_page_break():
    pytest.importorskip("reportlab")
    from threatcatalog.pdf_export import render_pdf
    fitz = pytest.importorskip("pymupdf")
    doc = fitz.open(stream=render_pdf(_ready_report()), filetype="pdf")
    p1, p2 = doc[0].get_text(), doc[1].get_text()
    assert "Security readiness" in p1 and "fixed rule" in p1
    assert "Executive summary" not in p1 and "Executive summary" in p2
