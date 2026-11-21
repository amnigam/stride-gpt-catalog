"""Report layout shared by all three report flows: the SAD page (automated), a SAD
declaration loaded on the review page, and the review page from a description.
Rendering only: none of this may change a control's status."""

from __future__ import annotations

import pytest

from threatcatalog import pipeline
from threatcatalog.models import (AICapability, AppProfile, ControlStatus, DataClassification,
                                  ObservedControl, PlatformFacet)
from threatcatalog.report import (clean_quote, fw_text, pci_groups, render_markdown,
                                  stride_label, summary_facts)
from test_sad import _stub_sad_run


def _section(md: str, heading: str) -> str:
    start = md.index(heading)
    nxt = md.find("\n## ", start + len(heading))
    return md[start:nxt if nxt != -1 else len(md)]


def _main_page_report(declared, profile=None):
    profile = profile or AppProfile(name="PeopleDesk",
                                    platforms=[PlatformFacet.WEB, PlatformFacet.CLOUD],
                                    ai_capabilities=[AICapability.LLM],
                                    data_classification=DataClassification.RESTRICTED)
    return pipeline.run(profile, description="Okta SSO; encrypted at rest; TLS 1.3; WAF.",
                        declared=declared,
                        observed_unmatched=[ObservedControl(name="tokenization",
                                                            description="masks pii")])


# ------------------------------------------------------------------ helpers --
def test_readable_labels():
    assert stride_label("ElevationOfPrivilege") == "Elevation of privilege"
    assert stride_label("InformationDisclosure") == "Information disclosure"
    assert fw_text("cis_v8:Control 6") == "CIS v8 Control 6"
    assert fw_text("owasp_llm:LLM01:2025") == "OWASP LLM LLM01:2025"


def test_table_quotes_read_as_sentences():
    q = "| Privileged access | The four engineers hold standing rights. |"
    assert clean_quote(q) == "Privileged access: The four engineers hold standing rights."
    assert clean_quote("A plain sentence.") == "A plain sentence."
    assert clean_quote(None) is None


# --------------------------------------------- flow 3: review page, no SAD --
def test_main_page_report_layout(declared_missing_ai):
    r = _main_page_report(declared_missing_ai)
    md = render_markdown(r)
    register = _section(md, "## Findings register")
    appendix = md[md.index("## Appendix — control evidence"):]
    implemented = [g.control.id for g in r.gap_items if g.status == ControlStatus.IMPLEMENTED]
    assert implemented
    assert all(cid not in register for cid in implemented)       # findings only in the body
    assert all(cid in appendix for cid in implemented)           # everything in the appendix
    assert "PCI exposed" not in md                               # PCI out of scope: no column
    assert "Control 3" not in register.replace("CIS v8 Control 3", "")   # framework named
    assert "*Catalog:*" in md and "*Tool version:*" in md and "*Generated:*" in md
    assert "control statuses confirmed by a reviewer" in md
    assert "from description keyword match" in md                # flow 3 keeps its labels
    assert "from SAD text" not in md
    c = summary_facts(r)["counts"]
    assert f"**Not present** {c['not_present']} · **Partial** {c['partial']}" in md


def test_top_findings_is_one_short_ranked_list(declared_missing_ai):
    f = summary_facts(_main_page_report(declared_missing_ai))
    tops = f["top_findings"]
    assert 0 < len(tops) <= 5
    ids = [x["control_id"] for x in tops]
    assert len(ids) == len(set(ids))
    scores = [x["score"] for x in tops]
    assert scores == sorted(scores, reverse=True)
    assert "key_gaps" not in f and "top_threats" not in f


def test_pci_view_grouped_by_requirement(pci_profile):
    r = pipeline.run(pci_profile, description="")
    md = render_markdown(r)
    g = pci_groups(r)
    reqs = [req for req, _ in g["groups"]]
    key = lambda q: tuple(int(x) if x.isdigit() else x for x in q.split("."))
    assert reqs == sorted(reqs, key=key)
    k = g["counts"]
    assert k["mapped"] == k["exposed"] + k["verify"] + k["in_place"]
    assert "| PCI requirement | Control | Status |" in md
    assert "PCI exposed |" in md                                 # column shown when in scope


# -------------------------------------------------- flow 1: SAD page draft --
def test_sad_report_labels_and_silence(catalog):
    _sad, _p, expected, report, _ledger = _stub_sad_run(catalog)
    md = render_markdown(report)
    assert "from SAD text" in md and "from description" not in md
    silent = [g for g in report.gap_items if g.status == ControlStatus.NOT_PRESENT]
    assert f"{len(silent)} of the {len(silent)} not-implemented control(s) are recorded only " \
           "because the SAD does not mention them" in md
    assert "Not present (SAD silent)" in _section(md, "## Findings register")
    assert "No control was left as unknown." in md
    assert "Every expected control could be assessed" not in md
    assert "Automated draft from the SAD" in md


# --------------------------- flow 2: SAD declaration loaded on review page --
def test_reviewer_override_clears_sad_silent_tag(catalog):
    from threatcatalog import sad as sadflow
    from threatcatalog.declaration import (apply_edit, export_json, import_json,
                                           reviewed_sad_context, sad_handoff, to_ledger)
    _sad, profile, expected, report, ledger = _stub_sad_run(catalog)
    rows, meta = import_json(export_json(sadflow.declaration_rows(ledger),
                                         meta=sadflow.declaration_meta(report)))
    target = expected[1].id
    apply_edit(rows[target], ControlStatus.UNKNOWN, "Asked the team", False, "Priya")
    reviewed = pipeline.run(profile, declared=to_ledger(rows, expected), controls=catalog.controls)
    reviewed.sad = reviewed_sad_context(sad_handoff(meta), profile, "Priya")
    md = render_markdown(reviewed)
    register = _section(md, "## Findings register")
    line = next(x for x in register.splitlines() if x.startswith(f"| {target} "))
    assert "SAD silent" not in line and "Unknown" in line
    assert "(SAD silent)" in register                            # the untouched ones keep it
    assert "from SAD text" in md                                 # still the SAD's evidence
    assert "control statuses confirmed by a reviewer (Priya)" in md
    # statuses are exactly those carried over, plus the one reviewer change
    before = {g.control.id: g.status for g in report.gap_items}
    after = {g.control.id: g.status for g in reviewed.gap_items}
    assert {k for k in before if before[k] != after[k]} == {target}


def test_pdf_renders_for_every_flow(catalog, declared_missing_ai, pci_profile):
    pytest.importorskip("reportlab")
    from threatcatalog.pdf_export import render_pdf
    _sad, _p, _e, sad_report, _l = _stub_sad_run(catalog)
    for r in (sad_report, _main_page_report(declared_missing_ai),
              pipeline.run(pci_profile, description="")):
        assert render_pdf(r)[:4] == b"%PDF"


def test_top_findings_put_evidence_before_sad_silence(catalog):
    from threatcatalog.models import ControlEvidence, DreadScore, Threat
    from threatcatalog.report import sad_silent
    _sad, _p, _e, report, _l = _stub_sad_run(catalog)
    silent = [g for g in report.gap_items if sad_silent(g)][:2]
    evidenced = silent[1]
    evidenced.evidence = ControlEvidence(ai_status=ControlStatus.NOT_PRESENT,
                                         ai_note="Outbound internet is not restricted.")
    report.threats = [Threat(id=f"T{i}", stride="Tampering", title=g.control.title, description="",
                             enabling_gap=g.control.id) for i, g in enumerate(silent, 1)]
    report.dread = [DreadScore(threat_id=t.id, damage=8, reproducibility=8, exploitability=8,
                               affected_users=7, discoverability=6) for t in report.threats]
    tops = summary_facts(report)["top_findings"]
    assert [x["control_id"] for x in tops] == [evidenced.control.id, silent[0].control.id]
