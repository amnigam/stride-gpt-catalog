"""Step 3 of the report work: the architecture summary (from the SAD assessment
call or the review page's Detect call, carried in the declaration JSON), threats
built on it, DREAD with a rubric and a reason, and one action plan. None of it may
change a control status, add a model call, or drop a finding."""

from __future__ import annotations

import pytest

from threatcatalog import pipeline
from threatcatalog import sad as sadflow
from threatcatalog.architecture import parse_architecture, parse_input_completeness
from threatcatalog.catalog import resolve
from threatcatalog.declaration import (export_json, import_json, reviewed_sad_context,
                                       sad_handoff, to_ledger)
from threatcatalog.generators import DeterministicArtifactEngine
from threatcatalog.llm.engine import LLMArtifactEngine
from threatcatalog.llm.provider import StubRawLLM
from threatcatalog.llm import prompts
from threatcatalog.models import (ArchitectureSummary, Confidence, ControlStatus, DreadScore,
                                  LedgerEntry, Provenance, RubricScore, Threat)
from threatcatalog.report import render_markdown
from test_sad import _raw_assessment, _sad

ARCH = {"components": ["Supplier portal (App Service)", "Azure SQL"],
        "entry_points": ["Supplier portal login", "Bank-details form"],
        "data_stores": ["Azure SQL supplier master"],
        "external_integrations": ["BankVerify API"],
        "data_flows": ["Portal -> SQL: supplier records"],
        "trust_boundaries": ["Internet to Front Door"],
        "exposure": "Internet-facing; suppliers sign in with External ID."}


# ------------------------------------------------------------ R1 parsing --
def test_architecture_parsing_is_tolerant():
    a = parse_architecture({**ARCH, "components": "Single string", "data_flows": [{"name": "A -> B"}],
                            "entry_points": ["x"] * 3 + [" y  z "] + [str(i) for i in range(30)]})
    assert a.components == ["Single string"] and a.data_flows == ["A -> B"]
    assert "y z" in a.entry_points and len(a.entry_points) <= 15
    assert parse_architecture({}) is None and parse_architecture("nope") is None
    assert parse_architecture({"components": [], "exposure": None}) is None


def test_input_completeness_without_diagram():
    items = parse_input_completeness([{"id": "purpose", "score": "present"},
                                      {"id": "diagram", "score": "present"}], has_diagram=False)
    by = {i.id: i for i in items}
    assert by["purpose"].score == RubricScore.PRESENT
    assert by["diagram"].score == RubricScore.MISSING
    assert by["network"].score == RubricScore.MISSING           # not scored -> missing
    assert parse_input_completeness(None, True) == []


def test_detect_returns_extras_without_changing_controls(tiny_controls):
    text = "All users sign in through Okta SSO."
    obj = {"controls": [{"control_id": tiny_controls[0].id, "status": "implemented",
                         "confidence": "high", "source": "description",
                         "quote": text, "rationale": "SSO"}],
           "architecture": ARCH, "completeness": [{"id": "purpose", "score": "thin"}]}
    eng = LLMArtifactEngine(StubRawLLM(obj))
    new = eng.detect_controls(tiny_controls, text)
    assert eng.last_detect_extras["architecture"].exposure.startswith("Internet-facing")
    assert eng.last_detect_extras["completeness"][0].score == RubricScore.THIN
    old = LLMArtifactEngine(StubRawLLM([obj["controls"]])).detect_controls(tiny_controls, text)
    assert [(e.control_id, e.status) for e in new] == [(e.control_id, e.status) for e in old]


# ---------------------------------------------- flows 1 and 2: SAD + JSON --
def _sad_run_with_arch(catalog):
    sad = _sad("PayFlow is a web portal. All traffic uses TLS 1.2 everywhere.")
    raw = _raw_assessment(ai_capabilities=[], cardholder_data={"value": "no"})
    raw["architecture"] = ARCH
    a = sadflow.parse_assessment(raw, sad)
    profile = a.profile()
    expected = resolve(profile, catalog.controls)
    ledger = sadflow.build_sad_ledger(expected, [{"control_id": expected[0].id,
                                                  "status": "implemented", "basis": "stated",
                                                  "source": "diagram"}], sad.text)
    report = pipeline.run(profile, declared=ledger, controls=catalog.controls,
                          architecture=a.architecture)
    report.sad = sadflow.build_context(sad, a, "stub", "Amit")
    return profile, expected, ledger, report


def test_architecture_travels_from_sad_to_review_page(catalog):
    profile, expected, ledger, report = _sad_run_with_arch(catalog)
    assert report.architecture.components[0] == "Supplier portal (App Service)"
    assert report.sad.architecture == report.architecture
    rows, meta = import_json(export_json(sadflow.declaration_rows(ledger),
                                         meta=sadflow.declaration_meta(report)))
    h = sad_handoff(meta)
    assert h.sad.architecture == report.architecture
    r2 = pipeline.run(profile, declared=to_ledger(rows, expected), controls=catalog.controls,
                      architecture=h.sad.architecture)
    r2.sad = reviewed_sad_context(h, profile, "Priya")
    md = render_markdown(r2)
    assert "## System context" in md and "Bank-details form" in md
    # statuses do not depend on the architecture summary
    plain = pipeline.run(profile, declared=to_ledger(rows, expected), controls=catalog.controls)
    assert [g.status for g in plain.gap_items] == [g.status for g in r2.gap_items]


def test_old_json_without_architecture_says_so(catalog):
    profile, expected, ledger, report = _sad_run_with_arch(catalog)
    report.sad.architecture = None
    rows, meta = import_json(export_json(sadflow.declaration_rows(ledger),
                                         meta=sadflow.declaration_meta(report)))
    h = sad_handoff(meta)
    r2 = pipeline.run(profile, declared=to_ledger(rows, expected), controls=catalog.controls,
                      architecture=h.sad.architecture)
    r2.sad = reviewed_sad_context(h, profile, "Priya")
    md = render_markdown(r2)
    assert "## System context" not in md
    assert "No architecture summary was available" in md


# ------------------------------------------------------ R2 prompts / R3 --
def test_prompts_carry_architecture_and_rubric(catalog, web_llm_profile):
    from threatcatalog.gap import build_gap
    from threatcatalog.models import ImplementedLedger
    gap = build_gap(resolve(web_llm_profile, catalog.controls)[:3], ImplementedLedger(),
                    web_llm_profile)
    a = ArchitectureSummary(**ARCH)
    _s, u = prompts.threats_prompt(gap, web_llm_profile, a)
    assert "Bank-details form" in u and "EVERY" in u and "related_gaps" in u
    _s, u = prompts.threats_prompt(gap, web_llm_profile, None)
    assert "ARCHITECTURE: not available" in u
    _s, u = prompts.dread_prompt([], gap, web_llm_profile, a)
    assert "Internet-facing" in u and "Discoverability: 9-10" in u and '"rationale"' in u
    _s, u = prompts.action_plan_prompt([], gap, web_llm_profile, a)
    assert "set by the tool from the DREAD scores" in u and "control_ids" in u


class _PartialEngine(DeterministicArtifactEngine):
    """Covers only one finding, with a bad link and a duplicate id, scores nothing."""

    def generate_threats(self, gap, profile, architecture=None):
        f = [g for g in gap if g.is_finding][0].control.id
        return [Threat(id="T1", stride="Tampering", title="Change supplier bank details",
                       description="d", actor="malicious supplier", target="Bank-details form",
                       impact="Payment fraud", enabling_gap=f, related_gaps=["NOT-A-GAP"]),
                Threat(id="T1", stride="Spoofing", title="dup", description="", enabling_gap="BAD")]

    def score_dread(self, threats, gap, profile, architecture=None):
        return [DreadScore(threat_id="T1", damage=9, reproducibility=8, exploitability=7,
                           affected_users=6, discoverability=9, rationale="Internet-facing form"),
                DreadScore(threat_id="ghost", damage=1, reproducibility=1, exploitability=1,
                           affected_users=1, discoverability=1)]

    def generate_action_plan(self, threats, gap, profile, dread, architecture=None):
        return []


def test_nothing_is_dropped(catalog, web_llm_profile, declared_missing_ai):
    r = pipeline.run(web_llm_profile, declared=declared_missing_ai, engine=_PartialEngine(),
                     controls=catalog.controls, architecture=ArchitectureSummary(**ARCH))
    findings = {g.control.id for g in r.gap_items if g.is_finding}
    ids = [t.id for t in r.threats]
    assert len(ids) == len(set(ids))                                  # ids made unique
    assert {g for t in r.threats for g in t.gaps} == findings         # every finding covered
    assert all(g in findings for t in r.threats for g in t.gaps)      # no bad links kept
    assert {d.threat_id for d in r.dread} == set(ids)                 # every threat scored
    assert {c for a in r.actions for c in a.control_ids} == findings  # every finding actioned
    md = render_markdown(r)
    assert "malicious supplier → Bank-details form. Impact: Payment fraud" in md
    assert "Internet-facing form" in md                               # DREAD reason shown
    assert "## Action plan" in md and "## Recommendations" not in md


def test_action_plan_lists_go_live_first(catalog, web_llm_profile, declared_missing_ai):
    r = pipeline.run(web_llm_profile, declared=declared_missing_ai, controls=catalog.controls)
    from threatcatalog.report import action_rows
    timings = [x["timing"] for x in action_rows(r)]
    assert timings == sorted(timings, key=lambda t: 0 if t == "Before go-live" else 1)
    assert all("Close this gap" not in a.action for a in r.actions)


class _InflatingEngine(DeterministicArtifactEngine):
    """A model that labels every action Critical / before go-live, whatever DREAD says."""
    def generate_action_plan(self, threats, gap, profile, dread, architecture=None):
        from threatcatalog.models import ActionItem
        return [ActionItem(id=f"A{i}", action="Do it", threat_ids=[t.id], control_ids=t.gaps,
                           priority="Critical", timing="Before go-live")
                for i, t in enumerate(threats, start=1)]


def test_action_priority_follows_dread_not_model_labels(catalog, web_llm_profile,
                                                       declared_missing_ai):
    r = pipeline.run(web_llm_profile, declared=declared_missing_ai, engine=_InflatingEngine(),
                     controls=catalog.controls)
    worst = {}
    order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
    by_t = {d.threat_id: d.priority.value for d in r.dread}
    for t in r.threats:
        for g in t.gaps:
            p = by_t[t.id]
            if g not in worst or order[p] < order[worst[g]]:
                worst[g] = p
    for a in r.actions:
        assert a.priority == min((worst[c] for c in a.control_ids), key=order.get)
    if any(d.priority.value != "Critical" for d in r.dread):
        assert any(a.priority != "Critical" for a in r.actions)      # labels not kept
    assert all(a.timing == "Within 90 days" for a in r.actions
               if a.priority in ("Medium", "Low"))


def test_long_exposure_is_cut_at_a_word():
    long = "Suppliers reach the portal over the internet through Front Door " * 15
    a = parse_architecture({"exposure": long, "components": ["x " * 150]})
    assert a.exposure.endswith("…") and len(a.exposure) <= 600
    assert not a.exposure[:-1].endswith(" ")
    assert len(a.components[0]) <= 200 and a.components[0].endswith("…")


# --------------------------------------------------- offline DREAD rules --
def test_offline_dread_new_factors(catalog, pci_profile):
    expected = resolve(pci_profile, catalog.controls)
    pci = next(c for c in expected if c.pci and c.default_expectation.value == "required")
    led = [LedgerEntry(control_id=pci.id, status=ControlStatus.NOT_PRESENT,
                       provenance=Provenance.DECLARED, confidence=Confidence.HIGH)]
    r = pipeline.run(pci_profile, declared=led, controls=catalog.controls)
    t = next(t for t in r.threats if t.enabling_gap == pci.id)
    d = next(x for x in r.dread if x.threat_id == t.id)
    assert "PCI-mapped" in d.rationale and d.rationale.startswith("Offline rules:")


def test_pdf_renders_new_sections(catalog, web_llm_profile, declared_missing_ai):
    pytest.importorskip("reportlab")
    from threatcatalog.pdf_export import render_pdf
    r = pipeline.run(web_llm_profile, declared=declared_missing_ai, engine=_PartialEngine(),
                     controls=catalog.controls, architecture=ArchitectureSummary(**ARCH))
    assert render_pdf(r)[:4] == b"%PDF"
