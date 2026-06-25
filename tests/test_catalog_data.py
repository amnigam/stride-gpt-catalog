"""Data-integrity tests for the *shipped* catalog. These catch authoring
mistakes (bad PCI ref, missing framework on an AI control, orphan layer) the
moment a YAML file is edited."""

from __future__ import annotations

from threatcatalog.models import Layer, Stride


def test_all_ids_unique(catalog):
    ids = [c.id for c in catalog.controls]
    assert len(ids) == len(set(ids))


def test_every_control_has_assessment_signal(catalog):
    for c in catalog.controls:
        assert c.assessment_signal.strip(), c.id


def test_base_layer_is_populated(catalog):
    base = [c for c in catalog.controls if Layer.BASE in c.layers]
    assert len(base) >= 5


def test_ai_llm_layer_present(catalog):
    llm = [c for c in catalog.controls if Layer.AI_LLM in c.layers]
    ids = {c.id for c in llm}
    # the controls the PeopleDesk example leans on must exist
    assert {"AI-PI-001", "AI-ENDP-001", "AI-OUT-001", "AI-RATE-001"} <= ids


def test_ai_controls_carry_framework_refs(catalog):
    # AI-layer controls should be traceable to an OWASP list (lineage matters).
    ai_layers = {Layer.AI_LLM, Layer.AI_LLM_TOOLS, Layer.AI_MCP, Layer.AI_AGENTIC}
    framework_tagged = 0
    ai_total = 0
    for c in catalog.controls:
        if set(c.layers) & ai_layers:
            ai_total += 1
            if c.threat_frameworks:
                framework_tagged += 1
    # most AI controls should be framework-anchored
    assert framework_tagged >= ai_total * 0.6


def test_pci_refs_are_well_formed(catalog):
    # PciRef validates on load; this asserts at least some PCI lineage exists.
    pci_controls = [c for c in catalog.controls if c.pci]
    assert len(pci_controls) >= 8


def test_stride_values_valid(catalog):
    valid = set(Stride)
    for c in catalog.controls:
        for s in c.stride:
            assert s in valid


def test_mcp_version_pinned_as_beta(catalog):
    # The MCP Top 10 is beta; the catalog must record that volatility.
    mcp = [c for c in catalog.controls if Layer.AI_MCP in c.layers]
    refs = [f for c in mcp for f in c.threat_frameworks if f.framework == "owasp_mcp"]
    assert refs and all("beta" in f.version for f in refs)


def test_every_control_has_verbose_guidance(catalog):
    # guidance is the plain-language description shown to app teams / PMs
    for c in catalog.controls:
        assert c.guidance and len(c.guidance.strip()) >= 60, c.id


def test_cis_v8_dimension_present_on_all(catalog):
    # CIS Controls v8 was added as a framework dimension across the catalog
    for c in catalog.controls:
        frames = {f.framework for f in c.threat_frameworks}
        assert "cis_v8" in frames, c.id


def test_owasp_api_and_mobile_frameworks_present(catalog):
    frames = {f.framework for c in catalog.controls for f in c.threat_frameworks}
    assert "owasp_api" in frames
    assert "owasp_mobile" in frames


def test_new_controls_exist(catalog):
    ids = {c.id for c in catalog.controls}
    expected = {"SAAS-ISO-001", "API-BOLA-001", "AI-VEC-001", "AI-MODEL-PROV-001",
                "AI-SANDBOX-001", "AI-PARAM-001", "AI-OBO-001", "ASI-AUTH-001",
                "MOB-RASP-001", "SCA-SBOM-001", "EDR-001", "IMMUT-001"}
    assert expected <= ids


def test_owasp_llm_refs_use_2025(catalog):
    for c in catalog.controls:
        for f in c.threat_frameworks:
            if f.framework == "owasp_llm":
                assert f.version == "2025", (c.id, f.ref)
