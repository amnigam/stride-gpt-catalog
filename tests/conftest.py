"""Shared fixtures. The real shipped catalog is used everywhere except where a
test deliberately constructs a tiny synthetic catalog to isolate behaviour."""

from __future__ import annotations

import pytest

from threatcatalog.catalog import Catalog
from threatcatalog.generators import DeterministicArtifactEngine
from threatcatalog.models import (AICapability, AppProfile, Confidence,
                                  Control, ControlStatus, DataClassification,
                                  Expectation, LedgerEntry, Layer,
                                  ObservedControl, PlatformFacet, Provenance,
                                  Stride, ThreatFrameworkRef)


@pytest.fixture(scope="session")
def catalog() -> Catalog:
    return Catalog.load()


@pytest.fixture
def engine() -> DeterministicArtifactEngine:
    return DeterministicArtifactEngine()


@pytest.fixture
def web_llm_profile() -> AppProfile:
    return AppProfile(
        name="PeopleDesk", platforms=[PlatformFacet.WEB, PlatformFacet.CLOUD],
        ai_capabilities=[AICapability.LLM],
        data_classification=DataClassification.RESTRICTED,
        handles_cardholder_data=False)


@pytest.fixture
def pci_profile() -> AppProfile:
    return AppProfile(
        name="Checkout", platforms=[PlatformFacet.WEB, PlatformFacet.CLOUD],
        ai_capabilities=[AICapability.NONE],
        data_classification=DataClassification.RESTRICTED,
        handles_cardholder_data=True)


@pytest.fixture
def tiny_controls() -> list[Control]:
    """A 3-control synthetic catalog: one base (PCI), one web, one llm."""
    return [
        Control(id="X-BASE-1", title="Base encryption", intent="encrypt at rest",
                layers=[Layer.BASE], stride=[Stride.INFO_DISCLOSURE],
                assessment_signal="encrypted?", pci=[{"requirement": "3.5.1"}],
                detect_keywords=["encrypted at rest"]),
        Control(id="X-WEB-1", title="WAF", intent="filter web attacks",
                layers=[Layer.PLATFORM_WEB], stride=[Stride.TAMPERING],
                assessment_signal="waf?", detect_keywords=["waf"]),
        Control(id="X-AI-1", title="Prompt injection defense",
                intent="treat input as data", layers=[Layer.AI_LLM],
                stride=[Stride.TAMPERING],
                threat_frameworks=[ThreatFrameworkRef(framework="owasp_llm", ref="LLM01:2025", version="2025")],
                assessment_signal="pi defense?", detect_keywords=["prompt injection"]),
    ]


@pytest.fixture
def declared_missing_ai() -> list[LedgerEntry]:
    """The PeopleDesk worked example: AI controls declared not-present."""
    ids = ["AI-PI-001", "AI-ENDP-001", "AI-OUT-001", "AI-RATE-001", "AI-LOG-001"]
    return [LedgerEntry(control_id=i, status=ControlStatus.NOT_PRESENT,
                        provenance=Provenance.DECLARED, confidence=Confidence.HIGH)
            for i in ids]
