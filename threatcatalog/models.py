"""
threatcatalog.models
====================

The single source of typed truth for the whole engine. Every artifact that
flows through the pipeline — catalog controls, the app profile, the implemented
ledger, the computed gap, and all four output artifacts — is one of these
models. Two reasons this matters:

1.  **Validation at the edges.** A malformed catalog entry or a hallucinated
    LLM status fails *here*, loudly, instead of silently corrupting a threat
    model three stages downstream.
2.  **One object, not a bag of dicts.** The resolver, gap engine, PCI pass and
    generators all pass these typed objects around. There is no "stringly
    typed" handoff anywhere in the pipeline.

Design note: PCI DSS is modelled as its own typed `PciRef` (not a loose string
in a generic dict) precisely because it is the *only* compliance regime wired
in for now. Giving it a real shape buys structural validation and a clean seam
to generalise later — see `pci.py`.
"""

from __future__ import annotations

from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field, computed_field, field_validator


# --------------------------------------------------------------------------- #
# Enums — closed vocabularies. If the LLM (or a catalog author) emits something
# outside these, Pydantic rejects it. That rejection is a feature.
# --------------------------------------------------------------------------- #
class Layer(str, Enum):
    """A catalog layer. A control is tagged with every layer it applies to;
    the resolver unions the layers an app's facets select."""

    BASE = "base"
    PLATFORM_WEB = "platform.web"
    PLATFORM_CLOUD = "platform.cloud"
    PLATFORM_ONPREM = "platform.onprem"
    PLATFORM_MOBILE = "platform.mobile"
    PLATFORM_SAAS = "platform.saas"        # multi-tenant SaaS concerns
    PLATFORM_API = "platform.api"          # API as a first-class attack surface
    AI_LLM = "ai.llm"
    AI_LLM_TOOLS = "ai.llm_tools"
    AI_MCP = "ai.mcp"
    AI_AGENTIC = "ai.agentic"
    AI_GENERATIVE = "ai.generative"


class PlatformFacet(str, Enum):
    WEB = "web"
    CLOUD = "cloud"
    ONPREM = "onprem"
    MOBILE = "mobile"
    MULTITENANT = "multitenant"            # SaaS / multi-tenant deployment
    API = "api"                            # exposes an API surface


class AICapability(str, Enum):
    """The AI-capability facet. Tiered by autonomy: each higher tier inherits
    the controls of the tier below (see `catalog.resolver.AI_INHERITS`)."""

    NONE = "none"
    LLM = "llm"
    LLM_TOOLS = "llm_tools"
    MCP = "mcp"
    AGENTIC = "agentic"
    GENERATIVE = "generative"


class Stride(str, Enum):
    SPOOFING = "Spoofing"
    TAMPERING = "Tampering"
    REPUDIATION = "Repudiation"
    INFO_DISCLOSURE = "InformationDisclosure"
    DOS = "DenialOfService"
    ELEVATION = "ElevationOfPrivilege"


class DataClassification(str, Enum):
    PUBLIC = "Public"
    INTERNAL = "Internal"
    CONFIDENTIAL = "Confidential"
    RESTRICTED = "Restricted"


class ControlStatus(str, Enum):
    IMPLEMENTED = "implemented"
    PARTIAL = "partial"
    NOT_PRESENT = "not_present"
    UNKNOWN = "unknown"        # absence of evidence — NEVER conflate with not_present
    NOT_APPLICABLE = "n_a"


class Provenance(str, Enum):
    DIAGRAM_VISION = "diagram_vision"
    DESCRIPTION = "description"
    DECLARED = "declared"
    VERIFIED = "verified"


class Confidence(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class Expectation(str, Enum):
    REQUIRED = "required"
    RECOMMENDED = "recommended"
    CONDITIONAL = "conditional"


class Priority(str, Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"


# --------------------------------------------------------------------------- #
# Framework / compliance references
# --------------------------------------------------------------------------- #
class ThreatFrameworkRef(BaseModel):
    """Where a control's threat lineage comes from (OWASP LLM/ASI/MCP, ATLAS…).
    `version` is mandatory because these lists move fast — the MCP Top 10 is
    still beta, the Agentic Top 10 only landed in Dec 2025."""

    framework: str
    ref: str
    version: str


class PciRef(BaseModel):
    """The only compliance regime wired in for now: PCI DSS v4.0.1.

    NOTE FOR CATALOG OWNERS: the requirement IDs shipped in the seed catalog are
    *illustrative* mappings. Validate them against the official PCI DSS v4.0.1
    document before relying on the compliance view for an assessment.
    """

    requirement: str
    version: str = "4.0.1"
    note: Optional[str] = None

    @field_validator("requirement")
    @classmethod
    def _well_formed(cls, v: str) -> str:
        parts = v.split(".")
        if not parts or not all(p.isdigit() for p in parts):
            raise ValueError(
                f"PCI requirement must be dotted numerics (e.g. '8.3.6'), got {v!r}"
            )
        return v


# --------------------------------------------------------------------------- #
# Catalog control
# --------------------------------------------------------------------------- #
class Control(BaseModel):
    id: str
    title: str
    intent: str
    guidance: Optional[str] = None        # plain-language detail for app teams / PMs
    layers: list[Layer] = Field(min_length=1)
    stride: list[Stride] = Field(min_length=1)
    assessment_signal: str                       # the question used to judge presence
    threat_frameworks: list[ThreatFrameworkRef] = Field(default_factory=list)
    pci: list[PciRef] = Field(default_factory=list)        # empty = no PCI lineage
    default_expectation: Expectation = Expectation.REQUIRED
    detect_keywords: list[str] = Field(default_factory=list)  # for the offline text detector
    notes: Optional[str] = None

    model_config = {"extra": "forbid"}            # typo in a YAML key -> hard fail


# --------------------------------------------------------------------------- #
# Application under review
# --------------------------------------------------------------------------- #
class AppProfile(BaseModel):
    name: str
    platforms: list[PlatformFacet] = Field(min_length=1)
    ai_capabilities: list[AICapability] = Field(default_factory=lambda: [AICapability.NONE])
    data_classification: DataClassification = DataClassification.INTERNAL
    handles_cardholder_data: bool = False         # the single PCI in-scope gate


# --------------------------------------------------------------------------- #
# Implemented-controls ledger (the evidence path's output)
# --------------------------------------------------------------------------- #
class LedgerEntry(BaseModel):
    control_id: str
    status: ControlStatus
    provenance: Provenance
    confidence: Confidence
    evidence: Optional[str] = None


class ObservedControl(BaseModel):
    """A control the app appears to implement that matches NO catalog control.
    Nothing is dropped: every observed control either matches the catalog or
    lands here for the out-of-catalog handler to judge."""

    name: str
    description: str
    provenance: Provenance = Provenance.DECLARED
    evidence: Optional[str] = None


class ImplementedLedger(BaseModel):
    entries: list[LedgerEntry] = Field(default_factory=list)
    observed_unmatched: list[ObservedControl] = Field(default_factory=list)

    def by_control(self) -> dict[str, LedgerEntry]:
        # Last write wins — merge_ledger() is responsible for ordering so that
        # higher-trust provenance (declared/verified) is applied last.
        return {e.control_id: e for e in self.entries}


# --------------------------------------------------------------------------- #
# Gap (deterministic core output)
# --------------------------------------------------------------------------- #
class GapItem(BaseModel):
    control: Control
    status: ControlStatus
    pci_exposed: list[PciRef] = Field(default_factory=list)
    compensating_notes: list[str] = Field(default_factory=list)

    @property
    def is_finding(self) -> bool:
        """A weak/missing control is a finding. UNKNOWN is NOT a finding — it is
        a clarification. This single rule is the spine of 'unknown != missing'."""
        return self.status in (ControlStatus.NOT_PRESENT, ControlStatus.PARTIAL)


# --------------------------------------------------------------------------- #
# Out-of-catalog assessment + catalog evolution
# --------------------------------------------------------------------------- #
class OutOfCatalogAssessment(BaseModel):
    observed: ObservedControl
    relevant: bool
    stride: list[Stride] = Field(default_factory=list)
    compensating: bool = False
    suggested_framework: Optional[str] = None
    suggested_layer: Optional[Layer] = None
    rationale: str = ""


class CatalogCandidate(BaseModel):
    """Lightweight 'keep for later' flag. Carries just enough context that a
    catalog owner can promote it in a minute rather than reverse-engineering
    what it was. No triage queue — the flag plus context IS the mechanism."""

    title: str
    description: str
    stride: list[Stride] = Field(default_factory=list)
    suggested_framework: Optional[str] = None
    suggested_layer: Optional[Layer] = None
    source_evidence: Optional[str] = None


# --------------------------------------------------------------------------- #
# Artifacts
# --------------------------------------------------------------------------- #
class Threat(BaseModel):
    id: str
    stride: Stride
    title: str
    description: str
    enabling_gap: Optional[str] = None            # control id whose gap enables this
    framework_ref: Optional[str] = None


class Recommendation(BaseModel):
    control_id: str
    title: str
    action: str
    frameworks: list[str] = Field(default_factory=list)


class Mitigation(BaseModel):
    threat_id: str
    action: str
    addresses_control: Optional[str] = None
    note: Optional[str] = None


class DreadScore(BaseModel):
    threat_id: str
    damage: int = Field(ge=1, le=10)
    reproducibility: int = Field(ge=1, le=10)
    exploitability: int = Field(ge=1, le=10)
    affected_users: int = Field(ge=1, le=10)
    discoverability: int = Field(ge=1, le=10)

    @computed_field
    @property
    def average(self) -> float:
        return round(
            (self.damage + self.reproducibility + self.exploitability
             + self.affected_users + self.discoverability) / 5.0, 2)

    @computed_field
    @property
    def priority(self) -> Priority:
        a = self.average
        if a >= 7.5:
            return Priority.CRITICAL
        if a >= 6.0:
            return Priority.HIGH
        if a >= 4.0:
            return Priority.MEDIUM
        return Priority.LOW


# --------------------------------------------------------------------------- #
# PCI compliance view
# --------------------------------------------------------------------------- #
class PciExposure(BaseModel):
    control_id: str
    control_title: str
    status: ControlStatus
    requirements: list[PciRef]


class PciComplianceView(BaseModel):
    in_scope: bool
    exposed: list[PciExposure] = Field(default_factory=list)        # weak/missing
    indeterminate: list[PciExposure] = Field(default_factory=list)  # unknown -> verify
    covered_count: int = 0


# --------------------------------------------------------------------------- #
# Final assembled report
# --------------------------------------------------------------------------- #
class ThreatModelReport(BaseModel):
    profile: AppProfile
    resolved_control_count: int
    gap_items: list[GapItem]
    clarifications: list[str] = Field(default_factory=list)
    threats: list[Threat] = Field(default_factory=list)
    recommendations: list[Recommendation] = Field(default_factory=list)
    mitigations: list[Mitigation] = Field(default_factory=list)
    dread: list[DreadScore] = Field(default_factory=list)
    pci_view: PciComplianceView = Field(default_factory=lambda: PciComplianceView(in_scope=False))
    candidates: list[CatalogCandidate] = Field(default_factory=list)
    compensating: list[OutOfCatalogAssessment] = Field(default_factory=list)
