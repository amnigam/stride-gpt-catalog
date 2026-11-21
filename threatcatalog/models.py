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
    PLATFORM_MESSAGING = "platform.messaging"  # event bus / queue / file-transfer integrations
    PLATFORM_CONTAINER = "platform.container"  # containers and Kubernetes
    AI_LLM = "ai.llm"
    AI_LLM_TOOLS = "ai.llm_tools"
    AI_MCP = "ai.mcp"
    AI_AGENTIC = "ai.agentic"
    AI_GENERATIVE = "ai.generative"
    AI_TRAINING = "ai.training"            # app trains or fine-tunes its own models


class PlatformFacet(str, Enum):
    WEB = "web"
    CLOUD = "cloud"
    ONPREM = "onprem"
    MOBILE = "mobile"
    MULTITENANT = "multitenant"            # SaaS / multi-tenant deployment
    API = "api"                            # exposes an API surface
    MESSAGING = "messaging"                # uses an event bus, queue or batch file transfer
    CONTAINER = "container"                # runs on containers / Kubernetes


class AICapability(str, Enum):
    """The AI-capability facet. Tiered by autonomy: each higher tier inherits
    the controls of the tier below (see `catalog.resolver.AI_INHERITS`)."""

    NONE = "none"
    LLM = "llm"
    LLM_TOOLS = "llm_tools"
    MCP = "mcp"
    AGENTIC = "agentic"
    GENERATIVE = "generative"
    TRAINING = "training"                  # trains or fine-tunes models on its own data


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
class EvidenceBasis(str, Enum):
    """What a control's final status rests on — the audit answer to 'who said so?'."""
    AI_UNREVIEWED = "ai_unreviewed"          # AI suggestion, no human has looked at it
    AI_CONFIRMED = "ai_confirmed"            # AI suggestion a reviewer confirmed
    REVIEWER_OVERRIDE = "reviewer_override"  # reviewer changed the AI's status
    REVIEWER_ONLY = "reviewer_only"          # no AI suggestion; reviewer declared it


class ControlEvidence(BaseModel):
    """Per-control evidence note. The AI's original suggestion (`ai_*`) is kept
    verbatim and never overwritten by a reviewer; `note` is the editable box the
    reviewer sees, pre-filled with the AI's rationale. The report shows both when
    they differ, so the ARB can see what the AI claimed and what a human changed."""

    ai_status: Optional[ControlStatus] = None
    ai_confidence: Optional[Confidence] = None
    ai_source: Optional[str] = None          # "description" | "diagram" | "keyword"
    ai_note: Optional[str] = None            # the AI's rationale, as first written
    ai_quote: Optional[str] = None           # verbatim excerpt / diagram element cited
    quote_verified: Optional[bool] = None    # description quotes are checked against the text
    # what the AI's status rests on in a SAD run: "stated" in the SAD, "inferred" from it,
    # or "silent" (the SAD never mentions the control). None outside SAD runs and in
    # declarations saved before this field existed (the report falls back to the note).
    ai_basis: Optional[str] = None
    # second-opinion check (same model): does the cited quote actually back ai_status?
    # False flags the row for the reviewer; it never changes the status
    quote_supports: Optional[bool] = None
    support_note: Optional[str] = None       # why the check says the quote falls short
    note: Optional[str] = None               # current content of the editable box
    reviewed: bool = False
    reviewer: Optional[str] = None
    reviewed_at: Optional[str] = None        # ISO-8601 UTC of the reviewer's last change

    @property
    def note_edited(self) -> bool:
        """True when the box no longer holds the AI's original text."""
        return (self.note or "").strip() != (self.ai_note or "").strip()

    @property
    def reviewer_note(self) -> Optional[str]:
        """The reviewer's own words, if they changed the box."""
        n = (self.note or "").strip()
        return n if (n and self.note_edited) else None


class LedgerEntry(BaseModel):
    control_id: str
    status: ControlStatus
    provenance: Provenance
    confidence: Confidence
    evidence: Optional[str] = None
    detail: Optional[ControlEvidence] = None   # AI rationale + reviewer note, when present


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
    evidence: Optional[ControlEvidence] = None
    basis: Optional[EvidenceBasis] = None

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
# SAD (solution architecture document) assessment context
# --------------------------------------------------------------------------- #
class RubricScore(str, Enum):
    PRESENT = "present"
    THIN = "thin"
    MISSING = "missing"


class CompletenessItem(BaseModel):
    """One line of the SAD completeness rubric, as scored for this document."""

    id: str
    title: str
    score: RubricScore
    hard_minimum: bool = False
    evidence: Optional[str] = None           # quote / section / diagram the score relied on
    comment: Optional[str] = None            # what is missing or thin


class FacetReason(BaseModel):
    """Why a profile facet was (or was not) selected from the SAD."""

    facet: str                               # e.g. "platform:web", "ai:mcp", "data:Confidential", "pci"
    selected: bool
    reason: str = ""
    quote: Optional[str] = None
    assumed: bool = False                    # not stated outright: inferred, keyword-only or a default
    source: str = "llm"                      # llm | default | reviewer (keyword, llm+keyword: older reports)


class SadContext(BaseModel):
    """What a SAD-driven report rests on: the document, the completeness result,
    the inferred profile and the rules applied. Rendered at the top of the report."""

    source_file: str
    sha256: str
    pages: Optional[int] = None
    pages_estimated: bool = False
    words: int = 0
    diagrams_read: list[str] = Field(default_factory=list)
    diagrams_skipped: list[str] = Field(default_factory=list)
    engine: str = ""
    document_title: Optional[str] = None
    document_version: Optional[str] = None
    completeness: list[CompletenessItem] = Field(default_factory=list)
    facets: list[FacetReason] = Field(default_factory=list)
    profile_confirmed_by: Optional[str] = None
    notes: list[str] = Field(default_factory=list)
    generated_at: Optional[str] = None
    # controls the SAD describes that are not in the catalog (carried to the review page)
    other_controls: list[ObservedControl] = Field(default_factory=list)
    # set when the SAD declaration was loaded on the review page and run from there:
    # the statuses are then the reviewer's, not purely automated
    reviewed: bool = False
    reviewed_by: Optional[str] = None


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
    sad: Optional[SadContext] = None          # set when the report was generated from a SAD
    diagrams_read: list[str] = Field(default_factory=list)     # main page: diagrams Detect read
    diagrams_skipped: list[str] = Field(default_factory=list)  # main page: uploads not read, and why
    # document control (set by pipeline.run; optional so older report objects still render)
    generated_at: Optional[str] = None
    tool_version: Optional[str] = None
    catalog_version: Optional[str] = None
    # assessment basis for review-page runs (the SAD record covers SAD runs)
    description_words: Optional[int] = None
    engine: Optional[str] = None
