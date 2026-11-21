"""
threatcatalog.generators
========================

The LLM boundary, abstracted. Everything that *reasons* (threats, recs,
mitigations, DREAD, the out-of-catalog relevance judgement, diagram vision)
sits behind the `ArtifactEngine` protocol. Two implementations:

* `DeterministicArtifactEngine` (this file) derives artifacts from the computed
  gap with explicit rules. It needs no API key, so the pipeline runs and the
  test-suite asserts real behaviour *offline*. It is also a sane fallback.
* `LLMArtifactEngine` (in `llm/engine.py`) builds prompts and calls a real
  model, validating the response against the same Pydantic models.

Because both implement one protocol, the pipeline is identical either way — the
only thing that changes is whether a human-readable narrative or a deterministic
one comes out. The *gap itself* is always deterministic; the engine only shapes
how it is expressed.

Wisdom: a compensating (out-of-catalog) control only ever *softens* a finding
here — it reduces DREAD and annotates the mitigation. It never deletes a threat.
Letting an unverified, non-baseline control erase a finding is how real exposure
gets talked away.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from .models import (ActionItem, AppProfile, ArchitectureSummary, ControlStatus, DataClassification, DreadScore,
                     GapItem, LedgerEntry, Mitigation, ObservedControl,
                     OutOfCatalogAssessment, Recommendation, Stride, Threat)


@runtime_checkable
class ArtifactEngine(Protocol):
    def extract_controls(self, expected, diagram_image: bytes | None = None,
                         diagram_media_type: str = "image/png") -> list[LedgerEntry]: ...
    def detect_controls(self, expected, description: str = "",
                        diagram_image: bytes | None = None,
                        diagram_media_type: str = "image/png") -> list[LedgerEntry]: ...
    def generate_threats(self, gap: list[GapItem], profile: AppProfile,
                         architecture: ArchitectureSummary | None = None) -> list[Threat]: ...
    def generate_action_plan(self, threats: list[Threat], gap: list[GapItem],
                             profile: AppProfile, dread: list[DreadScore],
                             architecture: ArchitectureSummary | None = None) -> list[ActionItem]: ...
    def score_dread(self, threats: list[Threat], gap: list[GapItem], profile: AppProfile,
                    architecture: ArchitectureSummary | None = None) -> list[DreadScore]: ...
    def judge_out_of_catalog(self, observed: ObservedControl,
                             profile: AppProfile) -> OutOfCatalogAssessment: ...


def _clamp(n: int) -> int:
    return max(1, min(10, n))


def default_actions(findings: list[GapItem], threats: list[Threat],
                    dread: list[DreadScore], start: int = 1) -> list[ActionItem]:
    """One action per finding control, from the control's intent. Used offline, and
    to fill in any finding a model's action plan left out (nothing is dropped).
    Priority is the worst DREAD priority of the threats it closes; timing is before
    go-live for Critical, or High on a missing control."""
    by_threat = {d.threat_id: d for d in dread}
    order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
    out = []
    for i, gi in enumerate(findings, start=start):
        tids = [t.id for t in threats if gi.control.id in t.gaps]
        prios = [by_threat[x].priority.value for x in tids if x in by_threat]
        prio = min(prios, key=lambda p: order.get(p, 9)) if prios else "High"
        missing = gi.status == ControlStatus.NOT_PRESENT
        timing = ("Before go-live" if prio == "Critical" or (prio == "High" and missing)
                  else "Within 90 days")
        verb = "Put in place" if missing else "Complete"
        out.append(ActionItem(id=f"A{i}", action=f"{verb}: {gi.control.title}. {gi.control.intent}",
                              threat_ids=tids, control_ids=[gi.control.id], priority=prio,
                              timing=timing))
    return out


def _gap_by_control(gap: list[GapItem]) -> dict[str, GapItem]:
    return {gi.control.id: gi for gi in gap}


class DeterministicArtifactEngine:
    """Offline, rules-based engine. Outputs are stable and assertable."""

    # ---- evidence path (no vision offline) ----
    def extract_controls(self, expected, diagram_image=None,
                         diagram_media_type="image/png") -> list[LedgerEntry]:
        return []  # offline: no vision; the pipeline uses the text detector + declaration

    def detect_controls(self, expected, description: str = "", diagram_image=None,
                        diagram_media_type="image/png") -> list[LedgerEntry]:
        """Offline Detect: keyword matching over the description only."""
        from .intake import detect_from_text
        return detect_from_text(description, expected)

    # ---- threats ----
    def generate_threats(self, gap: list[GapItem], profile: AppProfile,
                         architecture: ArchitectureSummary | None = None) -> list[Threat]:
        # Offline: one threat per gap (no architecture reasoning without a model).
        # not_present first, then partial — i.e. worst gaps surface first.
        findings = sorted([gi for gi in gap if gi.is_finding],
                          key=lambda gi: 0 if gi.status == ControlStatus.NOT_PRESENT else 1)
        threats: list[Threat] = []
        for i, gi in enumerate(findings, start=1):
            c = gi.control
            primary = c.stride[0]
            stride_names = ", ".join(s.value for s in c.stride)
            verb = "is not in place" if gi.status == ControlStatus.NOT_PRESENT else "is only partial"
            fw = c.threat_frameworks[0].ref if c.threat_frameworks else None
            threats.append(Threat(
                id=f"T{i}", stride=primary,
                title=f"{c.title} {verb}",
                description=(f"{c.intent} Because this control {verb}, the application is "
                             f"exposed to {stride_names} risk linked to '{c.title}'."),
                enabling_gap=c.id, framework_ref=fw))
        return threats

    # ---- recommendations (control-centric, gap-closing) ----
    def generate_recommendations(self, gap: list[GapItem], profile: AppProfile) -> list[Recommendation]:
        recs: list[Recommendation] = []
        for gi in gap:
            if not gi.is_finding:
                continue
            c = gi.control
            fws = [f"{f.framework}:{f.ref}" for f in c.threat_frameworks]
            verb = "Adopt" if gi.status == ControlStatus.NOT_PRESENT else "Strengthen"
            recs.append(Recommendation(
                control_id=c.id, title=f"{verb}: {c.title}",
                action=f"{c.intent} Close this gap for an app of this type and data class.",
                frameworks=fws))
        return recs

    # ---- mitigations (threat-specific) ----
    def generate_mitigations(self, threats, gap, profile, compensating) -> list[Mitigation]:
        gbc = _gap_by_control(gap)
        comp_strides: set[Stride] = set()
        comp_names: list[str] = []
        for a in compensating:
            if a.relevant and a.compensating:
                comp_strides.update(a.stride)
                comp_names.append(a.observed.name)
        mitigations: list[Mitigation] = []
        for t in threats:
            gi = gbc.get(t.enabling_gap) if t.enabling_gap else None
            note = None
            if gi and set(gi.control.stride) & comp_strides:
                note = (f"Partially offset by compensating control(s) "
                        f"{', '.join(comp_names)} — unverified, not in baseline.")
            action = (gi.control.intent if gi else
                      "Implement the control that addresses this threat.")
            mitigations.append(Mitigation(
                threat_id=t.id, action=action,
                addresses_control=t.enabling_gap, note=note))
        return mitigations

    # ---- action plan (one action per finding control) ----
    def generate_action_plan(self, threats, gap, profile, dread, architecture=None) -> list[ActionItem]:
        return default_actions([gi for gi in gap if gi.is_finding], threats, dread)

    # ---- DREAD (gap-state modulates the score) ----
    def score_dread(self, threats, gap, profile, architecture=None) -> list[DreadScore]:
        from .report import sad_silent
        gbc = _gap_by_control(gap)
        comp_strides: set[Stride] = set()  # filled by pipeline via mitigations? keep simple: none here
        scores: list[DreadScore] = []
        for t in threats:
            gi = gbc.get(t.enabling_gap) if t.enabling_gap else None
            missing = gi is not None and gi.status == ControlStatus.NOT_PRESENT
            if missing:
                d, r, e, a, disc = 7, 8, 8, 7, 6
            else:  # partial
                d, r, e, a, disc = 5, 6, 6, 6, 5
            if profile.data_classification == DataClassification.RESTRICTED:
                d += 2
            elif profile.data_classification == DataClassification.CONFIDENTIAL:
                d += 1
            if t.stride == Stride.INFO_DISCLOSURE:
                d += 1
            if t.stride == Stride.DOS:
                a += 1
            why = ["control not present" if missing else "control partial"]
            if profile.data_classification in (DataClassification.RESTRICTED,
                                               DataClassification.CONFIDENTIAL):
                why.append(f"{profile.data_classification.value} data")
            if gi and gi.pci_exposed:
                d += 1
                why.append("PCI-mapped")
            if gi and gi.control.default_expectation.value != "required":
                a -= 1
                why.append("recommended, not required")
            if gi and sad_silent(gi):
                r -= 1
                why.append("SAD silent, so unconfirmed")
            # compensating offset, if any was annotated on the gap item
            if gi and gi.compensating_notes:
                e -= 2
                d -= 2
                why.append("compensating control noted")
            scores.append(DreadScore(
                threat_id=t.id, damage=_clamp(d), reproducibility=_clamp(r),
                exploitability=_clamp(e), affected_users=_clamp(a),
                discoverability=_clamp(disc), rationale="Offline rules: " + ", ".join(why) + "."))
        return scores

    # ---- out-of-catalog relevance judgement ----
    def judge_out_of_catalog(self, observed: ObservedControl,
                             profile: AppProfile) -> OutOfCatalogAssessment:
        text = (observed.name + " " + observed.description).lower()
        stride: list[Stride] = []
        if any(k in text for k in ("token", "mask", "encrypt", "redact", "pii", "tokeniz")):
            stride = [Stride.INFO_DISCLOSURE]
        elif any(k in text for k in ("log", "audit")):
            stride = [Stride.REPUDIATION]
        elif any(k in text for k in ("rate", "throttle", "quota")):
            stride = [Stride.DOS]
        relevant = bool(stride)
        return OutOfCatalogAssessment(
            observed=observed, relevant=relevant, stride=stride,
            compensating=relevant,
            suggested_framework=None,
            rationale=("Maps to "
                       + (", ".join(s.value for s in stride) if stride else "no modelled threat")
                       + "; treat as compensating only where it actually applies."))
