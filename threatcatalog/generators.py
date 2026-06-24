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

from .models import (AppProfile, ControlStatus, DataClassification, DreadScore,
                     GapItem, LedgerEntry, Mitigation, ObservedControl,
                     OutOfCatalogAssessment, Recommendation, Stride, Threat)


@runtime_checkable
class ArtifactEngine(Protocol):
    def extract_controls(self, expected, diagram_image: bytes | None = None,
                         diagram_media_type: str = "image/png") -> list[LedgerEntry]: ...
    def generate_threats(self, gap: list[GapItem], profile: AppProfile) -> list[Threat]: ...
    def generate_recommendations(self, gap: list[GapItem], profile: AppProfile) -> list[Recommendation]: ...
    def generate_mitigations(self, threats: list[Threat], gap: list[GapItem],
                             profile: AppProfile,
                             compensating: list[OutOfCatalogAssessment]) -> list[Mitigation]: ...
    def score_dread(self, threats: list[Threat], gap: list[GapItem],
                    profile: AppProfile) -> list[DreadScore]: ...
    def judge_out_of_catalog(self, observed: ObservedControl,
                             profile: AppProfile) -> OutOfCatalogAssessment: ...


def _clamp(n: int) -> int:
    return max(1, min(10, n))


def _gap_by_control(gap: list[GapItem]) -> dict[str, GapItem]:
    return {gi.control.id: gi for gi in gap}


class DeterministicArtifactEngine:
    """Offline, rules-based engine. Outputs are stable and assertable."""

    # ---- evidence path (no vision offline) ----
    def extract_controls(self, expected, diagram_image=None,
                         diagram_media_type="image/png") -> list[LedgerEntry]:
        return []  # offline: no vision; the pipeline uses the text detector + declaration

    # ---- threats ----
    def generate_threats(self, gap: list[GapItem], profile: AppProfile) -> list[Threat]:
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

    # ---- DREAD (gap-state modulates the score) ----
    def score_dread(self, threats, gap, profile) -> list[DreadScore]:
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
            # compensating offset, if any was annotated on the gap item
            if gi and gi.compensating_notes:
                e -= 2
                d -= 2
            scores.append(DreadScore(
                threat_id=t.id, damage=_clamp(d), reproducibility=_clamp(r),
                exploitability=_clamp(e), affected_users=_clamp(a),
                discoverability=_clamp(disc)))
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
