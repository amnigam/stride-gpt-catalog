"""
threatcatalog.pipeline
======================

End-to-end orchestration. Wires the two paths together:

    facets ─► resolve ─► expected controls ┐
                                           ├─► gap engine ─► artifacts + PCI ─► report
    diagram + description + declaration ───┘            (out-of-catalog feeds in)

The pipeline is engine-agnostic: pass `DeterministicArtifactEngine()` for an
offline run or `LLMArtifactEngine(...)` for a model-backed one. The gap is
computed deterministically either way.
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone

from . import __version__
from .catalog import Catalog, resolve
from .gap import build_gap
from .generators import ArtifactEngine, DeterministicArtifactEngine, default_actions, action_priority
from .intake import detect_from_text, merge_ledger
from .models import (ActionItem, AppProfile, ArchitectureSummary, Control, ControlStatus, LedgerEntry,
                     ObservedControl, Threat, ThreatModelReport)
from .out_of_catalog import attach_compensating, process_observed
from .pci import build_pci_view


def _clarifications(gap) -> list[str]:
    """UNKNOWN controls become clarifications, not findings. Required and
    PCI-mapped unknowns are listed first — those are the ones worth chasing."""
    unknowns = [gi for gi in gap if gi.status == ControlStatus.UNKNOWN]
    unknowns.sort(key=lambda gi: (0 if gi.control.pci else 1,
                                  0 if gi.control.default_expectation.value == "required" else 1))
    return [f"Confirm whether '{gi.control.title}' is implemented "
            f"({gi.control.assessment_signal})" for gi in unknowns]


def catalog_version(controls: list[Control]) -> str:
    """'123 controls · 1a2b3c4d': a stable fingerprint of the catalog content used,
    so two reports can be told apart when the catalog changed between them."""
    blob = "\n".join(c.model_dump_json() for c in sorted(controls, key=lambda c: c.id))
    return f"{len(controls)} controls \u00b7 {hashlib.sha256(blob.encode()).hexdigest()[:8]}"


def _cover_threats(threats: list[Threat], gap, profile) -> list[Threat]:
    """Keep only links to real findings, give every threat a unique id, and add the
    offline threat for any finding the engine did not cover."""
    findings = {gi.control.id for gi in gap if gi.is_finding}
    out, ids = [], set()
    for t in threats:
        rel = [g for g in t.related_gaps if g in findings and g != t.enabling_gap]
        eg = t.enabling_gap if t.enabling_gap in findings else (rel.pop(0) if rel else None)
        tid = t.id if (t.id and t.id not in ids) else f"T{len(out) + 1}"
        while tid in ids:
            tid = f"T{len(ids) + 1}x"
        ids.add(tid)
        out.append(t.model_copy(update={"id": tid, "enabling_gap": eg, "related_gaps": rel}))
    covered = {g for t in out for g in t.gaps}
    missing = [gi for gi in gap if gi.is_finding and gi.control.id not in covered]
    if missing:
        n = len(out)
        for t in DeterministicArtifactEngine().generate_threats(missing, profile):
            n += 1
            tid = f"T{n}"
            while tid in ids:
                n += 1
                tid = f"T{n}"
            ids.add(tid)
            out.append(t.model_copy(update={"id": tid}))
    return out


def _cover_dread(dread, threats, gap, profile):
    """Keep scores for known threats (first one wins) and score any threat the
    engine skipped with the offline rules, so every threat has a priority."""
    tids = {t.id for t in threats}
    out, seen = [], set()
    for d in dread:
        if d.threat_id in tids and d.threat_id not in seen:
            seen.add(d.threat_id)
            out.append(d)
    rest = [t for t in threats if t.id not in seen]
    if rest:
        out += DeterministicArtifactEngine().score_dread(rest, gap, profile)
    return out


def _cover_actions(actions: list[ActionItem], gap, threats, dread) -> list[ActionItem]:
    """Renumber, keep links to real findings/threats, set priority and timing from
    the DREAD scores (a model's own labels are not kept, so the plan matches Key
    focus items), and add an action for any finding the engine's plan left out."""
    findings = [gi for gi in gap if gi.is_finding]
    fids = {gi.control.id for gi in findings}
    tids = {t.id for t in threats}
    out = []
    for a in actions:
        cids = [c for c in a.control_ids if c in fids]
        ats = [t for t in a.threat_ids if t in tids]
        prio, timing = action_priority(cids, ats, gap, threats, dread)
        out.append(a.model_copy(update={
            "id": f"A{len(out) + 1}", "control_ids": cids, "threat_ids": ats,
            "priority": prio, "timing": timing}))
    covered = {c for a in out for c in a.control_ids}
    missing = [gi for gi in findings if gi.control.id not in covered]
    out += default_actions(missing, threats, dread, start=len(out) + 1)
    return _lift_to_gap_priority(out, findings, threats, dread)


def _lift_to_gap_priority(actions, findings, threats, dread):
    """Each finding's most urgent action must be as urgent as the finding itself
    (its worst threat), so a Critical gap is never left with only a Medium action."""
    from .generators import _PRIO_ORDER
    status = {gi.control.id: gi.status for gi in findings}
    out = list(actions)
    for gi in findings:
        cid = gi.control.id
        need, _ = action_priority([cid], [], findings, threats, dread)
        idx = [i for i, a in enumerate(out) if cid in a.control_ids]
        if not idx:
            continue
        best = min(idx, key=lambda i: _PRIO_ORDER.get(out[i].priority, 9))
        if _PRIO_ORDER.get(out[best].priority, 9) > _PRIO_ORDER[need]:
            missing = any(status.get(c) == ControlStatus.NOT_PRESENT for c in out[best].control_ids)
            timing = ("Before go-live" if need == "Critical" or (need == "High" and missing)
                      else out[best].timing)
            out[best] = out[best].model_copy(update={"priority": need, "timing": timing})
    return out


def run(profile: AppProfile,
        description: str = "",
        declared: list[LedgerEntry] | None = None,
        observed_unmatched: list[ObservedControl] | None = None,
        engine: ArtifactEngine | None = None,
        controls: list[Control] | None = None,
        diagram_image: bytes | None = None,
        diagram_media_type: str = "image/png",
        architecture: ArchitectureSummary | None = None,
        progress=None) -> ThreatModelReport:
    """`progress(msg)`, when given, is called before each step so a UI can show
    where a long run is. It never changes the result."""
    say = progress or (lambda _m: None)
    engine = engine or DeterministicArtifactEngine()
    controls = controls if controls is not None else Catalog.load().controls

    # 1. expected control set
    expected = resolve(profile, controls)

    # 2. implemented ledger (evidence path): text detection + optional vision + declaration
    detected = detect_from_text(description, expected)
    vision = engine.extract_controls(expected, diagram_image, diagram_media_type)
    ledger = merge_ledger(detected, vision, declared or [],
                          observed_unmatched=observed_unmatched or [])

    # 3. deterministic gap
    gap = build_gap(expected, ledger, profile)

    weak = sum(1 for g in gap if g.status not in (ControlStatus.IMPLEMENTED,
                                                ControlStatus.NOT_APPLICABLE))
    say(f"Gap computed: {weak} of {len(expected)} expected controls are not fully implemented.")

    # 4. out-of-catalog: judge, flag candidates, attach compensating notes
    if ledger.observed_unmatched:
        say(f"Judging {len(ledger.observed_unmatched)} control(s) not in the catalog…")
    assessments, candidates = process_observed(ledger.observed_unmatched, engine, profile, expected)
    attach_compensating(gap, assessments)

    # 5. artifacts driven by the gap
    #    (the architecture summary, when there is one, makes them specific to this system;
    #    every finding is still covered by a threat and an action, so nothing is dropped)
    say("Generating threats for each gap…")
    threats = _cover_threats(engine.generate_threats(gap, profile, architecture), gap, profile)
    say(f"Scoring {len(threats)} threat(s) with DREAD…")
    dread = _cover_dread(engine.score_dread(threats, gap, profile, architecture),
                         threats, gap, profile)
    say("Building the action plan…")
    actions = _cover_actions(engine.generate_action_plan(threats, gap, profile, dread,
                                                         architecture), gap, threats, dread)

    # 6. compliance pass (deterministic second read off the same gap)
    say("Running the PCI compliance pass and assembling the report…")
    pci_view = build_pci_view(gap, profile)

    return ThreatModelReport(
        profile=profile, resolved_control_count=len(expected), gap_items=gap,
        clarifications=_clarifications(gap), threats=threats,
        actions=actions, dread=dread, architecture=architecture,
        pci_view=pci_view, candidates=candidates,
        compensating=[a for a in assessments
                      if a.relevant and a.compensating and not a.covered_by],
        covered_elsewhere=[a for a in assessments if a.covered_by],
        generated_at=datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        tool_version=__version__, catalog_version=catalog_version(controls),
        description_words=len(description.split()) if description else 0)
