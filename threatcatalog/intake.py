"""
threatcatalog.intake
====================

The evidence path's deterministic plumbing. Two evidence sources only — the
architecture diagram and the description-plus-declaration step. There is NO
code scanning: this tool asks whether enterprise controls are in place, which
is the wrong question to answer by reading source.

* `declaration_template` turns the resolved catalog into a questionnaire — each
  control's `assessment_signal` is one question.
* `detect_from_text` is a conservative keyword detector over the description
  (and any diagram-vision text). It only ever proposes `IMPLEMENTED` with LOW
  confidence — it never asserts `NOT_PRESENT`, because absence of a keyword is
  not evidence of absence.
* `merge_ledger` combines detection with declaration so that higher-trust
  declared/verified statuses win.

The vision extractor (LLM) feeds this same path: its output is just more
`LedgerEntry` rows with `provenance=diagram_vision`. It lives behind the LLM
seam (see `generators.ArtifactEngine.extract_controls`) so the deterministic
pipeline runs without it.
"""

from __future__ import annotations

from .models import (Confidence, Control, ControlStatus, ImplementedLedger,
                     LedgerEntry, ObservedControl, Provenance)


def declaration_template(expected: list[Control]) -> list[dict]:
    """One question per expected control, for the architect to answer."""
    return [{"control_id": c.id, "title": c.title, "question": c.assessment_signal,
             "default_expectation": c.default_expectation.value} for c in expected]


def detect_from_text(text: str, expected: list[Control]) -> list[LedgerEntry]:
    """Conservative detector: proposes IMPLEMENTED (low confidence) when a
    control's keywords appear in the text. Never proposes NOT_PRESENT."""
    if not text:
        return []
    haystack = text.lower()
    out: list[LedgerEntry] = []
    for c in expected:
        for kw in c.detect_keywords:
            if kw.lower() in haystack:
                out.append(LedgerEntry(
                    control_id=c.id, status=ControlStatus.IMPLEMENTED,
                    provenance=Provenance.DESCRIPTION, confidence=Confidence.LOW,
                    evidence=f"matched '{kw}' in description"))
                break
    return out


# Trust ordering — later (higher) wins when both sources speak to a control.
_PROVENANCE_RANK = {
    Provenance.DESCRIPTION: 0,
    Provenance.DIAGRAM_VISION: 1,
    Provenance.DECLARED: 2,
    Provenance.VERIFIED: 3,
}


def merge_ledger(*sources: list[LedgerEntry],
                 observed_unmatched: list[ObservedControl] | None = None
                 ) -> ImplementedLedger:
    """Merge entries from multiple sources; the highest-trust provenance wins
    per control id. `observed_unmatched` carries controls that matched nothing
    in the catalog (for the out-of-catalog handler)."""
    best: dict[str, LedgerEntry] = {}
    for source in sources:
        for entry in source:
            cur = best.get(entry.control_id)
            if cur is None or _PROVENANCE_RANK[entry.provenance] >= _PROVENANCE_RANK[cur.provenance]:
                best[entry.control_id] = entry
    return ImplementedLedger(entries=list(best.values()),
                             observed_unmatched=list(observed_unmatched or []))
