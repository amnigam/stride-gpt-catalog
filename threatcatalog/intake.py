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

import re

from .models import (Confidence, Control, ControlEvidence, ControlStatus, ImplementedLedger,
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
                note = (f"Keyword match: '{kw}' appears in the description. A keyword is a "
                        f"weak signal; confirm the control is actually in place.")
                out.append(LedgerEntry(
                    control_id=c.id, status=ControlStatus.IMPLEMENTED,
                    provenance=Provenance.DESCRIPTION, confidence=Confidence.LOW,
                    evidence=f"matched '{kw}' in description",
                    detail=ControlEvidence(
                        ai_status=ControlStatus.IMPLEMENTED, ai_confidence=Confidence.LOW,
                        ai_source="keyword", ai_note=note, note=note,
                        ai_quote=_sentence_with(text, kw), quote_verified=True)))
                break
    return out


def _sentence_with(text: str, kw: str, limit: int = 240) -> str:
    """The sentence (or line) of `text` containing `kw`, trimmed — the excerpt a
    reviewer needs to judge the match without rereading the whole description."""
    i = text.lower().find(kw.lower())
    if i < 0:
        return kw
    start = max(text.rfind(".", 0, i), text.rfind("\n", 0, i)) + 1
    ends = [j for j in (text.find(".", i), text.find("\n", i)) if j >= 0]
    end = min(ends) + 1 if ends else len(text)
    s = " ".join(text[start:end].split())
    return s if len(s) <= limit else s[:limit - 1] + "\u2026"


# Bullet glyphs (PDF Symbol/Wingdings bullets come through as Private Use Area
# characters such as U+F0B7) and page markers sit between sentences in an
# extracted SAD but never in a quote, so they must not break the match.
_NOISE = re.compile(r"[\ue000-\uf8ff\u2022\u2023\u2043\u25aa\u25ab\u25cf\u25cb\u25e6\u25a0\u25a1]"
                    r"|--- Page \d+ ---"
                    r"|^[ \t]*(?:[-*+]|\d{1,2}[.)])[ \t]+", re.M)   # list markers at line start


def _norm(s: str) -> str:
    s = _NOISE.sub(" ", s)
    return " ".join(s.lower().replace("\u2019", "'").replace("\u201c", '"')
                    .replace("\u201d", '"').split()).strip(" .\"'\u2026")


def quote_in_text(quote: str | None, text: str) -> bool:
    """Is an AI-cited quote really in the description? Whitespace/case/quote-mark
    insensitive. A cheap guard against the model inventing evidence."""
    if not quote or not text:
        return False
    q = _norm(quote)
    if not q:
        return False
    if q in _norm(text):
        return True
    # tolerate an elided middle ("... foo ... bar ...") by checking each fragment
    parts = [p for p in (_norm(x) for x in quote.replace("\u2026", "...").split("...")) if len(p) >= 12]
    return bool(parts) and all(p in _norm(text) for p in parts)


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
