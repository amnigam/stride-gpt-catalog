"""
threatcatalog.declaration
=========================

The reviewed Control Declaration: one row per expected control, holding the
final status plus a `ControlEvidence` note. This module is the pure logic behind
the declaration form, kept out of the Streamlit file so it is testable:

* `apply_detection` writes AI suggestions into rows WITHOUT clobbering anything a
  reviewer has already touched (re-running Detect is safe).
* `apply_edit` records a reviewer's change with their name and a UTC timestamp,
  while the AI's original suggestion stays untouched in `ai_*`.
* `evidence_basis` answers "what does this status rest on?" for the report.
* `needs_note` is the soft prompt: rows where a reviewer note is expected but
  missing. It never blocks a run.
* `to_ledger` turns rows into `LedgerEntry`s for the pipeline.
* `export_json` / `import_json` persist a declaration between sessions and ARB rounds.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone

from pydantic import BaseModel, Field

from .models import (Confidence, Control, ControlEvidence, ControlStatus,
                     EvidenceBasis, LedgerEntry, Provenance)

_WEAK = (ControlStatus.PARTIAL, ControlStatus.NOT_PRESENT)
_EXPORT_VERSION = 1


class DeclarationRow(BaseModel):
    control_id: str
    status: ControlStatus = ControlStatus.UNKNOWN
    evidence: ControlEvidence = Field(default_factory=ControlEvidence)


def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def ensure_rows(rows: dict[str, DeclarationRow], expected: list[Control]) -> dict[str, DeclarationRow]:
    """Add a blank row for any expected control that has none. Rows for controls
    no longer expected (facets changed) are kept, just not shown or used."""
    for c in expected:
        rows.setdefault(c.id, DeclarationRow(control_id=c.id))
    return rows


def touched(row: DeclarationRow) -> bool:
    """Has a reviewer done anything to this row?"""
    ev = row.evidence
    return bool(ev.reviewed or ev.reviewer or ev.note_edited or row.status != (ev.ai_status or ControlStatus.UNKNOWN))


def apply_detection(rows: dict[str, DeclarationRow], detected: list[LedgerEntry],
                    expected: list[Control]) -> dict[str, DeclarationRow]:
    """Write AI suggestions into the rows. Untouched rows take the AI's status and
    note; touched rows keep the reviewer's status and note, but their `ai_*`
    fields are refreshed so the report still shows what the AI now claims."""
    ensure_rows(rows, expected)
    by_id = {e.control_id: e for e in detected}
    for c in expected:
        row = rows[c.id]
        was_touched = touched(row)
        e = by_id.get(c.id)
        ev = row.evidence
        if e is not None:
            d = e.detail or ControlEvidence(ai_note=e.evidence)
            ev.ai_status = e.status
            ev.ai_confidence = e.confidence
            ev.ai_source = d.ai_source or e.provenance.value
            ev.ai_note = d.ai_note or e.evidence
            ev.ai_quote = d.ai_quote
            ev.quote_verified = d.quote_verified
        else:
            ev.ai_status = None
            ev.ai_confidence = None
            ev.ai_source = None
            ev.ai_note = None
            ev.ai_quote = None
            ev.quote_verified = None
        if not was_touched:
            row.status = ev.ai_status or ControlStatus.UNKNOWN
            ev.note = ev.ai_note          # empty box when there is no evidence
    return rows


def apply_edit(row: DeclarationRow, status: ControlStatus, note: str | None,
               reviewed: bool, reviewer: str | None, now: str | None = None) -> bool:
    """Apply what the reviewer entered for one row. Returns True if anything
    changed. Editing the status or the note counts as reviewing the row."""
    note = (note or "").strip() or None
    ev = row.evidence
    status_changed = status != row.status
    note_changed = (note or "") != (ev.note or "").strip()
    reviewed_changed = reviewed != ev.reviewed
    if not (status_changed or note_changed or reviewed_changed):
        return False
    row.status = status
    ev.note = note
    ev.reviewed = reviewed if reviewed_changed else (reviewed or status_changed or note_changed)
    ev.reviewer = (reviewer or "").strip() or ev.reviewer or "unnamed reviewer"
    ev.reviewed_at = now or _now()
    return True


def evidence_basis(status: ControlStatus, ev: ControlEvidence | None) -> EvidenceBasis | None:
    """What the final status rests on. None when there is nothing to say (an
    untouched unknown control with no AI suggestion)."""
    if ev is None:
        return None
    if ev.ai_status is None:
        if status == ControlStatus.UNKNOWN and not (ev.reviewed or ev.reviewer_note):
            return None
        return EvidenceBasis.REVIEWER_ONLY
    if status != ev.ai_status:
        return EvidenceBasis.REVIEWER_OVERRIDE
    if ev.reviewed or ev.reviewer:
        return EvidenceBasis.AI_CONFIRMED
    return EvidenceBasis.AI_UNREVIEWED


BASIS_LABEL = {
    EvidenceBasis.AI_UNREVIEWED: "AI (not reviewed)",
    EvidenceBasis.AI_CONFIRMED: "AI, reviewer confirmed",
    EvidenceBasis.REVIEWER_OVERRIDE: "Reviewer override",
    EvidenceBasis.REVIEWER_ONLY: "Reviewer",
}


def needs_note(row: DeclarationRow) -> str | None:
    """Soft prompt: why this row should carry a reviewer note, or None. A reviewer
    override needs the reviewer's own words; a weak status needs some note."""
    ev = row.evidence
    if ev.ai_status is not None and row.status != ev.ai_status and not ev.reviewer_note:
        return "status changed from the AI's suggestion without a reviewer note"
    if row.status in _WEAK and not (ev.note or "").strip():
        return f"marked {row.status.value.replace('_', ' ')} without a note"
    if ev.ai_status is None and row.status != ControlStatus.UNKNOWN and not ev.reviewer_note:
        return "declared without AI evidence and without a reviewer note"
    return None


def to_ledger(rows: dict[str, DeclarationRow], expected: list[Control]) -> list[LedgerEntry]:
    """Rows -> ledger entries for the pipeline. An unknown row is still passed
    when it carries evidence, so a reviewer can downgrade an AI 'implemented' to
    'unknown' and have it stick. Unreviewed AI suggestions keep the AI's own
    provenance and confidence; reviewed rows become DECLARED / HIGH."""
    out: list[LedgerEntry] = []
    for c in expected:
        row = rows.get(c.id)
        if row is None:
            continue
        ev = row.evidence
        basis = evidence_basis(row.status, ev)
        if row.status == ControlStatus.UNKNOWN and basis is None and ev.ai_status is None:
            continue
        if basis == EvidenceBasis.AI_UNREVIEWED:
            prov = (Provenance.DIAGRAM_VISION if ev.ai_source == "diagram"
                    else Provenance.DESCRIPTION)
            conf = ev.ai_confidence or Confidence.LOW
        else:
            prov, conf = Provenance.DECLARED, Confidence.HIGH
        out.append(LedgerEntry(control_id=c.id, status=row.status, provenance=prov,
                               confidence=conf, evidence=ev.note,
                               detail=ev.model_copy()))
    return out


def export_json(rows: dict[str, DeclarationRow], meta: dict | None = None) -> str:
    return json.dumps({"format": "threatcatalog.declaration", "version": _EXPORT_VERSION,
                       "saved_at": _now(), **(meta or {}),
                       "rows": [r.model_dump(mode="json") for r in rows.values()]}, indent=2)


def import_json(text: str | bytes) -> tuple[dict[str, DeclarationRow], dict]:
    """Parse an exported declaration. Returns (rows, meta). Raises ValueError on a
    file that is not a declaration export."""
    data = json.loads(text)
    if not isinstance(data, dict) or data.get("format") != "threatcatalog.declaration":
        raise ValueError("not a threatcatalog declaration export")
    rows = {}
    for r in data.get("rows", []):
        row = DeclarationRow.model_validate(r)
        rows[row.control_id] = row
    meta = {k: v for k, v in data.items() if k not in ("rows",)}
    return rows, meta
