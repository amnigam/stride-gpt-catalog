"""
threatcatalog.architecture
==========================

The architecture summary threats are built on, and the completeness checklist
for review-page inputs. Both are returned by calls the flows already make (the
SAD assessment call, and the review page's Detect call), so they add no model
calls. Everything here is parsing and shaping; nothing changes a control status.
"""

from __future__ import annotations

from typing import Any

from .models import ArchitectureSummary, CompletenessItem, RubricScore

_LIST_LIMIT = 15
_ITEM_LIMIT = 200

# The JSON shape both prompts ask for (kept in one place so they stay identical).
ARCH_SHAPE = ('"architecture": {"components": [..], "entry_points": [..], "data_stores": [..], '
              '"external_integrations": [..], "data_flows": [..], "trust_boundaries": [..], '
              '"exposure": string}')
ARCH_RULES = ("architecture: a factual summary of the system as described, for building "
              "threats. Each list holds short phrases (at most 15 items, 20 words each), "
              "naming components as the document does. entry_points: where users, partners or "
              "other systems send input in. data_stores: where data rests. data_flows: "
              "'<from> -> <to>: <what>'. trust_boundaries: where trust changes (internet to "
              "edge, app to database, tenant to tenant, app to third party). exposure: one "
              "sentence on who can reach the system and how they sign in. Use [] or null for "
              "what the document does not describe; never invent components.")


def _str_list(v: Any) -> list[str]:
    if isinstance(v, str):
        v = [v]
    if not isinstance(v, list):
        return []
    out = []
    for x in v:
        if isinstance(x, dict):                      # tolerate {"name": ..} items
            x = x.get("name") or x.get("description") or ""
        x = " ".join(str(x).split())
        if x and x not in out:
            out.append(x[:_ITEM_LIMIT])
    return out[:_LIST_LIMIT]


def parse_architecture(raw: Any) -> ArchitectureSummary | None:
    """Normalise the model's architecture object. None when it is absent or empty,
    so a report can say plainly that threats rest on the control gaps alone."""
    if not isinstance(raw, dict):
        return None
    exp = raw.get("exposure")
    a = ArchitectureSummary(
        components=_str_list(raw.get("components")),
        entry_points=_str_list(raw.get("entry_points")),
        data_stores=_str_list(raw.get("data_stores")),
        external_integrations=_str_list(raw.get("external_integrations")),
        data_flows=_str_list(raw.get("data_flows")),
        trust_boundaries=_str_list(raw.get("trust_boundaries")),
        exposure=(" ".join(str(exp).split())[:_ITEM_LIMIT] or None) if isinstance(exp, str) else None)
    return None if a.empty else a


def parse_input_completeness(raw: Any, has_diagram: bool) -> list[CompletenessItem]:
    """The SAD completeness checklist applied to a review-page description and its
    diagrams. Warns only: nothing here stops a run. Empty when the model returned
    nothing usable (the report then says the check was not run)."""
    from .sad import RUBRIC
    if not isinstance(raw, list):
        return []
    scored = {}
    for r in raw:
        if isinstance(r, dict) and isinstance(r.get("id"), str):
            scored[r["id"]] = r
    if not scored:
        return []
    items = []
    for spec in RUBRIC:
        r = scored.get(spec["id"], {})
        sc = str(r.get("score") or "missing").lower()
        score = RubricScore(sc) if sc in {x.value for x in RubricScore} else RubricScore.MISSING
        comment = r.get("comment") if isinstance(r.get("comment"), str) else None
        if spec["id"] not in scored:
            comment = comment or "Not assessed by the model; treated as missing."
        if spec["id"] == "diagram" and not has_diagram:
            score, comment = RubricScore.MISSING, "No architecture diagram was uploaded."
        ev = r.get("evidence") if isinstance(r.get("evidence"), str) else None
        items.append(CompletenessItem(id=spec["id"], title=spec["title"], score=score,
                                      hard_minimum=spec["hard_minimum"], evidence=ev,
                                      comment=comment))
    return items
