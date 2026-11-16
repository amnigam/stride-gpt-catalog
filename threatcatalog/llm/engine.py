"""
threatcatalog.llm.engine
========================

`LLMArtifactEngine` implements the same `ArtifactEngine` protocol as the
deterministic engine, but produces artifacts by prompting a model.

Real models do not return perfectly schema-shaped JSON. GPT-5.2 might send
`enabling_gap` as a `{"control_id": ...}` object, `framework_ref` as a list,
DREAD scores as strings, a STRIDE value with a space in it, or wrap the whole
array in `{"threats": [...]}`. Rather than fail the run on each of these, we
**normalize** every record into our schema first, then validate. Validation is
still the backstop — anything that cannot be coerced to a sane value is rejected
— but harmless shape drift no longer crashes the pipeline.

The diagram-vision extractor lives here too (`extract_controls`); offline runs
simply use `DeterministicArtifactEngine`, whose extractor is a no-op.
"""

from __future__ import annotations

from ..models import (AppProfile, Confidence, ControlEvidence, ControlStatus, DreadScore, GapItem,
                      Layer, LedgerEntry, Mitigation, ObservedControl,
                      OutOfCatalogAssessment, Provenance, Recommendation, Stride,
                      Threat)
from . import prompts
from .provider import RawLLM


# --------------------------------------------------------------------------- #
# Coercion helpers — turn "what the model sent" into "what the schema expects".
# --------------------------------------------------------------------------- #
def _first(v):
    if isinstance(v, list):
        return v[0] if v else None
    return v


def _as_opt_str(v):
    """Best-effort single string, or None. Digs a sensible key out of a dict and
    the first element out of a list."""
    v = _first(v)
    if v is None:
        return None
    if isinstance(v, str):
        return v or None
    if isinstance(v, dict):
        for k in ("control_id", "ref", "id", "name", "value", "title"):
            if isinstance(v.get(k), str):
                return v[k]
        return None
    return str(v)


def _as_str(v, default=""):
    s = _as_opt_str(v)
    return s if s is not None else default


def _as_str_list(v):
    if v is None:
        return []
    if isinstance(v, str):
        return [v] if v else []
    if isinstance(v, list):
        return [s for s in (_as_opt_str(x) for x in v) if s]
    s = _as_opt_str(v)
    return [s] if s else []


def _as_int(v, default=5):
    v = _first(v)
    try:
        return max(1, min(10, int(round(float(v)))))
    except (TypeError, ValueError):
        return default


_STRIDE_ALIASES = {}
for _s in Stride:
    _STRIDE_ALIASES[_s.value.lower().replace(" ", "").replace("_", "")] = _s
_STRIDE_ALIASES.update({
    "infodisclosure": Stride.INFO_DISCLOSURE,
    "informationdisclosure": Stride.INFO_DISCLOSURE,
    "dos": Stride.DOS,
    "denialofservice": Stride.DOS,
    "eop": Stride.ELEVATION,
    "elevationofprivileges": Stride.ELEVATION,
    "privilegeescalation": Stride.ELEVATION,
})


def _coerce_stride(v, default=Stride.TAMPERING):
    s = _as_opt_str(v)
    if not s:
        return default
    return _STRIDE_ALIASES.get(s.lower().replace(" ", "").replace("_", ""), default)


def _coerce_stride_list(v):
    items = v if isinstance(v, list) else ([v] if v else [])
    out = []
    for x in items:
        s = _as_opt_str(x)
        if not s:
            continue
        st = _STRIDE_ALIASES.get(s.lower().replace(" ", "").replace("_", ""))
        if st:
            out.append(st)
    return out


def _coerce_layer(v):
    s = _as_opt_str(v)
    if not s:
        return None
    try:
        return Layer(s)
    except ValueError:
        return None


def _listify(data, *keys):
    """Accept a list, or an object that wraps the list under a known key (or any
    single list value), or a single object that should be wrapped."""
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        for k in keys:
            if isinstance(data.get(k), list):
                return data[k]
        for val in data.values():
            if isinstance(val, list):
                return val
        return [data]
    return []


class LLMArtifactEngine:
    def __init__(self, raw: RawLLM):
        self.raw = raw

    # ---- diagram vision: reports only controls it can SEE, never absence ----
    def extract_controls(self, expected, diagram_image: bytes | None = None,
                         diagram_media_type: str = "image/png") -> list[LedgerEntry]:
        """Diagram-only extraction (pipeline path). Same parser as Detect."""
        if not diagram_image:
            return []
        return self.detect_controls(expected, "", diagram_image, diagram_media_type)

    def detect_controls(self, expected, description: str = "",
                        diagram_image: bytes | None = None,
                        diagram_media_type: str = "image/png") -> list[LedgerEntry]:
        """Read the description and/or diagram in ONE call and return an entry per
        evidenced control, each carrying the AI's rationale and cited source.
        Description quotes are checked against the text (`quote_verified`)."""
        from ..intake import quote_in_text
        has_img = bool(diagram_image) and hasattr(self.raw, "complete_json_image")
        if not description.strip() and not has_img:
            return []
        system, user = prompts.detect_prompt(expected, description, has_diagram=has_img)
        if has_img:
            import base64
            b64 = base64.b64encode(diagram_image).decode()
            data = self.raw.complete_json_image(system, user, b64, diagram_media_type)
        else:
            data = self.raw.complete_json(system, user)

        valid = {c.id for c in expected}
        entries: list[LedgerEntry] = []
        seen: set[str] = set()
        for d in _listify(data, "controls", "items"):
            if not isinstance(d, dict):
                continue
            cid = _as_opt_str(d.get("control_id"))
            if cid not in valid or cid in seen:
                continue
            seen.add(cid)
            status = _as_str(d.get("status"), "implemented")
            if status not in ("implemented", "partial"):
                status = "implemented"          # detection never asserts absence
            conf = _as_str(d.get("confidence"), "medium")
            if conf not in ("low", "medium", "high"):
                conf = "medium"
            source = _as_str(d.get("source"), "")
            if source not in ("description", "diagram"):
                source = "diagram" if (has_img and not description.strip()) else \
                         ("description" if not has_img else "diagram")
            quote = _as_opt_str(d.get("quote")) or _as_opt_str(d.get("evidence"))
            rationale = _as_opt_str(d.get("rationale")) or _as_opt_str(d.get("evidence"))
            verified = None
            if source == "description":
                verified = quote_in_text(quote, description)
                if not verified and conf == "high":
                    conf = "medium"             # unverifiable citation caps confidence
            prov = Provenance.DIAGRAM_VISION if source == "diagram" else Provenance.DESCRIPTION
            entries.append(LedgerEntry(
                control_id=cid, status=ControlStatus(status), provenance=prov,
                confidence=Confidence(conf), evidence=quote or rationale,
                detail=ControlEvidence(
                    ai_status=ControlStatus(status), ai_confidence=Confidence(conf),
                    ai_source=source, ai_note=rationale, ai_quote=quote,
                    quote_verified=verified, note=rationale)))
        return entries

    # ---- SAD (solution architecture document) ----
    def _call_with_images(self, system: str, user: str,
                          images: list[tuple[bytes, str]] | None) -> dict | list:
        """One call carrying the text and every diagram image."""
        import base64
        images = images or []
        if images and hasattr(self.raw, "complete_json_images"):
            enc = [(base64.b64encode(b).decode(), mt) for b, mt in images]
            return self.raw.complete_json_images(system, user, enc)
        if images and hasattr(self.raw, "complete_json_image"):
            b, mt = images[0]
            return self.raw.complete_json_image(system, user, base64.b64encode(b).decode(), mt)
        return self.raw.complete_json(system, user)

    def assess_sad(self, text: str, rubric: list[dict], images=None,
                   image_labels: list[str] | None = None) -> dict:
        """Completeness rubric + profile in one call. Returns the raw object;
        `threatcatalog.sad.parse_assessment` normalises it."""
        from ..models import AICapability, PlatformFacet
        system, user = prompts.sad_assess_prompt(
            text, rubric, [p.value for p in PlatformFacet],
            [a.value for a in AICapability if a != AICapability.NONE],
            len(images or []), image_labels)
        data = self._call_with_images(system, user, images)
        if isinstance(data, list):
            data = data[0] if data and isinstance(data[0], dict) else {}
        return data if isinstance(data, dict) else {}

    def detect_sad_controls(self, expected, text: str, images=None,
                            image_labels: list[str] | None = None) -> tuple[list[dict], list[dict]]:
        """Return (control records, other controls) as plain dicts, shape-coerced.
        `threatcatalog.sad.build_sad_ledger` applies the SAD status rules."""
        system, user = prompts.sad_detect_prompt(expected, text, len(images or []), image_labels)
        data = self._call_with_images(system, user, images)
        if isinstance(data, dict):
            ctrl_raw = data.get("controls")
            other_raw = data.get("other_controls") or []
            if not isinstance(ctrl_raw, list):
                ctrl_raw = _listify(data, "controls", "items")
        else:
            ctrl_raw, other_raw = _listify(data, "controls", "items"), []
        controls = []
        for d in ctrl_raw:
            if not isinstance(d, dict):
                continue
            controls.append({
                "control_id": _as_opt_str(d.get("control_id")),
                "status": (_as_str(d.get("status"), "implemented") or "implemented").lower(),
                "basis": (_as_str(d.get("basis"), "stated") or "stated").lower(),
                "source": (_as_str(d.get("source"), "text") or "text").lower(),
                "quote": _as_opt_str(d.get("quote")) or _as_opt_str(d.get("evidence")),
                "rationale": _as_opt_str(d.get("rationale")) or _as_opt_str(d.get("evidence")),
            })
        others = []
        for d in other_raw if isinstance(other_raw, list) else []:
            if isinstance(d, dict) and _as_opt_str(d.get("name")):
                others.append({"name": _as_str(d.get("name")),
                               "description": _as_str(d.get("description"))})
        return controls, others

    # ---- threats ----
    def generate_threats(self, gap: list[GapItem], profile: AppProfile) -> list[Threat]:
        system, user = prompts.threats_prompt(gap, profile)
        data = self.raw.complete_json(system, user)
        out = []
        for i, d in enumerate(_listify(data, "threats", "items", "result"), start=1):
            if not isinstance(d, dict):
                continue
            out.append(Threat.model_validate({
                "id": _as_str(d.get("id")) or f"T{i}",
                "stride": _coerce_stride(d.get("stride")),
                "title": _as_str(d.get("title")) or "Untitled threat",
                "description": _as_str(d.get("description")),
                "enabling_gap": _as_opt_str(d.get("enabling_gap")),
                "framework_ref": _as_opt_str(d.get("framework_ref")),
            }))
        return out

    # ---- recommendations ----
    def generate_recommendations(self, gap, profile) -> list[Recommendation]:
        system, user = prompts.recommendations_prompt(gap, profile)
        data = self.raw.complete_json(system, user)
        out = []
        for d in _listify(data, "recommendations", "items"):
            if not isinstance(d, dict):
                continue
            out.append(Recommendation.model_validate({
                "control_id": _as_str(d.get("control_id")),
                "title": _as_str(d.get("title")) or "Recommendation",
                "action": _as_str(d.get("action")),
                "frameworks": _as_str_list(d.get("frameworks")),
            }))
        return out

    # ---- mitigations ----
    def generate_mitigations(self, threats, gap, profile, compensating) -> list[Mitigation]:
        system, user = prompts.mitigations_prompt(threats, gap, profile)
        data = self.raw.complete_json(system, user)
        out = []
        for d in _listify(data, "mitigations", "items"):
            if not isinstance(d, dict):
                continue
            out.append(Mitigation.model_validate({
                "threat_id": _as_str(d.get("threat_id")),
                "action": _as_str(d.get("action")),
                "addresses_control": _as_opt_str(d.get("addresses_control")),
                "note": _as_opt_str(d.get("note")),
            }))
        return out

    # ---- DREAD ----
    def score_dread(self, threats, gap, profile) -> list[DreadScore]:
        system, user = prompts.dread_prompt(threats, gap, profile)
        data = self.raw.complete_json(system, user)
        out = []
        for d in _listify(data, "dread", "scores", "items"):
            if not isinstance(d, dict):
                continue
            out.append(DreadScore.model_validate({
                "threat_id": _as_str(d.get("threat_id")),
                "damage": _as_int(d.get("damage")),
                "reproducibility": _as_int(d.get("reproducibility")),
                "exploitability": _as_int(d.get("exploitability")),
                "affected_users": _as_int(d.get("affected_users")),
                "discoverability": _as_int(d.get("discoverability")),
            }))
        return out

    # ---- out-of-catalog relevance judgement ----
    def judge_out_of_catalog(self, observed: ObservedControl, profile) -> OutOfCatalogAssessment:
        system, user = prompts.ooc_prompt(observed, profile)
        data = self.raw.complete_json(system, user)
        if isinstance(data, list):
            data = data[0] if data else {}
        if not isinstance(data, dict):
            data = {}
        return OutOfCatalogAssessment.model_validate({
            "observed": observed.model_dump(),
            "relevant": bool(data.get("relevant", False)),
            "stride": _coerce_stride_list(data.get("stride")),
            "compensating": bool(data.get("compensating", False)),
            "suggested_framework": _as_opt_str(data.get("suggested_framework")),
            "suggested_layer": _coerce_layer(data.get("suggested_layer")),
            "rationale": _as_str(data.get("rationale")),
        })
