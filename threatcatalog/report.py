"""
threatcatalog.report
====================

Renders a `ThreatModelReport` to Markdown. Pure formatting — no logic, no model
calls. Kept deliberately separate so the same report object can be rendered to
other formats (DOCX, JSON) without touching the engine.
"""

from __future__ import annotations

from .models import ControlStatus, ThreatModelReport

_STATUS_LABEL = {
    ControlStatus.IMPLEMENTED: "Implemented",
    ControlStatus.PARTIAL: "Partial",
    ControlStatus.NOT_PRESENT: "Not present",
    ControlStatus.UNKNOWN: "Unknown",
    ControlStatus.NOT_APPLICABLE: "N/A",
}


def summary_facts(r: ThreatModelReport) -> dict:
    """Compute the executive-summary facts once, so the Markdown and PDF renderers
    share identical numbers. Pure data — no formatting."""
    gi = r.gap_items
    not_present = [g for g in gi if g.status == ControlStatus.NOT_PRESENT]
    partial = [g for g in gi if g.status == ControlStatus.PARTIAL]
    implemented = [g for g in gi if g.status == ControlStatus.IMPLEMENTED]
    n_unknown = sum(1 for g in gi if g.status == ControlStatus.UNKNOWN)

    threats_by_id = {t.id: t for t in r.threats}
    threat_by_control = {t.enabling_gap: t for t in r.threats if t.enabling_gap}
    dread_by_threat = {d.threat_id: d for d in r.dread}

    def sev(control_id: str) -> float:
        t = threat_by_control.get(control_id)
        return dread_by_threat[t.id].average if (t and t.id in dread_by_threat) else 0.0

    p = r.profile
    if r.pci_view.in_scope:
        pci_text = (f"in scope — {len(r.pci_view.exposed)} requirement-mapped control(s) "
                    f"exposed, {len(r.pci_view.indeterminate)} to verify")
    else:
        pci_text = "out of scope"

    posture = (
        f"{p.name} ({', '.join(f.value for f in p.platforms)} · "
        f"{', '.join(a.value for a in p.ai_capabilities)} · {p.data_classification.value} "
        f"data) was assessed against {r.resolved_control_count} expected controls. The review "
        f"identified {len(not_present) + len(partial)} gap(s) ({len(not_present)} not in place, "
        f"{len(partial)} partial), {len(implemented)} confirmed in place, and {n_unknown} that "
        f"could not be confirmed. PCI DSS v4.0.1 is {pci_text}.")

    top_threats = []
    for d in sorted(r.dread, key=lambda d: d.average, reverse=True)[:4]:
        t = threats_by_id.get(d.threat_id)
        top_threats.append((d.priority.value, d.average,
                            t.title if t else d.threat_id, t.framework_ref if t else None))

    key_gaps = []
    for g in sorted(not_present, key=lambda g: (0 if g.pci_exposed else 1, -sev(g.control.id)))[:5]:
        tags = (["PCI"] if g.pci_exposed else []) + \
               ([g.control.threat_frameworks[0].ref] if g.control.threat_frameworks else [])
        key_gaps.append((g.control.id, g.control.title, tags))

    strengths = [(g.control.id, g.control.title) for g in sorted(
        implemented, key=lambda g: 0 if (g.control.threat_frameworks or g.control.pci) else 1)[:5]]

    notes = []
    if r.compensating:
        notes.append(f"{len(r.compensating)} compensating control(s) noted "
                     f"(these soften, but do not eliminate, a finding)")
    if n_unknown:
        notes.append(f"{n_unknown} unknown control(s) need confirmation — treated as "
                     f"clarifications, not findings (unknown \u2260 missing)")

    return {"posture": posture, "top_threats": top_threats, "key_gaps": key_gaps,
            "strengths": strengths, "notes": notes,
            "all_confirmed": not (not_present or partial or n_unknown)}


def _executive_summary(r: ThreatModelReport) -> list[str]:
    """Markdown executive summary, built from the shared summary_facts."""
    f = summary_facts(r)
    lines = ["## Executive summary\n", f["posture"] + "\n"]
    if f["top_threats"]:
        lines.append("**Top threats (by DREAD):**")
        for prio, avg, title, fw in f["top_threats"]:
            lines.append(f"- [{prio} · {avg}] {title}" + (f" ({fw})" if fw else ""))
        lines.append("")
    if f["key_gaps"]:
        lines.append("**Key gaps to close:**")
        for cid, title, tags in f["key_gaps"]:
            lines.append(f"- {cid} {title}" + (f" ({', '.join(tags)})" if tags else ""))
        lines.append("")
    if f["strengths"]:
        lines.append("**Strengths (confirmed in place):**")
        for cid, title in f["strengths"]:
            lines.append(f"- {cid} {title}")
        lines.append("")
    if f["notes"]:
        lines.append("**Also note:** " + "; ".join(f["notes"]) + ".\n")
    if f["all_confirmed"]:
        lines.append("_No gaps and nothing outstanding — all expected controls are confirmed in place._\n")
    return lines


def render_markdown(r: ThreatModelReport) -> str:
    p = r.profile
    out: list[str] = []
    out.append(f"# Threat Model — {p.name}\n")
    out.append(f"*Platforms:* {', '.join(f.value for f in p.platforms)}  ")
    out.append(f"*AI capability:* {', '.join(a.value for a in p.ai_capabilities)}  ")
    out.append(f"*Data classification:* {p.data_classification.value}  ")
    out.append(f"*Resolved controls:* {r.resolved_control_count}  ")
    out.append(f"*PCI in scope:* {'yes' if p.handles_cardholder_data else 'no'}\n")

    # Executive summary — deterministic roll-up, first thing a reader sees
    out.extend(_executive_summary(r))

    # Gap register
    out.append("## Control gap register\n")
    out.append("| Control | Status | Frameworks | PCI exposed |")
    out.append("|---|---|---|---|")
    for gi in r.gap_items:
        fws = ", ".join(f.ref for f in gi.control.threat_frameworks) or "—"
        pci = ", ".join(x.requirement for x in gi.pci_exposed) or "—"
        out.append(f"| {gi.control.id} {gi.control.title} | {_STATUS_LABEL[gi.status]} "
                   f"| {fws} | {pci} |")
    out.append("")

    # Threats
    out.append("## Threat model\n")
    if r.threats:
        out.append("| ID | STRIDE | Threat | Enabling gap | Maps to |")
        out.append("|---|---|---|---|---|")
        for t in r.threats:
            out.append(f"| {t.id} | {t.stride.value} | {t.title} "
                       f"| {t.enabling_gap or '—'} | {t.framework_ref or '—'} |")
    else:
        out.append("*No findings — all expected controls implemented or unknown.*")
    out.append("")

    # Recommendations
    out.append("## Recommendations (gap-closing)\n")
    for rec in r.recommendations:
        fw = f"  _{', '.join(rec.frameworks)}_" if rec.frameworks else ""
        out.append(f"- **{rec.title}** ({rec.control_id}) — {rec.action}{fw}")
    if not r.recommendations:
        out.append("- None.")
    out.append("")

    # Mitigations
    out.append("## Mitigations (threat-specific)\n")
    for m in r.mitigations:
        note = f"  _{m.note}_" if m.note else ""
        out.append(f"- **{m.threat_id}** → {m.action}{note}")
    if not r.mitigations:
        out.append("- None.")
    out.append("")

    # DREAD
    out.append("## DREAD scoring\n")
    if r.dread:
        out.append("| Threat | D | R | E | A | D | Avg | Priority |")
        out.append("|---|---|---|---|---|---|---|---|")
        for s in sorted(r.dread, key=lambda x: x.average, reverse=True):
            out.append(f"| {s.threat_id} | {s.damage} | {s.reproducibility} | "
                       f"{s.exploitability} | {s.affected_users} | {s.discoverability} "
                       f"| {s.average} | {s.priority.value} |")
    else:
        out.append("*No scored threats.*")
    out.append("")

    # Clarifications
    if r.clarifications:
        out.append("## Clarifications needed (unknown ≠ missing)\n")
        for c in r.clarifications:
            out.append(f"- {c}")
        out.append("")

    # PCI view
    out.append("## PCI DSS v4.0.1 compliance view\n")
    if not r.pci_view.in_scope:
        out.append("*Not in scope — the application does not handle cardholder data.*\n")
    else:
        out.append(f"In scope. Covered PCI-mapped controls: {r.pci_view.covered_count}.\n")
        if r.pci_view.exposed:
            out.append("**Exposed (weak/missing):**")
            for e in r.pci_view.exposed:
                reqs = ", ".join(x.requirement for x in e.requirements)
                out.append(f"- {e.control_id} {e.control_title} "
                           f"({_STATUS_LABEL[e.status]}) → PCI {reqs}")
        if r.pci_view.indeterminate:
            out.append("\n**Indeterminate (verify):**")
            for e in r.pci_view.indeterminate:
                reqs = ", ".join(x.requirement for x in e.requirements)
                out.append(f"- {e.control_id} {e.control_title} → PCI {reqs}")
        out.append("")

    # Out-of-catalog
    if r.compensating or r.candidates:
        out.append("## Out-of-catalog controls\n")
        for a in r.compensating:
            out.append(f"- Compensating: **{a.observed.name}** — {a.rationale}")
        if r.candidates:
            out.append("\n*Catalog candidates (flagged for later promotion):*")
            for c in r.candidates:
                strides = ", ".join(s.value for s in c.stride) or "unmapped"
                out.append(f"- {c.title} — [{strides}]")
        out.append("")

    return "\n".join(out)
