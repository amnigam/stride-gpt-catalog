"""Human-readable rendering of one catalog control (Markdown).

Shared by the Control Catalog page and the control-details panel on the
threat modeling page, so both explain a control the same way."""

from __future__ import annotations

from ..models import Control


def control_markdown(c: Control, heading: str = "###", internals: bool = True) -> str:
    """`heading` is the Markdown heading for the title line ("" = bold text).
    `internals` adds the fields only catalog maintainers need (expectation,
    detection keywords, maintainer notes)."""
    title = f"{heading} {c.id} — {c.title}" if heading else f"**{c.id} — {c.title}**"
    out = [title, "", f"_{c.intent}_", ""]
    if c.guidance:
        out += [c.guidance, ""]
    out.append(f"- **Assessment question:** {c.assessment_signal}")
    out.append(f"- **Layers:** {', '.join(x.value for x in c.layers)}")
    out.append(f"- **STRIDE:** {', '.join(s.value for s in c.stride)}")
    if internals:
        out.append(f"- **Expectation:** {c.default_expectation.value}")
    if c.threat_frameworks:
        fw = "; ".join(f"{f.framework} {f.ref} (v{f.version})" for f in c.threat_frameworks)
        out.append(f"- **Threat frameworks:** {fw}")
    if c.pci:
        out.append("- **PCI DSS v4.0.1:** "
                   + ", ".join(r.requirement for r in c.pci) + "  _(illustrative — verify)_")
    if internals and c.detect_keywords:
        out.append(f"- **Detection keywords:** {', '.join(c.detect_keywords)}")
    if internals and c.notes:
        out.append(f"- **Notes:** {c.notes}")
    return "\n".join(out)
