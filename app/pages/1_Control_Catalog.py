"""
Control catalog — reference page.

A browsable, filterable description of every control the engine knows about. It
is generated entirely from the YAML catalog (the same source the threat-modeling
run uses), so it can never drift from what an assessment is actually measured
against. Anyone running the exercise can keep this open as the reference, or
export the (filtered) view to Markdown to circulate.
"""

from __future__ import annotations

from collections import Counter

import streamlit as st

from threatcatalog.catalog import Catalog
from threatcatalog.models import Layer, Stride

st.set_page_config(page_title="Control Catalog", layout="wide")
st.title("Control catalog — reference")
st.caption("Generated from the catalog the engine uses, so it stays in sync. "
           "Edit the YAML under threatcatalog/catalog/data/ and this page updates.")

catalog = Catalog.load()
controls = catalog.controls

# Human-readable description of each layer, so the structure is explained too.
LAYER_BLURB = {
    Layer.BASE: "Applies to every application, regardless of type.",
    Layer.PLATFORM_WEB: "Browser-facing web / SaaS applications.",
    Layer.PLATFORM_CLOUD: "Cloud-hosted workloads (VPC, IAM, KMS…).",
    Layer.PLATFORM_ONPREM: "On-premises deployments.",
    Layer.PLATFORM_MOBILE: "Mobile clients (OWASP MASVS).",
    Layer.AI_LLM: "LLM-integrated apps (OWASP LLM Top 10 2025).",
    Layer.AI_LLM_TOOLS: "LLMs that call tools / functions.",
    Layer.AI_MCP: "Apps using Model Context Protocol servers (OWASP MCP Top 10, beta).",
    Layer.AI_AGENTIC: "Autonomous / agentic systems (OWASP Agentic/ASI Top 10 2026).",
    Layer.AI_GENERATIVE: "Generative output & provenance risks.",
}

# ---- summary metrics ----
pci_n = sum(1 for c in controls if c.pci)
fw_n = sum(1 for c in controls if c.threat_frameworks)
layer_counts = Counter(l for c in controls for l in c.layers)
c1, c2, c3, c4 = st.columns(4)
c1.metric("Controls", len(controls))
c2.metric("Layers", len(layer_counts))
c3.metric("Framework-anchored", fw_n)
c4.metric("PCI-mapped", pci_n)

# ---- filters ----
with st.sidebar:
    st.header("Filter")
    query = st.text_input("Search", help="Matches id, title, intent, signal, keywords.")
    layers_present = [l for l in Layer if l in layer_counts]
    sel_layers = st.multiselect("Layer", [l.value for l in layers_present])
    sel_stride = st.multiselect("STRIDE", [s.value for s in Stride])
    fw_present = sorted({f.framework for c in controls for f in c.threat_frameworks})
    sel_fw = st.multiselect("Framework", fw_present)
    pci_only = st.checkbox("PCI-mapped only")


def matches(c) -> bool:
    if query:
        hay = " ".join([c.id, c.title, c.intent, c.assessment_signal,
                        " ".join(c.detect_keywords)]).lower()
        if query.lower() not in hay:
            return False
    if sel_layers and not ({l.value for l in c.layers} & set(sel_layers)):
        return False
    if sel_stride and not ({s.value for s in c.stride} & set(sel_stride)):
        return False
    if sel_fw and not ({f.framework for f in c.threat_frameworks} & set(sel_fw)):
        return False
    if pci_only and not c.pci:
        return False
    return True


filtered = [c for c in controls if matches(c)]


def control_to_markdown(c) -> str:
    out = [f"### {c.id} — {c.title}", "", f"_{c.intent}_", ""]
    out.append(f"- **Layers:** {', '.join(l.value for l in c.layers)}")
    out.append(f"- **STRIDE:** {', '.join(s.value for s in c.stride)}")
    out.append(f"- **Expectation:** {c.default_expectation.value}")
    out.append(f"- **Assessment signal:** {c.assessment_signal}")
    if c.threat_frameworks:
        fw = "; ".join(f"{f.framework} {f.ref} (v{f.version})" for f in c.threat_frameworks)
        out.append(f"- **Threat frameworks:** {fw}")
    if c.pci:
        out.append("- **PCI DSS v4.0.1:** "
                   + ", ".join(r.requirement for r in c.pci) + "  _(illustrative — verify)_")
    if c.detect_keywords:
        out.append(f"- **Detection keywords:** {', '.join(c.detect_keywords)}")
    if c.notes:
        out.append(f"- **Notes:** {c.notes}")
    return "\n".join(out)


def full_markdown(items) -> str:
    doc = ["# Control catalog reference\n",
           f"{len(items)} controls. PCI mappings are illustrative seeds — validate "
           "against the official PCI DSS v4.0.1 document before assessment.\n"]
    for l in Layer:
        group = [c for c in items if l in c.layers]
        if not group:
            continue
        doc.append(f"\n## {l.value} — {LAYER_BLURB.get(l, '')}\n")
        for c in group:
            doc.append(control_to_markdown(c) + "\n")
    return "\n".join(doc)


st.write(f"Showing **{len(filtered)}** of {len(controls)} controls.")
st.download_button("⬇ Export this view to Markdown", full_markdown(filtered),
                   file_name="control_catalog_reference.md", mime="text/markdown")

# ---- grouped, browsable detail ----
for layer in Layer:
    group = [c for c in filtered if layer in c.layers]
    if not group:
        continue
    st.subheader(f"{layer.value}")
    st.caption(LAYER_BLURB.get(layer, ""))
    for c in group:
        pci_tag = "  · PCI" if c.pci else ""
        fw_tag = "  · " + ", ".join(sorted({f.framework for f in c.threat_frameworks})) \
            if c.threat_frameworks else ""
        with st.expander(f"{c.id} — {c.title}{fw_tag}{pci_tag}"):
            st.markdown(control_to_markdown(c))
