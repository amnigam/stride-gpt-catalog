"""
threatcatalog.references
========================

The external frameworks the catalog maps to, for the Help page's References tab.
Versions and counts are read from the catalog itself, so the page stays correct
when controls are added or re-mapped.
"""

from __future__ import annotations

from .models import Control

# key -> (name, what the report uses it for, official source)
FRAMEWORKS: dict[str, tuple[str, str, str]] = {
    "owasp_llm": ("OWASP Top 10 for LLM Applications",
                  "Threat lineage for controls on apps that call a language model.",
                  "https://genai.owasp.org/llm-top-10/"),
    "owasp_asi": ("OWASP Top 10 for Agentic Applications",
                  "Threat lineage for agent, tool-use and multi-agent controls (ASI01-ASI10).",
                  "https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/"),
    "owasp_mcp": ("OWASP MCP Top 10 (beta)",
                  "Threat lineage for Model Context Protocol controls. Still in beta, so "
                  "numbering may change.",
                  "https://owasp.org/www-project-mcp-top-10/"),
    "owasp_api": ("OWASP API Security Top 10",
                  "Threat lineage for API controls (API1-API10).",
                  "https://owasp.org/API-Security/editions/2023/en/0x11-t10/"),
    "owasp_mobile": ("OWASP Mobile Top 10",
                     "Threat lineage for mobile app controls (M1-M10).",
                     "https://owasp.org/www-project-mobile-top-10/"),
    "owasp_masvs": ("OWASP MASVS",
                    "Verification requirements behind the mobile controls.",
                    "https://mas.owasp.org/MASVS/"),
    "cis_v8": ("CIS Critical Security Controls",
               "Cross-cutting safeguard family on every control in the catalog.",
               "https://www.cisecurity.org/controls/v8-1"),
}

PCI = ("PCI DSS", "v4.0.1",
       "Requirement numbers on controls that matter for cardholder data; drives the PCI "
       "exposure view and the Not ready rule when PCI is in scope.",
       "https://www.pcisecuritystandards.org/document_library/")

METHODS = [
    ("STRIDE", "Threat categories: every control and every threat is tagged with one or "
               "more of Spoofing, Tampering, Repudiation, Information disclosure, Denial of "
               "service and Elevation of privilege.",
     "https://learn.microsoft.com/en-us/azure/security/develop/threat-modeling-tool-threats"),
    ("DREAD", "Risk scoring of each threat: Damage, Reproducibility, Exploitability, "
              "Affected users, Discoverability. The anchors and bands are defined in this "
              "app (see the DREAD scoring tab).", ""),
]

CAVEAT = ("The framework and PCI mappings are a curated starting point for the threat "
          "model, not an audited crosswalk. Validate them against the official documents "
          "before relying on them for a compliance assessment.")


def _fw(t) -> str:
    return getattr(t.framework, "value", t.framework)


def framework_rows(controls: list[Control]) -> list[dict]:
    """One row per framework the catalog uses, in FRAMEWORKS order, then any unknown
    framework key so nothing in the catalog is hidden."""
    used: dict[str, dict] = {}
    for c in controls:
        for t in c.threat_frameworks:
            row = used.setdefault(_fw(t), {"versions": set(), "controls": set(), "refs": {}})
            row["versions"].add(t.version)
            row["controls"].add(c.id)
            row["refs"].setdefault(t.ref, []).append(c.id)
    keys = [k for k in FRAMEWORKS if k in used] + sorted(k for k in used if k not in FRAMEWORKS)
    out = []
    for k in keys:
        name, use, url = FRAMEWORKS.get(k, (k, "", ""))
        u = used[k]
        out.append({"key": k, "name": name, "version": ", ".join(sorted(u["versions"])),
                    "use": use, "url": url, "controls": len(u["controls"]),
                    "refs": {r: sorted(set(ids)) for r, ids in sorted(u["refs"].items())}})
    return out


def pci_row(controls: list[Control]) -> dict:
    refs: dict[str, list[str]] = {}
    for c in controls:
        for p in c.pci:
            refs.setdefault(p.requirement, []).append(c.id)

    def key(s):
        return [int(x) if x.isdigit() else x for x in s.split(".")]
    name, version, use, url = PCI
    return {"name": name, "version": version, "use": use, "url": url,
            "controls": len({cid for ids in refs.values() for cid in ids}),
            "refs": {r: sorted(set(refs[r])) for r in sorted(refs, key=key)}}
