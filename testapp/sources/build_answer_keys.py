"""Render ANSWER_KEY.md and expected_results.json for each sample app."""
import json
import pathlib
import sys

HERE = pathlib.Path(__file__).parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parents[1]))
from answer_keys import CORVANE, HALCYON, MARLOWE, NORTHFIELD  # noqa: E402
from threatcatalog.catalog.loader import load_controls  # noqa: E402

SAD_LABEL = {"I": "implemented", "P": "partial", "PI": "partial (inferred, AI note)",
             "NPS": "not present (stated)", "NP": "not present (not stated)"}
TITLES = {c.id: c.title for c in load_controls()}
LAYERS = {c.id: "/".join(l.value for l in c.layers) for c in load_controls()}


def desc_status(sad, where):
    if where == "-":
        return "unknown"
    if where == "A" or (where == "D" and sad in ("NP", "NPS")):
        return "unknown → declare not present"
    label = {"I": "implemented", "P": "partial", "PI": "partial"}.get(sad, "unknown")
    return label + (" (diagram)" if where == "D" else "")


def render(key, folder, files, notes):
    out = folder / "ANSWER_KEY.md"
    f = key["facets"]
    c = key["controls"]
    counts = {k: sum(1 for v in c.values() if v[0] == k) for k in SAD_LABEL}
    lines = [f"# {key['name']} — answer key", "",
             "Expected results when this sample is run through the threat modeling utility. "
             "LLM output varies between runs and models, so treat this as the intended "
             "result: a status one step away (for example *partial* instead of *implemented*) "
             "is normal, but a control on the wrong side of present/absent is worth a look.", "",
             "## Files", ""]
    lines += [f"- `{n}` — {d}" for n, d in files]
    lines += ["", "## Expected facets (confirmation screen on the SAD page)", "",
              "| Facet | Expected |", "|---|---|",
              f"| Platforms | {', '.join(f['platforms'])} |",
              f"| AI capability | {', '.join(f['ai'])} |",
              f"| Data classification | {f['data_classification']} |",
              f"| Cardholder data (PCI) | {'Yes — PCI section in scope' if f['pci'] else 'No — PCI out of scope (stated explicitly)'} |",
              f"| Expected control count | {len(c)} |", ""]
    lines += notes + ["", "## Expected status mix on the SAD page", "",
                      "| Status | Controls |", "|---|---|"]
    lines += [f"| {SAD_LABEL[k]} | {v} |" for k, v in counts.items()]
    lines += ["", "Out-of-catalog controls the SAD describes (should appear as catalog candidates): "
              + "; ".join(key["out_of_catalog"]) + ".", "",
              "## Control-by-control expectations", "",
              "Description-page column: what Detect should pre-fill from the description text and the "
              "architecture diagram. That page never marks a control absent, so controls the "
              "description says are missing stay *unknown* and the reviewer declares them *not present*.", "",
              "| Control | Title | Layer | SAD page | Description page | Evidence in the sample |",
              "|---|---|---|---|---|---|"]
    for cid, (sad, where, why) in c.items():
        lines.append(f"| {cid} | {TITLES[cid]} | {LAYERS[cid]} | {SAD_LABEL[sad]} | {desc_status(sad, where)} | {why} |")
    out.write_text("\n".join(lines) + "\n")
    js = {"application": key["name"], "facets": f, "out_of_catalog": key["out_of_catalog"],
          "controls": {cid: {"sad_status": SAD_LABEL[s], "description_status": desc_status(s, w), "evidence": y}
                       for cid, (s, w, y) in c.items()}}
    (folder / "expected_results.json").write_text(json.dumps(js, indent=2, ensure_ascii=False) + "\n")
    print("wrote", out)


render(CORVANE, HERE.parent / "corvane-supplier-hub", [
    ("Corvane_SupplierHub_SAD_v1.2.docx", "SAD for the SAD upload page (Word, diagram embedded)"),
    ("Corvane_SupplierHub_SAD_v1.2.pdf", "the same SAD as PDF"),
    ("Corvane_SupplierHub_SAD_v0.1_DRAFT_incomplete.docx", "deliberately insufficient draft: the SAD page should STOP with no report"),
    ("Corvane_SupplierHub_Description.txt", "description for the main page (paste into the description box)"),
    ("Corvane_SupplierHub_Architecture.png", "architecture diagram for the main page"),
], [
    "## Insufficient-SAD test",
    "",
    "Upload `Corvane_SupplierHub_SAD_v0.1_DRAFT_incomplete.docx`. It has a purpose but no diagram "
    "and no components or technology stack, so two hard minimums (diagram, components) are missing. "
    "Expected: the page stops, produces the completeness feedback document, and no threat report.",
    "",
    "## Things this sample is designed to test",
    "",
    "- WAF, login rate limit, CSPM and the SCM restriction appear only on the diagram, not in the "
    "description text, so the description page can only find them by reading the image.",
    "- Explicit absences (no PIM, no SIEM, prod data in UAT, no SRI, HSTS not configured) should come "
    "back *not present* with a quote, not just silence.",
    "- PaaS patching and Front Door managed certificates should be *partial (inferred)* with a 'confirm' note.",
    "- PCI should be out of scope because the SAD says so explicitly.",
    "- Messaging is in scope only through the BankVerify retry queue (§7), which names no broker. "
    "Expect the messaging facet to be selected (inferred) and most MSG-* controls to come back "
    "*not present*; MSG-DLQ-001 is *partial* (retries are capped, no dead-letter queue stated).",
])

render(HALCYON, HERE.parent / "halcyon-claimpilot", [
    ("Halcyon_ClaimPilot_SAD_v2.0.docx", "SAD for the SAD upload page (Word, three diagrams embedded)"),
    ("Halcyon_ClaimPilot_SAD_v2.0.pdf", "the same SAD as PDF"),
    ("Halcyon_ClaimPilot_Description.txt", "description for the main page"),
    ("Halcyon_ClaimPilot_Architecture_Overview.png", "overview diagram for the main page (it takes one image)"),
    ("Halcyon_ClaimPilot_Agent_Interaction.png", "agent/tool/MCP diagram (Figure 2 of the SAD)"),
    ("Halcyon_ClaimPilot_Deployment_Network.png", "deployment and network diagram (Figure 3 of the SAD)"),
], [
    "## Things this sample is designed to test",
    "",
    "- Wide facet set: AI facets agentic, mcp, generative and training (which pull in the llm and "
    "llm_tools layers), plus five platform facets. Expect a long run; use a generous output budget.",
    "- PCI in scope through MOTO card entry, even though online payments use hosted fields. "
    "A tool that reads only the online path would wrongly set PCI to no.",
    "- Classic agentic gaps stated in the SAD: token passthrough to an MCP server, unpinned MCP tool "
    "lists, a shared service account instead of on-behalf-of, a RAG index with no document-level "
    "filter, unsandboxed code execution, an open web-fetch tool (SSRF and indirect prompt injection), "
    "unredacted LLM traces, and no AI red teaming. These should be the highest-rated findings.",
    "- Strong platform controls (Shield, WAF, mTLS, CMKs, private endpoints, SCPs, GitOps) should come "
    "back implemented and not generate findings.",
    "- CSRF is only inferable (bearer tokens, not cookies) and should be *partial* with a note.",
])

MINIMAL_NOTE = ("Minimal demo app: one platform layer only, so the run is quick and the report short. "
                "The SAD states plainly that there is no web UI, no API, no queue or file transfer, no "
                "containers and no AI. If the model still ticks one of those facets on the confirmation "
                "screen, untick it before running; that is a good moment to show the reviewer step.")

render(MARLOWE, HERE.parent / "marlowe-shift-reporter", [
    ("Marlowe_ShiftReporter_SAD_v1.0.docx", "SAD for the SAD upload page (Word, diagram embedded)"),
    ("Marlowe_ShiftReporter_SAD_v1.0.pdf", "the same SAD as PDF"),
    ("Marlowe_ShiftReporter_Description.txt", "description for the main page (paste into the description box)"),
    ("Marlowe_ShiftReporter_Architecture.png", "architecture diagram for the main page"),
], [
    "## Things this sample is designed to test",
    "",
    "- " + MINIMAL_NOTE,
    "- On-premises only: expect the onprem facet (firewall, host hardening, EDR) and *not* cloud. "
    "The reports are viewed in an existing Power BI Report Server that the SAD puts out of scope, "
    "so web should stay unticked.",
    "- Firewall rules, the MFA jump host, the CIS baseline and Defender for Endpoint are clearest on the "
    "diagram, so the description page needs the image to find them.",
    "- Stated absences (no TDE or disk encryption, no dependency scanning, no Splunk alerting, "
    "no pentest) should come back *not present* with a quote.",
    "- Internal classification, no PCI: expect a short report with a handful of High findings at most.",
])

render(NORTHFIELD, HERE.parent / "northfield-sms-reminders", [
    ("Northfield_SMSReminders_SAD_v1.0.docx", "SAD for the SAD upload page (Word, diagram embedded)"),
    ("Northfield_SMSReminders_SAD_v1.0.pdf", "the same SAD as PDF"),
    ("Northfield_SMSReminders_Description.txt", "description for the main page (paste into the description box)"),
    ("Northfield_SMSReminders_Architecture.png", "architecture diagram for the main page"),
], [
    "## Things this sample is designed to test",
    "",
    "- " + MINIMAL_NOTE,
    "- Serverless on Google Cloud: expect the cloud facet only. Cloud Functions run on Google-managed "
    "containers and Cloud Scheduler calls the function over HTTPS, so a model may tick container or api; "
    "the SAD says the team builds no containers and the function accepts only internal, authenticated calls.",
    "- Health-related personal data makes it Confidential. PCI is out of scope (stated).",
    "- The headline gaps are deliberate and stated: DEBUG logs with full phone numbers and message text, "
    "standing Owner for every engineer, unrestricted egress and the API key duplicated in Cloud Build.",
    "- Strong points (keyless service accounts, IAM DB auth, private IP, Terraform with drift check, "
    "Semgrep, DPIA) should come back implemented and produce no findings.",
])
