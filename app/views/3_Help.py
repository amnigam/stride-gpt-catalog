"""
Help — how to use the tool, and how threats are scored with DREAD.

1. How to use: which page to start on (SAD upload if a SAD exists, otherwise the
   description + diagram page) and a short walk-through of each.
2. DREAD: what the five factors mean, how the app turns them into an average and
   a priority, and a worked example scored live by the real engine (see
   `threatcatalog.help_example`), so the numbers here never drift from the app.
"""

from __future__ import annotations

import pandas as pd
import streamlit as st

from threatcatalog.help_example import EXAMPLE_CONTROL_ID, dread_example
from threatcatalog.llm.prompts import DREAD_ANCHORS
from threatcatalog.models import ControlStatus, DataClassification
from threatcatalog.catalog.loader import load_controls
from threatcatalog.references import CAVEAT, METHODS, framework_rows, pci_row
from threatcatalog.report import READINESS_LEGEND

st.set_page_config(page_title="Help", layout="wide")
st.title("Help")
st.caption("How to run a threat model with this tool, and how its threats are scored.")

how_tab, dread_tab, ref_tab = st.tabs(["How to use", "DREAD scoring", "References"])

# --------------------------------------------------------------------------- #
# 1 · How to use: the three flows
# --------------------------------------------------------------------------- #
with how_tab:
    st.header("Three ways to produce a threat model")
    st.markdown("Pick the flow that matches what you have for the application. All three "
                "produce the same report (Markdown or PDF); they differ in where the control "
                "statuses come from and who has checked them.")
    st.table(pd.DataFrame([
        ("1 · SAD → automated draft", "A Solution Architecture Document (DOCX, PDF or "
         "Markdown)", "SAD Threat Model", "Not present (SAD silent)",
         "Automated draft, no person has reviewed it"),
        ("2 · SAD draft → human review", "The declaration JSON saved by flow 1",
         "Threat Model Review", "Stays Not present (SAD silent) until a reviewer changes it",
         "From SAD, then reviewed"),
        ("3 · Description + diagrams", "A written description and up to 10 architecture "
         "diagrams", "Threat Model Review", "Unknown: an open question, not a finding",
         "Reviewed (once the reviewer confirms or edits statuses)"),
    ], columns=["Flow", "You start with", "Page", "A control the input doesn't mention",
                "The report says"]), hide_index=True)
    st.caption("Flow 1 is deliberately strict: whatever the SAD omits is taken as accepted "
               "by the business. Flows 2 and 3 are where an AppSec reviewer or security "
               "champion confirms, corrects or relaxes statuses with evidence.")

    st.subheader("📄 Flow 1 · SAD → automated draft")
    st.page_link("views/2_SAD_Threat_Model.py", label="Open SAD Threat Model", icon="➡️")
    st.markdown(
        "**Use it when** the application has a SAD and you want a first, automated read "
        "before anyone spends review time on it.\n\n"
        "1. **Pick the model** in the sidebar (AWS Bedrock for confidential documents, "
        "or OpenAI / Anthropic).\n"
        "2. **Upload the SAD.** Diagrams inside the document are read automatically; add "
        "extra diagram images if they live elsewhere. Confirm the document may be sent to "
        "the selected provider.\n"
        "3. **Check the SAD.** One call scores it against a 12-item completeness checklist "
        "and proposes the application profile (platforms, AI use, data classification, "
        "PCI scope). If purpose, an architecture diagram or the components are missing, "
        "the page **stops without a report** and gives you a feedback checklist for the "
        "SAD author.\n"
        "4. **Confirm the profile** on one screen: tick or untick facets, set the data "
        "classification and PCI scope.\n"
        "5. **Run.** Controls are detected across the text and every diagram, cited quotes "
        "are checked against the SAD, and the report is built. Download it as Markdown or "
        "PDF, **and download the declaration JSON** if the application will go to review "
        "(flow 2).")
    st.info("Status rules in flow 1: a control the SAD **does not mention is Not present** "
            "(tagged *SAD silent*); a control the SAD only implies is **Partial** with a "
            "note to confirm it; a cited quote that is not in the SAD drops the control to "
            "Partial. The model is told to stay strict: it never marks a control Implemented "
            "without clear evidence.")

    st.subheader("🔁 Flow 2 · SAD draft → human review")
    st.page_link("review.py", label="Open Threat Model Review", icon="➡️")
    st.markdown(
        "**Use it when** a flow-1 draft needs to be confirmed by AppSec or a security "
        "champion before it goes to the ARB.\n\n"
        "1. **Enter your name** under *Reviewer* in the sidebar, so every change is "
        "attributed to you.\n"
        "2. **Load a saved declaration** and pick the JSON from flow 1. The profile, the "
        "AI evaluations, their quotes and the SAD record come with it.\n"
        "3. **Review each control.** Change a status or edit the note to record your own "
        "evidence, or tick *Reviewed* to confirm the AI evaluation as it is. The AI's "
        "original evaluation is never overwritten. Rows that need a note are flagged, "
        "but nothing blocks the run.\n"
        "4. **Run threat model.** The report keeps the SAD's Assessment basis and is "
        "labelled *From SAD, then reviewed*. If you change the profile, the report says "
        "so.")

    st.subheader("✏️ Flow 3 · Description + diagrams")
    st.page_link("review.py", label="Open Threat Model Review", icon="➡️")
    st.markdown(
        "**Use it when** there is no SAD, or you are working through the design with the "
        "application team.\n\n"
        "1. **Pick the model** in the sidebar. *Deterministic (offline)* needs no key but "
        "cannot read diagrams.\n"
        "2. **Set the application facets**: name, platforms, AI capability, data "
        "classification and PCI scope. These decide which controls are expected.\n"
        "3. **Describe the architecture** and **upload the diagrams** (PNG / JPG, up to "
        "10: context, deployment / network, data flow…).\n"
        "4. **Detect controls.** The AI reads the description and all the diagrams "
        "together and pre-fills the declaration, with its reasoning and the sentence or "
        "diagram element it relied on.\n"
        "5. **Review the declaration** as in flow 2. Use *Find control* to jump to a "
        "control by ID or name (e.g. CORS); *Control details* under the table explains "
        "what each control covers and what to check.\n"
        "6. **Run threat model** and download the report as Markdown or PDF.")
    st.info("In flow 3 a control the AI finds no evidence for stays **Unknown**, not "
            "missing. Unknowns are open questions for the team rather than findings, and "
            "they keep the readiness marker at *Ready with conditions* until resolved.")

    st.subheader("Tips")
    st.markdown(
        "- **Save the declaration (JSON)** between ARB rounds; it reloads exactly as you "
        "left it, including who reviewed what.\n"
        "- **Controls you have that aren't in the catalog** can be listed on the Threat "
        "Model Review page. If relevant, they soften the score of related threats as a "
        "*compensating control* (see DREAD scoring); they never close a finding.\n"
        "- The report's first page carries the **Security readiness** marker; how it is "
        "set is explained under the marker and in *DREAD scoring*.\n"
        "- The **Control Catalog** page lists every control the tool checks, with "
        "guidance you can share with the application team.")
    st.page_link("views/1_Control_Catalog.py", label="Open Control Catalog", icon="📚")

# --------------------------------------------------------------------------- #
# 2 · DREAD
# --------------------------------------------------------------------------- #
with dread_tab:
    st.header("What is DREAD?")
    st.markdown(
        "Every threat in the report is a consequence of a **control gap**: a control "
        "that is *not present* or only *partial*. DREAD rates how serious each threat is, "
        "so you can decide what to fix first. It scores five factors, each from "
        "**1 (low) to 10 (high)**:")

    st.table(pd.DataFrame([
        ("D", "Damage", "How bad is it if the attack succeeds?"),
        ("R", "Reproducibility", "How reliably can the attack be repeated?"),
        ("E", "Exploitability", "How much effort or skill does the attack take?"),
        ("A", "Affected users", "How many users or systems are hit?"),
        ("D", "Discoverability", "How easy is the weakness to find?"),
    ], columns=["Letter", "Factor", "Question it answers"]), hide_index=True)

    st.subheader("Score anchors")
    st.markdown(
        "Every AI engine is given these anchors, word for word, so a score means the "
        "same thing on every run and every model:")
    st.table(pd.DataFrame(
        [(f, b, m[0].upper() + m[1:]) for f, bands in DREAD_ANCHORS for b, m in bands],
        columns=["Factor", "Score", "Means"]), hide_index=True)

    st.subheader("From five scores to a priority")
    st.markdown("The app averages the five factors (rounded to two decimals):")
    st.latex(r"\text{DREAD average} = \frac{D + R + E + A + D}{5}")
    st.markdown("and maps the average to a priority band:")
    st.table(pd.DataFrame([
        ("Critical", "7.5 or higher", "Before go-live"),
        ("High", "6.0 to 7.49", "Before go-live if the control is not present; "
                                "otherwise within 90 days"),
        ("Medium", "4.0 to 5.99", "Within 90 days"),
        ("Low", "below 4.0", "Within 90 days"),
    ], columns=["Priority", "Average", "Action plan timing"]), hide_index=True)
    st.caption("The bands are fixed in the app. In the action plan, each action takes the "
               "worst priority of the threats that exploit its controls, and its timing "
               "follows this table. The app sets both from the scores; the model does not.")

    st.subheader("From priorities to Security readiness")
    st.markdown("The marker on the report's first page is set by a fixed rule, checked in "
                "this order:")
    st.table(pd.DataFrame([
        ("Not ready", "Any Critical finding backed by evidence, or any PCI-mapped control "
                      "that is not present."),
        ("Ready with conditions", "Any High finding (a Critical that rests only on the SAD "
                                  "being silent counts as High), a finding without a DREAD "
                                  "score, or a control not yet assessed (Unknown)."),
        ("Ready", "None of the above. Medium and Low gaps remain and are listed in the "
                  "action plan."),
    ], columns=["Marker", "When"]), hide_index=True)
    st.caption("The report prints this explanation under the marker: " + READINESS_LEGEND
               + " On a SAD run the marker is also tagged Automated draft.")

    st.subheader("How the app sets the five scores")
    st.markdown(
        "- **With an AI engine** (OpenAI, Anthropic, Bedrock), the model scores each "
        "threat 1-10 per factor against the anchors above. It sees the app profile, the "
        "system's exposure (from System context), and each threat's target, impact and "
        "evidence type (stated, inferred or SAD silent). It is told that:\n"
        "    - a *missing* control scores higher than a *partial* one;\n"
        "    - a compensating control lowers exploitability;\n"
        "    - when the SAD does not mention a control, the gap is likely but unconfirmed, "
        "so reproducibility and exploitability must not be raised for it;\n"
        "    - it must use the full range, so threats do not all score alike.\n"
        "  It also gives a one-line reason per threat (the **Why** column in the report).\n"
        "- **With the offline engine**, the scores follow fixed rules, shown below.\n"
        "- **Either way, the average and the priority band are calculated by the app**, "
        "never by the model, so the same five scores always give the same priority.")
    st.markdown("**Offline scoring rules**")
    st.table(pd.DataFrame([
        ("Starting scores, control not present", "D 7 · R 8 · E 8 · A 7 · D 6"),
        ("Starting scores, control partial", "D 5 · R 6 · E 6 · A 6 · D 5"),
        ("Data classification Restricted", "Damage +2"),
        ("Data classification Confidential", "Damage +1"),
        ("Threat is Information Disclosure (STRIDE)", "Damage +1"),
        ("Threat is Denial of Service (STRIDE)", "Affected users +1"),
        ("Control is PCI-mapped and PCI is in scope", "Damage +1"),
        ("Control is recommended or conditional, not required", "Affected users −1"),
        ("SAD does not mention the control (SAD silent)", "Reproducibility −1"),
        ("A compensating control was flagged", "Damage −2, Exploitability −2"),
        ("Every factor", "Kept between 1 and 10"),
    ], columns=["Condition", "Effect"]), hide_index=True)

    # ---------------- worked example ----------------
    st.header("Worked example: MFA is not in place")
    threat, s = dread_example()
    st.markdown(
        f"**Scenario.** An internal HR portal (web application) holds **Confidential** "
        f"employee data. Staff sign in with a password only. The catalog's base-layer "
        f"control **{EXAMPLE_CONTROL_ID} · Multi-factor and phishing-resistant "
        f"authentication** is therefore **not present**, which produces this threat:")
    st.markdown(f"> **{threat.id} · {threat.title}** (STRIDE: {threat.stride.value})  \n"
                f"> {threat.description}")

    st.markdown("**Scoring it, one factor at a time**")
    st.table(pd.DataFrame([
        ("Damage", s.damage,
         "An attacker logs in as a real employee and reads Confidential HR records. "
         "Base 7 for a missing control, +1 because the data is Confidential."),
        ("Reproducibility", s.reproducibility,
         "Once a password is phished or reused from a breach, logging in works every "
         "time. Nothing else stands in the way."),
        ("Exploitability", s.exploitability,
         "No special skill: credential stuffing and phishing kits are off-the-shelf."),
        ("Affected users", s.affected_users,
         "Every account is exposed, but each stolen password opens one account at a "
         "time, so not a full 10."),
        ("Discoverability", s.discoverability,
         "The login page is visible, but an attacker still has to probe to confirm no "
         "second factor is asked for."),
    ], columns=["Factor", "Score", "Why"]), hide_index=True)

    total = s.damage + s.reproducibility + s.exploitability + s.affected_users + s.discoverability
    st.latex(rf"\frac{{{s.damage} + {s.reproducibility} + {s.exploitability} + "
             rf"{s.affected_users} + {s.discoverability}}}{{5}} = \frac{{{total}}}{{5}} "
             rf"= {s.average}")
    st.success(f"**Average {s.average} → {s.priority.value}.** In the report this appears "
               f"as: `| {threat.id} | {s.damage} | {s.reproducibility} | {s.exploitability} "
               f"| {s.affected_users} | {s.discoverability} | {s.average} | "
               f"{s.priority.value} |`")

    st.markdown("**How the context changes the result** (same threat, offline rules):")
    variants = [
        ("As above: not present, Confidential", {}),
        ("Data is Restricted instead", {"classification": DataClassification.RESTRICTED}),
        ("MFA is partial (e.g. admins only)", {"status": ControlStatus.PARTIAL}),
        ("Compensating control flagged (e.g. device-posture conditional access)",
         {"compensating": True}),
    ]
    rows = []
    for label, kw in variants:
        _, v = dread_example(**kw)
        rows.append((label, v.damage, v.reproducibility, v.exploitability,
                     v.affected_users, v.discoverability, f"{v.average:g}", v.priority.value))
    st.table(pd.DataFrame(rows, columns=["Scenario", "D", "R", "E", "A", "D ", "Average",
                                         "Priority"]), hide_index=True)
    st.caption("Two points of extra damage from Restricted data are enough to cross into "
               "Critical; a partial control or a compensating control pulls it back down. "
               "That is why accurate control statuses and data classification matter.")

    with st.expander("Try it yourself"):
        c1, c2, c3 = st.columns(3)
        st_status = c1.selectbox("MFA status", ["not_present", "partial"])
        st_dc = c2.selectbox("Data classification", [d.value for d in DataClassification],
                             index=2)
        st_comp = c3.checkbox("Compensating control flagged")
        _, t = dread_example(ControlStatus(st_status), DataClassification(st_dc), st_comp)
        st.metric("DREAD average", t.average, help=f"Priority: {t.priority.value}")
        st.write(f"D {t.damage} · R {t.reproducibility} · E {t.exploitability} · "
                 f"A {t.affected_users} · D {t.discoverability} → **{t.priority.value}**")


# --------------------------------------------------------------------------- #
# 3 · References
# --------------------------------------------------------------------------- #
with ref_tab:
    st.header("Frameworks and standards")
    st.markdown("Every control in the catalog is mapped to the frameworks below. The "
                "report shows these references next to each finding. Versions and counts "
                "are read from the catalog, so this page stays current.")
    controls = load_controls()
    fws = framework_rows(controls)
    pci = pci_row(controls)
    st.table(pd.DataFrame(
        [(f["name"], f["version"], f["controls"], f["use"], f["url"]) for f in fws]
        + [(pci["name"], pci["version"], pci["controls"], pci["use"], pci["url"])],
        columns=["Framework", "Version", "Controls mapped", "Used for", "Official source"]),
        hide_index=True)
    st.warning(CAVEAT)

    st.subheader("Which controls map to each reference")
    for f in fws + [dict(pci, key="pci")]:
        with st.expander(f"{f['name']} ({f['version']}): {len(f['refs'])} references, "
                         f"{f['controls']} controls"):
            if f["url"]:
                st.markdown(f"Official source: {f['url']}")
            st.table(pd.DataFrame([(r, ", ".join(ids)) for r, ids in f["refs"].items()],
                                  columns=["Reference", "Controls"]), hide_index=True)

    st.subheader("Methods")
    st.table(pd.DataFrame([(n, d, u or "Defined in this app") for n, d, u in METHODS],
                          columns=["Method", "How the tool uses it", "Source"]),
             hide_index=True)
