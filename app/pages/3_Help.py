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
from threatcatalog.models import ControlStatus, DataClassification

st.set_page_config(page_title="Help", layout="wide")
st.title("Help")
st.caption("How to run a threat model with this tool, and how its threats are scored.")

how_tab, dread_tab = st.tabs(["How to use", "DREAD scoring"])

# --------------------------------------------------------------------------- #
# 1 · How to use
# --------------------------------------------------------------------------- #
with how_tab:
    st.header("Which page should I use?")
    st.markdown(
        "The tool has two ways in. Pick based on what you have for the application:\n\n"
        "- **You have a Solution Architecture Document (SAD)** → use **SAD Threat Model**. "
        "Upload the document and you get an automated report with one confirmation step.\n"
        "- **You don't have a SAD** → use **Threat Modeling**. Describe the application, "
        "upload its architecture diagram, review the controls, then run the model.")

    left, right = st.columns(2)

    with left:
        st.subheader("📄 I have a SAD")
        st.page_link("pages/2_SAD_Threat_Model.py", label="Open SAD Threat Model", icon="➡️")
        st.markdown(
            "1. **Pick the model** in the sidebar (AWS Bedrock for confidential documents, "
            "or OpenAI / Anthropic).\n"
            "2. **Upload the SAD** as DOCX, PDF or Markdown. Diagrams inside the document "
            "are read automatically; add extra diagram images if they live elsewhere.\n"
            "3. **Check the SAD.** One click scores it for completeness and proposes the "
            "application profile (platforms, AI use, data classification, PCI scope). If "
            "the SAD is missing essentials, the page **stops without a report** and gives "
            "you a feedback checklist to send to the SAD author.\n"
            "4. **Confirm the profile.** Each facet shows why it was chosen; adjust if "
            "needed. This is the only manual step.\n"
            "5. **Run.** Controls are detected across the text and every diagram, and the "
            "report is built. Download it as Markdown or PDF, plus the declaration JSON.")
        st.info("On this page, a control the SAD **does not mention is reported as not "
                "present**, and a control the SAD only implies is **partial** with a note "
                "to confirm it. Expect a strict report: it reflects what the document "
                "actually evidences.")

    with right:
        st.subheader("✏️ No SAD: description + diagram")
        st.page_link("streamlit_app.py", label="Open Threat Modeling", icon="➡️")
        st.caption("Listed as *streamlit app* in the sidebar.")
        st.markdown(
            "1. **Pick the model** in the sidebar. *Deterministic (offline)* needs no key "
            "but cannot read diagrams.\n"
            "2. **Set the application facets**: name, platforms, AI capability, data "
            "classification and PCI scope. These decide which controls are expected.\n"
            "3. **Describe the architecture** in the text box and **upload the diagram** "
            "(PNG / JPG).\n"
            "4. **Detect controls.** The AI reads the description and diagram and "
            "pre-fills the control declaration, with its reasoning and the sentence or "
            "diagram element it relied on.\n"
            "5. **Review the declaration.** Correct statuses, add evidence notes, tick "
            "*Reviewed*. Use *Find control* to jump to one by ID or name (e.g. CORS). "
            "Your changes are recorded under your name (set it in the sidebar).\n"
            "6. **Run threat model** and download the report as Markdown or PDF.")
        st.info("On this page, a control the AI finds no evidence for stays **unknown**, "
                "not missing. Unknowns become *clarifications* in the report rather than "
                "findings, so the reviewer decides.")

    st.subheader("Tips")
    st.markdown(
        "- **Moving from SAD to a human review:** download the declaration JSON from the "
        "SAD page and load it on the Threat Modeling page (*Load a saved declaration*) to "
        "review and correct each control before re-running.\n"
        "- **Save your declaration** between ARB rounds; it reloads exactly as you left it.\n"
        "- **Controls you have that aren't in the catalog** can be listed on the Threat "
        "Modeling page. If relevant, they soften the score of related threats as a "
        "*compensating control* (see DREAD scoring).\n"
        "- The **Control Catalog** page lists every control the tool checks, with guidance.")
    st.page_link("pages/1_Control_Catalog.py", label="Open Control Catalog", icon="📚")

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
        ("D", "Damage", "How bad is it if the attack succeeds?",
         "Data exposed or altered, money lost, systems down. Higher for more sensitive data."),
        ("R", "Reproducibility", "How reliably can the attack be repeated?",
         "10 = works every time; 1 = needs rare timing or conditions."),
        ("E", "Exploitability", "How much effort or skill does the attack take?",
         "10 = a script or a stolen password; 1 = an expert with insider access."),
        ("A", "Affected users", "How many users or systems are hit?",
         "10 = everyone; 1 = a single user or an isolated component."),
        ("D", "Discoverability", "How easy is the weakness to find?",
         "10 = visible from outside or publicly known; 1 = needs deep internal knowledge."),
    ], columns=["Letter", "Factor", "Question it answers", "How to think about the scale"]),
        hide_index=True)

    st.subheader("From five scores to a priority")
    st.markdown("The app averages the five factors (rounded to two decimals):")
    st.latex(r"\text{DREAD average} = \frac{D + R + E + A + D}{5}")
    st.markdown("and maps the average to a priority band:")
    st.table(pd.DataFrame([
        ("Critical", "7.5 or higher", "Fix before go-live / raise at ARB."),
        ("High", "6.0 to 7.49", "Fix in the current delivery plan."),
        ("Medium", "4.0 to 5.99", "Schedule; track to closure."),
        ("Low", "below 4.0", "Accept or fix opportunistically."),
    ], columns=["Priority", "Average", "Typical response"]), hide_index=True)
    st.caption("The bands are fixed in the app. The 'typical response' column is a "
               "suggested reading, not something the tool enforces.")

    st.subheader("How the app sets the five scores")
    st.markdown(
        "- **With an AI engine** (OpenAI, Anthropic, Bedrock), the model scores each "
        "threat 1-10 per factor, told that a *missing* control scores higher on damage and "
        "exploitability than a *partial* one, and that a compensating control lowers them.\n"
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
