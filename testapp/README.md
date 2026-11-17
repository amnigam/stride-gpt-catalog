# PeopleDesk — test subject

A small, deliberately representative application used to exercise the engine
end to end. It is the canonical example referenced throughout the test suite
(`tests/test_pipeline.py`).

![PeopleDesk architecture](peopledesk_architecture.png)

## What it is

PeopleDesk is an **internal HR web application** deployed on AWS. HR staff sign
in through **Okta SSO**. The **employee database is encrypted at rest** and all
traffic uses **TLS 1.3**; a **WAF** fronts the app behind an ALB. The
distinguishing feature is an **LLM summarizer**: on request, the app pulls an
employee's records and asks an **external model endpoint** to summarize them.

## Why this subject

It sits exactly at the altitude this tool targets. The web/cloud plumbing is
mostly sound, so a generic web threat model would say "looks fine." The
interesting exposure is the **AI egress**: Restricted employee PII leaving the
trust boundary to a third-party model. That is what the AI-layer controls
(prompt-injection defense, data minimization, no-retention endpoint, output
filtering, authorization scoping, rate limiting, LLM logging) exist to govern —
and it is precisely what the facet-aware catalog pulls in once you declare the
app as **LLM-integrated**.

## Facets (the tool's inputs)

| Field | Value |
|---|---|
| Platforms | web, cloud |
| AI capability | `llm` (LLM-integrated) |
| Data classification | Restricted (employee PII) |
| Handles cardholder data | No → PCI out of scope |

## Evidence supplied to the tool

* **Description** (the paragraph above) — the text detector recognises SSO,
  encryption-at-rest, TLS and WAF and marks them *implemented* (low confidence).
* **Declaration** — the architect declares the AI controls **not present**
  (`AI-PI-001`, `AI-ENDP-001`, `AI-OUT-001`, `AI-RATE-001`, `AI-LOG-001`).
* **Out-of-catalog** — "PII display tokenization" (masks identifiers on screen
  after the model call); the engine recognises it as a compensating
  InformationDisclosure control and flags it as a catalog candidate.

## Expected result (what the tests assert)

* The declared-absent **AI controls surface as findings**, with threats and
  DREAD scores (Restricted data + missing controls ⇒ at least one Critical/High).
* The **described controls are not findings** (SSO, encryption, TLS, WAF).
* Web controls that were **neither described nor declared** (CSRF, session,
  headers, secrets…) become **clarifications, not findings** — unknown ≠ missing.
* **PCI section is out of scope** (no cardholder data).
* **Tokenization** appears as a compensating control and a catalog candidate.

Run it yourself with the example intake:

```bash
python -m threatcatalog.cli testapp/peopledesk_intake.json --out /tmp/peopledesk.md
```

---

# Sample applications for end-to-end testing

Two fictional applications with everything needed to test both input modes.
Each folder has an `ANSWER_KEY.md` with the expected facets and the expected
status of every control, so a run can be checked line by line.

| Sample | What it is | SAD page | Main page (description + diagram) |
|---|---|---|---|
| [`corvane-supplier-hub/`](corvane-supplier-hub/ANSWER_KEY.md) | Simple web app on Azure (App Service, SQL, Blob, Front Door). 53 controls: web, cloud, no AI, Confidential, no PCI. | `Corvane_SupplierHub_SAD_v1.2.docx` or `.pdf`; `..._v0.1_DRAFT_incomplete.docx` must stop the run | `Corvane_SupplierHub_Description.txt` + `Corvane_SupplierHub_Architecture.png` |
| [`halcyon-claimpilot/`](halcyon-claimpilot/ANSWER_KEY.md) | Agentic AI claims app on AWS (EKS, Bedrock, LangGraph agents, MCP, RAG, Kafka, fine-tuned model). 111 controls: web, cloud, api, container, messaging + agentic, mcp, generative, training; Restricted; PCI in scope. | `Halcyon_ClaimPilot_SAD_v2.0.docx` or `.pdf` (3 diagrams embedded) | `Halcyon_ClaimPilot_Description.txt` + `Halcyon_ClaimPilot_Architecture_Overview.png` |

On the main page set the facets by hand to the values in the answer key, paste
the description, upload the diagram and press Detect. The SAD page infers the
facets itself; compare its confirmation screen with the answer key.

Each SAD deliberately mixes controls that are stated as in place, stated with
limits (partial), only inferable from the tech stack (partial with an AI note),
stated as missing, and not mentioned at all, so every status appears in the
report. The sources and build scripts are in [`sources/`](sources/).
