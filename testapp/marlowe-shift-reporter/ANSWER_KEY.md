# Marlowe Shift Reporter — answer key

Expected results when this sample is run through the threat modeling utility. LLM output varies between runs and models, so treat this as the intended result: a status one step away (for example *partial* instead of *implemented*) is normal, but a control on the wrong side of present/absent is worth a look.

## Files

- `Marlowe_ShiftReporter_SAD_v1.0.docx` — SAD for the SAD upload page (Word, diagram embedded)
- `Marlowe_ShiftReporter_SAD_v1.0.pdf` — the same SAD as PDF
- `Marlowe_ShiftReporter_Description.txt` — description for the main page (paste into the description box)
- `Marlowe_ShiftReporter_Architecture.png` — architecture diagram for the main page

## Expected facets (confirmation screen on the SAD page)

| Facet | Expected |
|---|---|
| Platforms | onprem |
| AI capability | none |
| Data classification | Internal |
| Cardholder data (PCI) | No — PCI out of scope (stated explicitly) |
| Expected control count | 37 |

## Things this sample is designed to test

- Minimal demo app: one platform layer only, so the run is quick and the report short. The SAD states plainly that there is no web UI, no API, no queue or file transfer, no containers and no AI. If the model still ticks one of those facets on the confirmation screen, untick it before running; that is a good moment to show the reviewer step.
- On-premises only: expect the onprem facet (firewall, host hardening, EDR) and *not* cloud. The reports are viewed in an existing Power BI Report Server that the SAD puts out of scope, so web should stay unticked.
- Firewall rules, the MFA jump host, the CIS baseline and Defender for Endpoint are clearest on the diagram, so the description page needs the image to find them.
- Stated absences (no TDE or disk encryption, no dependency scanning, no Splunk alerting, no pentest) should come back *not present* with a quote.
- Internal classification, no PCI: expect a short report with a handful of High findings at most.

## Expected status mix on the SAD page

| Status | Controls |
|---|---|
| implemented | 15 |
| partial | 10 |
| partial (inferred, AI note) | 1 |
| not present (stated) | 5 |
| not present (not stated) | 6 |

Out-of-catalog controls the SAD describes (should appear as catalog candidates): Reconciliation of computed shift output against ERP goods-receipt totals (>2% variance flags the report 'unverified').

## Control-by-control expectations

Description-page column: what Detect should pre-fill from the description text and the architecture diagram. That page never marks a control absent, so controls the description says are missing stay *unknown* and the reviewer declares them *not present*.

| Control | Title | Layer | SAD page | Description page | Evidence in the sample |
|---|---|---|---|---|---|
| IAM-SSO-001 | Centralized authentication / SSO | base | implemented | implemented | AD accounts with Windows integrated sign-in to the reports (§6.1) |
| IAM-LPA-001 | Least-privilege access (RBAC) | base | partial | partial | Read-only views on the MES, but db_owner on SHIFTKPI (§6.2, OI-1) |
| DATA-ENC-001 | Data-at-rest encryption | base | not present (stated) | unknown → declare not present | No TDE and no disk encryption (§4.2, §10) |
| DATA-TLS-001 | Strong transport encryption (TLS 1.2+) | base | partial | partial | TLS 1.2 on SQL, plain-text SMTP to the relay (§5) |
| LOG-AUD-001 | Centralized audit logging | base | partial | partial | Local log files only; Windows events to Splunk, app logs not forwarded (§11.1) |
| DATA-CLS-001 | Data classification applied | base | implemented | implemented | Classified Marlowe Internal under ISP-04 (§4.1) |
| SEC-SECRETS-001 | Secrets management | base | implemented | implemented | gMSA with AD-rotated password; no stored secrets (§6.2) |
| IN-VAL-001 | Input validation and output encoding | base | implemented | implemented | MES rows range-checked; parameterised SQL (§7) |
| SCA-SBOM-001 | Software composition analysis & SBOM | base | not present (stated) | unknown | Dependencies pinned but not scanned; no SBOM (§8.4) |
| IAM-MFA-001 | Multi-factor and phishing-resistant authentication | base | partial | partial (diagram) | Duo MFA on the admin jump host; no MFA for report readers (§6.1; diagram) |
| IAM-PAM-001 | Privileged access governance | base | implemented | implemented | CyberArk check-out with session recording (§6.1) |
| IAM-S2S-001 | Service-to-service authentication (mTLS / workload identity) | base | implemented | implemented | gMSA with Kerberos to both databases (§5, §6.2) |
| DATA-MASK-001 | Data masking, tokenisation and field-level encryption | base | not present (not stated) | unknown | Not mentioned |
| DATA-LIFE-001 | Data lifecycle, retention and disposal | base | implemented | implemented | Three-year retention with a monthly purge job (§4.2) |
| LOG-RED-001 | Log and telemetry redaction | base | not present (not stated) | unknown | Not mentioned |
| LOG-CORR-001 | End-to-end correlation and security alerting | base | not present (stated) | unknown → declare not present | No Splunk alerts or correlation for this application (§11.1) |
| EXT-TPR-001 | Third-party integration and data-sharing approval | base | partial | partial | Contract with confidentiality clause, no vendor security assessment (§9) |
| NET-EGRESS-001 | Egress control and exfiltration protection | base | implemented | implemented (diagram) | No internet route from the server VLAN; outbound denied by default (§8.2; diagram) |
| RES-DEP-001 | Dependency resilience and fail-safe behaviour | base | partial | partial | Retries then alerts Plant IT, but the report shows stale data unflagged (§7) |
| RES-DR-001 | Backup and recovery assurance | base | partial | partial | Nightly Veeam and SQL backups; restore never tested, single server (§11.2) |
| IR-RESP-001 | Application incident containment | base | not present (not stated) | unknown | Not mentioned |
| SDLC-SAST-001 | SAST, DAST and secure code review in the pipeline | base | partial | partial | Peer review only, no SAST (§8.4) |
| SDLC-PIPE-001 | CI/CD pipeline and build integrity | base | partial | partial | Branch policy, but manual deployment over RDP (§8.4) |
| VULN-PATCH-001 | Vulnerability and patch management with SLAs | base | implemented | implemented | Monthly WSUS, critical within 14 days, weekly Qualys (§8.3) |
| SEC-PENTEST-001 | Pre-go-live penetration test and retest | base | not present (stated) | unknown | Not planned (§10) |
| ERR-HAND-001 | Secure error handling | base | not present (not stated) | unknown | Not mentioned |
| DATA-CRYPTO-001 | Approved cryptography and certificate lifecycle | base | partial (inferred, AI note) | unknown | SQL TLS certificates from the internal CA imply a certificate lifecycle; no crypto standard named (§5) |
| IAM-LCM-001 | Identity lifecycle and access recertification | base | implemented | implemented | ServiceNow requests, quarterly recertification, HR-driven leavers (§6.3) |
| IAM-ATO-001 | Account recovery and account-takeover protection | base | not present (not stated) | unknown | Not mentioned |
| DATA-RES-001 | Data residency and cross-border transfer | base | implemented | implemented | All data stays in the Harrogate data centre, UK (§4.2) |
| DATA-PRIV-001 | Privacy by design and data subject rights | base | not present (not stated) | unknown | Supervisor names are personal data; no DPIA or privacy review mentioned |
| DATA-NONPROD-001 | Production data kept out of non-production | base | implemented | implemented | Test uses a synthetic MES dataset (§4.2) |
| NET-MGMT-001 | Management and admin plane isolation | base | implemented | implemented (diagram) | RDP only from the MFA jump host in the admin VLAN (§6.1, §8.2; diagram) |
| ONP-FW-001 | Network firewall | platform.onprem | implemented | implemented (diagram) | Plant firewall: RDP from jump host, SQL from Report Server only (§8.2; diagram) |
| ONP-HARD-001 | Host hardening (CIS benchmark) | platform.onprem | partial | partial (diagram) | CIS L1 GPO baseline with 12 exceptions; SQL Server not hardened (§8.1; diagram) |
| EDR-001 | Endpoint detection & response (EDR) telemetry | platform.onprem/platform.cloud | implemented | implemented (diagram) | Defender for Endpoint on both servers (§8.1; diagram) |
| IMMUT-001 | Immutable infrastructure and configuration drift management | platform.cloud/platform.onprem | not present (stated) | unknown | Servers built by hand, manual changes over RDP, no drift detection (§8.1) |
