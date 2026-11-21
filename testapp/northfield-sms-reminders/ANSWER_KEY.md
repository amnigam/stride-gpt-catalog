# Northfield SMS Reminders — answer key

Expected results when this sample is run through the threat modeling utility. LLM output varies between runs and models, so treat this as the intended result: a status one step away (for example *partial* instead of *implemented*) is normal, but a control on the wrong side of present/absent is worth a look.

## Files

- `Northfield_SMSReminders_SAD_v1.0.docx` — SAD for the SAD upload page (Word, diagram embedded)
- `Northfield_SMSReminders_SAD_v1.0.pdf` — the same SAD as PDF
- `Northfield_SMSReminders_Description.txt` — description for the main page (paste into the description box)
- `Northfield_SMSReminders_Architecture.png` — architecture diagram for the main page

## Expected facets (confirmation screen on the SAD page)

| Facet | Expected |
|---|---|
| Platforms | cloud |
| AI capability | none |
| Data classification | Confidential |
| Cardholder data (PCI) | No — PCI out of scope (stated explicitly) |
| Expected control count | 42 |

## Things this sample is designed to test

- Minimal demo app: one platform layer only, so the run is quick and the report short. The SAD states plainly that there is no web UI, no API, no queue or file transfer, no containers and no AI. If the model still ticks one of those facets on the confirmation screen, untick it before running; that is a good moment to show the reviewer step.
- Serverless on Google Cloud: expect the cloud facet only. Cloud Functions run on Google-managed containers and Cloud Scheduler calls the function over HTTPS, so a model may tick container or api; the SAD says the team builds no containers and the function accepts only internal, authenticated calls.
- Health-related personal data makes it Confidential. PCI is out of scope (stated).
- The headline gaps are deliberate and stated: DEBUG logs with full phone numbers and message text, standing Owner for every engineer, unrestricted egress and the API key duplicated in Cloud Build.
- Strong points (keyless service accounts, IAM DB auth, private IP, Terraform with drift check, Semgrep, DPIA) should come back implemented and produce no findings.

## Expected status mix on the SAD page

| Status | Controls |
|---|---|
| implemented | 20 |
| partial | 12 |
| partial (inferred, AI note) | 1 |
| not present (stated) | 4 |
| not present (not stated) | 5 |

Out-of-catalog controls the SAD describes (should appear as catalog candidates): Quiet-hours rule: no SMS outside 09:00-20:00 UK time; Daily send cap of 3,000 messages with an on-call alert.

## Control-by-control expectations

Description-page column: what Detect should pre-fill from the description text and the architecture diagram. That page never marks a control absent, so controls the description says are missing stay *unknown* and the reviewer declares them *not present*.

| Control | Title | Layer | SAD page | Description page | Evidence in the sample |
|---|---|---|---|---|---|
| IAM-SSO-001 | Centralized authentication / SSO | base | implemented | implemented | Google Workspace accounts for engineers (§6.1) |
| IAM-LPA-001 | Least-privilege access (RBAC) | base | implemented | implemented | Service account and DB user limited to one view and one insert table (§6.2) |
| DATA-ENC-001 | Data-at-rest encryption | base | implemented | implemented | Google default encryption at rest (§4.2) |
| DATA-TLS-001 | Strong transport encryption (TLS 1.2+) | base | implemented | implemented | TLS 1.2+ to SignalPost and Cloud SQL (§5, §10) |
| LOG-AUD-001 | Centralized audit logging | base | partial | partial | Cloud Logging 30 days; not forwarded to a SIEM (§11.1) |
| DATA-CLS-001 | Data classification applied | base | implemented | implemented | Classified Northfield Confidential by the DPO (§4.1) |
| SEC-SECRETS-001 | Secrets management | base | partial | partial | Secret Manager, but the key is also a Cloud Build substitution variable (§8.3) |
| IN-VAL-001 | Input validation and output encoding | base | partial | partial | Phone numbers validated; first name inserted unchecked (§7) |
| SCA-SBOM-001 | Software composition analysis & SBOM | base | implemented | implemented (diagram) | pip-audit blocks High/Critical; CycloneDX SBOM per release (§8.3; diagram) |
| IAM-MFA-001 | Multi-factor and phishing-resistant authentication | base | implemented | implemented | Workspace 2-step verification with security keys (§6.1) |
| IAM-PAM-001 | Privileged access governance | base | not present (stated) | unknown → declare not present | Standing Owner role for all three engineers, no JIT (§6.1) |
| IAM-S2S-001 | Service-to-service authentication (mTLS / workload identity) | base | implemented | implemented | Keyless service account, OIDC from Scheduler, IAM DB auth (§5, §6.2) |
| DATA-MASK-001 | Data masking, tokenisation and field-level encryption | base | implemented | implemented | Send log keeps only the last three digits of the mobile number (§4.2) |
| DATA-LIFE-001 | Data lifecycle, retention and disposal | base | partial | partial | 90-day send-log purge; SignalPost keeps content 12 months (§4.2) |
| LOG-RED-001 | Log and telemetry redaction | base | not present (stated) | unknown → declare not present | DEBUG logs hold full phone number and message text (§11.1) |
| LOG-CORR-001 | End-to-end correlation and security alerting | base | partial | partial | Operational alerts to on-call; no SIEM or security alerting (§11.1) |
| EXT-TPR-001 | Third-party integration and data-sharing approval | base | implemented | implemented | SignalPost VSA completed, DPA signed (§9) |
| NET-EGRESS-001 | Egress control and exfiltration protection | base | not present (stated) | unknown → declare not present | Unrestricted outbound internet from the function (§8.2) |
| RES-DEP-001 | Dependency resilience and fail-safe behaviour | base | implemented | implemented | Backoff for two hours, then 'not sent' and reception phones; idempotency key (§7) |
| RES-DR-001 | Backup and recovery assurance | base | partial | unknown | Daily backups + PITR; restore not tested (§11.3) |
| IR-RESP-001 | Application incident containment | base | partial | partial | Pause the scheduler job; no wrong-recipient playbook (§11.2) |
| SDLC-SAST-001 | SAST, DAST and secure code review in the pipeline | base | implemented | implemented | Semgrep on every pull request, findings fail the build (§8.3) |
| SDLC-PIPE-001 | CI/CD pipeline and build integrity | base | implemented | implemented | Terraform via Cloud Build with WIF, branch protection (§8.3) |
| VULN-PATCH-001 | Vulnerability and patch management with SLAs | base | partial (inferred, AI note) | unknown | Serverless: Google patches the runtime; no patch SLA stated (§8.1) |
| SEC-PENTEST-001 | Pre-go-live penetration test and retest | base | not present (stated) | unknown | Not planned (§10) |
| ERR-HAND-001 | Secure error handling | base | not present (not stated) | unknown | Not mentioned |
| DATA-CRYPTO-001 | Approved cryptography and certificate lifecycle | base | not present (not stated) | unknown | Not mentioned |
| IAM-LCM-001 | Identity lifecycle and access recertification | base | partial | unknown | HR leaver process, but no periodic access review of project roles (§6.1) |
| IAM-ATO-001 | Account recovery and account-takeover protection | base | not present (not stated) | unknown | Not mentioned (no end-user accounts) |
| DATA-RES-001 | Data residency and cross-border transfer | base | implemented | implemented | europe-west2 only; SignalPost UK-only processing (§4.2) |
| DATA-PRIV-001 | Privacy by design and data subject rights | base | implemented | implemented | DPIA approved, opt-in consent checked before sending (§4.2) |
| DATA-NONPROD-001 | Production data kept out of non-production | base | partial | partial | Test uses real appointments with phone numbers replaced (§4.2) |
| NET-MGMT-001 | Management and admin plane isolation | base | not present (not stated) | unknown | Not mentioned |
| CLD-SEG-001 | Network segmentation / VPC boundaries | platform.cloud | implemented | implemented | Dedicated project; private-IP database over the Shared VPC connector (§2, §8.2) |
| CLD-KMS-001 | Managed key management (KMS) | platform.cloud | partial | partial | Google-managed keys only, no CMEK (§4.2) |
| CLD-IAM-001 | Cloud IAM roles (least privilege) | platform.cloud | partial | partial | Service accounts least-privilege, but engineers hold basic Owner (§6) |
| CLD-SG-001 | Restrictive security groups | platform.cloud | implemented | implemented (diagram) | Shared VPC firewall denies all ingress; SQL only from connector range (§8.2; diagram) |
| IMMUT-001 | Immutable infrastructure and configuration drift management | platform.cloud/platform.onprem | implemented | implemented | All infrastructure in Terraform with nightly drift check (§8.3) |
| CLD-CSPM-001 | Cloud posture management and guardrails | platform.cloud | partial | partial (diagram) | Org policies inherited; Security Command Center not enabled (§8.1; diagram) |
| CLD-LOG-001 | Cloud control-plane audit logging | platform.cloud | implemented | implemented (diagram) | Cloud Audit Logs to a locked bucket, 400 days (§11.1; diagram) |
| CLD-PE-001 | Private endpoints for managed services | platform.cloud | implemented | implemented | Cloud SQL private IP only, public IP disabled (§8.2) |
| EDR-001 | Endpoint detection & response (EDR) telemetry | platform.onprem/platform.cloud | not present (not stated) | unknown | Not mentioned (serverless) |
