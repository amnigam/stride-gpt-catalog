# Corvane Supplier Hub — answer key

Expected results when this sample is run through the threat modeling utility. LLM output varies between runs and models, so treat this as the intended result: a status one step away (for example *partial* instead of *implemented*) is normal, but a control on the wrong side of present/absent is worth a look.

## Files

- `Corvane_SupplierHub_SAD_v1.2.docx` — SAD for the SAD upload page (Word, diagram embedded)
- `Corvane_SupplierHub_SAD_v1.2.pdf` — the same SAD as PDF
- `Corvane_SupplierHub_SAD_v0.1_DRAFT_incomplete.docx` — deliberately insufficient draft: the SAD page should STOP with no report
- `Corvane_SupplierHub_Description.txt` — description for the main page (paste into the description box)
- `Corvane_SupplierHub_Architecture.png` — architecture diagram for the main page

## Expected facets (confirmation screen on the SAD page)

| Facet | Expected |
|---|---|
| Platforms | web, cloud |
| AI capability | none |
| Data classification | Confidential |
| Cardholder data (PCI) | No — PCI out of scope (stated explicitly) |
| Expected control count | 53 |

## Insufficient-SAD test

Upload `Corvane_SupplierHub_SAD_v0.1_DRAFT_incomplete.docx`. It has a purpose but no diagram and no components or technology stack, so two hard minimums (diagram, components) are missing. Expected: the page stops, produces the completeness feedback document, and no threat report.

## Things this sample is designed to test

- WAF, login rate limit, CSPM and the SCM restriction appear only on the diagram, not in the description text, so the description page can only find them by reading the image.
- Explicit absences (no PIM, no SIEM, prod data in UAT, no SRI, HSTS not configured) should come back *not present* with a quote, not just silence.
- PaaS patching and Front Door managed certificates should be *partial (inferred)* with a 'confirm' note.
- PCI should be out of scope because the SAD says so explicitly.

## Expected status mix on the SAD page

| Status | Controls |
|---|---|
| implemented | 23 |
| partial | 14 |
| partial (inferred, AI note) | 2 |
| not present (stated) | 6 |
| not present (not stated) | 8 |

Out-of-catalog controls the SAD describes (should appear as catalog candidates): Sanctions screening of new suppliers (EU consolidated list); Duplicate-supplier detection on tax ID / IBAN.

## Control-by-control expectations

Description-page column: what Detect should pre-fill from the description text and the architecture diagram. That page never marks a control absent, so controls the description says are missing stay *unknown* and the reviewer declares them *not present*.

| Control | Title | Layer | SAD page | Description page | Evidence in the sample |
|---|---|---|---|---|---|
| IAM-SSO-001 | Centralized authentication / SSO | base | implemented | implemented | Entra ID SSO for staff; External ID for suppliers (§6.1) |
| IAM-LPA-001 | Least-privilege access (RBAC) | base | implemented | implemented | Server-side RBAC via Entra app roles; own-company scoping (§6.2) |
| DATA-ENC-001 | Data-at-rest encryption | base | implemented | implemented | TDE on SQL, SSE on Storage (§4.2) |
| DATA-TLS-001 | Strong transport encryption (TLS 1.2+) | base | implemented | implemented | TLS 1.2 minimum, HTTPS only (§5, §10) |
| LOG-AUD-001 | Centralized audit logging | base | partial | partial | Audit table + App Insights, but not centralised in the SIEM (§11.1) |
| DATA-CLS-001 | Data classification applied | base | implemented | implemented | Classified Corvane Confidential, tagged in the data catalogue (§4.1) |
| SEC-SECRETS-001 | Secrets management | base | implemented | implemented | Key Vault + managed identity, no secrets in config (§10) |
| IN-VAL-001 | Input validation and output encoding | base | partial | partial | Server-side validation only on the registration form (§10) |
| SCA-SBOM-001 | Software composition analysis & SBOM | base | implemented | unknown | Dependabot + CycloneDX SBOM per build (§10) |
| IAM-MFA-001 | Multi-factor and phishing-resistant authentication | base | partial | partial | MFA enforced for staff, optional SMS OTP for suppliers (§6.1) |
| IAM-PAM-001 | Privileged access governance | base | not present (stated) | unknown | Standing Contributor rights, no PIM (§10) |
| IAM-S2S-001 | Service-to-service authentication (mTLS / workload identity) | base | implemented | implemented | Managed identity to SQL/Storage/Key Vault; Entra-only SQL auth (§5) |
| DATA-MASK-001 | Data masking, tokenisation and field-level encryption | base | partial | partial | IBAN masked in UI but stored in clear apart from TDE (§4.2) |
| DATA-LIFE-001 | Data lifecycle, retention and disposal | base | not present (not stated) | unknown | No retention/disposal rule for supplier data (audit retention only) |
| LOG-RED-001 | Log and telemetry redaction | base | not present (not stated) | unknown | Not mentioned |
| LOG-CORR-001 | End-to-end correlation and security alerting | base | not present (stated) | unknown → declare not present | No SIEM forwarding or security alerting until phase 2 (§11.1) |
| EXT-TPR-001 | Third-party integration and data-sharing approval | base | partial | unknown | BankVerify assessed; SendGrid assessment not started (§9) |
| NET-EGRESS-001 | Egress control and exfiltration protection | base | not present (stated) | unknown → declare not present | Outbound internet from App Service not restricted (§8.2; diagram label) |
| RES-DEP-001 | Dependency resilience and fail-safe behaviour | base | implemented | implemented | BankVerify outage -> retry, approval blocked: fails closed (§7) |
| RES-DR-001 | Backup and recovery assurance | base | partial | partial | PITR + GRS, but restores never tested (§11.2) |
| IR-RESP-001 | Application incident containment | base | not present (not stated) | unknown | Not mentioned |
| SDLC-SAST-001 | SAST, DAST and secure code review in the pipeline | base | partial | partial | CodeQL SAST, no DAST (§10) |
| SDLC-PIPE-001 | CI/CD pipeline and build integrity | base | implemented | implemented | GitHub Actions with OIDC, branch protection, required review (§8.3) |
| VULN-PATCH-001 | Vulnerability and patch management with SLAs | base | partial (inferred, AI note) | unknown | PaaS: OS/runtime patching by Microsoft; app patch SLAs not stated (§8.1) |
| SEC-PENTEST-001 | Pre-go-live penetration test and retest | base | implemented | unknown | External pentest before go-live with retest (§10) |
| ERR-HAND-001 | Secure error handling | base | not present (not stated) | unknown | Not mentioned |
| DATA-CRYPTO-001 | Approved cryptography and certificate lifecycle | base | partial (inferred, AI note) | partial (diagram) | Front Door managed certificate implies certificate lifecycle; no crypto standard named |
| IAM-LCM-001 | Identity lifecycle and access recertification | base | implemented | unknown | JML from HR + quarterly review of Approver/Admin; dormant supplier accounts disabled (§6.3) |
| IAM-ATO-001 | Account recovery and account-takeover protection | base | partial | unknown | E-mailed reset code only; no ATO detection (§6.1) |
| DATA-RES-001 | Data residency and cross-border transfer | base | implemented | implemented | West Europe + North Europe, no data leaves the EU (§4.2) |
| DATA-PRIV-001 | Privacy by design and data subject rights | base | not present (not stated) | unknown | No DPIA or data-subject-rights process mentioned |
| DATA-NONPROD-001 | Production data kept out of non-production | base | not present (stated) | unknown | UAT refreshed monthly from a production copy (§8.4) |
| NET-MGMT-001 | Management and admin plane isolation | base | implemented | implemented (diagram) | SCM/Kudu restricted to corporate IPs; OIDC deploys (§8.2; diagram) |
| WEB-WAF-001 | Web application firewall | platform.web | implemented | implemented (diagram) | Front Door WAF, DRS 2.1, Prevention mode (§10; description omits it, diagram shows it) |
| WEB-CSRF-001 | CSRF protection | platform.web | implemented | implemented | Global antiforgery filter on POST handlers (§10) |
| WEB-SESS-001 | Secure session management | platform.web | partial | partial | Secure/HttpOnly cookies but 8-hour sliding expiry, SameSite not stated (§6.1) |
| WEB-HDR-001 | Security response headers | platform.web | not present (stated) | unknown | HSTS not configured; no other headers stated (§10) |
| WEB-RATE-001 | Request rate limiting | platform.web | partial | partial (diagram) | Rate limit only on /Account/Login (§10; diagram) |
| BIZ-TXN-001 | Business transaction integrity | platform.web/platform.api | implemented | implemented | Maker-checker; bank change forces re-approval (§7) |
| BIZ-ABUSE-001 | Business workflow abuse prevention | platform.web/platform.api | partial | unknown | reCAPTCHA on registration only (§7) |
| WEB-DDOS-001 | DDoS protection and bot mitigation | platform.web/platform.api | implemented | unknown | Front Door built-in DDoS protection (§10) |
| FILE-ING-001 | Secure file ingestion and processing | platform.web/platform.api | partial | partial | Type/size limits and GUID names; malware scanning not yet enabled (§10) |
| WEB-SCRIPT-001 | Client-side script integrity | platform.web | not present (stated) | unknown | jQuery/Bootstrap from public CDN without SRI (§10) |
| WEB-CORS-001 | CORS policy | platform.web | not present (not stated) | unknown | Not mentioned (server-rendered app) |
| CLD-SEG-001 | Network segmentation / VPC boundaries | platform.cloud | implemented | implemented | Dedicated VNet with app and private-endpoint subnets (§8.2) |
| CLD-KMS-001 | Managed key management (KMS) | platform.cloud | partial | partial | Platform-managed keys only; CMK deferred (§4.2, OI-5) |
| CLD-IAM-001 | Cloud IAM roles (least privilege) | platform.cloud | implemented | implemented | Managed identity with scoped access; Entra-only SQL (§5) |
| CLD-SG-001 | Restrictive security groups | platform.cloud | implemented | implemented | NSGs on both subnets; App Service access restricted to Front Door (§8.2) |
| IMMUT-001 | Immutable infrastructure and configuration drift management | platform.cloud/platform.onprem | partial | partial | Bicep IaC, but portal hotfixes allowed and no drift detection (§8.3); the description only says Bicep, so expect implemented there |
| CLD-CSPM-001 | Cloud posture management and guardrails | platform.cloud | implemented | implemented (diagram) | Azure Policy baseline + Defender for Cloud CSPM (§8.1; diagram) |
| CLD-LOG-001 | Cloud control-plane audit logging | platform.cloud | not present (not stated) | unknown | Azure Activity Log collection not mentioned |
| CLD-PE-001 | Private endpoints for managed services | platform.cloud | implemented | implemented | Private endpoints for SQL, Storage, Key Vault; public access disabled (§8.2) |
| EDR-001 | Endpoint detection & response (EDR) telemetry | platform.onprem/platform.cloud | not present (not stated) | unknown | Not mentioned (PaaS) |
