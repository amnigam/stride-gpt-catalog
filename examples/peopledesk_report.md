# Threat Model — PeopleDesk

*Platforms:* web, cloud  
*AI capability:* llm  
*Data classification:* Restricted  
*Expected controls:* 71  
*PCI in scope:* no

*Generated:* 2026-11-22 10:55:39 UTC  
*Review state:* 6 of 71 control statuses confirmed by a reviewer

## Key focus items

*This page summarises the security findings to inform the Architecture Review Board. It does not decide the review outcome.*

### Security readiness: Not ready

3 evidence-backed critical finding(s).

*Security readiness is set by the tool from this report's findings, with a fixed rule; no person chooses it. Not ready: a Critical finding backed by evidence, or a PCI-mapped control that is not present. Ready with conditions: any High finding, a finding without a DREAD score, or a control not yet assessed. Ready: none of these; Medium and Low gaps remain and are listed in the action plan. Severity comes from each threat's DREAD score (see DREAD scoring). The marker informs the ARB; it does not decide the outcome.*

**Address before go-live:**
- AI-RATE-001 Rate / spend limits on model endpoint — Critical, not present
- AI-PI-001 Prompt-injection defense — Critical, not present
- AI-LOG-001 LLM prompt/response logging and decision traceability — Critical, not present

**Risks for the business to consider:**
- AI-ENDP-001 No-retention / enterprise model endpoint — High, not present
- AI-OUT-001 Output filtering for sensitive disclosure — High, not present
- AI-AUTHZ-001 Authorization scoping on AI features — High, partial

**Open questions for the team:**
- AI-DM-001 Data minimization before model call — status unknown
- AI-VEC-001 Vector store / RAG document-level access control — status unknown
- AI-MODEL-PROV-001 Model provenance & integrity — status unknown
- AI-GOV-001 AI system and model governance — status unknown
- AI-CFG-001 AI model, prompt and guardrail change control — status unknown
- AI-SPL-001 System prompt leakage protection — status unknown
- AI-EVAL-001 AI security evaluation and red teaming — status unknown
- AI-OUT-ACT-001 AI output validation before action — status unknown
- AI-SRC-001 External content provenance and trust — status unknown
- AI-RAG-ING-001 RAG ingestion integrity — status unknown
- …and 51 more (see the findings register)

| Role | Name | Date |
|---|---|---|
| Prepared by |  | |
| Reviewed by (AppSec / security champion) |  | |
| Business risk owner |  | |

## Executive summary

**Expected** 71 · **Confirmed in place** 4 · **Not present** 5 · **Partial** 1 · **To verify** 65 · **Reviewed** 6 of 71

*To verify: controls whose status is still Unknown, plus statuses that rest on an AI evaluation no reviewer has confirmed. Reviewed: controls whose status a reviewer has confirmed or set.*

PeopleDesk — a web and cloud application with an LLM integration, handling data classified as Restricted — was assessed against the 71 security controls expected for an application of this type (the controls such a system should have in place).

The review confirmed 4 control(s) already in place and identified 6 gap(s) — 5 not implemented and 1 only partially implemented. A further 61 control(s) could not be confirmed from the evidence provided and are flagged for verification — an unconfirmed control is treated as a question to resolve, not a failure.

Confirmed protections include Centralized authentication / SSO, Data-at-rest encryption, and Strong transport encryption (TLS 1.2+); the most important gaps to close are Rate / spend limits on model endpoint, Prompt-injection defense, and LLM prompt/response logging and decision traceability.

The application does not handle cardholder data, so PCI DSS v4.0.1 is out of scope.

**Top findings (ranked by DREAD):**
- [Critical · 7.8] Rate / spend limits on model endpoint is not in place (AI-RATE-001, OWASP LLM LLM10:2025)
- [Critical · 7.6] Prompt-injection defense is not in place (AI-PI-001, OWASP LLM LLM01:2025)
- [Critical · 7.6] LLM prompt/response logging and decision traceability is not in place (AI-LOG-001, CIS v8 Control 8)
- [High · 7.0] No-retention / enterprise model endpoint is not in place (AI-ENDP-001, OWASP LLM LLM03:2025)
- [High · 7.0] Output filtering for sensitive disclosure is not in place (AI-OUT-001, OWASP LLM LLM02:2025)

**Strengths (confirmed in place):**
- IAM-SSO-001 Centralized authentication / SSO
- DATA-ENC-001 Data-at-rest encryption
- DATA-TLS-001 Strong transport encryption (TLS 1.2+)
- WEB-WAF-001 Web application firewall

**Also note:** 1 compensating control(s) noted (these soften, but do not eliminate, a finding); 4 control status(es) rest on AI evaluations that no reviewer has confirmed; 61 unknown control(s) need confirmation — treated as clarifications, not findings (unknown ≠ missing).

## Assessment basis

*Description:* 43 words  
*Diagrams read:* 0  
*Engine:* not recorded  
*Reviewed by:* no reviewer recorded  
*Generated:* 2026-11-22 10:55:39 UTC  
*Tool version:* 0.1.0  
*Catalog:* 123 controls · b09d74e8  

### Limitations of this assessment

- 61 control(s) are unknown: they are open questions, not findings, and are not reflected in the threats or DREAD scores.
- The description and diagrams were not checked for completeness against the SAD checklist.
- No architecture summary was available, so threats rest on the control gaps alone and do not name this system's components.

## Findings register

*Controls not present, partial or unknown. Controls confirmed in place are listed with their evidence in the appendix.*

| Control | Status | Basis | Frameworks |
|---|---|---|---|
| AI-PI-001 Prompt-injection defense | Not present | Reviewer | OWASP LLM LLM01:2025, OWASP Agentic ASI01:2026, CIS v8 Control 16 |
| AI-ENDP-001 No-retention / enterprise model endpoint | Not present | Reviewer | OWASP LLM LLM03:2025, CIS v8 Control 15 |
| AI-OUT-001 Output filtering for sensitive disclosure | Not present | Reviewer | OWASP LLM LLM02:2025, CIS v8 Control 3 |
| AI-LOG-001 LLM prompt/response logging and decision traceability | Not present | Reviewer | CIS v8 Control 8 |
| AI-RATE-001 Rate / spend limits on model endpoint | Not present | Reviewer | OWASP LLM LLM10:2025, CIS v8 Control 13 |
| AI-AUTHZ-001 Authorization scoping on AI features | Partial | Reviewer | CIS v8 Control 6 |
| AI-DM-001 Data minimization before model call | Unknown | — | OWASP LLM LLM02:2025, CIS v8 Control 3 |
| AI-VEC-001 Vector store / RAG document-level access control | Unknown | — | OWASP LLM LLM08:2025, OWASP LLM LLM02:2025, CIS v8 Control 3 |
| AI-MODEL-PROV-001 Model provenance & integrity | Unknown | — | OWASP LLM LLM03:2025, CIS v8 Control 2 |
| AI-GOV-001 AI system and model governance | Unknown | — | CIS v8 Control 2, OWASP LLM LLM03:2025 |
| AI-CFG-001 AI model, prompt and guardrail change control | Unknown | — | CIS v8 Control 4 |
| AI-SPL-001 System prompt leakage protection | Unknown | — | CIS v8 Control 3, OWASP LLM LLM07:2025 |
| AI-EVAL-001 AI security evaluation and red teaming | Unknown | — | CIS v8 Control 18, OWASP LLM LLM01:2025 |
| AI-OUT-ACT-001 AI output validation before action | Unknown | — | CIS v8 Control 16, OWASP LLM LLM05:2025 |
| AI-SRC-001 External content provenance and trust | Unknown | — | CIS v8 Control 16, OWASP LLM LLM01:2025, OWASP LLM LLM09:2025 |
| AI-RAG-ING-001 RAG ingestion integrity | Unknown | — | CIS v8 Control 3, OWASP LLM LLM04:2025, OWASP LLM LLM08:2025 |
| AI-MON-001 AI runtime alerting | Unknown | — | CIS v8 Control 8, OWASP LLM LLM10:2025 |
| AI-TRANS-001 AI transparency, grounding and overreliance | Unknown | — | CIS v8 Control 16, OWASP LLM LLM09:2025 |
| IAM-LPA-001 Least-privilege access (RBAC) | Unknown | — | CIS v8 Control 6 |
| LOG-AUD-001 Centralized audit logging | Unknown | — | CIS v8 Control 8 |
| DATA-CLS-001 Data classification applied | Unknown | — | CIS v8 Control 3 |
| SEC-SECRETS-001 Secrets management | Unknown | — | CIS v8 Control 6 |
| IN-VAL-001 Input validation and output encoding | Unknown | — | CIS v8 Control 16 |
| SCA-SBOM-001 Software composition analysis & SBOM | Unknown | — | CIS v8 Control 2 |
| IAM-MFA-001 Multi-factor and phishing-resistant authentication | Unknown | — | CIS v8 Control 6 |
| IAM-PAM-001 Privileged access governance | Unknown | — | CIS v8 Control 5, CIS v8 Control 6 |
| IAM-S2S-001 Service-to-service authentication (mTLS / workload identity) | Unknown | — | CIS v8 Control 6, CIS v8 Control 12 |
| DATA-MASK-001 Data masking, tokenisation and field-level encryption | Unknown | — | CIS v8 Control 3 |
| DATA-LIFE-001 Data lifecycle, retention and disposal | Unknown | — | CIS v8 Control 3 |
| LOG-RED-001 Log and telemetry redaction | Unknown | — | CIS v8 Control 3, CIS v8 Control 8 |
| LOG-CORR-001 End-to-end correlation and security alerting | Unknown | — | CIS v8 Control 8 |
| EXT-TPR-001 Third-party integration and data-sharing approval | Unknown | — | CIS v8 Control 15 |
| NET-EGRESS-001 Egress control and exfiltration protection | Unknown | — | CIS v8 Control 13, OWASP LLM LLM06:2025 |
| RES-DEP-001 Dependency resilience and fail-safe behaviour | Unknown | — | CIS v8 Control 16 |
| RES-DR-001 Backup and recovery assurance | Unknown | — | CIS v8 Control 11 |
| IR-RESP-001 Application incident containment | Unknown | — | CIS v8 Control 17 |
| SDLC-SAST-001 SAST, DAST and secure code review in the pipeline | Unknown | — | CIS v8 Control 16 |
| SDLC-PIPE-001 CI/CD pipeline and build integrity | Unknown | — | CIS v8 Control 16 |
| VULN-PATCH-001 Vulnerability and patch management with SLAs | Unknown | — | CIS v8 Control 7 |
| SEC-PENTEST-001 Pre-go-live penetration test and retest | Unknown | — | CIS v8 Control 18 |
| ERR-HAND-001 Secure error handling | Unknown | — | CIS v8 Control 16 |
| DATA-CRYPTO-001 Approved cryptography and certificate lifecycle | Unknown | — | CIS v8 Control 3 |
| IAM-LCM-001 Identity lifecycle and access recertification | Unknown | — | CIS v8 Control 5, CIS v8 Control 6 |
| IAM-ATO-001 Account recovery and account-takeover protection | Unknown | — | CIS v8 Control 6 |
| DATA-RES-001 Data residency and cross-border transfer | Unknown | — | CIS v8 Control 3 |
| DATA-PRIV-001 Privacy by design and data subject rights | Unknown | — | CIS v8 Control 3 |
| DATA-NONPROD-001 Production data kept out of non-production | Unknown | — | CIS v8 Control 3, CIS v8 Control 16 |
| NET-MGMT-001 Management and admin plane isolation | Unknown | — | CIS v8 Control 12, CIS v8 Control 13 |
| CLD-SEG-001 Network segmentation / VPC boundaries | Unknown | — | CIS v8 Control 12 |
| CLD-KMS-001 Managed key management (KMS) | Unknown | — | CIS v8 Control 3 |
| CLD-IAM-001 Cloud IAM roles (least privilege) | Unknown | — | CIS v8 Control 6 |
| CLD-SG-001 Restrictive security groups | Unknown | — | CIS v8 Control 12 |
| IMMUT-001 Immutable infrastructure and configuration drift management | Unknown | — | CIS v8 Control 4 |
| CLD-CSPM-001 Cloud posture management and guardrails | Unknown | — | CIS v8 Control 4 |
| CLD-LOG-001 Cloud control-plane audit logging | Unknown | — | CIS v8 Control 8 |
| CLD-PE-001 Private endpoints for managed services | Unknown | — | CIS v8 Control 12 |
| EDR-001 Endpoint detection & response (EDR) telemetry | Unknown | — | CIS v8 Control 13 |
| WEB-CSRF-001 CSRF protection | Unknown | — | CIS v8 Control 16 |
| WEB-SESS-001 Secure session management | Unknown | — | CIS v8 Control 6 |
| WEB-HDR-001 Security response headers | Unknown | — | CIS v8 Control 16 |
| WEB-RATE-001 Request rate limiting | Unknown | — | OWASP API API4:2023, CIS v8 Control 13 |
| BIZ-TXN-001 Business transaction integrity | Unknown | — | CIS v8 Control 16 |
| BIZ-ABUSE-001 Business workflow abuse prevention | Unknown | — | CIS v8 Control 16, OWASP API API6:2023 |
| WEB-DDOS-001 DDoS protection and bot mitigation | Unknown | — | CIS v8 Control 13 |
| FILE-ING-001 Secure file ingestion and processing | Unknown | — | CIS v8 Control 10, CIS v8 Control 16 |
| WEB-SCRIPT-001 Client-side script integrity | Unknown | — | CIS v8 Control 16 |
| WEB-CORS-001 CORS policy | Unknown | — | CIS v8 Control 16 |

## Threat model

| ID | STRIDE | Threat | Gaps | Maps to |
|---|---|---|---|---|
| T1 | Tampering | Prompt-injection defense is not in place | AI-PI-001 | OWASP LLM LLM01:2025 |
| T2 | Information disclosure | No-retention / enterprise model endpoint is not in place | AI-ENDP-001 | OWASP LLM LLM03:2025 |
| T3 | Information disclosure | Output filtering for sensitive disclosure is not in place | AI-OUT-001 | OWASP LLM LLM02:2025 |
| T4 | Repudiation | LLM prompt/response logging and decision traceability is not in place | AI-LOG-001 | CIS v8 Control 8 |
| T5 | Denial of service | Rate / spend limits on model endpoint is not in place | AI-RATE-001 | OWASP LLM LLM10:2025 |
| T6 | Elevation of privilege | Authorization scoping on AI features is only partial | AI-AUTHZ-001 | CIS v8 Control 6 |

## DREAD scoring

| Threat | D | R | E | A | D | Avg | Priority | Why |
|---|---|---|---|---|---|---|---|---|
| T5 | 9 | 8 | 8 | 8 | 6 | 7.8 | Critical | Offline rules: control not present, Restricted data. |
| T1 | 9 | 8 | 8 | 7 | 6 | 7.6 | Critical | Offline rules: control not present, Restricted data. |
| T4 | 9 | 8 | 8 | 7 | 6 | 7.6 | Critical | Offline rules: control not present, Restricted data. |
| T2 | 8 | 8 | 6 | 7 | 6 | 7.0 | High | Offline rules: control not present, Restricted data, compensating control noted. |
| T3 | 8 | 8 | 6 | 7 | 6 | 7.0 | High | Offline rules: control not present, Restricted data, compensating control noted. |
| T6 | 7 | 6 | 6 | 6 | 5 | 6.0 | High | Offline rules: control partial, Restricted data. |

## Action plan

| # | Action | Closes | Controls | Priority | Timing | Owner |
|---|---|---|---|---|---|---|
| A1 | Put in place: Prompt-injection defense. Untrusted text (user fields, retrieved records, tool output) is treated as data, not instructions. | T1 | AI-PI-001 | Critical | Before go-live |  |
| A5 | Put in place: LLM prompt/response logging and decision traceability. Prompts and responses are logged for audit and incident reconstruction, and every AI output can be traced to its model, prompt and guardrail versions, retrieved sources, user and business record. | T4 | AI-LOG-001 | Critical | Before go-live |  |
| A6 | Put in place: Rate / spend limits on model endpoint. Per-user and global limits cap model cost and abuse. | T5 | AI-RATE-001 | Critical | Before go-live |  |
| A2 | Put in place: No-retention / enterprise model endpoint. The model endpoint does not retain prompts; provider due diligence is done. | T2 | AI-ENDP-001 | High | Before go-live |  |
| A3 | Put in place: Output filtering for sensitive disclosure. Model output is filtered against the viewer's clearance before being returned. | T3 | AI-OUT-001 | High | Before go-live |  |
| A4 | Complete: Authorization scoping on AI features. AI features enforce the same per-record authorization as the rest of the app. | T6 | AI-AUTHZ-001 | High | Within 90 days |  |

## Clarifications needed (unknown ≠ missing)

- Confirm whether 'AI model, prompt and guardrail change control' is implemented (Are prompts, guardrails, model versions and tool permissions version-controlled and changed only via approval?)
- Confirm whether 'AI security evaluation and red teaming' is implemented (Is adversarial AI testing (injection, jailbreak, tool misuse, disclosure) planned and evidenced before release?)
- Confirm whether 'Least-privilege access (RBAC)' is implemented (Are permissions scoped to least privilege via roles (RBAC) rather than broad/shared access?)
- Confirm whether 'Centralized audit logging' is implemented (Are security-relevant events centrally logged (and retained)?)
- Confirm whether 'Secrets management' is implemented (Are secrets stored in a managed secrets vault rather than code/config/client-side?)
- Confirm whether 'Input validation and output encoding' is implemented (Is untrusted input validated and output encoded (injection defenses)?)
- Confirm whether 'Software composition analysis & SBOM' is implemented (Are dependencies inventoried (SBOM) and continuously scanned for known-vulnerable components (SCA)?)
- Confirm whether 'Multi-factor and phishing-resistant authentication' is implemented (Is MFA enforced for all users, and phishing-resistant MFA for admins and sensitive access?)
- Confirm whether 'Privileged access governance' is implemented (Is privileged access just-in-time, brokered through PAM, separated by duty and periodically reviewed?)
- Confirm whether 'Service-to-service authentication (mTLS / workload identity)' is implemented (Do internal and partner service calls authenticate the calling workload (mTLS, workload identity, signed tokens)?)
- Confirm whether 'Data masking, tokenisation and field-level encryption' is implemented (Are Restricted/PCI fields tokenised, field-encrypted or masked, with row/column-level access enforced?)
- Confirm whether 'Data lifecycle, retention and disposal' is implemented (Are retention periods, authorised sharing and secure deletion defined for all data stores, including logs, backups and AI stores?)
- Confirm whether 'Log and telemetry redaction' is implemented (Are PII, secrets, tokens and prompts redacted before reaching logs and telemetry?)
- Confirm whether 'End-to-end correlation and security alerting' is implemented (Is a correlation ID propagated end to end and recorded in audit logs, with owned security alerts?)
- Confirm whether 'Third-party integration and data-sharing approval' is implemented (Does every third-party integration have a vendor review, an approved data scope, contract terms and a verified endpoint?)
- Confirm whether 'Egress control and exfiltration protection' is implemented (Is outbound traffic (including agent tool calls and retrieval) restricted to approved destinations with data-loss checks?)
- Confirm whether 'Application incident containment' is implemented (Is there an app-specific incident runbook with the ability to revoke credentials and disable integrations or agents?)
- Confirm whether 'SAST, DAST and secure code review in the pipeline' is implemented (Are SAST, DAST and security code review run in the pipeline with high-severity findings blocking release?)
- Confirm whether 'CI/CD pipeline and build integrity' is implemented (Are branches protected, pipeline secrets scoped, and artifacts signed with build provenance verified at deploy?)
- Confirm whether 'Vulnerability and patch management with SLAs' is implemented (Are vulnerabilities tracked with severity-based remediation SLAs and an exception process?)
- Confirm whether 'Pre-go-live penetration test and retest' is implemented (Is an independent penetration test planned before go-live and after major change, with retest of findings?)
- Confirm whether 'Secure error handling' is implemented (Do errors return generic messages to callers, with stack traces and internals kept server-side?)
- Confirm whether 'Approved cryptography and certificate lifecycle' is implemented (Are only approved algorithms used, with keys and certificates inventoried, rotated and monitored for expiry?)
- Confirm whether 'Identity lifecycle and access recertification' is implemented (Is app access provisioned and removed via joiner/mover/leaver events and recertified periodically?)
- Confirm whether 'Account recovery and account-takeover protection' is implemented (Are account recovery and MFA reset strongly verified, and login protected against credential stuffing?)
- Confirm whether 'Production data kept out of non-production' is implemented (Are dev/test environments free of unmasked production data and isolated from production?)
- Confirm whether 'Management and admin plane isolation' is implemented (Are admin consoles and management ports reachable only via bastion/PAM and never from the internet?)
- Confirm whether 'Network segmentation / VPC boundaries' is implemented (Are workloads segmented across VPC/subnet boundaries with controlled flows?)
- Confirm whether 'Managed key management (KMS)' is implemented (Are encryption keys managed/rotated via a KMS?)
- Confirm whether 'Cloud IAM roles (least privilege)' is implemented (Do cloud workloads use scoped IAM roles rather than broad static credentials?)
- Confirm whether 'Restrictive security groups' is implemented (Are security-group/firewall rules restrictive (deny by default)?)
- Confirm whether 'Cloud posture management and guardrails' is implemented (Do org-level policies block risky cloud configurations, with posture management detecting drift?)
- Confirm whether 'Cloud control-plane audit logging' is implemented (Are cloud control-plane logs enabled everywhere, tamper-protected and sent to the SIEM?)
- Confirm whether 'Private endpoints for managed services' is implemented (Are managed data services reached via private endpoints with public network access disabled?)
- Confirm whether 'Secure session management' is implemented (Are sessions managed securely (HttpOnly/Secure/SameSite, rotation, timeout)?)
- Confirm whether 'Secure file ingestion and processing' is implemented (Are uploaded files type-checked, malware-scanned, processed in isolation and stored outside the web root?)
- Confirm whether 'Client-side script integrity' is implemented (Are scripts on payment and sensitive pages inventoried, integrity-checked and monitored for tampering?)
- Confirm whether 'Immutable infrastructure and configuration drift management' is implemented (Are hosts deployed from versioned images and replaced (not patched in place), with configuration as reviewed code and drift detection in place?)
- Confirm whether 'Data minimization before model call' is implemented (Is the payload minimized so only necessary fields are sent to the model?)
- Confirm whether 'Vector store / RAG document-level access control' is implemented (Does vector/RAG retrieval enforce per-document/per-user access control (not just relevance)?)
- Confirm whether 'Model provenance & integrity' is implemented (Is the model/weights supply chain verified (trusted source + signing/hash/version pin)?)
- Confirm whether 'AI system and model governance' is implemented (Is the AI use case registered and approved, with models, providers, data classes, autonomy level and owner recorded?)
- Confirm whether 'System prompt leakage protection' is implemented (Are system prompts free of secrets and sensitive policy, with prompt-extraction resistance tested?)
- Confirm whether 'AI output validation before action' is implemented (Are AI outputs validated against schema, authorisation and business rules before they drive actions, with human review for low-confidence cases?)
- Confirm whether 'External content provenance and trust' is implemented (Is externally retrieved content source-restricted, provenance-tracked and sanitised before reaching the model?)
- Confirm whether 'RAG ingestion integrity' is implemented (Is RAG ingestion restricted to approved sources, scanned, versioned and source-tracked?)
- Confirm whether 'AI runtime alerting' is implemented (Do alerts fire on AI policy violations, token/cost spikes and model or retrieval failures, to an owning team?)
- Confirm whether 'AI transparency, grounding and overreliance' is implemented (Are users told when content is AI-generated, with cited sources and caveats on high-stakes answers?)
- Confirm whether 'Dependency resilience and fail-safe behaviour' is implemented (Do dependency calls use timeouts, bounded retries and circuit breakers, and fail closed when a security dependency is down?)
- Confirm whether 'Backup and recovery assurance' is implemented (Are RPO/RTO defined, backups immutable and separately controlled, and restores tested periodically?)
- Confirm whether 'Data residency and cross-border transfer' is implemented (Are storage and processing regions (including backups, logs and AI endpoints) mapped and compliant with residency rules?)
- Confirm whether 'Privacy by design and data subject rights' is implemented (Has a privacy impact assessment been done, and can the app fulfil access, correction and erasure requests?)
- Confirm whether 'Endpoint detection & response (EDR) telemetry' is implemented (Do managed hosts run an EDR/XDR agent feeding telemetry to a monitored detection pipeline?)
- Confirm whether 'CSRF protection' is implemented (Are state-changing requests protected with anti-CSRF tokens?)
- Confirm whether 'Request rate limiting' is implemented (Is request rate limiting enforced at the edge/app?)
- Confirm whether 'Business transaction integrity' is implemented (Are sensitive transactions validated server-side with enforced state transitions, idempotency keys and replay prevention?)
- Confirm whether 'Business workflow abuse prevention' is implemented (Are sensitive business flows protected with flow-level limits, velocity rules and fraud or bot signals?)
- Confirm whether 'DDoS protection and bot mitigation' is implemented (Is the app fronted by edge DDoS protection and bot mitigation?)
- Confirm whether 'CORS policy' is implemented (Is CORS restricted to an explicit origin allow-list with no reflected or wildcard origins on credentialed requests?)
- Confirm whether 'Data classification applied' is implemented (Is data classified and are controls applied by classification level?)
- Confirm whether 'Security response headers' is implemented (Are security headers (CSP, HSTS, X-Content-Type-Options) set?)

## PCI DSS v4.0.1 compliance view

*Not in scope — the application does not handle cardholder data.*

## Out-of-catalog controls

- Compensating: PII display tokenization (addresses Information disclosure). Maps to InformationDisclosure; treat as compensating only where it actually applies. It softens, but does not close, the related findings.
- Candidate: PII display tokenization (addresses Information disclosure risk). Described in the evidence but not in the catalog; it does not offset any finding in this report.

## Appendix — control evidence

> ⚠️ **Automated assessment.** The AI evaluations below were produced automatically and may need further analysis by AppSec. Each AI evaluation is kept as first written; where a reviewer changed a status or note, their change is shown next to it.

### 🟢 Implemented (4)

| **IAM-SSO-001** | **Centralized authentication / SSO** |
|---|---|
| Final status | Implemented · AI (not reviewed) |
| AI evaluation | **Implemented · low confidence · from description keyword match** |
| Cited evidence | “Staff sign in through Okta SSO.” |
| AI rationale | Keyword match: 'sso' appears in the description. A keyword is a weak signal; confirm the control is actually in place. |

| **DATA-ENC-001** | **Data-at-rest encryption** |
|---|---|
| Final status | Implemented · AI (not reviewed) |
| AI evaluation | **Implemented · low confidence · from description keyword match** |
| Cited evidence | “The employee database is encrypted at rest and all traffic uses TLS 1.” |
| AI rationale | Keyword match: 'encrypted at rest' appears in the description. A keyword is a weak signal; confirm the control is actually in place. |

| **DATA-TLS-001** | **Strong transport encryption (TLS 1.2+)** |
|---|---|
| Final status | Implemented · AI (not reviewed) |
| AI evaluation | **Implemented · low confidence · from description keyword match** |
| Cited evidence | “The employee database is encrypted at rest and all traffic uses TLS 1.” |
| AI rationale | Keyword match: 'tls 1.3' appears in the description. A keyword is a weak signal; confirm the control is actually in place. |

| **WEB-WAF-001** | **Web application firewall** |
|---|---|
| Final status | Implemented · AI (not reviewed) |
| AI evaluation | **Implemented · low confidence · from description keyword match** |
| Cited evidence | “A WAF fronts the application.” |
| AI rationale | Keyword match: 'waf' appears in the description. A keyword is a weak signal; confirm the control is actually in place. |
