# Threat Model — PeopleDesk

*Platforms:* web, cloud  
*AI capability:* llm  
*Data classification:* Restricted  
*Resolved controls:* 29  
*PCI in scope:* no

## Executive summary

PeopleDesk (web, cloud · llm · Restricted data) was assessed against 29 expected controls. The review identified 6 gap(s) (5 not in place, 1 partial), 4 confirmed in place, and 19 that could not be confirmed. PCI DSS v4.0.1 is out of scope.

**Top threats (by DREAD):**
- [Critical · 7.8] Rate / spend limits on model endpoint is not in place (LLM10:2025)
- [Critical · 7.6] Prompt-injection defense is not in place (LLM01:2025)
- [Critical · 7.6] LLM prompt/response logging is not in place (Control 8)
- [High · 7.0] No-retention / enterprise model endpoint is not in place (LLM03:2025)

**Key gaps to close:**
- AI-RATE-001 Rate / spend limits on model endpoint (LLM10:2025)
- AI-PI-001 Prompt-injection defense (LLM01:2025)
- AI-LOG-001 LLM prompt/response logging (Control 8)
- AI-ENDP-001 No-retention / enterprise model endpoint (LLM03:2025)
- AI-OUT-001 Output filtering for sensitive disclosure (LLM02:2025)

**Strengths (confirmed in place):**
- IAM-SSO-001 Centralized authentication / SSO
- DATA-ENC-001 Data-at-rest encryption
- DATA-TLS-001 Strong transport encryption (TLS 1.2+)
- WEB-WAF-001 Web application firewall

**Also note:** 1 compensating control(s) noted (these soften, but do not eliminate, a finding); 19 unknown control(s) need confirmation — treated as clarifications, not findings (unknown ≠ missing).

## Control gap register

| Control | Status | Frameworks | PCI exposed |
|---|---|---|---|
| AI-PI-001 Prompt-injection defense | Not present | LLM01:2025, Control 16 | — |
| AI-DM-001 Data minimization before model call | Unknown | LLM02:2025, Control 3 | — |
| AI-ENDP-001 No-retention / enterprise model endpoint | Not present | LLM03:2025, Control 15 | — |
| AI-OUT-001 Output filtering for sensitive disclosure | Not present | LLM02:2025, Control 3 | — |
| AI-AUTHZ-001 Authorization scoping on AI features | Partial | Control 6 | — |
| AI-LOG-001 LLM prompt/response logging | Not present | Control 8 | — |
| AI-RATE-001 Rate / spend limits on model endpoint | Not present | LLM10:2025, Control 13 | — |
| AI-VEC-001 Vector store / RAG document-level access control | Unknown | LLM08:2025, LLM02:2025, Control 3 | — |
| AI-MODEL-PROV-001 Model provenance & integrity | Unknown | LLM03:2025, Control 2 | — |
| IAM-SSO-001 Centralized authentication / SSO | Implemented | Control 6 | — |
| IAM-LPA-001 Least-privilege access (RBAC) | Unknown | Control 6 | — |
| DATA-ENC-001 Data-at-rest encryption | Implemented | Control 3 | — |
| DATA-TLS-001 Strong transport encryption (TLS 1.2+) | Implemented | Control 3 | — |
| LOG-AUD-001 Centralized audit logging | Unknown | Control 8 | — |
| DATA-CLS-001 Data classification applied | Unknown | Control 3 | — |
| SEC-SECRETS-001 Secrets management | Unknown | Control 6 | — |
| IN-VAL-001 Input validation and output encoding | Unknown | Control 16 | — |
| SCA-SBOM-001 Software composition analysis & SBOM | Unknown | Control 2 | — |
| CLD-SEG-001 Network segmentation / VPC boundaries | Unknown | Control 12 | — |
| CLD-KMS-001 Managed key management (KMS) | Unknown | Control 3 | — |
| CLD-IAM-001 Cloud IAM roles (least privilege) | Unknown | Control 6 | — |
| CLD-SG-001 Restrictive security groups | Unknown | Control 12 | — |
| IMMUT-001 Immutable infrastructure | Unknown | Control 4 | — |
| EDR-001 Endpoint detection & response (EDR) telemetry | Unknown | Control 13 | — |
| WEB-WAF-001 Web application firewall | Implemented | Control 13 | — |
| WEB-CSRF-001 CSRF protection | Unknown | Control 16 | — |
| WEB-SESS-001 Secure session management | Unknown | Control 6 | — |
| WEB-HDR-001 Security response headers | Unknown | Control 16 | — |
| WEB-RATE-001 Request rate limiting | Unknown | API4:2023, Control 13 | — |

## Threat model

| ID | STRIDE | Threat | Enabling gap | Maps to |
|---|---|---|---|---|
| T1 | Tampering | Prompt-injection defense is not in place | AI-PI-001 | LLM01:2025 |
| T2 | InformationDisclosure | No-retention / enterprise model endpoint is not in place | AI-ENDP-001 | LLM03:2025 |
| T3 | InformationDisclosure | Output filtering for sensitive disclosure is not in place | AI-OUT-001 | LLM02:2025 |
| T4 | Repudiation | LLM prompt/response logging is not in place | AI-LOG-001 | Control 8 |
| T5 | DenialOfService | Rate / spend limits on model endpoint is not in place | AI-RATE-001 | LLM10:2025 |
| T6 | ElevationOfPrivilege | Authorization scoping on AI features is only partial | AI-AUTHZ-001 | Control 6 |

## Recommendations (gap-closing)

- **Adopt: Prompt-injection defense** (AI-PI-001) — Untrusted text (user fields, retrieved records, tool output) is treated as data, not instructions. Close this gap for an app of this type and data class.  _owasp_llm:LLM01:2025, cis_v8:Control 16_
- **Adopt: No-retention / enterprise model endpoint** (AI-ENDP-001) — The model endpoint does not retain prompts; provider due diligence is done. Close this gap for an app of this type and data class.  _owasp_llm:LLM03:2025, cis_v8:Control 15_
- **Adopt: Output filtering for sensitive disclosure** (AI-OUT-001) — Model output is filtered against the viewer's clearance before being returned. Close this gap for an app of this type and data class.  _owasp_llm:LLM02:2025, cis_v8:Control 3_
- **Strengthen: Authorization scoping on AI features** (AI-AUTHZ-001) — AI features enforce the same per-record authorization as the rest of the app. Close this gap for an app of this type and data class.  _cis_v8:Control 6_
- **Adopt: LLM prompt/response logging** (AI-LOG-001) — Prompts and responses are logged for audit and incident reconstruction. Close this gap for an app of this type and data class.  _cis_v8:Control 8_
- **Adopt: Rate / spend limits on model endpoint** (AI-RATE-001) — Per-user and global limits cap model cost and abuse. Close this gap for an app of this type and data class.  _owasp_llm:LLM10:2025, cis_v8:Control 13_

## Mitigations (threat-specific)

- **T1** → Untrusted text (user fields, retrieved records, tool output) is treated as data, not instructions.
- **T2** → The model endpoint does not retain prompts; provider due diligence is done.  _Partially offset by compensating control(s) PII display tokenization — unverified, not in baseline._
- **T3** → Model output is filtered against the viewer's clearance before being returned.  _Partially offset by compensating control(s) PII display tokenization — unverified, not in baseline._
- **T4** → Prompts and responses are logged for audit and incident reconstruction.
- **T5** → Per-user and global limits cap model cost and abuse.
- **T6** → AI features enforce the same per-record authorization as the rest of the app.

## DREAD scoring

| Threat | D | R | E | A | D | Avg | Priority |
|---|---|---|---|---|---|---|---|
| T5 | 9 | 8 | 8 | 8 | 6 | 7.8 | Critical |
| T1 | 9 | 8 | 8 | 7 | 6 | 7.6 | Critical |
| T4 | 9 | 8 | 8 | 7 | 6 | 7.6 | Critical |
| T2 | 8 | 8 | 6 | 7 | 6 | 7.0 | High |
| T3 | 8 | 8 | 6 | 7 | 6 | 7.0 | High |
| T6 | 7 | 6 | 6 | 6 | 5 | 6.0 | High |

## Clarifications needed (unknown ≠ missing)

- Confirm whether 'Least-privilege access (RBAC)' is implemented (Are permissions scoped to least privilege via roles (RBAC) rather than broad/shared access?)
- Confirm whether 'Centralized audit logging' is implemented (Are security-relevant events centrally logged (and retained)?)
- Confirm whether 'Secrets management' is implemented (Are secrets stored in a managed secrets vault rather than code/config/client-side?)
- Confirm whether 'Input validation and output encoding' is implemented (Is untrusted input validated and output encoded (injection defenses)?)
- Confirm whether 'Software composition analysis & SBOM' is implemented (Are dependencies inventoried (SBOM) and continuously scanned for known-vulnerable components (SCA)?)
- Confirm whether 'Network segmentation / VPC boundaries' is implemented (Are workloads segmented across VPC/subnet boundaries with controlled flows?)
- Confirm whether 'Managed key management (KMS)' is implemented (Are encryption keys managed/rotated via a KMS?)
- Confirm whether 'Cloud IAM roles (least privilege)' is implemented (Do cloud workloads use scoped IAM roles rather than broad static credentials?)
- Confirm whether 'Restrictive security groups' is implemented (Are security-group/firewall rules restrictive (deny by default)?)
- Confirm whether 'Secure session management' is implemented (Are sessions managed securely (HttpOnly/Secure/SameSite, rotation, timeout)?)
- Confirm whether 'Immutable infrastructure' is implemented (Are hosts deployed from versioned images and replaced (not patched in place) with no manual drift?)
- Confirm whether 'Data minimization before model call' is implemented (Is the payload minimized so only necessary fields are sent to the model?)
- Confirm whether 'Vector store / RAG document-level access control' is implemented (Does vector/RAG retrieval enforce per-document/per-user access control (not just relevance)?)
- Confirm whether 'Model provenance & integrity' is implemented (Is the model/weights supply chain verified (trusted source + signing/hash/version pin)?)
- Confirm whether 'Endpoint detection & response (EDR) telemetry' is implemented (Do managed hosts run an EDR/XDR agent feeding telemetry to a monitored detection pipeline?)
- Confirm whether 'CSRF protection' is implemented (Are state-changing requests protected with anti-CSRF tokens?)
- Confirm whether 'Request rate limiting' is implemented (Is request rate limiting enforced at the edge/app?)
- Confirm whether 'Data classification applied' is implemented (Is data classified and are controls applied by classification level?)
- Confirm whether 'Security response headers' is implemented (Are security headers (CSP, HSTS, X-Content-Type-Options) set?)

## PCI DSS v4.0.1 compliance view

*Not in scope — the application does not handle cardholder data.*

## Out-of-catalog controls

- Compensating: **PII display tokenization** — Maps to InformationDisclosure; treat as compensating only where it actually applies.

*Catalog candidates (flagged for later promotion):*
- PII display tokenization — [InformationDisclosure]
