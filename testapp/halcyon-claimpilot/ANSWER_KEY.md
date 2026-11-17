# Halcyon ClaimPilot — answer key

Expected results when this sample is run through the threat modeling utility. LLM output varies between runs and models, so treat this as the intended result: a status one step away (for example *partial* instead of *implemented*) is normal, but a control on the wrong side of present/absent is worth a look.

## Files

- `Halcyon_ClaimPilot_SAD_v2.0.docx` — SAD for the SAD upload page (Word, three diagrams embedded)
- `Halcyon_ClaimPilot_SAD_v2.0.pdf` — the same SAD as PDF
- `Halcyon_ClaimPilot_Description.txt` — description for the main page
- `Halcyon_ClaimPilot_Architecture_Overview.png` — overview diagram for the main page (it takes one image)
- `Halcyon_ClaimPilot_Agent_Interaction.png` — agent/tool/MCP diagram (Figure 2 of the SAD)
- `Halcyon_ClaimPilot_Deployment_Network.png` — deployment and network diagram (Figure 3 of the SAD)

## Expected facets (confirmation screen on the SAD page)

| Facet | Expected |
|---|---|
| Platforms | web, cloud, api, container, messaging |
| AI capability | agentic, mcp, generative, training |
| Data classification | Restricted |
| Cardholder data (PCI) | Yes — PCI section in scope |
| Expected control count | 111 |

## Things this sample is designed to test

- Wide facet set: AI facets agentic, mcp, generative and training (which pull in the llm and llm_tools layers), plus five platform facets. Expect a long run; use a generous output budget.
- PCI in scope through MOTO card entry, even though online payments use hosted fields. A tool that reads only the online path would wrongly set PCI to no.
- Classic agentic gaps stated in the SAD: token passthrough to an MCP server, unpinned MCP tool lists, a shared service account instead of on-behalf-of, a RAG index with no document-level filter, unsandboxed code execution, an open web-fetch tool (SSRF and indirect prompt injection), unredacted LLM traces, and no AI red teaming. These should be the highest-rated findings.
- Strong platform controls (Shield, WAF, mTLS, CMKs, private endpoints, SCPs, GitOps) should come back implemented and not generate findings.
- CSRF is only inferable (bearer tokens, not cookies) and should be *partial* with a note.

## Expected status mix on the SAD page

| Status | Controls |
|---|---|
| implemented | 53 |
| partial | 37 |
| partial (inferred, AI note) | 2 |
| not present (stated) | 9 |
| not present (not stated) | 10 |

Out-of-catalog controls the SAD describes (should appear as catalog candidates): Settlement rules engine checking payouts against policy limits before payment; LaunchDarkly global 'autonomy off' fallback to manual adjuster queue.

## Control-by-control expectations

Description-page column: what Detect should pre-fill from the description text and the architecture diagram. That page never marks a control absent, so controls the description says are missing stay *unknown* and the reviewer declares them *not present*.

| Control | Title | Layer | SAD page | Description page | Evidence in the sample |
|---|---|---|---|---|---|
| IAM-SSO-001 | Centralized authentication / SSO | base | implemented | implemented | Okta SSO for staff, Cognito for customers (§7.1) |
| IAM-LPA-001 | Least-privilege access (RBAC) | base | implemented | implemented | JWT scopes per role; customers limited to own claims (§7.2) |
| DATA-ENC-001 | Data-at-rest encryption | base | implemented | implemented | KMS CMKs on all stores (§5.3) |
| DATA-TLS-001 | Strong transport encryption (TLS 1.2+) | base | implemented | implemented | TLS 1.2+ everywhere, Istio mTLS (§11) |
| LOG-AUD-001 | Centralized audit logging | base | implemented | implemented | CloudWatch -> Splunk; CloudTrail org trail (§12.1) |
| DATA-CLS-001 | Data classification applied | base | implemented | implemented | Halcyon Restricted, tags on resources and S3 objects (§5.1) |
| SEC-SECRETS-001 | Secrets management | base | partial | partial | Secrets Manager with rotation, except RepairNet key in a K8s Secret (§11) |
| IN-VAL-001 | Input validation and output encoding | base | implemented | implemented | OpenAPI validation at API Gateway + Bean Validation (§11) |
| SCA-SBOM-001 | Software composition analysis & SBOM | base | partial | unknown | Snyk scanning, no SBOM (§11) |
| IAM-MFA-001 | Multi-factor and phishing-resistant authentication | base | partial | partial | FastPass for staff; MFA optional for customers (§7.1) |
| IAM-PAM-001 | Privileged access governance | base | implemented | implemented | IAM Identity Center time-bound elevation, no standing admin (§7.3) |
| IAM-S2S-001 | Service-to-service authentication (mTLS / workload identity) | base | implemented | implemented | Istio mTLS STRICT + IRSA (§8.2) |
| DATA-MASK-001 | Data masking, tokenisation and field-level encryption | base | partial | partial | PAN tokenised, bank fields encrypted, medical notes in clear (§5.3) |
| DATA-LIFE-001 | Data lifecycle, retention and disposal | base | partial | unknown | 7-year claims retention; shared agent memory has no retention (§5.3, §4.6) |
| LOG-RED-001 | Log and telemetry redaction | base | not present (stated) | unknown → declare not present | Langfuse stores PII/medical data unredacted (§12.1) |
| LOG-CORR-001 | End-to-end correlation and security alerting | base | implemented | implemented | OpenTelemetry trace IDs end to end, SOC correlation rules (§12.1) |
| EXT-TPR-001 | Third-party integration and data-sharing approval | base | partial | unknown → declare not present | Payvanta/ClaimShield/Client360 assessed; RepairNet not (§9.2) |
| NET-EGRESS-001 | Egress control and exfiltration protection | base | partial | partial | Network Firewall allow-list, except uninspected NAT path for web fetch (§8.2) |
| RES-DEP-001 | Dependency resilience and fail-safe behaviour | base | implemented | unknown | Bedrock throttling -> manual queue (§12.2) |
| RES-DR-001 | Backup and recovery assurance | base | implemented | implemented | Global DB, RTO 4h/RPO 15m, fail-over tested Oct 2026 (§12.4) |
| IR-RESP-001 | Application incident containment | base | partial | unknown | Platform runbooks only; no AI playbook (§12.3) |
| SDLC-SAST-001 | SAST, DAST and secure code review in the pipeline | base | implemented | implemented | Checkmarx SAST + ZAP DAST, critical blocks release (§11) |
| SDLC-PIPE-001 | CI/CD pipeline and build integrity | base | implemented | unknown | Protected branches, two-person review, Terraform plan approval (§11) |
| VULN-PATCH-001 | Vulnerability and patch management with SLAs | base | implemented | unknown | Patch SLAs 7/30 days, weekly AMI rebuild (§11) |
| SEC-PENTEST-001 | Pre-go-live penetration test and retest | base | partial | unknown | Pentest excludes the agent and AI components (§11) |
| ERR-HAND-001 | Secure error handling | base | not present (not stated) | unknown | Not mentioned |
| DATA-CRYPTO-001 | Approved cryptography and certificate lifecycle | base | implemented | unknown | ACM auto-renewal, Cryptography Standard CS-04 (§11) |
| IAM-LCM-001 | Identity lifecycle and access recertification | base | implemented | unknown | Workday -> Okta lifecycle, quarterly recertification (§7.1) |
| IAM-ATO-001 | Account recovery and account-takeover protection | base | partial | unknown | Cognito adaptive auth in audit-only mode (§7.1) |
| DATA-RES-001 | Data residency and cross-border transfer | base | implemented | implemented | eu-west-2 with DR in eu-west-1; cross-region inference off (§5.3, §4.3) |
| DATA-PRIV-001 | Privacy by design and data subject rights | base | partial | unknown | DPIA done; DSAR process misses memory, traces and RAG (§5.3) |
| DATA-NONPROD-001 | Production data kept out of non-production | base | partial | unknown | Synthetic data except 5% prod sample in model-eval env (§5.3) |
| NET-MGMT-001 | Management and admin plane isolation | base | implemented | implemented | Private EKS API, SSM only, no bastion (§7.3) |
| WEB-WAF-001 | Web application firewall | platform.web | implemented | implemented | AWS WAF managed rule groups (§11) |
| WEB-CSRF-001 | CSRF protection | platform.web | partial (inferred, AI note) | unknown | Bearer tokens, not cookies, so CSRF is mitigated by design (§7.1) -> confirm |
| WEB-SESS-001 | Secure session management | platform.web | implemented | implemented | 15-min access tokens, rotating refresh tokens, revocation (§7.1) |
| WEB-HDR-001 | Security response headers | platform.web | implemented | implemented | CloudFront response-headers policy: CSP, HSTS, etc. (§11) |
| WEB-RATE-001 | Request rate limiting | platform.web | implemented | implemented | WAF rate-based rules + usage plans (§9.1) |
| BIZ-TXN-001 | Business transaction integrity | platform.web/platform.api | implemented | implemented | Idempotency keys, rules engine before payment (§10, §4.2) |
| BIZ-ABUSE-001 | Business workflow abuse prevention | platform.web/platform.api | partial | unknown | Fraud scoring, but no velocity limits per policy/payee (§11) |
| WEB-DDOS-001 | DDoS protection and bot mitigation | platform.web/platform.api | implemented | implemented | Shield Advanced (§11) |
| FILE-ING-001 | Secure file ingestion and processing | platform.web/platform.api | partial | unknown | Async malware scan; agents may read before the verdict (§11) |
| WEB-SCRIPT-001 | Client-side script integrity | platform.web | not present (not stated) | unknown | Not mentioned (CSP only covers part of it) |
| WEB-CORS-001 | CORS policy | platform.web | implemented | unknown | CORS limited to portal/console origins (§9.1) |
| API-BOLA-001 | Object-level authorization (BOLA) | platform.api | partial | partial | Customers scoped to own claims; any adjuster can open any regional claim (§7.2) |
| API-AUTHN-001 | API authentication & token validation | platform.api | implemented | implemented | JWT authorizers check issuer/audience/expiry/signature (§7.2) |
| API-RES-001 | API resource-consumption limits | platform.api | implemented | unknown | Usage plans, 10 MB payload limit, page size 100 (§9.1) |
| API-INV-001 | API inventory & version governance | platform.api | partial | unknown | External OpenAPI in catalogue; agent APIs and MCP tools not (§9.1) |
| API-SSRF-001 | SSRF protection on server-side fetches | platform.api | not present (stated) | unknown → declare not present | Web fetch accepts any URL, no private-address block (§4.4) |
| API-FPA-001 | Function- and property-level authorization | platform.api | implemented | unknown | Payout/refund endpoints need team-leader/adjuster scope (§7.2) |
| API-HOOK-001 | Webhook and callback authentication | platform.api | implemented | implemented | HMAC-SHA256 + 5-minute window on Payvanta webhooks (§9.1) |
| API-CONS-001 | Safe consumption of third-party APIs | platform.api | partial | unknown → declare not present | ClaimShield/PolicyCore schema-validated; RepairNet and web fetch not (§4.4) |
| CLD-SEG-001 | Network segmentation / VPC boundaries | platform.cloud | implemented | implemented | Three-tier VPC, data subnets without internet route (§8.2) |
| CLD-KMS-001 | Managed key management (KMS) | platform.cloud | implemented | implemented | CMK per data domain with rotation (§5.3) |
| CLD-IAM-001 | Cloud IAM roles (least privilege) | platform.cloud | implemented | unknown | IRSA per service with permission boundaries, no IAM users (§8.1) |
| CLD-SG-001 | Restrictive security groups | platform.cloud | implemented | unknown | Security groups per node group and data service (§8.2; Figure 3) |
| IMMUT-001 | Immutable infrastructure and configuration drift management | platform.cloud/platform.onprem | implemented | implemented | Terraform + Argo CD drift revert, console writes blocked by SCP (§8.1) |
| CLD-CSPM-001 | Cloud posture management and guardrails | platform.cloud | implemented | unknown | Security Hub, Config CIS conformance packs, SCPs (§8.1) |
| CLD-LOG-001 | Cloud control-plane audit logging | platform.cloud | implemented | implemented | CloudTrail organisation trail with Object Lock (§8.1; overview diagram) |
| CLD-PE-001 | Private endpoints for managed services | platform.cloud | implemented | implemented | VPC endpoints for Bedrock, S3, DynamoDB, KMS, etc. (§8.2) |
| EDR-001 | Endpoint detection & response (EDR) telemetry | platform.onprem/platform.cloud | partial (inferred, AI note) | unknown | GuardDuty EKS Runtime Monitoring suggests runtime detection; confirm EDR coverage (§8.3) |
| CTR-IMG-001 | Trusted, scanned and signed container images | platform.container | partial | partial | ECR scan on push; unsigned images, public base images (§8.3) |
| CTR-RUN-001 | Container runtime hardening | platform.container | implemented | implemented | Non-root, read-only FS, PSS restricted, seccomp (§8.3) |
| CTR-K8S-001 | Kubernetes cluster access and network policy | platform.container | partial | partial | Private API, access entries; NetworkPolicies only in payments (§8.2) |
| MSG-AUTH-001 | Broker authentication and topic access control | platform.messaging | implemented | implemented | MSK IAM auth + per-service topic ACLs (§10) |
| MSG-INT-001 | Message integrity and payload confidentiality | platform.messaging | partial | partial | TLS + at-rest encryption, but no signing and full PII in agent.tasks (§10) |
| MSG-REPLAY-001 | Replay, duplicate and ordering protection | platform.messaging | partial | partial | Idempotency on payments.commands; none on agent.tasks (§10) |
| MSG-SCHEMA-001 | Schema validation and registry governance | platform.messaging | implemented | implemented | Avro + Glue Schema Registry, BACKWARD compatibility (§10) |
| MSG-DLQ-001 | Poison-message handling and dead-letter security | platform.messaging | not present (not stated) | unknown | Not mentioned |
| MSG-QUOTA-001 | Broker quotas and backpressure | platform.messaging | not present (not stated) | unknown | Not mentioned |
| MSG-MFT-001 | Secure file transfer and batch integrations | platform.messaging | partial | partial | SFTP with SSH keys; no file encryption, signing or checksum (§10) |
| AI-PI-001 | Prompt-injection defense | ai.llm | partial | partial | Guardrails prompt-attack filter on chat input only (§4.4) |
| AI-DM-001 | Data minimization before model call | ai.llm | not present (not stated) | unknown | No minimisation; agent.tasks carries the full record (expect NP or P) |
| AI-ENDP-001 | No-retention / enterprise model endpoint | ai.llm | implemented | implemented | Bedrock in-region via VPC endpoint, no retention/training (§4.3) |
| AI-OUT-001 | Output filtering for sensitive disclosure | ai.llm | partial | partial | PII filter on customer chat, not on adjuster console (§4.4) |
| AI-AUTHZ-001 | Authorization scoping on AI features | ai.llm | implemented | unknown | Chat assistant scoped to session's claim IDs (§7.2) |
| AI-LOG-001 | LLM prompt/response logging and decision traceability | ai.llm | implemented | implemented | Langfuse traces linked to claim ID (§12.1) |
| AI-RATE-001 | Rate / spend limits on model endpoint | ai.llm | partial | unknown | Service quotas only; no per-user/claim budget (§4.3) |
| AI-VEC-001 | Vector store / RAG document-level access control | ai.llm | not present (stated) | unknown → declare not present | Single index, no document-level filter (§4.5) |
| AI-MODEL-PROV-001 | Model provenance & integrity | ai.llm | partial | partial | AWS catalogue models; fine-tuned artefacts unsigned (§4.3) |
| AI-GOV-001 | AI system and model governance | ai.llm | implemented | implemented | AI register AI-REG-0042, Steering Committee approval (§4.8) |
| AI-CFG-001 | AI model, prompt and guardrail change control | ai.llm | partial | unknown | Prompts in Git; Guardrails changed in the console (§4.3) |
| AI-SPL-001 | System prompt leakage protection | ai.llm | not present (not stated) | unknown | Not mentioned |
| AI-EVAL-001 | AI security evaluation and red teaming | ai.llm | not present (stated) | unknown → declare not present | No red teaming yet; accuracy eval only (§4.8) |
| AI-OUT-ACT-001 | AI output validation before action | ai.llm | partial | partial | Rules engine for payouts only (§4.2) |
| AI-SRC-001 | External content provenance and trust | ai.llm | not present (stated) | unknown → declare not present | Web fetch and RepairNet content passed as-is (§4.4) |
| AI-RAG-ING-001 | RAG ingestion integrity | ai.llm | partial | partial | Policy library curated; customer notes ingested automatically (§4.5) |
| AI-MON-001 | AI runtime alerting | ai.llm | not present (stated) | unknown | No alerts on AI-specific signals (§12.2) |
| AI-TRANS-001 | AI transparency, grounding and overreliance | ai.llm | implemented | unknown | AI disclosure, human option, clause citations (§4.4) |
| AI-TOOL-001 | Tool invocation allow-list | ai.llm_tools | implemented | implemented | Per-agent allow-list enforced by the orchestrator (§4.1) |
| AI-TOOL-002 | Tool output validation | ai.llm_tools | partial | unknown → declare not present | ClaimShield/PolicyCore validated; web fetch/RepairNet not (§4.4) |
| AI-AGENCY-001 | Excessive-agency limits | ai.llm_tools | partial | partial | Autonomous payouts up to £5,000 (§4.2) |
| AI-SANDBOX-001 | Tool execution sandboxing | ai.llm_tools | not present (not stated) | unknown → declare not present | Model-written Python runs inside the agent pod, no sandbox (§4.4); may come back NP-stated |
| AI-PARAM-001 | Strict tool-parameter typing | ai.llm_tools | implemented | implemented | Pydantic-typed constrained parameters (§4.1) |
| AI-OBO-001 | On-behalf-of token propagation | ai.llm_tools | not present (stated) | unknown → declare not present | Shared svc-claimpilot account, user identity not propagated (§4.2) |
| ASI-AUD-001 | Agent tool-call and decision audit trail | ai.llm_tools/ai.agentic | implemented | implemented | Tool-call audit in S3 Object Lock (§12.1) |
| MCP-TRUST-001 | MCP server provenance / trust verification | ai.mcp | partial | partial | Client360 in-house; RepairNet connected without review (§4.7) |
| MCP-TOKEN-001 | No token passthrough; scoped credentials | ai.mcp | not present (stated) | unknown → declare not present | Okta token passed through to Client360 (§4.7) |
| MCP-DESC-001 | Tool-description injection defense | ai.mcp | not present (not stated) | unknown | Not mentioned |
| MCP-LOG-001 | MCP call audit logging | ai.mcp | implemented | implemented | MCP gateway logs every call (§4.7) |
| MCP-PIN-001 | MCP tool-definition pinning (rug-pull detection) | ai.mcp | not present (stated) | unknown → declare not present | Tool lists loaded dynamically, not pinned (§4.7) |
| ASI-MEM-001 | Agent memory isolation | ai.agentic | partial | partial | Per-claim memory, but shared long-term 'lessons' memory (§4.6) |
| ASI-HITL-001 | Human-in-the-loop on high-risk actions | ai.agentic | partial | partial | Approval above £5,000 and for denials only (§4.2) |
| ASI-LOOP-001 | Goal/loop bounds | ai.agentic | implemented | implemented | 25 steps / 10 minutes per task (§4.2) |
| ASI-MULTI-001 | Multi-agent compromise containment | ai.agentic | not present (not stated) | unknown | Not mentioned |
| ASI-AUTH-001 | Inter-agent mutual authentication | ai.agentic | partial | unknown | mTLS for sync calls; agent.tasks unsigned, no agent identity (§4.2) |
| ASI-NHI-001 | Dedicated agent non-human identity | ai.agentic | partial | unknown | IRSA role per agent, but shared PolicyCore account (§4.2) |
| ASI-KILL-001 | Agent kill switch and circuit breaker | ai.agentic | implemented | implemented | LaunchDarkly per-agent and global kill switch (§4.2) |
| GEN-PROV-001 | Content provenance / watermarking | ai.generative | not present (not stated) | unknown | Not mentioned |
| GEN-SAFE-001 | Harmful-generation filtering | ai.generative | implemented | unknown | Guardrails content filters + approved letter templates (§4.4) |
| AI-TRAIN-001 | Training data governance | ai.training | partial | partial | Dataset approved, but faces/plates not scrubbed (§4.3) |
