from diagram import Diagram

OUT = "../halcyon-claimpilot/"


def overview() -> Diagram:
    d = Diagram(1800, 1150, "Halcyon ClaimPilot — Logical Architecture (Production)",
                "AWS eu-west-2 (London) · agentic claims assistant · SAD v2.0 · Figure 1")
    d.zone(20, 90, 250, 540, "Internet")
    d.zone(20, 650, 250, 480, "Halcyon corporate / data centre")
    d.zone(290, 90, 1230, 1040, "AWS account claimpilot-prod (eu-west-2)", fill="#FAFCFF", color="#1F5FBF")
    d.zone(580, 105, 700, 1010, "VPC claimpilot-prod · private subnets · 3 AZ", color="#1F5FBF")
    d.zone(600, 135, 660, 480, "EKS cluster claimpilot · private API endpoint · Istio mTLS (STRICT)", color="#6B87B5")
    d.zone(1540, 90, 250, 1040, "Third parties / internet services")

    d.node("cust", 40, 140, 210, 70, "Policyholders", "web portal + chat assistant", "user")
    d.node("adj", 40, 700, 210, 70, "Adjusters & call centre", "adjuster console · MOTO card entry", "user")
    d.node("pc", 40, 860, 210, 80, "PolicyCore", "policy administration system\n(on-premises)", "ext")
    d.node("cf", 320, 120, 230, 110, "CloudFront + AWS WAF", "Shield Advanced\nresponse-headers policy (CSP, HSTS)\nSPA origin: S3 (OAC)", "edge")
    d.node("apigw", 320, 330, 230, 120, "API Gateway (REST)", "JWT authorizers:\nCognito (customers) · Okta (staff)\nusage plans · throttling\nOpenAPI request validation", "edge")
    d.node("cog", 320, 500, 230, 60, "Amazon Cognito", "customer identities · MFA optional", "security")

    d.node("claims", 620, 175, 190, 70, "claims-api", "claims · documents · chat", "compute")
    d.node("orch", 850, 165, 190, 80, "Orchestrator agent", "LangGraph supervisor", "ai")
    d.node("mcp", 1070, 165, 170, 90, "MCP gateway", "+ Client360 MCP server\n(in-house)", "ai")
    d.node("pay", 660, 290, 150, 70, "payments-svc", "Payvanta tokens", "compute")
    d.node("agents", 850, 285, 390, 120, "Specialist agents",
           "Intake · Coverage (RAG) · Fraud Triage\nSettlement · Correspondence\nper-agent tool allow-lists", "ai")
    d.node("lf", 1060, 450, 180, 60, "Langfuse", "LLM traces (self-hosted)", "ops")

    d.node("msk", 880, 650, 220, 80, "Amazon MSK (Kafka)", "claims.events · agent.tasks\npayments.commands", "msg")
    d.node("egr", 1110, 650, 140, 80, "Egress", "Network Firewall\n+ NAT", "edge")
    d.node("aurora", 600, 820, 160, 90, "Aurora PostgreSQL", "claims · payments\nKMS CMK", "data")
    d.node("ddb", 790, 820, 150, 90, "DynamoDB", "agent memory\n(per-claim + shared)", "data")
    d.node("s3", 955, 820, 145, 90, "S3 documents", "claim docs · photos\nKMS CMK", "data")
    d.node("os", 1110, 820, 160, 90, "OpenSearch", "Serverless vector index\npolicy + claim notes", "data")

    d.node("bed", 1300, 300, 200, 90, "Amazon Bedrock", "foundation models\nGuardrails · VPC endpoint", "ai")
    d.node("sm", 1300, 410, 200, 80, "SageMaker endpoint", "fine-tuned damage-photo\nclassifier · Textract OCR", "ai")
    d.node("kms", 1300, 520, 200, 70, "KMS · Secrets Manager", "customer-managed keys", "security")
    d.node("tf", 1300, 780, 200, 80, "AWS Transfer Family", "SFTP · nightly bordereaux", "msg")
    d.node("mon", 1300, 900, 200, 90, "CloudTrail · GuardDuty", "Security Hub · Config\nCloudWatch", "ops")

    d.node("rn", 1555, 130, 220, 70, "RepairNet MCP server", "partner body-shop network\n(remote MCP, HTTPS)", "ext")
    d.node("c360", 1555, 240, 220, 70, "Client360 CRM", "SaaS", "ext")
    d.node("cs", 1555, 350, 220, 70, "ClaimShield", "fraud-scoring API", "ext")
    d.node("pv", 1555, 460, 220, 70, "Payvanta", "card processor · payouts", "ext")
    d.node("web", 1555, 570, 220, 70, "Public websites", "web-fetch tool targets", "ext")
    d.node("okta", 1555, 680, 220, 70, "Okta", "workforce SSO · FastPass", "security")
    d.node("re", 1555, 790, 220, 70, "Reinsurer", "SFTP endpoint", "ext")
    d.node("spl", 1555, 900, 220, 70, "Splunk Cloud", "SIEM", "ops")

    d.edge("cust", "cf", "HTTPS", sb=("l", 175), loff=(0, -8))
    d.edge("adj", "cf", "HTTPS", via=[(280, 735), (280, 210)], sa="r", sb=("l", 210), lpos=0.85, loff=(22, 0))
    d.edge("cf", "apigw", "/api/*", sa="b", sb="t", loff=(28, 0))
    d.edge("apigw", "claims", "REST", via=[(568, 390), (568, 200)], sa=("r", 390), sb=("l", 200), lpos=0.5, loff=(0, 0))
    d.edge("claims", "pc", "Direct Connect\nsvc-claimpilot", via=[(590, 228), (590, 900)], sa=("l", 228), sb=("r", 900), lpos=0.5, loff=(-60, 40))
    d.edge("claims", "orch", "", sa="r", sb="l")
    d.edge("orch", "agents", "", sa="b", sb="t")
    d.edge("orch", "mcp", "MCP", sa="r", sb="l", loff=(0, -6))
    d.edge("mcp", "rn", "remote MCP", sa=("r", 185), sb=("l", 185), lpos=0.5)
    d.edge("mcp", "c360", "user token", sa=("r", 250), sb=("l", 275), via=[(1400, 250), (1400, 275)], lpos=0.3)
    d.edge("agents", "bed", "InvokeModel", sa=("r", 330), sb=("l", 330), lpos=0.45, loff=(0, -6))
    d.edge("agents", "sm", "", via=[(1282, 372), (1282, 450)], sa=("r", 372), sb=("l", 450))
    d.edge("agents", "os", "RAG query", via=[(1262, 395), (1262, 865)], sa=("r", 395), sb=("r", 865), lpos=0.75, loff=(0, 0))
    d.edge("agents", "ddb", "memory", sa=("b", 865), sb=("t", 865), lpos=0.75, loff=(0, 0))
    d.edge("agents", "msk", "agent.tasks", sa=("b", 990), sb=("t", 990), lpos=0.5, loff=(0, 0))
    d.edge("agents", "lf", "traces", sa=("b", 1150), sb=("t", 1150), lpos=0.5, loff=(0, 6))
    d.edge("agents", "egr", "", via=[(1210, 560), (1180, 560)], sa=("b", 1210), sb="t")
    d.edge("msk", "pay", "payments.commands", via=[(735, 690)], sa="l", sb=("b", 735), lpos=0.5, loff=(0, 0))
    d.edge("claims", "aurora", "", sa=("b", 640), sb=("t", 640))
    d.edge("claims", "s3", "uploads", via=[(660, 790), (1027, 790)], sa=("b", 660), sb="t", lpos=0.8, loff=(0, -4))
    d.edge("egr", "cs", "", via=[(1530, 690), (1530, 385)], sa="r", sb=("l", 385))
    d.edge("egr", "pv", "", via=[(1530, 690), (1530, 495)], sa="r", sb=("l", 495))
    d.edge("egr", "web", "HTTPS egress", via=[(1530, 690), (1530, 605)], sa="r", sb=("l", 605), lpos=0.4, loff=(0, -8))
    d.edge("tf", "re", "SFTP", sa="r", sb=("l", 820), loff=(0, -6))
    d.edge("mon", "spl", "security logs", sa="r", sb=("l", 935), loff=(0, -6))
    d.note(24, 1142, "Legend: pink = AI components · teal = messaging · solid arrows = runtime flows · dashed boxes = trust boundaries",
           12, "#555")
    return d


def agents() -> Diagram:
    d = Diagram(1700, 1060, "Halcyon ClaimPilot — Agent, Tool and Model Interaction",
                "Figure 2 · how the orchestrator, specialist agents, tools, MCP servers, memory and RAG fit together")
    d.zone(20, 90, 260, 950, "Entry points")
    d.zone(300, 90, 1080, 950, "Agent runtime (EKS namespace: agents)", fill="#FFFBFD", color="#B0246E")
    d.zone(1400, 90, 280, 950, "Controls & oversight")

    d.node("chat", 40, 140, 220, 80, "Customer chat", "via claims-api\nBedrock Guardrails on input", "user")
    d.node("console", 40, 270, 220, 80, "Adjuster console", "assign / review claims", "user")
    d.node("ktask", 40, 400, 220, 80, "Kafka agent.tasks", "new FNOL & document events\n(no per-message signing)", "msg")
    d.node("hitl", 40, 820, 220, 110, "Adjuster approval queue", "payouts > £5,000\nclaim denials\n(human in the loop)", "user")

    d.node("orch", 640, 120, 400, 110, "Orchestrator (LangGraph supervisor)",
           "routes tasks to specialist agents\nmax 25 steps · 10-minute wall clock per task\nreads/writes claim memory", "ai")
    d.node("intake", 320, 300, 190, 110, "Intake agent", "FNOL from chat/e-mail\nOCR (Textract)\nphoto classifier", "ai")
    d.node("cov", 530, 300, 190, 110, "Coverage agent", "RAG over policy\nwordings & claim notes\nPolicyCore lookup", "ai")
    d.node("fraud", 740, 300, 190, 110, "Fraud Triage agent", "ClaimShield score\nPython analysis tool\nweb fetch", "ai")
    d.node("settle", 950, 300, 190, 110, "Settlement agent", "computes payout\nemits payments.commands\nrules-engine check", "ai")
    d.node("corr", 1160, 300, 200, 110, "Correspondence agent", "drafts customer letters\nGuardrails content filter", "ai")

    d.node("t_pc", 320, 500, 190, 80, "PolicyCore API", "shared account\nsvc-claimpilot (R/W)", "ext")
    d.node("t_rag", 530, 500, 190, 80, "RAG search", "OpenSearch single index\nno document-level filter", "data")
    d.node("t_py", 740, 500, 168, 80, "Python analysis", "LLM-written code runs\nin the fraud-agent pod", "compute")
    d.node("t_web", 740, 610, 190, 70, "Web fetch", "any URL · no allow-list", "ext")
    d.node("t_cs", 530, 610, 190, 70, "ClaimShield API", "schema-validated", "ext")
    d.node("t_pay", 950, 500, 190, 80, "Payments command", "≤ £5,000 automatic\n> £5,000 → approval", "msg")
    d.node("t_mcp", 1160, 500, 200, 80, "MCP gateway", "Client360 MCP (in-house)\nRepairNet MCP (remote)", "ai")
    d.node("bed", 640, 760, 400, 90, "Amazon Bedrock", "foundation models via VPC endpoint · in-region\nno training on Halcyon data", "ai")
    d.node("mem", 320, 900, 300, 100, "Agent memory (DynamoDB)", "short-term: per claim ID\nlong-term 'lessons': shared\nacross all claims", "data")
    d.node("rules", 1060, 900, 300, 100, "Settlement rules engine", "validates payout vs policy limits\nand excess before command", "security")

    d.node("allow", 1420, 140, 240, 80, "Tool allow-list per agent", "orchestrator config (Git)", "security")
    d.node("kill", 1420, 250, 240, 80, "Kill switch", "LaunchDarkly flag per agent\n+ global 'autonomy off'", "security")
    d.node("audit", 1420, 360, 240, 90, "Tool-call audit log", "S3 Object Lock (WORM)\nagent ID · claim ID · I/O hash", "ops")
    d.node("lf", 1420, 480, 240, 90, "Langfuse traces", "full prompts & responses\nno PII redaction", "ops")
    d.node("gr", 1420, 600, 240, 90, "Bedrock Guardrails", "prompt-attack filter: chat input\nPII filter: customer chat", "security")
    d.node("eval", 1420, 720, 240, 70, "AI red teaming", "not yet performed", "security")

    d.edge("chat", "orch", "", via=[(600, 180)], sa="r", sb=("l", 180))
    d.edge("console", "orch", "", via=[(282, 310), (282, 205)], sa="r", sb=("l", 205))
    d.edge("ktask", "orch", "", via=[(291, 440), (291, 215)], sa="r", sb=("l", 215))
    for a, x in (("intake", 415), ("cov", 625), ("fraud", 835), ("settle", 1045), ("corr", 1260)):
        d.edge("orch", a, "", via=[(840, 265), (x, 265)], sa="b", sb="t")
    d.edge("cov", "t_pc", "", via=[(560, 455), (415, 455)], sa=("b", 560), sb="t")
    d.edge("cov", "t_rag", "", sa=("b", 650), sb=("t", 650))
    d.edge("fraud", "t_py", "", sa="b", sb="t")
    d.edge("fraud", "t_web", "", via=[(921, 455), (921, 645)], sa=("b", 921), sb=("r", 645))
    d.edge("fraud", "t_cs", "", via=[(760, 470), (725, 470), (725, 645)], sa=("b", 760), sb=("r", 645))
    d.edge("settle", "t_pay", "", sa="b", sb="t")
    d.edge("corr", "t_mcp", "", sa="b", sb="t")
    d.edge("t_pay", "hitl", "> £5,000", via=[(1045, 720), (290, 720), (290, 875)], sa="b", sb="r", lpos=0.3)
    d.edge("t_pay", "rules", "", via=[(1100, 870)], sa=("b", 1100), sb="t")
    d.edge("orch", "bed", "all agents\ncall models", via=[(1385, 175), (1385, 805)], sa="r", sb="r", lpos=0.8, loff=(-6, 0))
    d.edge("orch", "mem", "", via=[(310, 150), (310, 950)], sa=("l", 150), sb="l", dashed=True)
    d.note(24, 1052, "Legend: pink = agents and models · purple = guardrails/controls · dashed = memory access", 12, "#555")
    return d


def deployment() -> Diagram:
    d = Diagram(1600, 980, "Halcyon ClaimPilot — Deployment and Network View",
                "Figure 3 · eu-west-2, three availability zones · Terraform-managed, GitOps via Argo CD")
    d.zone(20, 90, 1170, 870, "VPC claimpilot-prod 10.60.0.0/16", fill="#FAFCFF", color="#1F5FBF")
    d.zone(40, 120, 1130, 140, "Public subnets (3 AZ)", color="#B42318")
    d.zone(40, 280, 1130, 260, "Private application subnets (3 AZ) · security groups per node group", color="#1F5FBF")
    d.zone(40, 560, 1130, 180, "Private data subnets (3 AZ) · no route to internet", color="#1E7B43")
    d.zone(40, 760, 1130, 180, "Endpoint subnets · VPC interface/gateway endpoints", color="#6B3FB5")
    d.zone(1210, 90, 370, 870, "Outside the VPC")

    d.node("nat", 70, 160, 220, 80, "NAT gateways", "egress for web-fetch tool\n(not inspected)", "edge")
    d.node("nfw", 320, 160, 260, 80, "AWS Network Firewall", "domain allow-list for\nClaimShield, Payvanta, RepairNet", "edge")
    d.node("tf", 610, 160, 250, 80, "Transfer Family SFTP", "outbound push to reinsurer\nSSH key auth", "msg")
    d.node("alb", 890, 160, 250, 80, "Private NLB / VPC link", "API Gateway → EKS ingress", "edge")

    d.node("ng1", 70, 320, 330, 190, "EKS node group: core", "claims-api · payments-svc\nMCP gateway · Client360 MCP\nIstio ingress / sidecars\nnon-root · read-only root FS\nPod Security: restricted", "compute")
    d.node("ng2", 430, 320, 330, 190, "EKS node group: agents", "orchestrator + 5 agents\nPython analysis tool (in pod)\nLangfuse\nIRSA role per agent", "ai")
    d.node("ctl", 790, 320, 350, 190, "EKS control plane", "private API endpoint only\naccess entries (IAM) · audit logs on\nNetworkPolicies: default-deny in\npayments namespace only\nGuardDuty Runtime Monitoring", "security")

    d.node("aur", 70, 600, 250, 110, "Aurora PostgreSQL", "Multi-AZ · global DB to eu-west-1\nKMS CMK", "data")
    d.node("msk", 350, 600, 250, 110, "MSK brokers", "IAM auth · TLS · topic ACLs\nGlue Schema Registry", "msg")
    d.node("oss", 630, 600, 250, 110, "OpenSearch Serverless", "VPC endpoint access\nKMS CMK", "data")
    d.node("ec", 910, 600, 230, 110, "ElastiCache Redis", "session & rate counters\nTLS · AUTH", "data")

    d.node("ep", 70, 800, 1070, 110, "VPC endpoints",
           "Bedrock runtime · SageMaker runtime · S3 (gateway) · DynamoDB (gateway) · Secrets Manager · KMS · ECR api/dkr · STS · CloudWatch Logs · SSM",
           "security")

    d.node("dx", 1240, 140, 320, 90, "AWS Direct Connect", "to Halcyon data centre\nPolicyCore API (HTTPS)", "ext")
    d.node("ecr", 1240, 270, 320, 90, "Amazon ECR", "scan on push · images not signed\nbase images from Docker Hub", "ops")
    d.node("ci", 1240, 400, 320, 100, "GitLab CI → Argo CD", "Checkmarx SAST · OWASP ZAP DAST\nSnyk dependency scan\nTerraform plan/apply with approvals", "ops")
    d.node("logacct", 1240, 540, 320, 100, "Log archive account", "CloudTrail organisation trail\nS3 Object Lock", "ops")
    d.node("secacct", 1240, 680, 320, 100, "Security tooling account", "GuardDuty · Security Hub\nAWS Config conformance packs · SCPs", "security")
    d.node("ssm", 1240, 820, 320, 90, "Admin access", "SSM Session Manager · no bastion\nIAM Identity Center + time-bound elevation", "security")

    d.edge("ng2", "nat", "web fetch", via=[(500, 280), (180, 280)], sa=("t", 500), sb="b", lpos=0.5)
    d.edge("ng1", "nfw", "", via=[(330, 300), (450, 300)], sa=("t", 330), sb="b")
    d.edge("ng1", "dx", "PolicyCore", via=[(380, 270), (1200, 270), (1200, 185)], sa=("t", 380), sb="l", lpos=0.6)
    d.edge("alb", "ctl", "", sa="b", sb="t")
    d.edge("ci", "ecr", "push", sa="t", sb="b", loff=(30, 0))
    d.note(24, 972, "Legend: dashed boxes = network zones · arrows show the main egress paths", 12, "#555")
    return d


JOBS = {
    OUT + "Halcyon_ClaimPilot_Architecture_Overview.png": overview,
    OUT + "Halcyon_ClaimPilot_Agent_Interaction.png": agents,
    OUT + "Halcyon_ClaimPilot_Deployment_Network.png": deployment,
}
