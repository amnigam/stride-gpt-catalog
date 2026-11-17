from diagram import Diagram


def corvane_architecture() -> Diagram:
    d = Diagram(1560, 1000, "Corvane Supplier Hub — Solution Architecture (Production)",
                "Azure West Europe (backups geo-replicated to North Europe) · SAD v1.2 · Figure 1")
    d.zone(20, 90, 270, 200, "Internet")
    d.zone(20, 310, 270, 250, "Corvane corporate network")
    d.zone(305, 90, 995, 890, "Azure subscription sub-procurement-prod (Corvane tenant)",
           fill="#FAFCFF", color="#1F5FBF")
    d.zone(570, 360, 715, 450, "VNet vnet-suphub-prod 10.40.0.0/22", color="#1F5FBF")
    d.zone(590, 385, 470, 165, "snet-app-integration (NSG)", color="#6B87B5")
    d.zone(590, 615, 680, 180, "snet-private-endpoints (NSG: inbound from app subnet only)", color="#6B87B5")
    d.zone(1315, 90, 230, 890, "Third-party SaaS")

    d.node("sup", 45, 175, 220, 70, "Supplier users", "browser · ~4,000 companies", "user")
    d.node("staff", 45, 400, 220, 70, "Procurement staff", "Analysts · Approvers · Admins", "user")
    d.node("afd", 330, 180, 220, 140, "Azure Front Door Premium",
           "WAF policy: OWASP DRS 2.1\nPrevention mode\nRate limit rule: /Account/Login\nManaged TLS certificate", "edge")
    d.node("extid", 604, 110, 200, 70, "Entra External ID", "supplier sign-in\nSMS OTP opt-in", "security")
    d.node("entra", 824, 110, 200, 70, "Entra ID (workforce)", "SSO · Conditional Access MFA", "security")
    d.node("ai", 1080, 110, 200, 80, "Application Insights", "+ Log Analytics\n90-day retention", "ops")
    d.node("app", 620, 410, 420, 120, "App Service  app-suphub-prod",
           ".NET 8 Razor Pages · P1v3 × 2 instances\nSystem-assigned managed identity\n"
           "Access restriction: Front Door only · SCM site: corporate IPs only", "compute")
    d.node("sql", 604, 645, 200, 110, "Azure SQL Database", "sqldb-suphub · TDE\nEntra-only auth\nPITR 35 days", "data")
    d.node("blob", 856, 645, 200, 110, "Storage stsuphubdocs", "container supplier-docs\nSSE · GRS\npublic access off", "data")
    d.node("kv", 1080, 645, 180, 110, "Key Vault", "kv-suphub-prod\nRBAC · soft delete\npurge protection", "security")
    d.node("ci", 330, 840, 220, 90, "GitHub Actions", "OIDC federated deploy · Bicep\nCodeQL · Dependabot · SBOM", "ops")
    d.node("def", 604, 860, 450, 60, "Defender for Cloud (foundational CSPM) + Azure Policy", "", "security")
    d.node("bank", 1335, 400, 190, 80, "BankVerify API", "IBAN / account ownership", "ext")
    d.node("sg", 1335, 560, 190, 80, "SendGrid", "transactional e-mail", "ext")

    d.edge("sup", "afd", "HTTPS", sb=("l", 210), loff=(-6, -8))
    d.edge("staff", "afd", "HTTPS", via=[(300, 435), (300, 295)], sa="r", sb=("l", 295), lpos=0.5, loff=(26, 0))
    d.edge("afd", "app", "HTTPS\n(X-Azure-FDID\nheader checked)", via=[(440, 440)], sa="b", sb=("l", 440),
           lpos=0.45, loff=(0, -22))
    d.edge("app", "extid", "OIDC", sa=("t", 704), sb="b", loff=(0, 10))
    d.edge("app", "entra", "OIDC", sa=("t", 924), sb="b", loff=(0, 10))
    d.edge("app", "ai", "telemetry + audit events", via=[(1180, 425)], sa=("r", 425), sb="b", lpos=0.5, loff=(0, -40))
    d.edge("app", "bank", "HTTPS (outbound not restricted)", sa=("r", 455), sb=("l", 455), lpos=0.62, loff=(0, -6))
    d.edge("app", "sg", "HTTPS · API key from Key Vault", via=[(1300, 490), (1300, 600)], sa=("r", 490),
           sb=("l", 600), lpos=0.5, loff=(-40, -6))
    d.edge("app", "kv", "secrets (MI)", via=[(1170, 515)], sa=("r", 515), sb=("t", 1170), lpos=0.5, loff=(0, 30))
    d.edge("app", "sql", "TDS/TLS · private endpoint · MI", sa=("b", 704), sb="t", loff=(0, 6))
    d.edge("app", "blob", "HTTPS · private endpoint · MI", sa=("b", 956), sb="t", loff=(0, -10))
    d.edge("ci", "app", "deploy", via=[(578, 885), (578, 505)], sa="r", sb=("l", 505), dashed=True, lpos=0.5, loff=(-26, 0))
    d.note(24, 990, "Legend: solid arrow = runtime flow · dashed arrow = deployment · dashed boxes = trust boundaries",
           12, "#555")
    return d
