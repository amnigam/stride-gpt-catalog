"""Diagrams for the two minimal demo apps (Marlowe Shift Reporter, Northfield SMS Reminders)."""
from diagram import Diagram


def marlowe_architecture() -> Diagram:
    d = Diagram(1720, 960, "Marlowe Shift Reporter — Solution Architecture (Production)",
                "On-premises · Harrogate plant data centre (UK) · no public cloud · SAD v1.0 · Figure 1")
    d.zone(20, 90, 1360, 830, "Marlowe corporate network (on-premises)", fill="#FAFCFF", color="#1F5FBF")
    d.zone(300, 130, 1060, 460,
           "Server VLAN 10.20.30.0/24 · plant firewall: inbound RDP from jump host, SQL 1433 from Report Server only · no internet route",
           color="#B42318")
    d.zone(40, 130, 240, 460, "Plant office network", color="#6B87B5")
    d.zone(40, 640, 240, 260, "Admin VLAN", color="#6B87B5")
    d.zone(1400, 90, 300, 830, "External")

    d.node("mes", 330, 180, 230, 110, "MES database (existing)", "SQL Server 2019 · MESDB\nread-only views", "data")
    d.node("app", 700, 170, 320, 160, "Shift Reporter service",
           "vm-shiftrep-01 · Windows Server 2022\nPython 3.12 · Task Scheduler\nruns 06:00 / 14:00 / 22:00\n"
           "gMSA svc-shiftrep$\nDefender for Endpoint\nCIS L1 GPO baseline (12 exceptions)", "compute")
    d.node("smtp", 1160, 180, 175, 110, "Exchange SMTP relay", "mail-relay-01\nport 25 · no TLS", "ops")
    d.node("pbi", 330, 440, 230, 120, "Power BI Report Server", "existing shared platform\n(out of scope)\nWindows auth · AD groups", "ext")
    d.node("kpi", 700, 440, 320, 120, "SHIFTKPI database",
           "sql-plant-02 · SQL Server 2019 Standard\nno TDE · disk not encrypted\nnightly Veeam backup", "data")
    d.node("splunk", 1160, 440, 175, 120, "Splunk (group SOC)", "Windows Security\nevents only\n(app logs stay local)", "ops")
    d.node("mgr", 60, 200, 200, 80, "Plant managers", "and shift supervisors\nview reports", "user")
    d.node("ad", 330, 670, 230, 110, "Active Directory", "gMSA · AD groups\nServiceNow access requests", "security")
    d.node("ado", 700, 670, 320, 110, "Azure DevOps Server (on-prem)",
           "Git repo · branch policy · peer review\nno SAST · manual deploy over RDP", "ops")
    d.node("cyberark", 1160, 670, 175, 110, "CyberArk", "admin account check-out\nsession recording", "security")
    d.node("jump", 60, 670, 200, 90, "Admin jump host", "Duo MFA · only RDP\npath to server VLAN", "security")
    d.node("admins", 60, 810, 200, 70, "Plant IT admins (2)", "adm- accounts", "user")
    d.node("brennan", 1430, 180, 245, 110, "Brennan Maintenance", "external contractor\nweekly KPI summary e-mail", "ext")

    d.edge("app", "mes", "SQL read\nKerberos · TLS", sa=("l", 235), sb=("r", 235), loff=(0, -14))
    d.edge("app", "kpi", "SQL write · Kerberos · TLS", sa=("b", 860), sb=("t", 860), loff=(0, 0))
    d.edge("pbi", "kpi", "SQL read", sa="r", sb="l", loff=(0, -8))
    d.edge("mgr", "pbi", "HTTPS\nWindows auth", via=[(160, 500)], sa="b", sb=("l", 500), lpos=0.5, loff=(0, 0))
    d.edge("app", "smtp", "SMTP\nplain text", sa=("r", 235), sb=("l", 235), loff=(0, -14))
    d.edge("smtp", "brennan", "e-mail", sa=("r", 235), sb=("l", 235), loff=(0, -8))
    d.edge("app", "splunk", "Windows events", via=[(1250, 310)], sa=("r", 310), sb="t", lpos=0.5, loff=(-20, 30))
    d.edge("admins", "jump", "", sa="t", sb="b")
    d.edge("jump", "app", "RDP", via=[(290, 700), (290, 615), (640, 615), (640, 310)], sa=("r", 700),
           sb=("l", 310), lpos=0.5, loff=(0, -8))
    d.edge("ado", "app", "manual deploy", via=[(1090, 725), (1090, 285)], sa="r", sb=("r", 285), dashed=True,
           lpos=0.75, loff=(0, 0))
    d.note(24, 945, "Legend: solid arrow = runtime flow · dashed arrow = deployment · dashed boxes = network zones",
           12, "#555")
    return d


def northfield_architecture() -> Diagram:
    d = Diagram(1560, 900, "Northfield SMS Reminders — Solution Architecture (Production)",
                "Google Cloud · europe-west2 (London) · serverless, the team builds no containers · SAD v1.0 · Figure 1")
    d.zone(20, 90, 1180, 780, "Google Cloud organisation (Northfield org policies inherited)",
           fill="#FAFCFF", color="#1F5FBF")
    d.zone(40, 160, 580, 560, "Project nfp-reminders-prod (this application)", color="#1F5FBF")
    d.zone(650, 160, 530, 500, "Project nfp-clinicdesk-prod (existing ClinicDesk)", color="#6B87B5")
    d.zone(320, 395, 860, 105, "Shared VPC · deny all ingress", color="#B42318")
    d.zone(1220, 90, 320, 780, "Internet / third parties")

    d.node("sched", 60, 200, 200, 90, "Cloud Scheduler", "reminders-daily · 17:00 UK\nOIDC token", "ops")
    d.node("fn", 340, 200, 240, 150, "Cloud Functions (2nd gen)",
           "fn-send-reminders · Python 3.12\ningress: internal only\nauth required\nservice account sa-reminders",
           "compute")
    d.node("secret", 60, 320, 200, 70, "Secret Manager", "signalpost-api-key", "security")
    d.node("log", 60, 470, 200, 110, "Cloud Logging", "_Default bucket · 30 days\nDEBUG on: phone + text\nalert → on-call",
           "ops")
    d.node("audit", 60, 610, 200, 90, "Cloud Audit Logs", "admin + data access\nlocked bucket · 400 days", "ops")
    d.node("vpcc", 440, 420, 175, 70, "VPC Access connector", "egress: private ranges", "security")
    d.node("sql", 680, 200, 470, 150, "Cloud SQL for PostgreSQL 15 (existing)",
           "clinicdesk-prod · private IP only, public IP off\nview v_tomorrow_appointments (read)\n"
           "table reminders.reminder_log (insert)\nIAM database authentication", "data")
    d.node("cd", 680, 540, 470, 100, "ClinicDesk booking system (existing)",
           "SMS consent captured at booking\nreception sees 'reminder not sent'", "ext")
    d.node("build", 330, 760, 260, 90, "GitHub + Cloud Build",
           "Terraform · Semgrep · pip-audit · SBOM\nWorkload Identity Federation", "ops")
    d.node("eng", 650, 760, 330, 90, "Engineers (3)",
           "Workspace SSO · security-key 2SV\nstanding Project Owner on prod", "user")
    d.node("sp", 1250, 200, 260, 110, "SignalPost SMS API", "UK SMS gateway (third party)\nVSA + DPA in place", "ext")
    d.node("phones", 1250, 470, 260, 90, "Patients' mobile phones", "~1,900 SMS per day", "user")

    d.edge("sched", "fn", "HTTPS\n+ OIDC", sa=("r", 245), sb=("l", 245), loff=(0, -16))
    d.edge("fn", "secret", "", via=[(300, 320), (300, 355)], sa=("l", 320), sb=("r", 355))
    d.edge("fn", "log", "", via=[(370, 525)], sa=("b", 370), sb=("r", 525))
    d.edge("fn", "vpcc", "private\nranges", sa=("b", 570), sb=("t", 570), loff=(-40, 0))
    d.edge("vpcc", "sql", "TLS · IAM DB auth", via=[(915, 455)], sa="r", sb=("b", 915), lpos=0.5, loff=(0, -8))
    d.edge("cd", "sql", "", sa=("t", 1080), sb=("b", 1080))
    d.edge("fn", "sp", "HTTPS TLS 1.2 · direct internet egress (unrestricted)", via=[(500, 125), (1230, 125), (1230, 255)],
           sa=("t", 500), sb=("l", 255), lpos=0.5, loff=(0, -6))
    d.edge("sp", "phones", "SMS", sa="b", sb="t", loff=(24, 0))
    d.edge("build", "fn", "deploy", via=[(635, 805), (635, 290)], sa="r", sb=("r", 290), dashed=True,
           lpos=0.12, loff=(0, 0))
    d.note(24, 890, "Legend: solid arrow = runtime flow · dashed arrow = deployment · dashed boxes = trust boundaries",
           12, "#555")
    return d


JOBS = {
    "../marlowe-shift-reporter/Marlowe_ShiftReporter_Architecture.png": marlowe_architecture,
    "../northfield-sms-reminders/Northfield_SMSReminders_Architecture.png": northfield_architecture,
}
