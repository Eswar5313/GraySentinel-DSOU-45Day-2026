#!/usr/bin/env python3
"""
make_consent_lab_data.py — SYNTHETIC evidence for GraySentinel RIU war-room
"Consent Trap" (OAuth consent abuse against a Microsoft 365-style tenant).

LAB ONLY. Declared-synthetic: tenant corp.example, IPs RFC-5737, domains *.example.net/.org,
app IDs are made-up GUIDs, the "OSINT" block is simulated lookup output (no real lookups were
made and no real application is described). No phishing kit, no app code, no tokens — rows only
model the audit FIELDS a SOC/CTI analyst would see.

Outputs:
  cloud_audit_SYNTHETIC.csv      unified Entra audit + sign-in + Graph + Exchange + SharePoint + proxy
  consent_context_SYNTHETIC.json approved apps, user baselines, high-risk scopes, simulated OSINT
"""
import csv, json, os
from datetime import datetime, timedelta, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
UTC = timezone.utc
FIELDS = ["ts", "source", "action", "user", "app_name", "app_id", "publisher", "publisher_verified",
          "scopes", "consent_type", "src_ip", "country", "object", "count", "result", "detail"]

BAD_APP = "Secure Document Verification"
BAD_ID = "5d0c0000-0000-4000-8000-00000000c7a9"
BAD_PUB = "SecureDocs Verification Ltd"
BAD_IP = "203.0.113.45"                      # RFC-5737, modelled as a DE hosting provider
BAD_DOMAIN = "secure-docverify.example.net"
BAD_SCOPES = "User.Read Mail.ReadBasic Files.Read.All offline_access"
OK_APP, OK_ID = "Example Expense Cloud", "0e0e0000-0000-4000-8000-00000000e1e1"
NEW_OK_APP, NEW_OK_ID = "TeamBoard Planner", "7b7b0000-0000-4000-8000-00000000b0a2"
SSO_APP, SSO_ID = "Example PDF Reader", "9d9d0000-0000-4000-8000-00000000d0f3"
FIN, HR = "finance.user", "hr.user"


def iso(dt): return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def ist(h, m, s=0, day=8):
    """IST wall-clock on Oct <day> 2026 -> UTC datetime."""
    return datetime(2026, 10, day, h, m, s, tzinfo=UTC) - timedelta(hours=5, minutes=30)


def e(rows, dt, source, action, **kw):
    r = {k: "" for k in FIELDS}
    r.update(ts=iso(dt), source=source, action=action)
    r.update({k: str(v) for k, v in kw.items()}); rows.append(r)


def build():
    rows = []
    # ---- approved app consented by an admin months ago ----
    e(rows, datetime(2026, 6, 1, 6, 0, tzinfo=UTC), "entra_audit", "Consent to application", user="it.admin",
      app_name=OK_APP, app_id=OK_ID, publisher="Example Expense Inc", publisher_verified="true",
      scopes="User.Read Files.ReadWrite", consent_type="AllPrincipals", src_ip="198.51.100.10", country="IN",
      result="success", detail="admin consent; procurement ticket PRC-1182")
    # ---- 30-day baseline of normal cloud behaviour ----
    d0 = datetime(2026, 9, 8, 4, 0, tzinfo=UTC)
    for d in range(30):
        t = d0 + timedelta(days=d)
        if t.weekday() >= 5:
            continue
        for u, site, n in ((FIN, "Finance-Ops", 8), (HR, "HR-Policies", 5)):
            e(rows, t, "exchange_audit", "MailItemsAccessed", user=u, app_name="Outlook", src_ip="198.51.100.10",
              country="IN", count=40, result="success", detail="interactive client")
            e(rows, t + timedelta(minutes=30), "sharepoint_audit", "FileAccessed", user=u, app_name="Browser",
              src_ip="198.51.100.10", country="IN", object=site, count=n, result="success")
        e(rows, t + timedelta(hours=2), "graph_activity", "API request", user=FIN, app_name=OK_APP, app_id=OK_ID,
          src_ip="198.51.100.20", country="IN", object="/me/drive/root:/Expenses", count=6, result="success",
          detail="approved integration")
    # ---- false-positive controls ----
    e(rows, ist(11, 30, day=7), "entra_audit", "Consent to application", user="it.admin", app_name=NEW_OK_APP,
      app_id=NEW_OK_ID, publisher="TeamBoard Software GmbH", publisher_verified="true",
      scopes="User.Read Tasks.ReadWrite", consent_type="AllPrincipals", src_ip="198.51.100.10", country="IN",
      result="success", detail="admin consent; new company-approved SaaS; ticket PRC-1240")
    e(rows, ist(11, 45, day=7), "graph_activity", "API request", user=HR, app_name=NEW_OK_APP, app_id=NEW_OK_ID,
      src_ip="198.51.100.30", country="IN", object="/me/planner/tasks", count=4, result="success")
    e(rows, ist(8, 15), "entra_audit", "Consent to application", user="sales.user", app_name=SSO_APP, app_id=SSO_ID,
      publisher="Example PDF Corp", publisher_verified="true", scopes="User.Read", consent_type="Principal",
      src_ip="198.51.100.10", country="IN", result="success", detail="user consent; sign-in only scope")
    # ---- campaign: lure -> genuine consent screen -> app activity ----
    e(rows, ist(8, 41, 30), "proxy", "URL click", user=FIN, src_ip="198.51.100.10", country="IN",
      object=f"https://{BAD_DOMAIN}/share/Q3-audit-confirmation",
      result="redirect", detail="document-sharing lure; 302 to the genuine identity-provider /authorize endpoint "
                                f"with client_id={BAD_ID}")
    e(rows, ist(8, 42, 11), "entra_audit", "Consent to application", user=FIN, app_name=BAD_APP, app_id=BAD_ID,
      publisher=BAD_PUB, publisher_verified="false", scopes=BAD_SCOPES, consent_type="Principal",
      src_ip="198.51.100.10", country="IN", result="success",
      detail=f"user consent; first-seen app in tenant; reply URL https://{BAD_DOMAIN}/callback; MFA satisfied by existing session")
    e(rows, ist(8, 49, 32), "graph_activity", "API request", user=FIN, app_name=BAD_APP, app_id=BAD_ID,
      src_ip=BAD_IP, country="DE", object="/me, /me/mailFolders", count=12, result="success",
      detail="delegated token redeemed from app infrastructure; no interactive sign-in")
    e(rows, ist(9, 3, 18), "exchange_audit", "MailItemsAccessed", user=FIN, app_name=BAD_APP, app_id=BAD_ID,
      src_ip=BAD_IP, country="DE", count=340, result="success", detail="bulk sync-style access via app token")
    e(rows, ist(9, 7, 42), "sharepoint_audit", "FileAccessed", user=FIN, app_name=BAD_APP, app_id=BAD_ID,
      src_ip=BAD_IP, country="DE", object="Finance-Treasury", count=15, result="success",
      detail="site not opened by this user in 30-day baseline")
    e(rows, ist(9, 7, 58), "sharepoint_audit", "FileDownloaded", user=FIN, app_name=BAD_APP, app_id=BAD_ID,
      src_ip=BAD_IP, country="DE", object="Board-Packs", count=8, result="success",
      detail="site not opened by this user in 30-day baseline")
    e(rows, ist(9, 19, 40), "proxy", "URL click", user=HR, src_ip="198.51.100.10", country="IN",
      object=f"https://{BAD_DOMAIN}/share/policy-acknowledgement", result="redirect",
      detail=f"same lure domain; client_id={BAD_ID}")
    e(rows, ist(9, 21, 11), "entra_audit", "Consent to application", user=HR, app_name=BAD_APP, app_id=BAD_ID,
      publisher=BAD_PUB, publisher_verified="false", scopes=BAD_SCOPES, consent_type="Principal",
      src_ip="198.51.100.10", country="IN", result="success", detail="user consent; second user, same application")
    for u, n in ((FIN, 55), (HR, 31)):
        e(rows, ist(9, 31, 52), "graph_activity", "API request", user=u, app_name=BAD_APP, app_id=BAD_ID,
          src_ip=BAD_IP, country="DE", object="/me/messages, /me/drive/root/children", count=n, result="success",
          detail="same app, same infrastructure, multiple users")
    rows.sort(key=lambda r: r["ts"])
    return rows


CONTEXT = {
    "_note": "SYNTHETIC context for the Consent Trap lab. Tenant corp.example, RFC-5737 IPs. LAB ONLY.",
    "tenant": {"name": "corp.example", "employees": 4500, "user_consent_policy": "users may consent to any app (default)"},
    "approved_apps": {OK_ID: OK_APP, NEW_OK_ID: NEW_OK_APP},
    "high_risk_scopes": ["Mail.Read", "Mail.ReadBasic", "Mail.ReadWrite", "Mail.Send", "Files.Read.All",
                         "Files.ReadWrite.All", "Sites.Read.All", "offline_access", "MailboxSettings.ReadWrite",
                         "Directory.Read.All", "User.ReadBasic.All"],
    "trust_bait_words": ["secure", "verification", "verify", "document", "docs", "protect", "official", "update"],
    "users": {FIN: {"dept": "Finance", "countries": ["IN"], "sites": ["Finance-Ops"]},
              HR: {"dept": "HR", "countries": ["IN"], "sites": ["HR-Policies"]},
              "sales.user": {"dept": "Sales", "countries": ["IN"], "sites": []},
              "it.admin": {"dept": "IT", "countries": ["IN"], "sites": [], "admin": True}},
    "osint_SIMULATED": {
        "_note": "Simulated lookup results for the lab. No real WHOIS/CT/VT/urlscan query was made.",
        BAD_DOMAIN: {"registered": "2026-10-02", "registrar_privacy": True, "first_certificate": "2026-10-03",
                     "hosting_ip": BAD_IP, "hosting_country": "DE", "vendor_detections": "0 / 90 (new domain)",
                     "page_title": "Secure Document Verification — Sign in to view",
                     "co_hosted": ["secure-docsign.example.net", "hr-docverify.example.org"],
                     "claimed_vendor_site": "none — no company website, no privacy policy, no support contact"},
    },
}


def main():
    with open(os.path.join(HERE, "cloud_audit_SYNTHETIC.csv"), "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=FIELDS); w.writeheader(); w.writerows(build())
    with open(os.path.join(HERE, "consent_context_SYNTHETIC.json"), "w") as f:
        json.dump(CONTEXT, f, indent=2)
    print("wrote cloud_audit_SYNTHETIC.csv + consent_context_SYNTHETIC.json")


if __name__ == "__main__":
    main()
