#!/usr/bin/env python3
"""
make_session_lab_data.py — SYNTHETIC telemetry for GraySentinel SSOU war-room
"Ghost Session" (valid-session / identity-context abuse in a hybrid lab, corp.lab.internal).

LAB ONLY. This file IS the "safe adversary simulation" of Mission 08: it writes the telemetry a
blue team would see, using a synthetic identity and declared-synthetic values (RFC-5737 / RFC-1918
IPs, made-up session and token labels). Nothing here steals, replays or forges a real session or
token, and no real system is contacted — the second "environment" is just rows in a CSV.

Outputs:
  session_telemetry_SYNTHETIC.csv  unified IdP + cloud + remote-access + file-server + proxy + EDR rows
  session_context_SYNTHETIC.json   managed devices, user baseline, sensitive resources, working hours
"""
import csv, json, os
from datetime import datetime, timedelta, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
UTC = timezone.utc
FIELDS = ["ts", "source", "action", "user", "device", "src_ip", "country", "session_id", "token_id",
          "app", "resource", "count", "mfa", "result", "detail"]

USER = "finance.manager"
LT, LT_IP, EGRESS = "FIN-LT-22", "10.50.22.22", "198.51.100.22"       # managed laptop, office egress (IN)
GW_IP, VPN_POOL = "198.51.100.50", "10.50.99.14"                      # RA-GW-01 public side / VPN pool
FAR_IP = "203.0.113.88"                                               # second geography (NL), RFC-5737
S_OWNER, S_GHOST = "S-1001", "S-1002"
T_OWNER, T_GHOST = "T-A1", "T-B7"
GHOST_DEV = "UNREGISTERED-DEV"


def iso(dt): return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def ist(h, m, s=0, day=8, month=10):
    return datetime(2026, month, day, h, m, s, tzinfo=UTC) - timedelta(hours=5, minutes=30)


def e(rows, dt, source, action, **kw):
    r = {k: "" for k in FIELDS}
    r.update(ts=iso(dt), source=source, action=action, user=USER)
    r.update({k: str(v) for k, v in kw.items()}); rows.append(r)


def build():
    rows = []
    # ---- 30-day baseline: one device, one country, one finance app, one file server, office hours ----
    d0 = datetime(2026, 9, 8, 4, 30, tzinfo=UTC)          # 10:00 IST
    for d in range(30):
        t = d0 + timedelta(days=d)
        if t.weekday() >= 5:
            continue
        sid, tid = f"S-B{d:02d}", f"T-B{d:02d}"
        e(rows, t, "idp", "signin", device=LT, src_ip=EGRESS, country="IN", session_id=sid, token_id=tid,
          mfa="satisfied", result="success", detail="interactive sign-in; compliant managed device")
        e(rows, t + timedelta(minutes=10), "cloud", "app_access", device=LT, src_ip=EGRESS, country="IN",
          session_id=sid, token_id=tid, app="FinLedger", result="success")
        e(rows, t + timedelta(minutes=10, seconds=2), "proxy", "http_connect", device=LT, src_ip=LT_IP,
          app="FinLedger", resource="finledger.corp-cloud.lab", result="allowed")
        e(rows, t + timedelta(minutes=40), "fileserver", "auth", device=LT, src_ip=LT_IP, resource="FS-FIN-01",
          result="success", detail="Kerberos; Logon Type 3")
        e(rows, t + timedelta(minutes=41), "fileserver", "file_access", device=LT, src_ip=LT_IP,
          resource=r"\\FS-FIN-01\Reports", count=18 + d % 7, result="success")
        e(rows, t + timedelta(hours=8, minutes=20), "idp", "signout", device=LT, src_ip=EGRESS, country="IN",
          session_id=sid, token_id=tid, result="success")
    # ---- exercise day: Thu 08 Oct 2026 (times IST) ----
    e(rows, ist(10, 2), "idp", "signin", device=LT, src_ip=EGRESS, country="IN", session_id=S_OWNER,
      token_id=T_OWNER, mfa="satisfied", result="success", detail="interactive sign-in; compliant managed device")
    e(rows, ist(10, 7), "idp", "session_created", device=GHOST_DEV, src_ip=GW_IP, country="IN",
      session_id=S_GHOST, token_id=T_GHOST, mfa="inherited", result="success",
      detail="new cloud session; no MFA prompt (claim carried by existing session context); device not registered; via RA-GW-01")
    e(rows, ist(10, 7, 5), "ragw", "tunnel_up", device=GHOST_DEV, src_ip=GW_IP, country="IN",
      resource="RA-GW-01", result="success", detail=f"remote-access tunnel; pool address {VPN_POOL}; posture check skipped (legacy profile)")
    e(rows, ist(10, 13), "cloud", "app_access", device=LT, src_ip=EGRESS, country="IN", session_id=S_OWNER,
      token_id=T_OWNER, app="FinLedger", result="success", detail="normal finance application")
    e(rows, ist(10, 13, 2), "proxy", "http_connect", device=LT, src_ip=LT_IP, app="FinLedger",
      resource="finledger.corp-cloud.lab", result="allowed")
    e(rows, ist(10, 21), "cloud", "app_access", device=GHOST_DEV, src_ip=GW_IP, country="IN", session_id=S_GHOST,
      token_id=T_GHOST, app="Cloud Console", result="success",
      detail="tenant dashboard: users, groups, app registrations viewed; app never used by this identity")
    e(rows, ist(10, 26), "fileserver", "auth", device=GHOST_DEV, src_ip=VPN_POOL, resource="FS-FIN-02",
      result="success", detail="NTLM; Logon Type 3; server never accessed by this identity")
    e(rows, ist(10, 31), "fileserver", "file_access", device=GHOST_DEV, src_ip=VPN_POOL,
      resource=r"\\FS-FIN-02\Treasury", count=412, result="success", detail="412 files read in 4 minutes")
    e(rows, ist(10, 35), "edr", "scan", device=LT, src_ip=LT_IP, result="clean",
      detail="FIN-LT-22: no malware, no suspicious process; browser + office apps only")
    e(rows, ist(10, 39), "idp", "token_use", device=GHOST_DEV, src_ip=FAR_IP, country="NL", session_id=S_GHOST,
      token_id=T_GHOST, mfa="inherited", result="success",
      detail="same session + token now presented from a second geography; laptop session S-1001 still active in IN")
    e(rows, ist(10, 40), "cloud", "app_access", device=LT, src_ip=EGRESS, country="IN", session_id=S_OWNER,
      token_id=T_OWNER, app="FinLedger", result="success", detail="owner still working normally")
    e(rows, ist(10, 40, 2), "proxy", "http_connect", device=LT, src_ip=LT_IP, app="FinLedger",
      resource="finledger.corp-cloud.lab", result="allowed")
    e(rows, ist(10, 44), "cloud", "app_permission_grant", device=GHOST_DEV, src_ip=FAR_IP, country="NL",
      session_id=S_GHOST, token_id=T_GHOST, app="MailSync Helper", result="success",
      detail="delegated permissions granted: Mail.Read offline_access; disposable lab application")
    e(rows, ist(10, 51), "helpdesk", "user_statement", device=LT, result="recorded",
      detail="user: 'I was working normally. I didn't install anything or share my password.'")
    e(rows, ist(18, 20), "idp", "signout", device=LT, src_ip=EGRESS, country="IN", session_id=S_OWNER,
      token_id=T_OWNER, result="success")
    e(rows, ist(19, 40), "idp", "token_refresh", device=GHOST_DEV, src_ip=FAR_IP, country="NL", session_id=S_GHOST,
      token_id=T_GHOST, mfa="inherited", result="success",
      detail="browser session still active after the user's working hours; owner signed out at 18:20")
    rows.sort(key=lambda r: r["ts"])
    return rows


CONTEXT = {
    "_note": "SYNTHETIC context for the Ghost Session lab (corp.lab.internal). All identities are synthetic, "
             "disposable and lab-only. RFC-5737 / RFC-1918 addresses.",
    "managed_devices": {LT: {"owner": USER, "ip": LT_IP, "compliant": True, "edr": True}},
    "users": {USER: {"dept": "Finance", "countries": ["IN"], "apps": ["FinLedger"], "file_servers": ["FS-FIN-01"],
                     "work_hours_ist": [9, 19], "max_daily_files": 25, "privileged": False}},
    "sensitive_resources": ["FS-FIN-02", r"\\FS-FIN-02\Treasury", "Cloud Console"],
    "assets": {"IDP-01": "Identity Provider", "RA-GW-01": "Remote Access Gateway", "FS-FIN-02": "Finance file server (Treasury)",
               "FS-FIN-01": "Finance file server (Reports)", "SIEM-01": "SIEM", "corp-cloud.lab": "Cloud tenant"},
    "session_policy": {"lifetime_hours": 24, "mfa_reprompt_on_new_device": False, "token_binding": False},
    "lab_safety": "Synthetic + disposable + lab-only identity. No real credential, session or token is used.",
}


def main():
    with open(os.path.join(HERE, "session_telemetry_SYNTHETIC.csv"), "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=FIELDS); w.writeheader(); w.writerows(build())
    with open(os.path.join(HERE, "session_context_SYNTHETIC.json"), "w") as f:
        json.dump(CONTEXT, f, indent=2)
    print("wrote session_telemetry_SYNTHETIC.csv + session_context_SYNTHETIC.json")


if __name__ == "__main__":
    main()
