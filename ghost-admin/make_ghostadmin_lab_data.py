#!/usr/bin/env python3
"""
make_ghostadmin_lab_data.py — SYNTHETIC evidence for GraySentinel DSOU
war-room "Ghost Admin" (DC-02 / privileged-identity compromise).

All data is declared-synthetic lab data:
  * external/internal IPs are RFC-5737 (203.0.113.x) and RFC-1918 (10.x) ranges
  * domains are corp.example.com
  * no real credentials, no exploit content — only Windows Security event rows

Outputs (next to this script):
  ghostadmin_events_SYNTHETIC.csv   Windows Security + PowerShell + Sysmon rows
  ghostadmin_context_SYNTHETIC.json identity baseline, group, service-account context
"""
import csv, json, os
from datetime import datetime, timedelta, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
UTC = timezone.utc
FIELDS = ["ts", "host", "channel", "event_id", "user", "logon_type", "logon_id",
          "src_ip", "src_host", "status", "process", "parent", "cmdline",
          "group", "member", "target", "detail"]

ATTACKER_HOST, ATTACKER_IP = "WKS-FIN-204", "10.20.44.204"     # a normal finance workstation (first foothold)
VICTIM_USER = "s.menon"                                        # help-desk user, low priv normally
DC = "DC-02"
DC_IP = "10.20.0.12"
LOGON_ID = "0x7F31A9"


def iso(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def ev(rows, dt, host, channel, eid, **kw):
    r = {k: "" for k in FIELDS}
    r.update(ts=iso(dt), host=host, channel=channel, event_id=str(eid))
    r.update({k: str(v) for k, v in kw.items()})
    rows.append(r)


def build():
    rows = []
    base = datetime(2026, 9, 6, 4, 0, tzinfo=UTC)
    # ---- 30-day baseline: s.menon is console-only on WKS-FIN-204, never touches DCs ----
    for d in range(30):
        t = base + timedelta(days=d, minutes=(d * 11) % 40)
        if t.weekday() < 5:
            ev(rows, t, ATTACKER_HOST, "Security", 4624, user=VICTIM_USER,
               logon_type=2, logon_id=f"0x11{d:03d}", src_ip="127.0.0.1", src_host=ATTACKER_HOST)
        # legitimate domain admin maintenance on DC-02 from the PAW (control case)
        if d % 7 == 3:
            ev(rows, t + timedelta(hours=1), DC, "Security", 4624, user="da.patel",
               logon_type=10, logon_id=f"0x22{d:03d}", src_ip="10.20.9.10", src_host="PAW-ADMIN-01",
               detail="CHG-5582 scheduled patch")

    # ---- Attack window: Tue 06-Oct-2026, ~02:40 IST (Mon 21:10Z) ----
    t = datetime(2026, 10, 5, 21, 10, 0, tzinfo=UTC)
    # 1) failed logons against DC-02 (password guessing for a few service/admin names) — no alert fired
    for i, u in enumerate(["svc_backup", "svc_sql", "helpdesk.adm", "s.menon"] * 3):
        ev(rows, t + timedelta(seconds=18 * i), DC, "Security", 4625, user=u, logon_type=3,
           src_ip=ATTACKER_IP, src_host=ATTACKER_HOST,
           status="0xC000006A" if u == "s.menon" else "0xC0000064")
    # 2) successful network logon to DC-02 with s.menon from the finance workstation (unusual)
    t_ok = t + timedelta(minutes=5)
    ev(rows, t_ok, DC, "Security", 4624, user=VICTIM_USER, logon_type=3, logon_id=LOGON_ID,
       src_ip=ATTACKER_IP, src_host=ATTACKER_HOST, detail="AuthPkg=NTLM;no Kerberos PAC")
    # 3) special privileges assigned
    ev(rows, t_ok + timedelta(seconds=3), DC, "Security", 4672, user=VICTIM_USER, logon_id=LOGON_ID,
       detail="SeDebugPrivilege;SeEnableDelegationPrivilege;SeBackupPrivilege")
    # 4) privileged group change — s.menon added to Domain Admins (4728/4732)
    ev(rows, t_ok + timedelta(seconds=40), DC, "Security", 4728, user=VICTIM_USER,
       group="Domain Admins", member=VICTIM_USER, target="corp.example.com\\Domain Admins",
       detail="AddMemberToSecurityEnabledGlobalGroup")
    ev(rows, t_ok + timedelta(seconds=41), DC, "Security", 4732, user=VICTIM_USER,
       group="Administrators", member=VICTIM_USER, target="BUILTIN\\Administrators")
    # 5) PowerShell shortly after on DC-02
    p = t_ok + timedelta(seconds=95)
    ev(rows, p, DC, "Security", 4688, user=VICTIM_USER, logon_id=LOGON_ID,
       process="powershell.exe", parent="wsmprovhost.exe", cmdline="powershell.exe -NoP -Enc <b64>")
    ev(rows, p, DC, "Sysmon", 1, user=VICTIM_USER, logon_id=LOGON_ID,
       process="powershell.exe", parent="wsmprovhost.exe", cmdline="powershell.exe -NoP -Enc <b64>")
    ldap = ("Get-ADUser -Filter * -Properties memberOf; "
            "Get-ADGroupMember 'Domain Admins'; "
            "Get-ADReplAccount -All -Server DC-02 (DCSync-style replication read)")
    ev(rows, p + timedelta(seconds=2), DC, "PowerShell", 4104, user=VICTIM_USER,
       cmdline=ldap, detail="ScriptBlock decoded")
    # 6) LDAP query spike + directory replication request (DCSync indicator: 4662 with replication GUID)
    for i in range(14):
        ev(rows, p + timedelta(seconds=4 + i), DC, "Security", 4662, user=VICTIM_USER,
           detail="Object:domainDNS;Access=Control Access;Property=DS-Replication-Get-Changes-All"
                  if i == 13 else "Object:user;Access=Read Property (LDAP enumeration)")
    # 7) new service installed for persistence (7045) on DC-02
    ev(rows, p + timedelta(seconds=30), DC, "System", 7045, user=VICTIM_USER,
       process="svchost", detail="Service=WinSysMon2;ImagePath=%TEMP%\\wsm2.exe;Start=auto")
    # 8) lateral: s.menon (now DA) authenticates to a second DC and a file server
    lat = p + timedelta(seconds=60)
    ev(rows, lat, "DC-01", "Security", 4624, user=VICTIM_USER, logon_type=3, logon_id="0x801A",
       src_ip=DC_IP, src_host=DC, detail="AuthPkg=Kerberos")
    ev(rows, lat + timedelta(seconds=5), "FS-CORP-01", "Security", 4624, user=VICTIM_USER,
       logon_type=3, logon_id="0x802B", src_ip=DC_IP, src_host=DC)
    ev(rows, lat + timedelta(seconds=7), "FS-CORP-01", "Security", 5140, user=VICTIM_USER,
       src_ip=DC_IP, detail="Share=\\\\*\\SYSVOL")
    # 9) Kerberos TGT request for the privileged account from the odd host (4768)
    ev(rows, lat + timedelta(seconds=12), DC, "Security", 4768, user=VICTIM_USER,
       src_ip=ATTACKER_IP, detail="TGT requested; ticket encryption RC4 (downgrade)")
    # 10) EDR: clean
    ev(rows, p + timedelta(minutes=15), DC, "Defender", 1001, detail="Scan complete; 0 threats")
    rows.sort(key=lambda r: r["ts"])
    return rows


CONTEXT = {
    "_note": "SYNTHETIC context for Ghost Admin lab (RFC-5737 / corp.example.com).",
    "assets": {
        DC: {"role": "Domain Controller (Tier-0)", "ip": DC_IP, "interactive_logons_expected": False},
        "DC-01": {"role": "Domain Controller (Tier-0)", "ip": "10.20.0.11"},
        "PAW-ADMIN-01": {"role": "Privileged Access Workstation", "ip": "10.20.9.10"},
        ATTACKER_HOST: {"role": "Finance user workstation (Tier-2)", "ip": ATTACKER_IP},
    },
    "users": {
        VICTIM_USER: {"dept": "Help Desk", "tier": 2, "normally_admin": False,
                      "normal_hosts": [ATTACKER_HOST], "pwd_last_set": "2026-07-02T06:10:00Z",
                      "mfa": "none (on-prem account)"},
        "da.patel": {"dept": "IT", "tier": 0, "normally_admin": True,
                     "approved_sources": ["10.20.9.10"]},
    },
    "privileged_groups": ["Domain Admins", "Enterprise Admins", "Administrators", "Backup Operators"],
    "service_accounts": [{"name": "svc_backup", "spn": "backup/FS-CORP-01", "tier": 1}],
    "change_tickets": [{"id": "CHG-5582", "host": DC, "user": "da.patel", "window": "weekly patch"}],
    "siem_note": "AD/DC audit logs retained 7 days; no alert rule for 4728/4732 on Tier-0 before this case.",
}


def main():
    rows = build()
    with open(os.path.join(HERE, "ghostadmin_events_SYNTHETIC.csv"), "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=FIELDS)
        w.writeheader(); w.writerows(rows)
    with open(os.path.join(HERE, "ghostadmin_context_SYNTHETIC.json"), "w") as f:
        json.dump(CONTEXT, f, indent=2)
    print(f"wrote {len(rows)} events -> ghostadmin_events_SYNTHETIC.csv")
    print("wrote context      -> ghostadmin_context_SYNTHETIC.json")


if __name__ == "__main__":
    main()
