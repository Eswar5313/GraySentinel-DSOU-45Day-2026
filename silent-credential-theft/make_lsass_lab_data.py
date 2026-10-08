#!/usr/bin/env python3
"""
make_lsass_lab_data.py — SYNTHETIC evidence for GraySentinel DSOU war-room
"Silent Credential Theft" (FIN-WS-117: LSASS access -> unusual authentication).

LAB ONLY. Declared-synthetic: hosts are lab names, IPs are RFC-1918, hashes are fake
("SYNTH-…"), command lines are redacted placeholders. NO dumping tool, NO technique
instructions — rows only model the Windows Security / Sysmon / EDR FIELDS a SOC would see.

Outputs:
  lsass_events_SYNTHETIC.csv    unified Security + Sysmon + EDR export (one row per event)
  lsass_context_SYNTHETIC.json  assets, users, approved LSASS readers, sensitive shares, tickets
"""
import csv, json, os
from datetime import datetime, timedelta, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
UTC = timezone.utc
FIELDS = ["ts", "host", "channel", "event_id", "user", "logon_type", "src_ip", "src_host",
          "process", "parent", "cmdline", "target", "granted_access", "signed", "hash",
          "auth_pkg", "service", "share", "detail"]

WS, WS_IP = "FIN-WS-117", "10.20.31.117"
WS2, WS2_IP = "FIN-WS-121", "10.20.31.121"
FS, FS_IP = "FILE-SRV-03", "10.20.5.33"
FS_OLD = "FILE-SRV-01"
DC, PAW, PAW_IP = "DC-01", "PAW-ADMIN-01", "10.20.9.10"
USER, ADMIN = "f.rao", "adm.kiran"
BAD_IMG = r"C:\Users\f.rao\AppData\Local\Temp\dbgsvc.exe"
BAD_HASH = "SYNTH-SHA256-0000BADC0FFEE117"
DEFENDER = r"C:\ProgramData\Microsoft\Windows Defender\Platform\MsMpEng.exe"
EDR = r"C:\Program Files\LabEDR\edr-agent.exe"
LSASS = r"C:\Windows\System32\lsass.exe"


def iso(dt): return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def e(rows, dt, host, channel, eid, **kw):
    r = {k: "" for k in FIELDS}
    r.update(ts=iso(dt), host=host, channel=channel, event_id=str(eid))
    r.update({k: str(v) for k, v in kw.items()}); rows.append(r)


def build():
    rows = []
    # ---- 30-day baseline: normal working days (03:35Z = 09:05 IST) ----
    day0 = datetime(2026, 9, 8, 3, 35, tzinfo=UTC)
    for d in range(30):
        t = day0 + timedelta(days=d)
        if t.weekday() >= 5:
            continue
        e(rows, t, WS, "Security", 4624, user=USER, logon_type=2, src_ip="127.0.0.1", src_host=WS,
          auth_pkg="Kerberos", detail="interactive console logon")
        # expected LSASS readers: Defender (query-limited) + the EDR agent (signed, approved)
        e(rows, t + timedelta(minutes=3), WS, "Sysmon", 10, user="NT AUTHORITY\\SYSTEM", process=DEFENDER,
          target=LSASS, granted_access="0x1000", signed="true", hash="SYNTH-SHA256-DEFENDER",
          detail="AV engine routine scan")
        if t.weekday() == 0:
            e(rows, t + timedelta(minutes=5), WS, "Sysmon", 10, user="NT AUTHORITY\\SYSTEM", process=EDR,
              target=LSASS, granted_access="0x1410", signed="true", hash="SYNTH-SHA256-LABEDR",
              detail="EDR credential-guard inspection")
        # her normal file work: FILE-SRV-01 reports share, Kerberos AES
        e(rows, t + timedelta(minutes=20), DC, "Security", 4769, user=USER, src_ip=WS_IP, src_host=WS,
          service="cifs/" + FS_OLD, detail="TicketEncryptionType=0x12 (AES256)")
        e(rows, t + timedelta(minutes=20, seconds=4), FS_OLD, "Security", 4624, user=USER, logon_type=3,
          src_ip=WS_IP, src_host=WS, auth_pkg="Kerberos")
        e(rows, t + timedelta(minutes=21), FS_OLD, "Security", 5145, user=USER, src_ip=WS_IP,
          share=r"\\FILE-SRV-01\Finance-Reports", detail=r"Reports\monthly_close.xlsx (ReadData)")
    # ---- how the admin credential got onto the workstation (2 days earlier, legitimate) ----
    t = datetime(2026, 10, 5, 6, 10, tzinfo=UTC)
    e(rows, t, WS, "Security", 4624, user=ADMIN, logon_type=10, src_ip=PAW_IP, src_host=PAW,
      auth_pkg="Kerberos", detail="RDP remote support session; ticket INC-20931 (printer driver)")
    e(rows, t + timedelta(seconds=2), WS, "Security", 4672, user=ADMIN,
      detail="SeDebugPrivilege;SeBackupPrivilege;SeTakeOwnershipPrivilege")
    # ---- legitimate admin control case: PAW -> FILE-SRV-03 with an approved change ----
    t = datetime(2026, 10, 6, 5, 0, tzinfo=UTC)
    e(rows, t, FS, "Security", 4624, user=ADMIN, logon_type=3, src_ip=PAW_IP, src_host=PAW,
      auth_pkg="Kerberos", detail="approved maintenance CHG-4471")
    e(rows, t + timedelta(seconds=1), FS, "Security", 4672, user=ADMIN,
      detail="SeBackupPrivilege;SeRestorePrivilege")
    # ---- incident day: Thu 08 Oct 2026 (04:02Z = 09:32 IST) ----
    t0 = datetime(2026, 10, 8, 4, 2, 10, tzinfo=UTC)
    e(rows, t0, WS, "Security", 4624, user=USER, logon_type=2, src_ip="127.0.0.1", src_host=WS,
      auth_pkg="Kerberos", detail="interactive console logon")
    e(rows, t0 + timedelta(minutes=3), WS, "Sysmon", 10, user="NT AUTHORITY\\SYSTEM", process=DEFENDER,
      target=LSASS, granted_access="0x1000", signed="true", hash="SYNTH-SHA256-DEFENDER",
      detail="AV engine routine scan")
    a = datetime(2026, 10, 8, 4, 10, 5, tzinfo=UTC)
    for ch, eid in (("Security", 4688), ("Sysmon", 1)):
        e(rows, a, WS, ch, eid, user=USER, process=BAD_IMG, parent=r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE",
          cmdline="dbgsvc.exe <redacted-synthetic-arguments>", signed="false", hash=BAD_HASH,
          detail="unsigned binary in user-writable path; first seen in environment")
    e(rows, a + timedelta(seconds=15), WS, "Sysmon", 10, user=USER, process=BAD_IMG, target=LSASS,
      granted_access="0x1010", signed="false", hash=BAD_HASH,
      detail="PROCESS_VM_READ|PROCESS_QUERY_LIMITED_INFORMATION; call trace has unbacked memory region")
    e(rows, a + timedelta(seconds=17), WS, "EDR", 9001, user=USER, process=BAD_IMG, target=LSASS,
      hash=BAD_HASH, detail="EDR: suspicious credential-access behaviour (alert only, not blocked)")
    # failed authentication burst from the workstation
    f = datetime(2026, 10, 8, 4, 12, 30, tzinfo=UTC)
    for i, (u, dst) in enumerate([("svc.finbackup", FS), ("svc.finbackup", FS), (ADMIN, FS),
                                  ("administrator", FS), ("administrator", WS2), ("svc.finbackup", WS2)]):
        e(rows, f + timedelta(seconds=14 * i), dst, "Security", 4625, user=u, logon_type=3,
          src_ip=WS_IP, src_host=WS, auth_pkg="NTLM", detail="Status=0xC000006D bad username or password")
    # the user's own account lands on a server she never uses, over NTLM
    b = datetime(2026, 10, 8, 4, 14, 50, tzinfo=UTC)
    e(rows, b, FS, "Security", 4624, user=USER, logon_type=3, src_ip=WS_IP, src_host=WS,
      auth_pkg="NTLM", detail="network logon; no Kerberos ticket requested first")
    # explicit credentials for a privileged account, then success + special privileges
    e(rows, b + timedelta(seconds=30), WS, "Security", 4648, user=USER, process=BAD_IMG,
      target=f"{ADMIN}@{FS}", detail="logon attempted using explicit credentials")
    e(rows, b + timedelta(seconds=35), FS, "Security", 4624, user=ADMIN, logon_type=3, src_ip=WS_IP,
      src_host=WS, auth_pkg="NTLM", detail="network logon with explicit credentials")
    e(rows, b + timedelta(seconds=36), FS, "Security", 4672, user=ADMIN,
      detail="SeBackupPrivilege;SeDebugPrivilege;SeTakeOwnershipPrivilege")
    # unusual Kerberos service-ticket activity from the workstation
    k = b + timedelta(seconds=50)
    for i, spn in enumerate(["cifs/FILE-SRV-03", "MSSQLSvc/SQL-FIN-01:1433", "cifs/FILE-SRV-02", "HOST/FIN-WS-121"]):
        e(rows, k + timedelta(seconds=6 * i), DC, "Security", 4769, user=ADMIN, src_ip=WS_IP, src_host=WS,
          service=spn, detail="TicketEncryptionType=0x17 (RC4) — downgrade vs AES baseline")
    # sensitive share access on FILE-SRV-03
    s = datetime(2026, 10, 8, 4, 17, 5, tzinfo=UTC)
    for i, fn in enumerate(["payroll_2026_Q3.xlsx", "bank_mandates.pdf", "vendor_master.xlsx", "salary_revision.docx",
                            "bonus_pool.xlsx", "audit_adjustments.xlsx", "treasury_signatories.pdf", "tax_filing_FY26.xlsx",
                            "cfo_board_pack.pptx", "loan_covenants.pdf", "ap_aging.xlsx", "ar_aging.xlsx",
                            "payroll_bank_file.csv", "forecast_FY27.xlsx"]):
        e(rows, s + timedelta(seconds=4 * i), FS, "Security", 5145, user=ADMIN, src_ip=WS_IP,
          share=r"\\FILE-SRV-03\Finance$", detail="Payroll\\" + fn + " (ReadData)")
    # same privileged account appears on another workstation
    c = datetime(2026, 10, 8, 4, 20, 25, tzinfo=UTC)
    e(rows, c, WS2, "Security", 4624, user=ADMIN, logon_type=3, src_ip=WS_IP, src_host=WS,
      auth_pkg="NTLM", detail="network logon from a peer workstation")
    e(rows, c + timedelta(seconds=1), WS2, "Security", 4672, user=ADMIN, detail="SeDebugPrivilege;SeBackupPrivilege")
    rows.sort(key=lambda r: r["ts"])
    return rows


CONTEXT = {
    "_note": "SYNTHETIC context for the Silent Credential Theft lab. RFC-1918 IPs, fake hashes. LAB ONLY.",
    "assets": {
        WS: {"ip": WS_IP, "role": "Workstation", "owner": USER, "dept": "Finance"},
        WS2: {"ip": WS2_IP, "role": "Workstation", "owner": "p.iyer", "dept": "Finance"},
        FS: {"ip": FS_IP, "role": "File Server", "data": "Finance$ (payroll, treasury)"},
        FS_OLD: {"ip": "10.20.5.31", "role": "File Server", "data": "Finance-Reports"},
        DC: {"ip": "10.20.0.11", "role": "Domain Controller"},
        PAW: {"ip": PAW_IP, "role": "Privileged Access Workstation"},
    },
    "users": {
        USER: {"privileged": False, "dept": "Finance", "normal_hosts": [WS], "normal_servers": [FS_OLD]},
        ADMIN: {"privileged": True, "role": "Server admin (Tier 1)", "approved_sources": [PAW_IP]},
        "svc.finbackup": {"privileged": True, "role": "Backup service account", "approved_sources": ["10.20.5.40"]},
        "administrator": {"privileged": True, "role": "Built-in admin (should be disabled)"},
    },
    "approved_lsass_readers": [DEFENDER, EDR, r"C:\Windows\System32\wininit.exe", r"C:\Windows\System32\csrss.exe"],
    "sensitive_shares": [r"\\FILE-SRV-03\Finance$"],
    "change_tickets": [{"id": "CHG-4471", "host": FS, "user": ADMIN, "date": "2026-10-06", "source": PAW_IP}],
    "exposure_note": "adm.kiran opened an RDP support session on FIN-WS-117 on 05 Oct (INC-20931) — "
                     "a privileged credential was present in the workstation's LSASS afterwards.",
}


def main():
    with open(os.path.join(HERE, "lsass_events_SYNTHETIC.csv"), "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=FIELDS); w.writeheader(); w.writerows(build())
    with open(os.path.join(HERE, "lsass_context_SYNTHETIC.json"), "w") as f:
        json.dump(CONTEXT, f, indent=2)
    print("wrote lsass_events_SYNTHETIC.csv + lsass_context_SYNTHETIC.json")


if __name__ == "__main__":
    main()
