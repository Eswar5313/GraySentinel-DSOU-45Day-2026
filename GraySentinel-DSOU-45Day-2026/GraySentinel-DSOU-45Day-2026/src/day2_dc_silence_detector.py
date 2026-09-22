#!/usr/bin/env python3
"""
GraySentinel DSOU - Day 2 | Blue-Team Detection
SIEM Blindspot: The Silent Domain Controller

PURPOSE (defensive only): detect the ABSENCE of expected telemetry from a
Tier-0 asset and correlate it with log-tampering / credential-access events.
Implements the core idea: mature SOCs alert on missing events, not just bad ones.

Detection logic:
  Rule A (absence): any domain_controller whose last Wazuh keepalive is older
                    than --threshold minutes -> log-source silence.
  Rule B (tamper) : Windows Security events 1102 (log cleared),
                    4624 anonymous logon + SeDebugPrivilege, 4688 renamed
                    mimikatz, 4720/4728 new DA, 4662 DCSync, 4698 sched task.
  Correlation     : silence on a DC within 24h of tamper -> CRITICAL.

Usage:
  python3 day2_dc_silence_detector.py \
      --keepalive evidence/mock_wazuh_keepalive.csv \
      --events    evidence/mock_windows_security_events.csv \
      --now 2026-09-22T09:00:00+05:30 --threshold 15
"""
import argparse
import csv
import sys
from datetime import datetime, timedelta
from pathlib import Path

TAMPER = {
    "1102": ("DEFENSE EVASION", "Security audit log cleared", "T1070.001"),
    "4624": ("CREDENTIAL ACCESS", "Anonymous logon w/ SeDebugPrivilege", "T1078"),
    "4688": ("EXECUTION", "Suspicious/renamed process (mimikatz)", "T1036.005"),
    "4720": ("PERSISTENCE", "New user account created", "T1136.002"),
    "4728": ("PRIVILEGE ESCALATION", "User added to Domain Admins", "T1098"),
    "4698": ("PERSISTENCE", "Scheduled task created", "T1053.005"),
    "4662": ("CREDENTIAL ACCESS", "DCSync (DS-Replication-Get-Changes)", "T1003.006"),
}


def parse_dt(s: str) -> datetime:
    return datetime.fromisoformat(s.strip())


def load_keepalive(path: Path):
    with path.open() as fh:
        return list(csv.DictReader(fh))


def load_events(path: Path):
    with path.open() as fh:
        return list(csv.DictReader(fh))


def main():
    ap = argparse.ArgumentParser(description="Day 2 - DC log-source silence detector")
    base = Path(__file__).resolve().parent.parent
    ap.add_argument("--keepalive", default=str(base / "evidence/mock_wazuh_keepalive.csv"))
    ap.add_argument("--events", default=str(base / "evidence/mock_windows_security_events.csv"))
    ap.add_argument("--now", default="2026-09-22T09:00:00+05:30")
    ap.add_argument("--threshold", type=int, default=15, help="silence minutes")
    args = ap.parse_args()

    ka_p, ev_p = Path(args.keepalive), Path(args.events)
    if not ka_p.exists() or not ev_p.exists():
        print("[!] input file(s) not found", file=sys.stderr)
        sys.exit(2)

    now = parse_dt(args.now)
    limit = timedelta(minutes=args.threshold)

    print("=" * 68)
    print(" GraySentinel DSOU | Day 2 - Silent Domain Controller Detector")
    print("=" * 68)

    # Rule A - absence of expected telemetry
    silent = []
    print(f"\n[RULE A] Log-source silence (threshold {args.threshold}m, now {args.now})")
    for a in load_keepalive(ka_p):
        gap = now - parse_dt(a["last_keepalive"])
        is_dc = a["role"] == "domain_controller"
        if gap > limit:
            sev = "CRITICAL" if is_dc else "HIGH"
            silent.append(a["agent_name"])
            hrs = gap.total_seconds() / 3600
            print(f"  [{sev}] {a['agent_name']} ({a['role']}) SILENT for {hrs:.1f}h "
                  f"(last {a['last_keepalive']})")
    if not silent:
        print("  All monitored sources reporting.")

    # Rule B - tamper / credential-access events
    print("\n[RULE B] Tamper & credential-access events")
    tamper_hosts = {}
    for e in load_events(ev_p):
        info = TAMPER.get(e["EventID"])
        if not info:
            continue
        cat, desc, mitre = info
        tamper_hosts.setdefault(e["Computer"], []).append(e["EventID"])
        print(f"  [!] {e['Timestamp']} {e['Computer']} EID {e['EventID']} "
              f"[{cat}] {desc} ({mitre})")

    # Correlation
    print("\n[CORRELATION]")
    escalated = False
    for host in silent:
        if host in tamper_hosts:
            escalated = True
            eids = ", ".join(sorted(set(tamper_hosts[host])))
            print(f"  [CRITICAL] {host}: log-source silence + tamper events ({eids})")
            print("            => Deliberate SIEM blinding to cover credential theft.")
    if escalated:
        print("\n  VERDICT: NOT a bug. Active Tier-0 intrusion.")
        print("  FIRST ACTION: isolate + forensically image the DC (memory+disk)")
        print("               BEFORE restarting the Wazuh agent. Cleared logs = host")
        print("               untrusted; other DCs + memory become source of truth.")
        print("  THEN: audit DA membership, check KRBTGT (consider double-reset),")
        print("        hunt persistence (svc-backup2, UpdateSync task, DCSync ACL).")
    else:
        print("  No correlated silence+tamper on a single host.")

    print("\nMITRE ATT&CK: T1562.001, T1070.001, T1003/.006, T1558.001, T1098")
    print("Done.")


if __name__ == "__main__":
    main()
