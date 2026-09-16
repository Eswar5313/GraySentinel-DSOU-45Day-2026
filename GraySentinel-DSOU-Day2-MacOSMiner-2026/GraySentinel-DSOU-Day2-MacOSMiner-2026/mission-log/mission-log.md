# GraySentinel DSOU — Mission Log
## Day 2: macOS Miner Attack Chain

**Analyst:** Eswar Mahalingam | GS-STU-DSOU-2026-039A  
**Date:** 10 September 2026  
**Environment:** GrayOS — Kali Terminal (forensic@macos)

---

## Mission Timeline

| Time | Phase | Action | Outcome |
|---|---|---|---|
| Session Start | Briefing | Loaded GrayOS Day 2 mission | 6 phases, CVE-2026-65400 focus, 170 risks in scope |
| Phase 1 | Initial Access | pip install oletools → olevba → oleid on suspicious_document.doc | AutoExec macro + URLDownloadToFile cradle confirmed |
| Phase 2 | Exploitation | poc_screensharing.py 192.168.1.50 → /etc/passwd read | CVE-2026-65400 pre-auth RCE as root confirmed |
| Phase 3 | C2 + Backdoor | AdaptixC2 agent deployed → SSH keypair → authorized_keys | Go C2 active; root SSH backdoor implanted |
| Phase 4 | Miner Deploy | XMRig → /private/var/root/.config/sysmond + LaunchDaemon plist | Monero miner running as sysmond; KeepAlive persistence set |
| Phase 5 | OSINT | Tookie-OSINT -u attacker → dig attacker-domain.com MX | Attacker infrastructure mapped; domain attributed |
| Phase 6 | Remediation | killall → rm plist → rm sysmond → Wazuh rules deployed | System fully remediated; detection active |
| Post-mission | Reporting | Sigma rule, Wazuh XML, report.md, 2-page PDF generated | All artifacts committed to this repository |

---

## Observations

- CVE-2026-65400 is a pre-auth bypass — no credentials needed at any point for root access.
- XMRig process-name masquerade (`sysmond`) is a high-confidence evasion technique; binary hash validation is critical.
- AdaptixC2 uses port 443 (HTTPS) — blends with legitimate traffic; deep packet inspection or JA3 fingerprinting needed.
- LaunchDaemon KeepAlive is a robust persistence mechanism — killing the process alone is insufficient; plist must be removed.
- OSINT attribution enabled proactive domain blocking before any further lateral movement.

---

## Artifacts Produced

| File | Description |
|---|---|
| `detection/detection-rule.sigma` | 6-tripwire Sigma rule covering full attack chain |
| `detection/detection-rule-wazuh.xml` | Wazuh SIEM rules (7 rules, IDs 100200–100206) |
| `report/report.md` | Full phase-by-phase incident report |
| `report/GraySentinel_DSOU_Day2_Report.pdf` | Navy/gold 2-page PDF report |
| `mission-log/mission-log.md` | This log |
| `README.md` | Repository overview |

---

## Mission Status: COMPLETE ✅

All 6 phases completed. System remediated. Detection rules deployed.  
Awaiting GraySentinel DSOU Day 2 certificate — GS-STU-DSOU-2026-039A.
