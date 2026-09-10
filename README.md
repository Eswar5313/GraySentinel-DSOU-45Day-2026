# GraySentinel-DSOU-Day2-MacOSMiner-2026

**GraySentinel Cyber Defence Lab — DSOU Programme**  
**Day 2: macOS Miner Attack Chain**  
**Analyst:** Eswar Mahalingam | `GS-STU-DSOU-2026-039A`  
**Date:** 10 September 2026

---

## Mission Summary

Blue Team analysis of a complete macOS cryptomining attack chain:

```
Phishing (VBA Macro)
  → CVE-2026-65400 (Pre-auth RCE, CVSS 9.8)
    → AdaptixC2 C2 Framework
      → XMRig Miner (masquerades as sysmond)
        → LaunchDaemon KeepAlive Persistence
          → SSH Root Backdoor
            → OSINT Attribution
              → Detection & Remediation
```

**170 risks identified. 6 phases completed. System fully remediated.**

---

## Repository Structure

```
GraySentinel-DSOU-Day2-MacOSMiner-2026/
│
├── detection/
│   ├── detection-rule.sigma        # 6-tripwire Sigma detection rule (ATT&CK mapped)
│   └── detection-rule-wazuh.xml    # Wazuh SIEM rules (IDs 100200–100206)
│
├── report/
│   ├── report.md                   # Full phase-by-phase incident report
│   └── GraySentinel_DSOU_Day2_Report.pdf   # Navy/gold 2-page PDF report
│
├── mission-log/
│   └── mission-log.md              # Mission timeline and observations
│
└── README.md                       # This file
```

---

## Key CVE

| CVE | CVSS | Description |
|---|---|---|
| CVE-2026-65400 | 9.8 Critical | macOS Screen Sharing pre-auth RCE via SRP frame-length validation bypass |

---

## MITRE ATT&CK Coverage

| Technique | ID | Phase |
|---|---|---|
| Phishing | T1566 | 1 |
| Exploit Public-Facing Application | T1203 | 2 |
| Application Layer Protocol | T1071 | 3 |
| Account Manipulation | T1098 | 3 |
| Launch Daemon | T1543.004 | 4 |
| Resource Hijacking | T1496 | 4 |
| Gather Victim Network Information | T1591 | 5 |

---

## Tools Used

| Tool | Purpose |
|---|---|
| oletools (olevba, oleid) | Phishing document / VBA macro analysis |
| poc_screensharing.py | CVE-2026-65400 Screen Sharing exploit PoC |
| AdaptixC2 | Post-exploitation C2 framework (Go-based) |
| XMRig 6.26.0 | Monero cryptocurrency miner |
| Tookie-OSINT | Social media OSINT attribution |
| dig | DNS MX infrastructure mapping |
| Wazuh | SIEM detection rule deployment |

---

## Disclaimer

> All work performed inside the **GraySentinel GrayOS sandbox** (forensic@macos, Kali Terminal).  
> No real systems were targeted. All artifacts are **defensive and educational**.  
> Exploit code is not reproduced — only detection and remediation artifacts are included.

---

*GraySentinel Cyber Defence Lab · DSOU Programme · Blue Team Operator & Trainee*
