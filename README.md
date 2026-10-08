<!-- ═══════════════ CAREER CONTROL TOWER · REPOSITORY · GRAYSENTINEL ═══════════════ -->
<div align="center">

<img src="https://raw.githubusercontent.com/Eswar5313/Eswar5313/main/assets/headers/REPO_GRAYSENTINEL.svg" width="100%" alt="GraySentinel DSOU — Blue Team — Eswar Mahalingam" />

<a href="https://github.com/Eswar5313"><img src="https://img.shields.io/badge/⬅-CAREER_CONTROL_TOWER-0B1026?style=for-the-badge&labelColor=00E5FF" alt="CAREER CONTROL TOWER"/></a> <a href="https://eswar5313.github.io/Eswar-Master-Project-Portfolio-2026/"><img src="https://img.shields.io/badge/✦-MASTER_PORTFOLIO-0B1026?style=for-the-badge&labelColor=B388FF" alt="MASTER PORTFOLIO"/></a> <a href="https://eswar5313.github.io/Eswar-Portfolio-Lens-Index-2026/"><img src="https://img.shields.io/badge/✦-LENS_INDEX-0B1026?style=for-the-badge&labelColor=00E5FF" alt="LENS INDEX"/></a> <a href="https://eswar5313.github.io/GraySentinel-DSOU-45Day-2026/"><img src="https://img.shields.io/badge/✦-LIVE_DASHBOARD-0B1026?style=for-the-badge&labelColor=00E5FF" alt="LIVE DASHBOARD"/></a>

<img src="https://img.shields.io/badge/LABS-2_CERTIFIED-00E5FF?style=for-the-badge&labelColor=0B1026" alt="LABS: 2 CERTIFIED"/> <img src="https://img.shields.io/badge/SOC_TOOLS-8-B388FF?style=for-the-badge&labelColor=0B1026" alt="SOC TOOLS: 8"/> <img src="https://img.shields.io/badge/AUTOMATED_TESTS-114-00E5FF?style=for-the-badge&labelColor=0B1026" alt="AUTOMATED TESTS: 114"/> <img src="https://img.shields.io/badge/DETECTION_RULES-10%2B-B388FF?style=for-the-badge&labelColor=0B1026" alt="DETECTION RULES: 10+"/> <img src="https://img.shields.io/badge/EXPLOIT_CODE-0-00E5FF?style=for-the-badge&labelColor=0B1026" alt="EXPLOIT CODE: 0"/>

**GraySentinel Cyber Defence Lab · Blue Team Operator & Trainee · Jul 2026 – Present** — detection engineering · threat hunting · SOC automation

</div>

<img src="https://raw.githubusercontent.com/Eswar5313/Eswar5313/main/assets/divider.svg" width="100%" alt="" />

## 🧭 What this is

> My deliverables from the **GraySentinel Cyber Defence Lab — DSOU (Defensive Security Operations Unit) programme**, Blue Team track (Candidate 13, ID GS-STU-DSOU-2026-039A). Everything here is **defensive**: detection rules, threat-hunting scripts, investigation reports and SOC tooling built on **declared-synthetic lab data** (RFC-5737 IPs, `example.com`). There is no exploit or malware code in this repository. Lab CVE identifiers are programme scaffolding, not public advisories.

<img src="https://raw.githubusercontent.com/Eswar5313/Eswar5313/main/assets/divider.svg" width="100%" alt="" />
## 🗂️ Deliverables

| # | Deliverable | Type | Status | Proof |
|:-:|---|---|---|---|
| 01 | **Zero-Day Discovery** — vCenter rsyslog path traversal → RCE (6-phase guided lab) | Day 1 lab | ✅ Complete · certified | [Sigma rule](detection-rule.sigma) · [Wazuh rule](detection-rule-wazuh.xml) · [phase log](day1-phases.md) · [report PDF](GraySentinel_ZeroDay_Report_Eswar.pdf) · [certificate](GraySentinel_ZeroDay_GS-STU-DSOU-2026-039A.png) |
| 02 | **macOS Miner Attack Chain** — phishing macro → C2 → XMRig masquerade → LaunchDaemon persistence | Day 2 lab | ✅ Complete | [mission log](mission-log.md) · [report PDF](GraySentinel_DSOU_Day2_Report.pdf) · [full pack](GraySentinel-DSOU-Day2-MacOSMiner-2026/GraySentinel-DSOU-Day2-MacOSMiner-2026/) |
| 03 | **Authentication Log Investigation Tool** — brute force, spraying, success-after-failure, off-hours root | Individual project 01 | 🔵 Submitted for review · **13/13 tests** | [code](auth_investigator.py) · [tests](test_auth_investigator.py) · [lab log](auth.log) · [findings](findings.md) |
| 04 | **SOC Incident Summary Generator** — findings → P1 ticket (Markdown / HTML / JSON) | Individual project 02 | 🔵 Submitted for review · **12/12 tests** | [code](incident_summary.py) · [tests](test_incident_summary.py) · [ticket](incident_summary.md) · [report](report.md) |
| 05 | **macOS cryptominer kill-chain tools** — VBA macro analyzer + kill-chain reconstructor | Day 2 tooling | ✅ **21/21 tests** · verdict MALICIOUS · P1 | [pack](graysentinel-day2/graysentinel-day2/) |
| 06 | **vCenter compromise investigation** — investigation plan, falsifiable hunting hypotheses, Sigma + Wazuh detections, ransomware-readiness checklist | War-room case | ✅ Complete | [pack](graysentinel-day2/) |
| 07 | **Entra ID sign-in hunts** — device-code phishing + impossible travel (KQL + Sigma + analyzers) | Blue-team drills | ✅ Complete | [drills](graysentinel-drills/graysentinel-drills/) |
| 08 | **SOC war-room sprint** — Orkes Conductor RCE hunt + "silent domain controller" SIEM-blindspot detector | Sprint report | ✅ Complete | [pack](GraySentinel-DSOU-45Day-2026/GraySentinel-DSOU-45Day-2026/) · [report PDF](GraySentinel-DSOU-45Day-2026/GraySentinel-DSOU-45Day-2026/docs/GraySentinel_DSOU_SOC_Report.pdf) |
| 09 | **SOC war room — "The Silent RDP Login"** — RDP spray → valid-account Type 10 → hidden PowerShell → AD discovery → SMB to HR file server (H1 compromised · H2 rejected · H3 confirmed) | War-room case · 05 Oct 2026 | ✅ Complete · **18/18 tests** | [pack](rdp-silent-login/) · [submission](rdp-silent-login/SUBMISSION.md) · [report PDF](rdp-silent-login/GraySentinel_DSOU_RDP_SilentLogin_Report.pdf) · [Sigma](rdp-silent-login/rdp_powershell_chain.sigma.yml) · [Wazuh](rdp-silent-login/wazuh_local_rules_rdp.xml) |
| 10 | **SOC war room — "Ghost Admin"** — privileged-identity compromise on DC-02: NTLM logon → Domain Admins in 40s → DCSync → lateral to DC-01/file server (H1 compromised · H2 confirmed · H3 confirmed) | War-room case · 06 Oct 2026 | ✅ Complete · **18/18 tests** | [pack](ghost-admin/) · [submission](https://github.com/Eswar5313/GraySentinel-DSOU-45Day-2026/blob/main/ghost-admin/SUBMISSION.md) · [report PDF](https://github.com/Eswar5313/GraySentinel-DSOU-45Day-2026/blob/main/ghost-admin/GraySentinel_DSOU_GhostAdmin_Report.pdf) · [Sigma](https://github.com/Eswar5313/GraySentinel-DSOU-45Day-2026/blob/main/ghost-admin/privileged_identity_anomaly.sigma.yml) · [Wazuh](https://github.com/Eswar5313/GraySentinel-DSOU-45Day-2026/blob/main/ghost-admin/wazuh_local_rules_ghostadmin.xml) |
| 11 | **Intel war room — "Cloud Token Blackout"** — CI/CD cloud-credential abuse: long-lived runner key → AdministratorAccess → PII/secrets → public bucket; exposure card, TTP map, OSINT methodology, IoCs, Diamond, CISO brief | Intel brief · 06 Oct 2026 | ✅ Complete · **16/16 tests** | [pack](cloud-token-blackout/) · [submission](https://github.com/Eswar5313/GraySentinel-DSOU-45Day-2026/blob/main/cloud-token-blackout/SUBMISSION.md) · [report PDF](https://github.com/Eswar5313/GraySentinel-DSOU-45Day-2026/blob/main/cloud-token-blackout/GraySentinel_RIU_CloudTokenBlackout_Report.pdf) · [Sigma](https://github.com/Eswar5313/GraySentinel-DSOU-45Day-2026/blob/main/cloud-token-blackout/cicd_cloud_token_abuse.sigma.yml) |
| 12 | **Red-team war room — "Broken Pipeline"** — CI/CD → registry → Kubernetes supply-chain analysis + blue-team detection (LAB ONLY, no exploit code): stale identity → unsigned digest → cluster-admin SA → cloud | Adversary-sim analysis · 06 Oct 2026 | ✅ Complete · **16/16 tests** | [pack](broken-pipeline/) · [submission](https://github.com/Eswar5313/GraySentinel-DSOU-45Day-2026/blob/main/broken-pipeline/SUBMISSION.md) · [report PDF](https://github.com/Eswar5313/GraySentinel-DSOU-45Day-2026/blob/main/broken-pipeline/GraySentinel_SSOU_BrokenPipeline_Report.pdf) · [detections](https://github.com/Eswar5313/GraySentinel-DSOU-45Day-2026/blob/main/broken-pipeline/broken_pipeline_detections.yml) |

**Pipeline (projects 03 → 04):** `auth.log → auth_investigator.py → findings.json → incident_summary.py → P1 incident ticket (MD / HTML / JSON)`

<img src="https://raw.githubusercontent.com/Eswar5313/Eswar5313/main/assets/divider.svg" width="100%" alt="" />
## 🧪 Run it

```bash
python3 make_lab_data.py            # regenerate the synthetic lab log
python3 auth_investigator.py auth.log
python3 incident_summary.py findings.json
python3 -m unittest test_auth_investigator test_incident_summary
```

Step-by-step runbook: [STEP_BY_STEP.md](STEP_BY_STEP.md) · Screenshots: `01_*.png` – `04_*.png` in the repository root.

<img src="https://raw.githubusercontent.com/Eswar5313/Eswar5313/main/assets/divider.svg" width="100%" alt="" />
## 🎯 ATT&CK coverage (selected)

T1053.003 (cron) · T1110 (brute force / spraying) · T1078 (valid accounts) · T1566.001 (phishing attachment) · T1204.002 · T1059 · T1105 · T1496 (resource hijacking) · T1543.001 (LaunchDaemon) · T1071.001 · T1528 · T1550.001 · T1070.001 (log clearing) · T1021.001 (RDP) · T1059.001 (PowerShell) · T1133 (external remote services) · T1039 (network share data) · T1098 (account manipulation) · T1003.006 (DCSync) · T1078.004 (cloud accounts) · T1195.002 (supply chain) · T1552 (unsecured creds)

<img src="https://raw.githubusercontent.com/Eswar5313/Eswar5313/main/assets/divider.svg" width="100%" alt="" />
## 🛡️ Scope & integrity

- Detection and response only — every script reads logs and produces findings.
- All data is synthetic and labelled as such; real findings are only ever posted from real exports.
- Stdlib-only Python 3.8+ for the SOC tools so they run on any analyst workstation.

<img src="https://raw.githubusercontent.com/Eswar5313/Eswar5313/main/assets/divider.svg" width="100%" alt="" />

<div align="center">

**Eswar Mahalingam** · B.Com · MBA · PGDLSCM · CSCMP SCPro · Six Sigma Black Belt
Data Scientist @ Zidio Development · Ghaziabad NCR, India · Open to India · EU (Blue Card) · Gulf · Immediate joiner

[![LinkedIn](https://img.shields.io/badge/✦-LINKEDIN-0B1026?style=for-the-badge&labelColor=B388FF)](https://linkedin.com/in/eswar-mahalingam)
[![Email](https://img.shields.io/badge/✦-EMAIL-0B1026?style=for-the-badge&labelColor=00E5FF)](mailto:eswarmba05313@gmail.com)
[![Phone](https://img.shields.io/badge/✦-+91_9360548243-0B1026?style=for-the-badge&labelColor=B388FF)](tel:+919360548243)
[![Portfolio](https://img.shields.io/badge/✦-PORTFOLIO_SITE-0B1026?style=for-the-badge&labelColor=00E5FF)](https://eswar-3d-portfolio.netlify.app)
[![Profile](https://img.shields.io/badge/⬅-CAREER_CONTROL_TOWER-0B1026?style=for-the-badge&labelColor=00E5FF)](https://github.com/Eswar5313)

<img src="https://raw.githubusercontent.com/Eswar5313/Eswar5313/main/assets/kailash-footer.svg" width="100%" alt="" />

</div>
