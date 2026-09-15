## 📊 Dashboard — all 4 deliverables

**Live:** https://Eswar5313.github.io/GraySentinel-DSOU-Day1-ZeroDay-2026/ · **Step-by-step checker:** https://Eswar5313.github.io/GraySentinel-DSOU-Day1-ZeroDay-2026/graysentinel-day1/docs/

| # | Deliverable | Type | Status | Proof |
|---|---|---|---|---|
| 01 | Zero-Day Discovery — vCenter rsyslog traversal → RCE (lab CVE-2026-59310) | Day 1 guided lab · 6 phases | ✅ Complete · certified | [Sigma rule](detection/detection-rule.sigma) · [report](report/report.md) · [certificate](certificate/) |
| 02 | macOS Miner Attack Chain — phishing → Screen Sharing RCE → AdaptixC2 → XMRig (lab CVE-2026-65400) | Day 2 guided lab · 6 phases | 🟡 In progress | [day2-macos-miner/](day2-macos-miner/) |
| 03 | Authentication Log Investigation Tool | Individual Project 01 · Blue | 🔵 Submitted for review | [README](graysentinel-day1/project-01/README.md) · [report](graysentinel-day1/project-01/report.md) · 13/13 tests |
| 04 | SOC Incident Summary Generator | Individual Project 02 · Blue | 🔵 Submitted for review | [README](graysentinel-day1/project-02/README.md) · [report](graysentinel-day1/project-02/report.md) · 12/12 tests |

Pipeline: `auth.log → P01 auth_investigator → findings.json → P02 incident_summary → P1 ticket (MD/HTML/JSON)`.
