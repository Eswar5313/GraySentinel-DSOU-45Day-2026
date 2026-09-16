# GraySentinel DSOU — Day 2 · vCenter Compromise Investigation (CVE-2026-59310)

**SOC War Room** · Case GS-DAY2-2026 · Appliance `vcsa-prod-01`
**Analyst:** Eswar Mahalingam · GS-STU-DSOU-2026-039A · Blue Team Operator (Candidate 13)
**Reporting to:** Ritik Shrivas · **Verdict on "can we close?":** 🔴 NOT YET

> A CVSS 9.8 vCenter flaw was actively exploited; the patch is applied. The patch closes the
> door — it does not prove nobody came in before it. This pack works the **pre-patch exposure
> window** to decide whether the incident can actually be closed.

## Submission map (the four required deliverables)
| # | Mission | File |
|---|---------|------|
| 01 | Investigation Plan / Asset Triage | [`01_investigation_plan.md`](01_investigation_plan.md) |
| 02 | Hunting Hypotheses (H1 + H2, falsifiable) | [`02_hunting_hypotheses.md`](02_hunting_hypotheses.md) |
| 03 | Detection Engineering concept | [`03_detection_concept.md`](03_detection_concept.md) |
| 04 | Ransomware Readiness Checklist (10 domains) | [`04_ransomware_readiness_checklist.md`](04_ransomware_readiness_checklist.md) |
| ★ | Senior SOC question (5 perspectives) | [`senior_soc_answer.md`](senior_soc_answer.md) |

## Detection artifacts (real, deployable formats)
- **Sigma:** [`detections/vcenter_priv_vmops_anomalous_source.yml`](detections/vcenter_priv_vmops_anomalous_source.yml)
- **Wazuh:** [`detections/vcenter_wazuh_rules.xml`](detections/vcenter_wazuh_rules.xml) — 4 rules, escalates to level 14 on off-allow-list privileged ops
- Both validated well-formed → [`evidence/validation.txt`](evidence/validation.txt)

## ATT&CK coverage
T1190 Exploit Public-Facing App · T1078 Valid Accounts · T1136 Create Account · T1098 Account Manipulation ·
T1213 Data from Repositories · T1550 Alternate Auth · T1021 Remote Services · T1485 Data Destruction ·
T1490 Inhibit System Recovery · T1489 Service Stop · T1003/T1552 Credential Access

## The one-line thesis
vCenter is the **identity + control + availability + lateral-movement + recovery** plane in a single box.
Compromise there is estate-wide by default — so closure requires clearing the window, not applying the patch.

## Layout
```
graysentinel-day2/
├── 01_investigation_plan.md · 02_hunting_hypotheses.md
├── 03_detection_concept.md  · 04_ransomware_readiness_checklist.md
├── senior_soc_answer.md
├── detections/  vcenter_priv_vmops_anomalous_source.yml · vcenter_wazuh_rules.xml
├── evidence/    validation.txt
├── docs/        index.html (GitHub Pages checker)
└── README.md
```

## Integrity
GraySentinel lab exercise. CVE identifier is as given in the brief; authoritative source of truth is the
[CISA KEV catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog). All log paths, ATT&CK IDs,
and detection formats are real vSphere/Sigma/Wazuh — no fabricated exploit internals, no host data invented.
