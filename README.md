# GraySentinel Day 1 — Individual Projects · Eswar Mahalingam (Blue Team)

> Candidate 13 in the *Day 1 — 13 Candidates Individual Project Brief*. Assigned: **Project 01 Authentication Log Investigation Tool** · **Project 02 SOC Incident Summary Generator**. Framework: *Learn Less. Execute More. Prove Everything.*

| | Project | Tool | Tests | Evidence | README | Report |
|---|---|---|---|---|---|---|
| 01 | Authentication Log Investigation Tool | `project-01/src/auth_investigator.py` | 13 ✅ | `project-01/evidence/` + 3 screenshots | [README](project-01/README.md) | [report](project-01/report.md) |
| 02 | SOC Incident Summary Generator | `project-02/src/incident_summary.py` | 12 ✅ | `project-02/evidence/` + 4 screenshots | [README](project-02/README.md) | [report](project-02/report.md) |

**Pipeline:** `auth.log` → Project 01 → `findings.json` → Project 02 → incident ticket (MD / HTML / JSON).

**Live step-by-step checker (GitHub Pages):** https://Eswar5313.github.io/GraySentinel-DSOU-Day1-ZeroDay-2026/graysentinel-day1/docs/
**Runbook (copy-paste, every step with expected output):** [STEP_BY_STEP.md](STEP_BY_STEP.md)

```
graysentinel-day1/
├── README.md · STEP_BY_STEP.md · PUSH_TO_GITHUB.md
├── project-01/  README.md · report.md · src/ · data/ · tests/ · evidence/ · screenshots/
├── project-02/  README.md · report.md · src/ · data/ · tests/ · evidence/ · screenshots/
└── docs/        index.html (live checker) · render_screens.py
```

Python 3.8+ standard library only. All data is synthetic and sanitised (RFC-5737 IP ranges, fictional host/users) per the GraySentinel safety rule — nothing here touches a real system.

**Submission line for the group**
```
Name: Eswar Mahalingam
Project 01: https://github.com/Eswar5313/GraySentinel-DSOU-Day1-ZeroDay-2026/blob/main/graysentinel-day1/project-01/README.md
Project 02: https://github.com/Eswar5313/GraySentinel-DSOU-Day1-ZeroDay-2026/blob/main/graysentinel-day1/project-02/README.md
Evidence: Repository contains code + report + evidence (terminal_output.txt, findings.json, incident_summary.html, screenshots/)
Status: Submitted for Review
```
