# GraySentinel DSOU — Day 1: The Zero-Day Discovery

> Blue Team detection-engineering exercise. I researched a vCenter rsyslog
> path-traversal-to-RCE scenario (lab: CVE-2026-59310), wrote a Sigma detection
> rule, validated it with a safe attack simulation, and reported to the CISO.

**Operator:** Eswar Mahalingam — Blue Team Operator & Trainee (Officer Candidate)
**Program:** GraySentinel DSOU · **Credential ID:** GS-STU-DSOU-2026-039A
**Completed:** 09 Sep 2026 · **Verify:** valid 09 Sep 2026 – 08 Mar 2027

---

## What I did
Completed the six-phase "Zero-Day Discovery" mission and earned the Day 1
certificate. The mission's real objective is the **detection rule** — the two
artifacts below are the defensive deliverables I produced.

## Repository contents
```
GraySentinel-DSOU-Day1-ZeroDay-2026/
├── detection/
│   └── detection-rule.sigma      # three-tripwire Sigma rule (the deliverable)
├── report/
│   └── report.md                 # CISO-facing incident detection report
│   └── (PDF report if generated)
├── mission-log/
│   └── day1-phases.md            # what ran in each of the 6 phases
├── certificate/
│   └── GraySentinel_ZeroDay_GS-STU-DSOU-2026-039A.png
└── README.md
```

## The detection rule (summary)
A layered Sigma rule that fires on **any** of three signals, so it catches the
attack before *and* after it succeeds:

- **Traversal attempt** — `../` / `..%2f` in a syslog hostname/message
- **Persistence outcome** — auditd `openat` write into `/etc/cron.d/`
- **RCE moment** — `rsyslogd` spawning a shell

Tuned against config-management and template false positives. MITRE ATT&CK
T1053.003 (Cron). Full rule in [`detection/detection-rule.sigma`](detection/detection-rule.sigma).

## Skills demonstrated
Threat research · Sigma detection engineering · MITRE ATT&CK mapping ·
detection validation with Atomic Red Team · security reporting for leadership.

## Honesty & scope
- This was a **training sandbox** exercise against lab target `192.168.1.50`.
- The CVE identifier is **lab scaffolding** — I have not verified it as a real
  advisory, and the rule should be validated against real telemetry and the
  actual vendor bulletin before any production use.
- This repo intentionally publishes **defensive artifacts only** — the Sigma
  rule and the report. No exploit code, payload, or offensive module is included.

---
*Part of my 2026 cyber-security training portfolio.*
