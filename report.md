# Incident Detection Report — CVE-2026-59310

**Author:** Eswar Mahalingam · Blue Team Operator (Officer Candidate), GraySentinel DSOU
**Credential ID:** GS-STU-DSOU-2026-039A · **Date:** 09 Sep 2026 · **Classification:** Internal / Lab

## 1. Executive Summary
A path-traversal-to-RCE weakness in vCenter's rsyslog handling (tracked in this
exercise as CVE-2026-59310) allows a crafted syslog hostname to write a cron job
into `/etc/cron.d/`, which then executes as root. I researched the issue with
AI-assisted tooling, engineered a Sigma detection rule, validated it with a safe
attack simulation, and compiled this report for the CISO.

> **Scope note:** This was conducted in the GraySentinel lab against target
> `192.168.1.50`. The CVE identifier and its sibling IDs are lab scenario
> scaffolding — verify against the real vendor advisory before any production action.

## 2. Attack Path (observed in lab)
1. Attacker sends a syslog message with traversal sequences (`../`) in the hostname field.
2. rsyslog writes attacker-controlled content into `/etc/cron.d/`.
3. The dropped cron entry runs as root → remote code execution and persistence.

**MITRE ATT&CK:** T1053.003 (Scheduled Task/Job: Cron) · Initial Access via an exposed logging service.

## 3. Detection Engineering
The deliverable is a three-tripwire Sigma rule (`detection/detection-rule.sigma`)
that alerts if **any** condition fires:

| Tripwire | Signal | Catches |
|---|---|---|
| Traversal indicator | `../` / `..%2f` in syslog message | the attempt |
| Cron write | auditd `openat` (syscall 257) into `/etc/cron.d/` | the persistence outcome |
| rsyslog child shell | `rsyslogd` spawning `/sh` or `/bash` | the RCE moment |

Layering catches the attack *before and after* success, not just post-compromise.
False positives are tuned out: configuration-management writes to `/etc/cron.d/`
and benign rsyslog templates containing `../`.

## 4. Validation
Simulated the technique with `atomic-operator` (`--test`, Atomic Red Team) against
`192.168.1.50`. Result: the rule triggered as expected → detection confidence established.

## 5. Recommendations
1. **Patch** vCenter to the fixed build once the real advisory is confirmed.
2. **Harden** — restrict inbound syslog to trusted hosts; run rsyslog least-privilege.
3. **Monitor** — deploy the Sigma rule to the SIEM; alert at `critical`.
4. **Verify** field names (`ParentProcessName`/`ppid`) against the real log pipeline.
5. **Broaden** coverage — add vpxd/appliance logs, not just Linux-host auditd.

## 6. Next Steps
Confirm the CVE against the vendor advisory · test the rule on production telemetry ·
schedule periodic atomic re-tests to prevent detection drift.

---
*Prepared as the Phase 6 deliverable of the GraySentinel DSOU Day 1 "Zero-Day Discovery" mission.
This document describes the attack conceptually and contains no exploit code — appropriate for a CISO-facing report.*
