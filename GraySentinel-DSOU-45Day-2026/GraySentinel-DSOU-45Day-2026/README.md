# GraySentinel DSOU — 45-Day Blue-Team Sprint (2026)

**Analyst:** Eswar Mahalingam · **Track:** Blue Team / SOC Threat Hunting
**Report date:** 22 Sep 2026 (IST) · **Classification:** TLP:AMBER — internal SOC use

Defensive Security Operations Unit (DSOU) SOC War-Room deliverables. This
repository is **detection & threat-hunting only** — every script *detects*
attacker activity from logs. There is **no offensive/exploit code** here.

Two engagements are covered:

| # | Engagement | Trigger |
|---|-----------|---------|
| Day 1 | Workflow-Orchestration RCE — **Orkes Conductor CVE-2026-58138** (pre-auth GraalVM evaluator RCE, CVSS 9.8) | Active exploitation in the wild |
| Day 2 | SIEM Blindspot — **The Silent Domain Controller** (DC-02-PRD dark in Wazuh 48h after a log-clear + cred-dump) | Missing telemetry from a Tier-0 asset |

The full written analysis (Asset Map, Hunting Hypotheses, Detection Concept,
Machine-Identity/Persistence, Closure Checklist, Senior-SOC answers, ATT&CK
map) is in **[`docs/GraySentinel_DSOU_SOC_Report.pdf`](docs/GraySentinel_DSOU_SOC_Report.pdf)**.

---

## Repository structure

```
GraySentinel-DSOU-45Day-2026/
├── README.md
├── src/
│   ├── day1_conductor_rce_hunt.py      # hunts Conductor RCE from API + process logs
│   ├── day2_dc_silence_detector.py     # detects silent DC + tamper correlation
│   ├── sigma/
│   │   ├── conductor_evaluator_process_spawn.yml
│   │   └── dc_log_silence_and_audit_clear.yml
│   └── wazuh/
│       └── local_rules.xml             # Wazuh custom rules (DC log tamper + silence)
├── screenshots/
│   ├── 01_day1_conductor_hunt.png
│   ├── 02_day2_dc_silence.png
│   └── 03_report_overview.png
├── logs/
│   ├── day1_output.log
│   └── day2_output.log
├── evidence/
│   ├── mock_conductor_access.log
│   ├── mock_process_creation.log
│   ├── mock_wazuh_keepalive.csv
│   └── mock_windows_security_events.csv
└── docs/
    └── GraySentinel_DSOU_SOC_Report.pdf
```

---

## Quick start

No third-party packages required — pure Python 3 standard library.

```bash
# Day 1 — Conductor RCE hunt
python3 src/day1_conductor_rce_hunt.py

# Day 2 — Silent Domain Controller detector
python3 src/day2_dc_silence_detector.py --now 2026-09-22T09:00:00+05:30 --threshold 15
```

Both scripts default to the mock data in `evidence/`. Point them at real logs
with `--access/--procs` (Day 1) or `--keepalive/--events/--now` (Day 2).

---

## Day 1 — Orkes Conductor RCE (CVE-2026-58138)

**Root cause:** unsandboxed GraalVM evaluators (`HostAccess.ALL` /
`allowAllAccess(true)`) reachable through `INLINE`, `LAMBDA`, `DO_WHILE` and
`SWITCH` task types let an unauthenticated attacker run OS commands via a
crafted workflow definition. Affected **3.21.21 → 3.30.1**; fixed **3.30.2+**.

**Why patching isn't closure:** Conductor is a credential concentrator. If any
code executed before the patch, every secret the engine can read must be
treated as disclosed. The hunter therefore looks past the request body to the
behavioural chokepoint — **the Conductor JVM spawning a shell / network binary** —
and correlates it with external evaluator submissions.

`day1_conductor_rce_hunt.py` reports: API-layer exploitation attempts,
host-layer suspicious spawns (incl. cloud-metadata credential theft), and a
correlated verdict. See `screenshots/01_day1_conductor_hunt.png`.

**ATT&CK:** T1190 · T1059 · T1552.005

## Day 2 — The Silent Domain Controller

**Scenario:** DC-02-PRD stopped sending logs to Wazuh for ~48h right after
Event **1102** (audit log cleared), a **4624** anonymous logon with
**SeDebugPrivilege**, and a **4688** renamed `mimikatz.exe`. "Patched" and
"AV clean" do not clear it — this is deliberate SIEM blinding.

**Core idea:** mature SOCs alert on the **absence** of expected telemetry.
`day2_dc_silence_detector.py` implements Rule A (Tier-0 log-source silence),
Rule B (tamper / credential-access events) and correlates the two into a
CRITICAL verdict, then states the first responder action: **isolate and
forensically image the DC before restarting the agent** (cleared logs = host
untrusted). See `screenshots/02_day2_dc_silence.png`.

**ATT&CK:** T1562.001 · T1070.001 · T1003/.006 · T1558.001 · T1098

---

## Detection content

- **Sigma:** `src/sigma/*.yml` — portable rules for the Conductor process-spawn
  chokepoint and DC audit-clear + anonymous-privileged-logon.
- **Wazuh:** `src/wazuh/local_rules.xml` — drop into
  `/var/ossec/etc/rules/local_rules.xml`, restart `wazuh-manager`. Includes an
  escalation of the built-in agent-disconnected event (rule 502) to CRITICAL
  for Domain Controllers, so Tier-0 silence pages.

## Notes on the data

All files in `evidence/` are **synthetic mock data** created for this exercise —
no real hosts, IPs, or credentials. The scripts are read-only log analysers and
make no network connections or system changes.

## References

- The Hacker News — *Critical Pre-Auth RCE in Orkes Conductor Exploited in the Wild*
- FortiGuard Labs — *Orkes Conductor Evaluator Remote Code Execution* (Outbreak Alert)
- SecurityWeek — *Critical Orkes Conductor Vulnerability Exploited in Attacks*
- MITRE ATT&CK — https://attack.mitre.org · Sigma — https://sigmahq.io
- Wazuh docs — https://documentation.wazuh.com · CISA KEV — https://www.cisa.gov/known-exploited-vulnerabilities-catalog

---

*Prepared by Eswar Mahalingam for the GraySentinel DSOU 45-Day Sprint, 2026.*
