# GraySentinel DSOU — Day 2 · macOS Cryptominer Kill-Chain (Defensive)

**Candidate:** Eswar Mahalingam · GS-STU-DSOU-2026-039A · Blue Team Operator (Candidate 13)
**Reporting to:** Ritik Shrivas · **Case:** GS-DAY2-2026 · **Host:** `mac-victim-07`
**Verdict:** 🔴 MALICIOUS · **Incident priority:** P1 · **Tests:** 21/21 ✅

> Defensive triage of a phishing → macro → download → XMRig-style miner → LaunchDaemon
> persistence chain. **stdlib-only Python 3.8+**, no third-party packages, **100% synthetic
> lab data** (RFC-5737 IPs, `example.com`, inert VBA fixture). No live malware, no exploit code.

## Two tools (analyzer → reconstructor)

| # | Tool | What it does | Output |
|---|------|--------------|--------|
| A | `src/macro_analyzer.py` | Static triage of extracted VBA source. 10 ATT&CK-mapped rules, line-number evidence, exit code 2 on CRITICAL. | `findings.json` · `findings.md` |
| B | `src/killchain_reconstructor.py` | Correlates Tool A findings with EDR telemetry → timeline, IOC table, ATT&CK matrix, macOS containment checklist, P1–P4 priority. | `incident_brief.md` · `.html` · `.json` |

## Measured results (this run)

- **Macro analyzer:** 16 findings — 🔴 3 CRITICAL · 🟠 7 HIGH · 🟡 6 MEDIUM/LOW → verdict **MALICIOUS**
- **Reconstructor:** **P1** · 12 telemetry events · 2 C2 IPs (`198.51.100.44`, `203.0.113.9:8443`) · persistence plist + dropped `/tmp/.u` recovered
- **ATT&CK:** T1566.001 · T1204.002 · T1059.002 · T1105 · T1059.004 · T1496 · T1543.001 · T1071.001

## Run it (30 seconds)

```bash
python3 src/macro_analyzer.py data/invoice_Q3.docm.extracted.bas --json findings.json --md findings.md
python3 src/killchain_reconstructor.py --edr data/edr_telemetry.csv --macro findings.json \
    --md incident_brief.md --html incident_brief.html --json incident_brief.json
python3 -m unittest discover -s tests -v
```

Full copy-paste runbook with expected output → **[STEP_BY_STEP.md](STEP_BY_STEP.md)**
Analyst write-up → **[REPORT.md](REPORT.md)** · Live checker → `docs/` (enable GitHub Pages)

## Layout

```
graysentinel-day2/
├── src/       macro_analyzer.py · killchain_reconstructor.py
├── data/      invoice_Q3.docm.extracted.bas (inert) · edr_telemetry.csv
├── tests/     test_tools.py (21 tests)
├── evidence/  findings.* · incident_brief.* · terminal_session.txt
├── docs/      index.html (GitHub Pages checker)
├── README.md · REPORT.md · STEP_BY_STEP.md
```

## Integrity
All inputs are synthetic and declared. The VBA fixture is **inert** — every URL is RFC-5737/`example.com`,
no working payload, no download or execution. Tooling is **detection-only**. Nothing here can harm a system.
