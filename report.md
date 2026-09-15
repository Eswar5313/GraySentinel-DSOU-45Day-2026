# Project 02 — SOC Incident Summary Generator · Analyst Report

**Candidate:** Eswar Mahalingam (Blue Team) · **Date:** 14 Sep 2026 · **Input:** Project 01 findings (soc-lab-01) · **Status:** Submitted for Review

## Problem
Findings are not an incident record. Analysts retype the same facts into three audiences' formats under time pressure, with inconsistent priority calls.

## Objective
One command: findings → ranked, correlated, actionable incident summary (MD/HTML/JSON) following NIST SP 800-61 stages.

## Scenario
10 findings from the overnight `soc-lab-01` investigation (brute force → root compromise → persistence; separate spray campaign; local escalation probing) must become a P1 ticket before shift hand-over.

## Approach
Load → score (severity/priority/SLA/risk/confidence) → correlate by source in time → IOC extraction with actions → per-finding playbook → NIST checklist → render.

## Implementation
`src/incident_summary.py`: `load_findings_json/csv()`, `overall_severity()`, `risk_score()`, `confidence()`, `correlate()`, `iocs()`, `playbook_for()`, `build()`, `to_markdown()`, `to_html()`. Incident ID is deterministic (CRC32 of source path + date) so re-runs update the same ticket.

## Testing
`python3 -m unittest -v tests.test_incident_summary` → **12/12 OK**. Includes empty-input, CSV-input and determinism tests.

## Evidence
`evidence/terminal_output.txt`, `evidence/incident_summary.{md,html,json}`, `evidence/incident_summary_from_csv.md`, `screenshots/01–04`.

## Result
GS-INC-20260915-805: CRITICAL/P1, risk 100/100, 23 IOCs, 9 techniques, 4-stage checklist, escalation to SOC Lead + IR Manager + system owner; page on-call within 15 min.

## Security Relevance
Standardises Tier-1 → Tier-2/IR hand-over; makes priority calls auditable; gives network/identity teams a block/reset list they can act on immediately.

## Limitations
Keyword playbook; lab-calibrated scoring; no IOC enrichment; no ticketing integration.

## Learning
The correlation step ("Chain: …") was the highest-value line for a reader — one sentence that says scan vs intrusion. Also learned to keep IDs deterministic; random IDs broke re-run comparisons in testing.

## Future Improvement
TheHive/Jira push, IOC enrichment, STIX export, more input schemas, PDF.
