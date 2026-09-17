# GraySentinel DSOU — Blue Team Drills (Entra ID Sign-in Hunts)

Addition folder for `GraySentinel-DSOU-45Day-2026` (candidate 13 · Blue Team · reports to Ritik Shrivas).

| # | Drill | Attack | Detection pack | Hunt tool |
|---|-------|--------|----------------|-----------|
| 01 | Device Code Phishing | OAuth device-code token theft (bypasses MFA) | `drill-01-device-code-phishing/detection/` (KQL + Sigma) | `hunt/analyze_device_code.py` |
| 02 | Impossible Travel | Stolen session / residential-proxy identity | `drill-02-impossible-travel/detection/` (KQL + Sigma) | `hunt/analyze_impossible_travel.py` |

Each drill folder = attack explainer → 15-min hunt runbook → detection rule → analyzer script that turns an Entra ID Sign-in Logs CSV export into the exact `Timestamp | User | ... | Legit? + Why` line Ritik asked for → findings template.

**Integrity note.** `hunt/sample_*_SYNTHETIC.csv` files are declared-synthetic lab data (RFC-5737 IPs, example.com tenant) used only to prove the scripts run. Findings posted to the group must come from a real export (`Entra ID > Sign-in logs > Download > CSV`). Scripts are stdlib-only Python 3.

```
python3 drill-01-device-code-phishing/hunt/analyze_device_code.py <export.csv>
python3 drill-02-impossible-travel/hunt/analyze_impossible_travel.py <export.csv>
```
MITRE ATT&CK: T1528 (Steal Application Access Token), T1078.004 (Valid Accounts: Cloud), T1550.001 (Use Alternate Authentication Material: Application Access Token).
