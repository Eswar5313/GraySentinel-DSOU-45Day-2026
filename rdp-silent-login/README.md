# 🔥 GraySentinel DSOU · SOC War Room · 05 Oct 2026 — *The Silent RDP Login*

**Analyst:** Eswar Mahalingam · Candidate 13 · GS-STU-DSOU-2026-039A · Blue Team
**Verdict:** H1 **COMPROMISED** · H2 **REJECTED** · H3 **CONFIRMED** → **P1, contain** · **18/18 tests pass**

Failed RDP → successful RDP (valid HR account, no MFA, internet-exposed NAT) → privileged session → hidden encoded PowerShell → AD discovery → SMB to FS-HR-01 → payroll files read → POST to first-seen host. Defender: 0 detections (living-off-the-land).

| File | What it is |
|---|---|
| [`SUBMISSION.md`](SUBMISSION.md) | Full answer: triage · 3 hypotheses · timeline · detection · lateral hunt · containment · senior SOC answer |
| [`GraySentinel_DSOU_RDP_SilentLogin_Report.pdf`](GraySentinel_DSOU_RDP_SilentLogin_Report.pdf) | Same submission as a 5-page report |
| [`rdp_chain_hunter.py`](rdp_chain_hunter.py) | Hunt tool — reconstructs every Type-10 session, scores H1/H2/H3, runs the chain detection, lateral-movement checks |
| [`test_rdp_chain_hunter.py`](test_rdp_chain_hunter.py) | 18 unit tests incl. legit-admin control case, window boundary, garbage input |
| [`rdp_powershell_chain.sigma.yml`](rdp_powershell_chain.sigma.yml) | Sigma correlation rule (temporal_ordered, 15 min) |
| [`wazuh_local_rules_rdp.xml`](wazuh_local_rules_rdp.xml) | Wazuh rules 100810–100816 (spray → success → PowerShell chain) |
| [`make_rdp_lab_data.py`](make_rdp_lab_data.py) | Generates the synthetic evidence set |
| [`rdp_events_SYNTHETIC.csv`](rdp_events_SYNTHETIC.csv) · [`auth_context_SYNTHETIC.json`](auth_context_SYNTHETIC.json) | 77 Windows/Sysmon/PowerShell events + IdP/VPN/firewall context |
| [`hunt_output.txt`](hunt_output.txt) · [`hunt_results.json`](hunt_results.json) · [`test_output.txt`](test_output.txt) | Captured runs |
| [`MENTOR_MESSAGE.md`](MENTOR_MESSAGE.md) | Copy-paste submission message |
| [`dashboard_rdp_tab.png`](dashboard_rdp_tab.png) | Screenshot of the live dashboard tab |

```bash
cd rdp-silent-login
python3 make_rdp_lab_data.py
python3 rdp_chain_hunter.py rdp_events_SYNTHETIC.csv auth_context_SYNTHETIC.json --json hunt_results.json
python3 -m unittest test_rdp_chain_hunter -v
```

ATT&CK: T1133 · T1110.003 · T1078 · T1021.001 · T1059.001 · T1027 · T1087.002 · T1482 · T1021.002 · T1039 · T1074.001 · T1048
Scope: detection & response only. All data synthetic (RFC-5737 IPs, example.com). No exploit code.
