# Mission 03 — Detection Engineering
**Case GS-DAY2-2026** · Analyst: Eswar Mahalingam (GS-STU-DSOU-2026-039A)

## Detection concept

| Field | Value |
|-------|-------|
| **Detection Name** | `VCENTER-PRIV-VMOPS-ANOMALOUS-SOURCE` — Privileged virtual-infrastructure action from an unexpected identity/source |
| **Telemetry** | vCenter `vpxd-audit.log` + Events & Alarms (vpx_event) → SIEM (Wazuh). Fields: `user`, `source_ip`, `operation`, `target` (VM/host/role), `result`, `timestamp`. Enriched with admin-source allow-list + change-ticket feed. |
| **Detection Logic** | Fire when a **privileged operation** — `CreateUser`, `AddPermission`/`RoleModify`, `AddIdentitySource`, `CloneVM`, `ExportVM`/datastore download, `CreateSnapshot` on a Tier-0 VM, or `vpxuser` credential change — occurs AND (source_ip ∉ admin allow-list **OR** user created < 24h ago **OR** no matching change ticket **OR** outside 08:00–20:00 local). Correlated form: any two of these within a 30-min window on one appliance → escalate one severity. |
| **Severity** | **High** by default; **Critical** if the target is a Tier-0 VM (DC, backup server, PKI) or if `vpxuser`/host creds were subsequently used against an ESXi host. |
| **False Positives** | Break-glass admin from a new jump host; approved onboarding of a new admin; scheduled backup/DR clone or snapshot; vendor support session. |
| **FP Suppression** | Allow-list jump hosts + backup service accounts; auto-correlate to the change/HR ticket feed; suppress known DR windows. Un-ticketed events never auto-suppress. |
| **Analyst Response** | 1) Confirm the source IP and identity against allow-list + ticket. 2) If unexplained → disable the account, kill active sessions, snapshot the appliance. 3) Pull the full task chain for that user in-window. 4) Check whether `vpxuser`/host creds were reused on ESXi. 5) Escalate to H2 / IR + credential rotation if any privileged change is unexplained. |

A concrete Sigma rule and a Wazuh rule implementing this concept are in **`detections/`**.
