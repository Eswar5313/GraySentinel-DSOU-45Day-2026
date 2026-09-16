# Mission 02 — Hunting Hypotheses
**Case GS-DAY2-2026 · vCenter CVE-2026-59310** · Analyst: Eswar Mahalingam (GS-STU-DSOU-2026-039A)

Both hypotheses are tested against the exposure window `[vulnerable → patched]`. Each is falsifiable and ends in a conclusion, not a guess.

---
## H1 — "The vulnerable vCenter was accessed before remediation."
*ATT&CK: T1190 Exploit Public-Facing Application · T1078 Valid Accounts*

| Field | Detail |
|-------|--------|
| **Evidence required** | Successful auth/session events, exploit-pattern requests, first-seen source IPs, session tokens issued to `administrator@vsphere.local`/`vpxuser` |
| **Data source** | `websso.log`, `vmware-sts-idmd`, `vpxd.log`, appliance `auth.log`, `/var/log/audit/`, reverse-proxy/WAF logs, netflow |
| **Expected indicators** | Auth success from an IP with no prior history; login outside business hours; UI/API access immediately following a burst of 4xx/5xx on the vSphere endpoint; token issuance with no matching human login; user-agent anomalies |
| **Possible false positives** | Legitimate admin working late; the security team's own remediation/validation activity; approved vulnerability scanner; monitoring service accounts |
| **How to clear FPs** | Cross-check source IP against the admin jump-host allow-list and the change ticket for the patch; confirm scanner IPs; match service-account activity to its normal cadence |
| **Investigation conclusion** | **Confirmed** if any authenticated session originates from a non-allow-listed source inside the window with no ticket. **Refuted** if every in-window session maps to a known admin/scanner/service identity. Until refuted, treat as live. |

---
## H2 — "An attacker used vCenter access to influence virtual infrastructure or harvest credentials."
*ATT&CK: T1098 Account Manipulation · T1136 Create Account · T1213 Data from Repositories · T1550 Alternate Auth · T1021 Remote Services*

| Field | Detail |
|-------|--------|
| **Evidence required** | New SSO/local accounts, role/global-permission grants, added identity source, VMDK/snapshot download or clone, console sessions, `vpxuser` password/cert changes, host-level command push to ESXi |
| **Data source** | `vpxd-audit.log`, Events & Alarms (vpx_event), SSO user store, ESXi `hostd.log`/`vpxa.log`, datastore access logs, netflow to backup/ESXi subnets |
| **Expected indicators** | Account created then immediately granted Administrator; permission change from a non-standard source; VM clone/export followed by outbound transfer; snapshot of a domain-controller VM; extraction of `vpxuser` creds used to log into ESXi hosts directly; guest-ops (file pull) into running VMs |
| **Possible false positives** | Legitimate onboarding of a new admin; scheduled backup jobs cloning/snapshotting VMs; DR test; approved VM export |
| **How to clear FPs** | Every account/permission/VM-export must tie to an HR ticket, backup schedule, or change record. No ticket → suspicious |
| **Investigation conclusion** | **Confirmed** if any privileged change or VM data-access in-window lacks an owning ticket, *or* if `vpxuser`/host creds were reused against ESXi. **Refuted** only when every privileged action is accounted for. Confirmation here = escalate to full IR + credential rotation across the estate. |

---
## Analyst note
H1 answers *"were they in?"* H2 answers *"what did they touch?"* You cannot close on H1 alone — even a single confirmed pre-patch session forces H2 to be worked to completion, because vCenter access converts directly into estate-wide identity and VM control.
