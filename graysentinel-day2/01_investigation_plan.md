# Mission 01 — Asset Triage & Investigation Plan
**Case:** GS-DAY2-2026 · vCenter CVE-2026-59310 (CVSS 9.8, actively exploited) · Host: `vcsa-prod-01`
**Analyst:** Eswar Mahalingam · GS-STU-DSOU-2026-039A · Blue Team Operator

## Position: patch ≠ closure
Remediation stops *future* exploitation. It does not tell us whether the box was owned **before** the patch. vCenter is the identity + control plane for the whole virtual estate, so we treat this as **assume-breach until evidence says otherwise**. Close only after the pre-patch exposure window is cleared.

## Evidence to collect (what · where · why)
| # | Evidence | Data source (vCenter/ESXi) | Why it matters |
|---|----------|----------------------------|----------------|
| 1 | vCenter version / build | VAMI, `vpxd.log`, `/etc/vmware/.buildInfo` | Confirms whether the build was in the vulnerable range and for how long |
| 2 | Exposure history | Perimeter/proxy logs, external scan records, CISA KEV date | Was 443/vSphere UI reachable from untrusted networks during the window? |
| 3 | Authentication activity | SSO logs `vmware-sts-idmd`, `websso.log`, appliance `auth.log`, `/var/log/audit/` | Logins to vpxuser/administrator@vsphere.local, odd source IPs, odd hours |
| 4 | Administrative actions | `vpxd-audit.log`, Events & Alarms (vpx_event DB) | Role grants, permission edits, global-permission changes |
| 5 | Configuration changes | `vpxd.log`, `vsphere_client_virgo.log` | Identity-source added (rogue AD/LDAP), cert/SSO trust changes, service edits |
| 6 | VM activity | Task/Event log, `hostd.log` (ESXi) | Clone, snapshot, datastore browse/download (VMDK exfil), console access, export |
| 7 | Network connections | Appliance netflow/firewall, `iptables`, connection logs | New outbound to unknown IPs (C2), east-west to ESXi/backup subnets |
| 8 | New accounts | SSO user store, local `/etc/passwd` on VCSA, ESXi local users | Rogue SSO/local admin created for persistence |
| 9 | Unusual privileged activity | Audit log + task log correlation | Privileged ops from non-admin sources, service-account misuse |
| 10 | Timestamps / timeline | All of the above, normalised to UTC | Anchor every action to the pre/post-patch window; establish sequence |

## Collection order (fast → forensic)
1. **Snapshot the appliance state** (memory + disk image of VCSA) before touching it — preserve volatile evidence.
2. Pull SSO/auth logs and audit logs first (identity is where compromise shows first).
3. Export Events & Alarms DB range covering **[first-vulnerable-date → patch-date + 7d]**.
4. Pull ESXi `hostd`/`vpxa` logs for hosts managed by this vCenter.
5. Netflow for the appliance for the same window.
6. Hash and store everything read-only; log chain-of-custody.

## Window definition
`exposure_window = [build_became_vulnerable OR internet_exposure_start]  →  patch_applied`.
Every finding is judged **inside vs outside** this window. Anything inside = investigate; the point of the exercise is that the window is *before* the patch.

*Scenario is a GraySentinel lab exercise; CVE identifier is as given in the brief. Log paths/sources are real vSphere locations.*
