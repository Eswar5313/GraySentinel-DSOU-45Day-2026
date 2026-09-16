# Mission 04 — Ransomware Readiness Checklist
**"What must the SOC investigate if ransomware is suspected after a vCenter compromise?"**
Case GS-DAY2-2026 · Analyst: Eswar Mahalingam (GS-STU-DSOU-2026-039A)

> Post-vCenter ransomware follows a known path: own the management plane → harvest creds → push encryptor to ESXi/datastores → **delete snapshots + backups** → encrypt VMDKs. Work these ten domains in order.

## ☐ 1. Identity  *(T1078)*
- Which SSO/AD accounts logged into vCenter in-window? Any from unusual sources/hours?
- `administrator@vsphere.local` and `vpxuser` session history — any unexplained use?

## ☐ 2. Privileged accounts  *(T1098, T1136)*
- New SSO/local admins created? Role or **global permission** grants without a ticket?
- Added identity source (rogue AD/LDAP) giving attacker a persistent admin path?

## ☐ 3. Virtual infrastructure  *(T1485, T1490)*
- Snapshots **deleted** on Tier-0 VMs? VMs powered off/encrypted? Rogue VMs deployed?
- Datastore files renamed/encrypted (`.vmdk` → attacker extension)? ESXiArgs-style pattern?

## ☐ 4. Management plane  *(T1489, T1562)*
- Direct logins to ESXi hosts (bypassing vCenter)? SSH enabled on hosts?
- Services stopped/tampered (logging, AV, `vpxa`)? Lockdown mode disabled?

## ☐ 5. Network activity  *(T1071, T1048)*
- Outbound C2 from the appliance? Large egress (VMDK/backup exfil)?
- East-west from vCenter to backup and ESXi management subnets?

## ☐ 6. Backup integrity  *(T1490 Inhibit System Recovery)*
- Backup jobs disabled/deleted? Repository reachable/writable from compromised creds?
- **Immutable/offline copy** confirmed intact and restorable? Last known-good restore point?

## ☐ 7. Credential exposure  *(T1003, T1552)*
- `vpxuser` / host creds harvested from vCenter and reused on ESXi?
- AD/service creds stored in vCenter, backup, or automation extracted? Kerberos/NTLM abuse?

## ☐ 8. Lateral movement  *(T1021, T1550)*
- vCenter → ESXi → guest VM pivots (guest-ops file push/exec)?
- Reuse of harvested creds against DCs, backup servers, jump hosts?

## ☐ 9. Persistence  *(T1136, T1505)*
- Rogue accounts, added identity sources, scheduled tasks/cron on the appliance?
- Web-shell/extension on vCenter? Modified startup on ESXi?

## ☐ 10. Evidence preservation  *(pre-remediation)*
- Image the VCSA appliance + capture memory **before** rebuild.
- Export vpxd/audit/SSO logs + Events DB read-only; hash everything; chain-of-custody.
- Preserve at least one encrypted VMDK sample + ransom note for IR/legal.

**Do not restore or rebuild until 1–10 are worked and backups are proven clean & immutable.** Restoring onto an estate where creds are still valid = re-encryption.
