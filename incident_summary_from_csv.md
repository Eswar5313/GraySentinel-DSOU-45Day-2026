# SOC Incident Summary — GS-INC-20260915-977

| Field | Value |
|---|---|
| **Severity / Priority** | **HIGH / P2** |
| Risk score | 55 / 100 |
| Confidence | MEDIUM — findings are consistent but not yet corroborated by host forensics |
| Response SLA | 1 hour |
| Notify | SOC Lead + system owner |
| Activity window | 2026-09-14 02:09:00 → 2026-09-14 03:02:11 |
| Events analysed | 56 |
| Findings | HIGH: 1, MEDIUM: 1, LOW: 1 |
| Analyst | Eswar Mahalingam (Blue Team, GS-STU-DSOU-2026-039A) |
| Generated | 2026-09-15 01:26:43 |
| Source | `data/alerts_sample.csv` |

## 1. Executive summary

- 3 security findings were raised on the monitored host between 02:09 and 03:02 on 2026-09-14.
- Overall severity is HIGH (priority P2); risk score 55/100; confidence: MEDIUM.
- The highest-impact finding is: SSH brute force (many failures from one source) (203.0.113.200).

## 2. Attack narrative

1. From 203.0.113.200: the attacker at 203.0.113.200 — 02:09 — username enumeration / invalid-user probing (test, guest, oracle); then 02:10 — ssh brute force (many failures from one source) (root, admin).
2. From 192.0.2.30: the attacker at 192.0.2.30 — 03:02 — privileged account login outside business hours (root).

## 3. Timeline

| Time | End | ID | Severity | Finding | Source | Accounts | Events |
|---|---|---|---|---|---|---|---|
| 02:09:00 | 02:10:00 | A03 | LOW | Username enumeration / invalid-user probing | `203.0.113.200` | test, guest, oracle | 3 |
| 02:10:00 | 02:14:30 | A01 | HIGH | SSH brute force (many failures from one source) | `203.0.113.200` | root, admin | 52 |
| 03:02:11 | 03:02:11 | A02 | MEDIUM | Privileged account login outside business hours | `192.0.2.30` | root | 1 |

## 4. Indicators of Compromise

| Type | Value | Seen in | Recommended action |
|---|---|---|---|
| IPv4 | `203.0.113.200` | SSH brute force (many failures from one source) | Block at perimeter; add to threat-intel watchlist; search other logs |
| Account | `root` | SSH brute force (many failures from one source) | Force password reset; monitor |
| Account | `admin` | SSH brute force (many failures from one source) | Force password reset; monitor |
| IPv4 | `192.0.2.30` | Privileged account login outside business hours | Block at perimeter; add to threat-intel watchlist; search other logs |

## 5. MITRE ATT&CK

- T1078 Valid Accounts
- T1087 Account Discovery
- T1110.001 Password Guessing

## 6. Recommended actions per finding

| ID | Sev | Finding | Action |
|---|---|---|---|
| A01 | HIGH | SSH brute force (many failures from one source) | Block source IP at perimeter firewall/fail2ban; enforce key-only SSH (`PasswordAuthentication no`); rate-limit port 22; check whether the IP appears in other logs. |
| A02 | MEDIUM | Privileged account login outside business hours | Confirm with the account owner; if unconfirmed, treat as part of the compromise chain; add a time-based alert rule for privileged logins. |
| A03 | LOW | Username enumeration / invalid-user probing | Block source IP; ensure sshd returns identical responses for valid/invalid users (default in modern OpenSSH); add IP to watchlist. |

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

Priority **P2** → notify **SOC Lead + system owner** within **1 hour**. Open a ticket, attach this summary and the raw log, and hand over with the checklist above.
