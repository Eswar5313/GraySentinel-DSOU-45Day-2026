# Drill 01 — Device Code Phishing

**Attack.** Attacker starts the OAuth 2.0 device-authorization flow (`POST /oauth2/v2.0/devicecode`), receives a user code (e.g. `84JS92K`), and phishes the victim: "Teams session expired, enter this code at microsoft.com/devicelogin". The victim signs in on a *genuine* Microsoft page (MFA already satisfied on their normal device), so no password is stolen and no MFA prompt looks odd — but the access + refresh token is issued to the **attacker's** client. Code is valid for 15 minutes. Indian analogy: someone asks you to approve a UPI collect request "to verify your account" — you typed your PIN on the real app, but the money went to them.

**Hunt (15 min).**
1. Entra ID → Monitoring → Sign-in logs → User sign-ins (interactive) **and** non-interactive.
2. Add filter *Authentication protocol = Device code* (older UI: Authentication Details column shows "Device code flow").
3. Widen date range to 7–30 days. Export CSV.
4. For each row check: user's normal location/ISP? App = Microsoft Office / Azure CLI / Teams? Is the device a headless box, kiosk, TV or CLI where device code is expected? Any Conditional Access policy that should have blocked it?
5. Run `hunt/analyze_device_code.py export.csv` → paste the table into the group.

**Legit vs Not — decision rules (used by the script)**

| Signal | Legit | Suspicious |
|---|---|---|
| Client app | Azure CLI, Az PowerShell, Teams Rooms, Intune device enrolment, Visual Studio | Microsoft Office / Graph / "Microsoft Authentication Broker" from a user PC that has browsers |
| Location / ASN | User's home city and known ISP | New country, datacenter/VPS/VPN ASN |
| Prior device-code use by user | Regular pattern | First ever |
| Conditional Access | Policy applied and passed | No policy / not applied |
| Follow-on activity | none unusual | Mailbox rules, OAuth consent, mass file download within 1 h |

**Prevention.** Conditional Access → Authentication flows → block **Device code flow** for all users except a named admin/dev group; enable Microsoft-managed "Block device code flow" policy; user awareness: Microsoft never sends a login code by mail for you to enter on a page.
