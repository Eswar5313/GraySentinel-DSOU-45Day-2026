# Drill 01 — Device Code Phishing · Findings (fill from REAL export only)

Tenant: ____ · Export window: ____ to ____ · Rows with device code flow: __

| Timestamp (UTC) | User | App | IP / ASN | Location | Was it legit? | Why |
|---|---|---|---|---|---|---|
| | | | | | Yes/No | |

Actions for every **No**: revoke refresh tokens (`Revoke-MgUserSignInSession -UserId <upn>`) → password reset → review inbox rules + OAuth consents → confirm Conditional Access "Block device code flow" is enforced.
