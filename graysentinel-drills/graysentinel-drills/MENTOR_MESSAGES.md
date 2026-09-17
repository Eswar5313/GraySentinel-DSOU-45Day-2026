# Group messages for Ritik — copy-paste (replace the ⟨ ⟩ rows with lines from YOUR real export)

Run the analyzer on your real CSV; it prints the rows in exactly the format below. Never post the SYNTHETIC sample as a finding.

---
## Drill 01 — Device Code Phishing

🛡️ Drill submission — Device Code Phishing · Eswar (Cand. 13)

Hunt done: Entra ID > Sign-in logs (interactive + non-interactive) > filter Authentication protocol = Device code, last 30 d, CSV exported and scored.

Timestamp | User | App | Was it legit? + Why
⟨2026-09-17T04:41Z⟩ | ⟨user⟩ | ⟨Microsoft Office⟩ | **No** — new country (⟨NL⟩), hosting ASN (⟨M247⟩), Office is not a device-code-native client, no CA policy applied → treat as token theft, sessions revoked, mailbox rules checked.
⟨2026-09-17T03:12Z⟩ | ⟨user⟩ | ⟨Azure CLI⟩ | **Yes** — home ISP/location, Azure CLI legitimately uses device code, CA passed.
⟨…⟩ | ⟨…⟩ | ⟨…⟩ | ⟨…⟩

Scoring used: new country +3 · non-native app +2 · VPN/hosting ASN +2 · CA not applied +1 · first app use +1 → score ≥3 = No.
Detection pack: KQL (30-day per-user baseline join, RiskScore) + Sigma (T1528) — repo GraySentinel-DSOU-45Day-2026 › graysentinel-drills/drill-01-device-code-phishing/
Fix pushed: Conditional Access › Authentication flows › block Device code flow for everyone except the admin/dev group.

---
## Drill 02 — Impossible Travel

🛡️ Drill submission — Impossible Travel · Eswar (Cand. 13)

Hunt done: Identity Protection > Risky sign-ins (Impossible travel / Unfamiliar sign-in properties) cross-checked against raw Sign-in logs for IP, ASN and MFA result; implied speed computed (haversine ÷ Δt, 900 km/h flight ceiling).

Timestamp | User | Location 1 → Location 2 | Time Delta | MFA Status | Was it legit? + Why
⟨2026-09-17 04:10Z⟩ | ⟨user⟩ | ⟨Mumbai, IN → São Paulo, BR⟩ | ⟨40 min⟩ | ⟨satisfied by claim in token⟩ | **No** — 13,774 km/40 min, hosting ASN, MFA never re-challenged = replayed session → revoked, password reset, MFA methods reviewed.
⟨2026-09-17 06:25Z⟩ | ⟨user⟩ | ⟨Ghaziabad, IN → Frankfurt, DE⟩ | ⟨25 min⟩ | ⟨fresh Authenticator MFA⟩ | **Yes** — 2nd ASN is our Zscaler egress, fresh MFA passed, compliant device.
⟨…⟩ | ⟨…⟩ | ⟨…⟩ | ⟨…⟩ | ⟨…⟩ | ⟨…⟩

Rule of thumb: speed > 900 km/h AND (consumer VPN/hosting/plain foreign ISP) AND MFA "satisfied by claim in token" → stolen session, not travel.
Detection pack: KQL (prev() pairing + geo_distance_2points + TokenReplay flag) + Sigma (T1550.001) — same repo › drill-02-impossible-travel/
Hardening: token protection + 1 h sign-in frequency for privileged users, revoke on high risk.
