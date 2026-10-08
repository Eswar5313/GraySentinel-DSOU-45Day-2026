🟡 Intel War Room submission — Consent Trap (OAuth consent abuse) · Eswar (Cand. 13)

🎯 CTI Lead's question — legitimate SaaS or identity intrusion? IDENTITY-BASED INTRUSION VIA OAUTH CONSENT. Confidence HIGH, attribution NONE. First-seen app, unverified publisher, Mail + Files + offline_access by user consent → API from a German hosting IP at +7 min → 340 mail items at +21 min → 23 treasury/board files at +26 min → second employee consents to the same app ID at +39 min. No password stolen, MFA never bypassed — the user approved it on the genuine consent screen.

📄 1) Intel card: consent phishing ("illicit consent grant") · target = M365 tenants with default user consent, finance/HR/execs · mechanism = delegated token + refresh token used from attacker infrastructure · actor = unattributed · infra = look-alike domain registered 6 days earlier, one hosting IP, two sibling domains. MFA protects the sign-in, not the grant; a password reset does not remove it.

🧠 2) TTP map: T1566.002 → T1204.001 → T1528 → T1550.001 / T1078.004 → T1526/T1538 → T1114.002 → T1213.002 (T1098 not observed — hunt item). Senior TTP: the app is the MECHANISM; the attack is persistent delegated access. Remove the grant + tokens and fix the consent policy — blocking a name is useless.

🌐 3) OSINT (methodology; lab values simulated, nothing real queried): RDAP age, CT sibling certs, passive DNS co-hosting, URLScan redirect chain carrying the client_id, publisher footprint. "0/90 on VirusTotal" is NOT evidence of safety. Valid indicator only if it ties to our app ID / redirect URI / calling IP.

🛡️ 4) Hunt table: 08:42 consent 🟡 · 08:49 API 🟡 · 09:03 mailbox from DE 🔴 · 09:07 files outside baseline 🔴 · 09:21 second user 🔴 · 09:31 multi-user API 🔴. Controls stay 🟢: admin-approved new SaaS, verified sign-in-only app.

🔐 5) IoCs: app ID …c7a9 (hunt the ID, names change), unverified publisher, redirect domain, 203.0.113.45, scope set. Hypothesis: non-admin consent to unapproved app with data scopes + same app acting from outside baseline within 60 min → fired for both users. Sigma (3 rules + 2 correlations) + KQL hunts.

💎 6) Diamond: Adversary unknown (Low) · Capability consent phishing + Graph collection (High) · Infrastructure fresh look-alike domain + single host (Medium) · Victim finance/HR in a default-consent tenant (High). Attribution needs app-ID/infrastructure overlap with a documented cluster from two independent sources.

⚔️ 7) Strongest stop point = AT CONSENT: one tenant policy (no user consent for unverified publishers / data scopes, admin-consent workflow) kills every lure and every future app name. Before consent is unreliable; after consent is the best detection point but mail was read in 21 minutes.

🚨 8) 24h: revoke grants + refresh tokens FIRST, disable the service principal, scope both users, preserve logs, purge lure, warn treasury. 7d: historical consent hunt, related domains, inbox rules, apps with similar scopes. 30d: restrict user consent, app governance, CA for workload identities, allow-listing for sensitive groups.

📄 9) CISO brief: confirmed mail + document exposure, elevated BEC risk, possible DPDP/GDPR duty. It is a policy gap, not user carelessness.

🧠 Senior — B is harder to DETECT (no execution, valid events, high false positives, survives reimage + password reset); A is harder to PREVENT. So: endpoint detection for A, consent governance + identity hunting for B.

📦 Pack (20/20 tests, report PDF, Sigma, KQL, hunter, synthetic evidence):
https://github.com/Eswar5313/GraySentinel-DSOU-45Day-2026/tree/main/consent-trap
📊 Dashboard: https://eswar5313.github.io/GraySentinel-DSOU-45Day-2026/#consenttrap
