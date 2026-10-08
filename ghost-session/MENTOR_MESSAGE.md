🔴 Red-Team War Room submission — Ghost Session (valid-session abuse, cloud + internal) · Eswar (Cand. 13)
«LAB ONLY. Synthetic disposable identity, no real credentials, no session/token theft, no production, no persistence outside the lab, no offensive code.»

🎯 Thesis: nobody broke in — the attacker was let in AS the user. One authenticated session context used from a second environment: no password event, no MFA prompt, no malware, EDR clean. Blue-team analyzer (20/20 tests) fails that session on all five dimensions: Device + Location + Time + Behaviour + Resource.

🗺️ 1) Attack surface map (12 assets): IDP-01 (no device binding, MFA inherited), RA-GW-01 (legacy profile, flat reach), cloud tenant + console, OAuth apps (user consent), FS-FIN-02 (over-broad rights, NTLM), SIEM/EDR (identity + cloud logs not correlated with endpoint).

🧠 2) Hypotheses
H1 valid session abuse → T1078 / T1550.004: the signal is NO new auth event + new session on an unregistered device. Owner check = Device + Location + Time + Behaviour + Resource.
H2 identity → internal → T1133 / T1021.002 / T1039: first-seen (user, server) pair, NTLM instead of Kerberos, 412 files vs ≤25/day. Hunt abnormal access, not successful auth.
H3 cloud app abuse → T1098 / T1528: Mail.Read + offline_access grant from the suspect session. Safe response: revoke grant + tokens, then reset.

🛡️ 3) Evasion concept "the borrowed session": only SSO, VPN, file share and consent are used → AV sees nothing because nothing runs on the endpoint. Key detection: cloud says yes, endpoint says no (no proxy/DNS request from the laptop).

🔐 4) Identity lab: 9 concepts shown. Senior — harder than malware because every event is legitimate by design: auth succeeds, MFA reads "satisfied", tools are trusted, movement uses the user's own rights, evidence sits in logs nobody joins.

🚨 5) Detection challenge: investigate 10:39 first (same token, second country, owner still active); scope 10:31 (412 files) in parallel. Compromise vs remote work = device, fresh MFA, concurrency, geography, endpoint match, behaviour, user statement. Safe containment: revoke sessions + tokens, remove app grant, block device/IP at gateway.

🧬 6) Timeline 10:02 → 19:40 with risk/evidence/confidence per event. Pivot = 10:39: everything earlier is owner-explainable; one token in IN and NL 18 min apart is not. Remove it and the tool drops from CONTAIN to INVESTIGATE.

🔎 7) DFIR: reset + reimage first would destroy the session picture, the entry path, the negative evidence that clears the user — and the 10:44 app grant survives a password reset anyway. Preserve → revoke → scope → reset.

⚔️ 8) Safe simulation: 7 phases with an authorised second sign-in of the synthetic identity. WHO/WHERE/WHEN/WHAT/HOW/IMPACT all answered by the analyzer.

🛡️ 9) Before vs After: device-bound tokens + conditional access, phishing-resistant MFA, short finance sessions, consent governance, PIM, least privilege, segmentation, continuous identity hunting.

🧠 Senior — trade-offs: A (malware) = control of a machine, paid for in noise, artifacts and a fast defender playbook. B (session) = the user's reach with almost no noise, but bounded by permissions and session lifetime and it collapses on revocation. Strong EDR + weak identity governance pushes attackers to B.

📄 10–11) Closure report (11 sections) + decision 🔴 CONTAIN: evidence + correlation + user context + identity risk + Treasury sensitivity. False positive costs one re-authentication; waiting costs more data and a foothold in mail.

📦 Pack (20/20 tests, report PDF, 7 detection rules, analyzer, synthetic telemetry):
https://github.com/Eswar5313/GraySentinel-DSOU-45Day-2026/tree/main/ghost-session
📊 Dashboard: https://eswar5313.github.io/GraySentinel-DSOU-45Day-2026/#ghostsession
