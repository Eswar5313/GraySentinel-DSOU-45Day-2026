# Drill 02 — Impossible Travel

**Attack.** Session/refresh token or credentials are stolen and replayed from another geography. Residential proxies (e.g. "Mumbai" IPs sold by proxy providers) make most replays look local, but the attacker occasionally slips to their own exit → Mumbai 09:00, São Paulo 09:40. 13,700 km in 40 min is not a flight, it's two identities. Indian analogy: a metro card tapped in at Rajiv Chowk and 10 minutes later at Chennai Central — the card was cloned.

**Hunt (15 min).**
1. Entra ID → Protection → Identity Protection → Risky sign-ins (or Sign-in logs → filter Risk detail).
2. Filter *Risk event type = Impossible travel* OR *Unfamiliar sign-in properties*; also export raw Sign-in logs for the same users (the raw log gives IP, ASN, MFA result).
3. For each pair: is the 2nd IP a VPN/proxy/hosting ASN? Did MFA actually challenge, or was it "already satisfied by token/claim in token" (= replayed session)?
4. Run `hunt/analyze_impossible_travel.py export.csv` → prints `Timestamp | User | Loc1 → Loc2 | Δt | Speed | MFA | Legit? + Why`.

**Legit vs Not — decision rules**

| Signal | Legit | Suspicious |
|---|---|---|
| Implied speed | < 900 km/h (commercial flight) or corporate VPN egress | > 900 km/h with no VPN explanation |
| 2nd ASN | Company VPN / Zscaler / known cloud egress | Consumer VPN, hosting, residential-proxy brand |
| MFA | Fresh MFA challenge passed on 2nd sign-in | "Previously satisfied" / claim in token — stolen session |
| Device | Same registered/compliant device ID | New/unmanaged device |
| User confirms | travelling / VPN on | no |

**Prevention.** Token protection (Conditional Access → Session → Require token protection), sign-in frequency 1 h for privileged, block legacy auth, Continuous Access Evaluation, revoke on risk = high.
