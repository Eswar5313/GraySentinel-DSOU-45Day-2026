🟢 SOC War Room submission — Ghost Admin (DC-02, privileged identity) · Eswar (Cand. 13)

🎯 Not an account-reset ticket. A Tier-2 help-desk identity was used to get Domain Admin + DCSync on a DC in 3 minutes. Investigate the identity's whole path, not the password.

🗺️ 1) Identity attack surface
USER s.menon (help desk, not normally admin) → WKS-FIN-204/10.20.44.204 → NTLM logon to DC-02 (Type 3, no Kerberos PAC) → added to Domain Admins + Administrators → DC-02 (encoded PS, 4662 replication read) → DC-01 + FS-CORP-01.

🧠 2) Hypotheses
H1 credential compromise → COMPROMISED (12 failed→1 success from a non-PAW host, NTLM to a DC, 0 Tier-0 baseline, not an admin acct; real DA da.patel from the PAW is NOT flagged)
H2 privilege escalation → CONFIRMED (added to Domain Admins 40s after logon, SeDebug/SeEnableDelegation/SeBackup, encoded PS right after)
H3 lateral movement → CONFIRMED (onward to DC-01 + FS-CORP-01, SYSVOL access, RC4 TGT, DCSync)

🛡️ 3) Detection — Privileged Identity Anomaly
DC logon (4624 Type 3/10) from outside PAW range + within 15 min same account: priv-group add (4728/4732) OR DCSync (4662 replication) OR encoded PS on DC OR onward Tier-0 logon → HIGH; CRITICAL on DCSync or new DC service (7045). Sigma correlation + Wazuh 100820-100827 + Python reference with tests.

🔐 4) Persistence hunt + critical question
Found: priv-group adds, new DC service WinSysMon2, RC4 TGT. If the password is reset you must STILL check: active Kerberos tickets (reset doesn't kill them — rotate krbtgt ×2), every privileged group's members, persistence (service/tasks/WMI/ACL backdoors, AdminSDHolder), service accounts, and every credential DCSync exposed. Password reset ≠ containment when DA + DCSync already happened.

🚨 5) Closure: identity + source host isolated, all group changes reviewed, timeline rebuilt, PS + lateral + DC activity investigated, persistence + service accounts checked, EDR/SIEM preserved, creds rotated incl. krbtgt ×2, monitoring raised, owner informed.

🧠 Senior — B wins: thousands of failed logons are loud, pre-auth, low blast radius. ONE privileged logon from an unusual host is quiet, already holds the keys, and via DCSync touches every identity in the domain. Detection value is correlating that one logon with what it did next.

📦 Pack (18/18 tests, report PDF, Sigma, Wazuh, hunter, synthetic evidence):
https://github.com/Eswar5313/GraySentinel-DSOU-45Day-2026/tree/main/ghost-admin
📊 Dashboard: https://eswar5313.github.io/GraySentinel-DSOU-45Day-2026/#ghostadmin
