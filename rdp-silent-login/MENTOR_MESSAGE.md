🛡️ SOC War Room submission — The Silent RDP Login (HR-WS-017) · Eswar (Cand. 13)

🎯 Verdict: NOT a false positive, NOT just brute force → valid-account compromise via RDP, used for discovery + payroll data access. P1, contain now.

🔍 1) Triage
• User: ananya.rao (HR) · Src: 203.0.113.45 / DESKTOP-9KX2TQ (external, not VPN, not IT jump host)
• 23 failed 4625 (administrator ×8, hr.admin ×6, ananya.rao ×9) in 5 min → 4624 Type 10 at 03:23:02 IST
• No MFA on RDP · 0 RDP logons in 30-day baseline · not in RDP-allowed group
• Dest HR-WS-017 exposed via forgotten NAT rule 203.0.113.200:3389 (2025 "vendor access", no owner)
• 4672: SeDebug/SeBackup/SeTakeOwnership/SeImpersonate (user is local admin)
• explorer → cmd → powershell -NoP -NonI -W Hidden -Enc … (4104: whoami, nltest /dclist, net group "Domain Admins", enum \\FS-HR-01\HR$\Payroll, POST p.csv out)
• No password change since Jun · KEY: same IP had the correct password in Entra on 3 Oct (2 MFA pushes denied) · same IP also hit HR-WS-021 (6) + FIN-WS-004 (4), all failed

🧠 2) Hypotheses
H1 credential compromise → COMPROMISED (6 indicators incl. IdP proof + user not on VPN)
H2 legitimate admin → REJECTED (no admin acct, source, ticket or window; real helpdesk RDP in same data scores INFO)
H3 initial access for more → CONFIRMED (hidden PS, discovery, SMB + Type 3 on FS-HR-01, 3 payroll files read, egress to first-seen 198.51.100.23:443)

🔎 3) Timeline (IST)
03:17 first failure → 03:23:02 RDP success + privileged session → 03:24:31 cmd → 03:24:40 hidden PowerShell → 03:24:45 whoami/nltest/net → 03:25:11 LDAP DC-01 → 03:25:41 Type 3 on FS-HR-01 → 03:25:45 payroll files read → 03:26:01 outbound 443 → 03:31–03:35 sprays 2 more hosts → 03:43 Defender: 0 threats

🛡️ 4) Detection — Suspicious RDP-to-PowerShell Chain
4624 Type 10 from non-approved / never-seen source + powershell with -enc / -w hidden / -nop on same host + user within 15 min → HIGH; CRITICAL if ≥10 prior 4625 same IP, SeDebug in 4672, or 445/389/first-seen egress in window. Sigma correlation + Wazuh rules 100810–100816 + Python reference with tests — fires on the attack, silent on all 5 legit admin sessions.

🧬 5) Lateral movement
✅ SMB FS-HR-01 · ✅ Type 3 FS-HR-01 · ✅ LDAP DC-01 · ✅ HR payroll access · ✅ same IP on 3 hosts · ❌ outbound RDP / WinRM / PsExec / remote proc · ⚠️ lsass access + persistence still to check in memory image
No-malware proof = Auth (IdP password proof, no VPN, never-RDP user) + Behaviour (03:23, HR doing AD admin enum) + Process (hands-on-keyboard hidden PS) + Network (DC + file server + new external host in 3 min) + File (3 payroll files in 4 s).

🚨 6) Containment
Isolate host (keep RAM) · kill RDP session + delete NAT rule · disable account, revoke tokens, reset password from clean device · verify MFA (number matching) · block both IPs · preserve RDP, PS, Sysmon, process tree, network evidence · review FS-HR-01 file access · hunt same user / IP / -Enc blob fleet-wide · save SIEM queries · forensic image · inform HR Head + Legal/DPO.

🧠 7) Senior SOC — B wins
A single "successful RDP" happens all day and says only that someone logged in. The chain (failures → success → privileges → PowerShell → internal access) adds identity, behavioural, process and network context, multiplies confidence and kills false positives — legit admin RDP doesn't chain into hidden encoded PowerShell + AD enum from a public IP. One event = something happened; a correlated chain = who, how, how far, how sure.

📦 Pack (18/18 tests, report PDF, Sigma, Wazuh, hunter, synthetic evidence):
https://github.com/Eswar5313/GraySentinel-DSOU-45Day-2026/tree/main/rdp-silent-login
📊 Live dashboard: https://eswar5313.github.io/GraySentinel-DSOU-45Day-2026/#rdp
