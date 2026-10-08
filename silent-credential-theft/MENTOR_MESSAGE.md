🟢 SOC War Room submission — Silent Credential Theft (FIN-WS-117, LSASS → authentication) · Eswar (Cand. 13)

🎯 Not a false positive. An unsigned binary spawned by Word read LSASS memory; 4.5 min later a privileged account that never uses this desk logged on to FILE-SRV-03 with explicit credentials and read 14 payroll files; 10 min later it was on a second workstation. The user's session was used, not her hands.

🔍 1) Triage: f.rao on FIN-WS-117 (10.20.31.117) · WINWORD.EXE → %TEMP%\dbgsvc.exe · unsigned, hash first-seen · Sysmon 10 GrantedAccess 0x1010 (VM_READ) at 09:40:20 IST · EDR credential-access alert. 27 of 28 LSASS accesses in 30 days are Defender/EDR agent (expected) — exactly one is not.

🧠 2) Hypotheses
H1 credential access → SUPPORTED (unapproved image, unsigned, user-writable path, VM_READ mask, Office parent, EDR alert)
H2 legitimate admin → REJECTED (no ticket, source is not the PAW, admin tools are not launched by Word; the real admin logon from PAW with CHG-4471 is scored LEGITIMATE)
H3 credential abuse → SUPPORTED (4648 for adm.kiran, 2 new destinations, Finance$ reads, peer workstation, 4 RC4 service tickets, 6 failures first)

🔎 3) Timeline (IST): 09:32 logon → 09:40:05 process → 09:40:20 LSASS access → 09:42:30 six 4625 → 09:44:50 f.rao Type 3 NTLM to FILE-SRV-03 → 09:45:20 4648 → 09:45:25 adm.kiran Type 3 + 4672 → 09:45:40 4769 ×4 (RC4) → 09:47 Finance$\Payroll ×14 → 09:50:25 adm.kiran on FIN-WS-121.

🛡️ 4) Detection — Suspicious LSASS Process Access: Sysmon 10 + TargetImage lsass.exe + memory-read mask + source NOT on a signed-PATH allow-list → HIGH; CRITICAL if 4648 for an admin or Type 3 to a file server follows from the same host in 15 min. Never fires because lsass.exe exists; a fake "MsMpEng.exe" in %TEMP% still fires. Sigma (4 rules + ordered correlation) + Wazuh 100840–100848 + Python reference.

🧬 5) Lateral hunt — investigate in this order: FIN-WS-117 → DC-01 (all tickets for f.rao/adm.kiran/svc.finbackup) → FILE-SRV-03 → FIN-WS-121 → SQL-FIN-01 + FILE-SRV-02 (tickets requested) → every host adm.kiran touched in 30 days. Lateral vs admin = source host, ticket, auth package, what preceded, what followed.

🚨 6) Containment: isolate (do not power off), preserve memory + Sysmon/EDR + DC + file-server logs, quarantine a copy of the binary and the Word doc, disable + reset adm.kiran (kill sessions first), review svc.finbackup, rotate service accounts behind the RC4 SPNs, inform Finance owner. NO reimage until we can answer: how it started, which process, which account, where it authenticated next.

🧠 7) + Senior — B wins. Each event alone has an innocent explanation and high daily volume. Joined on host + account + time they become one causal story: access → authentication → server → files. The account hand-off (f.rao → adm.kiran) and the lineage (Word → binary → LSASS → 4648 by the same binary) exist only in correlation. Tool scores A alone 1/4 MEDIUM, the chain 4/4 CRITICAL.

📦 Pack (20/20 tests, report PDF, Sigma, Wazuh, hunter, synthetic evidence):
https://github.com/Eswar5313/GraySentinel-DSOU-45Day-2026/tree/main/silent-credential-theft
📊 Dashboard: https://eswar5313.github.io/GraySentinel-DSOU-45Day-2026/#silentcred
