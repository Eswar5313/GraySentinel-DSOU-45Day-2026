# Day 2 Analyst Report — macOS Cryptominer Kill-Chain
**Eswar Mahalingam · GS-STU-DSOU-2026-039A · GraySentinel DSOU** · Case GS-DAY2-2026 · Host `mac-victim-07`

## 1. Executive summary
A macro-enabled document (`invoice_Q3.docm`) delivered by email auto-executed on open, pivoted through
`osascript` to a shell, pulled a second-stage binary from `198.51.100.44`, launched an XMRig-style miner
(`/tmp/.u`) beaconing to `203.0.113.9:8443`, and installed a LaunchDaemon masquerading as
`com.apple.softwareupdated.helper` for reboot persistence. CPU pinned at 98%. **Priority: P1.**

## 2. Kill chain (Lockheed-Martin ↔ ATT&CK)
| Stage | What happened | ATT&CK |
|---|---|---|
| Delivery | Phishing email, macro-enabled attachment | T1566.001 |
| Execution | User opens doc → `AutoOpen`/`Document_Open` fires | T1204.002 |
| Execution | VBA → `osascript` `do shell script` | T1059.002 |
| C2 stage-1 | `curl` pulls `/assets/update.bin` from 198.51.100.44 | T1105 |
| Execution | `sh` `chmod +x` and runs `/tmp/.u --pool …` | T1059.004 |
| Impact | XMRig-style CPU hijack (98% sustained) | T1496 |
| Persistence | LaunchDaemon `com.apple.softwareupdated.helper.plist` | T1543.001 |
| C2 | HTTPS beacon to 203.0.113.9:8443/gate every ~5 min | T1071.001 |

## 3. How the tools produced this
- **Tool A (macro_analyzer.py)** parsed the extracted VBA and fired 16 rules incl. 3 CRITICAL
  (encoded PowerShell T1059.001, download cradle T1105, LaunchDaemon T1543.001). Verdict MALICIOUS,
  exit code 2 — this alone gates the doc as unsafe in CI.
- **Tool B (killchain_reconstructor.py)** ingested those findings + 12 EDR rows, ordered them into a
  timeline, extracted IOCs (2 C2 IPs, 1 dropped binary, 1 persistence plist, file hashes), mapped the
  ATT&CK matrix, and scored **P1** (CRITICAL macro + persistence + live C2 all present).

## 4. Indicators of Compromise
| Type | Value |
|---|---|
| C2 / stage-1 | `198.51.100.44:80` |
| C2 / miner pool | `203.0.113.9:8443` |
| Dropped file | `/tmp/.u` |
| Persistence | `/Library/LaunchDaemons/com.apple.softwareupdated.helper.plist` |
| Masquerade | service name `com.apple.softwareupdated.helper` |

## 5. Containment & eradication (executed order)
1. Network-isolate `mac-victim-07`.
2. `sudo launchctl bootout system/com.apple.softwareupdated.helper`
3. `sudo rm /Library/LaunchDaemons/com.apple.softwareupdated.helper.plist`
4. `sudo rm -f /tmp/.u`
5. Block `198.51.100.44` and `203.0.113.9:8443` at proxy/firewall.
6. Pull the phishing mail + attachment; hunt the doc hash across mail flow.
7. Fleet-sweep the plist name + `/tmp/.u` on all macOS endpoints.
8. Rotate host credentials; preserve logs; reimage before return to service.

## 6. Detection value / lessons
- The **auto-exec + osascript + download cradle** trio is the highest-fidelity early signal — catchable
  at the macro layer before any binary lands. Gate macro docs on Tool A's exit code.
- The **Apple-service masquerade** (T1036.005) is why the plist survived a casual look; hunt by
  *content/path pattern*, not by trusting the display name.
- Miner impact (sustained CPU) is a *lagging* signal; persistence + C2 are the ones that matter for scope.

*All data synthetic and declared. Inert fixture — no live payload. Detection-only tooling.*
