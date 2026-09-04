' Register EDRAgent with sc.exe (does not launch edr-agent.exe).
' MSI deferred VBScript has no WScript.Sleep — use ping for delays.
' Logs: %ProgramData%\EDR Agent\logs\msi_register.log
Option Explicit
On Error Resume Next
Dim sh, fso, sys, pf, pd, agent, cfg, logDir, logFile, binArg, rc, n
Set sh = CreateObject("WScript.Shell")
Set fso = CreateObject("Scripting.FileSystemObject")
sys = sh.ExpandEnvironmentStrings("%SystemRoot%\System32")
pf = sh.ExpandEnvironmentStrings("%ProgramFiles%")
pd = sh.ExpandEnvironmentStrings("%ProgramData%")
agent = pf & "\EDR Agent\edr-agent.exe"
cfg = pd & "\EDR Agent\config.yml"
logDir = pd & "\EDR Agent\logs"
If Not fso.FolderExists(pd & "\EDR Agent") Then fso.CreateFolder pd & "\EDR Agent"
If Not fso.FolderExists(logDir) Then fso.CreateFolder logDir
logFile = logDir & "\msi_register.log"

Sub Log(msg)
  Dim f
  Set f = fso.OpenTextFile(logFile, 8, True)
  If Not f Is Nothing Then
    f.WriteLine Now & " " & msg
    f.Close
  End If
End Sub

Sub Pause()
  sh.Run """" & sys & "\ping.exe"" -n 2 127.0.0.1", 0, True
End Sub

If Not fso.FileExists(agent) Then
  Log "FAIL agent missing: " & agent
Else
  binArg = """""""" & agent & """""" --config """""" & cfg & """"""""
  Log "register begin agent=" & agent

  rc = sh.Run("""" & sys & "\sc.exe"" config EDRAgent binPath= " & binArg & " start= auto DisplayName= ""EDR Agent""", 0, True)
  Log "sc config exit=" & CStr(rc)
  If rc <> 0 Then
    For n = 1 To 12
      rc = sh.Run("""" & sys & "\sc.exe"" create EDRAgent binPath= " & binArg & " start= auto DisplayName= ""EDR Agent""", 0, True)
      Log "sc create attempt " & CStr(n) & " exit=" & CStr(rc)
      If rc = 0 Then Exit For
      Pause
    Next
  End If

  sh.Run """" & sys & "\sc.exe"" description EDRAgent ""Endpoint Detection and Response Agent""", 0, True
  ' Uninstall may leave the service Disabled (StartService 1058); always re-enable.
  sh.Run """" & sys & "\sc.exe"" config EDRAgent start= auto", 0, True
  sh.RegWrite "HKLM\SYSTEM\CurrentControlSet\Services\EDRAgent\DelayedAutostart", 1, "REG_DWORD"

  rc = sh.Run("""" & sys & "\sc.exe"" query EDRAgent", 0, True)
  Log "sc query exit=" & CStr(rc)
  If rc = 0 Then
    Log "OK EDRAgent registered"
  Else
    Log "FAIL EDRAgent missing after create (reboot if marked for deletion)"
  End If
End If
