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
If Not fso.FileExists(cfg) Then
  Dim stock
  stock = pf & "\EDR Agent\config.default.yml"
  If fso.FileExists(stock) Then
    fso.CopyFile stock, cfg, True
  ElseIf fso.FileExists(pd & "\EDR Agent\config.enterprise.yml") Then
    fso.CopyFile pd & "\EDR Agent\config.enterprise.yml", cfg, True
  End If
End If

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
    For n = 1 To 5
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

  ' Replace a leftover Everyone-deny DACL so Administrators and the console can start EDRAgent.
  rc = sh.Run("""" & sys & "\sc.exe"" sdset EDRAgent ""D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWRPLORC;;;IU)""", 0, True)
  Log "sc sdset exit=" & CStr(rc)
  sh.Run """" & sys & "\sc.exe"" start EDRAgent", 0, False
  Log "sc start requested"

  rc = sh.Run("""" & sys & "\sc.exe"" query EDRAgent", 0, True)
  Log "sc query exit=" & CStr(rc)
  If rc = 0 Then
    Log "OK EDRAgent registered"
  Else
    Log "FAIL EDRAgent missing after create (reboot if marked for deletion)"
  End If

  ' Launcher (edr-console) sets Mesa env then starts the original Fyne UI.
  Dim ui, prod, runCmd
  ui = pf & "\EDR Agent\edr-console.exe"
  If Not fso.FileExists(ui) Then
    ui = pf & "\EDR Agent\edr-agent-ui.exe"
  End If
  runCmd = """" & ui & """"
  prod = ""
  On Error Resume Next
  prod = sh.RegRead("HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductName")
  On Error Resume Next
  If InStr(1, LCase(CStr(prod)), "server", 1) = 0 Then
    runCmd = """" & ui & """ --tray"
  End If
  If fso.FileExists(ui) Then
    sh.RegWrite "HKLM\Software\Microsoft\Windows\CurrentVersion\Run\EDR Agent", runCmd, "REG_SZ"
    Log "HKLM Run set: " & runCmd
  End If
End If
