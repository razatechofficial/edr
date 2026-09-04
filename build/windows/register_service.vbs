' Register EDRAgent via WMI/sc without launching edr-agent.exe.
' Running the CGO sensor during MSI often fails (AV lock / DLL load); SCM
' Create only needs the on-disk path. Hardening still runs best-effort later.
Option Explicit
On Error Resume Next
Dim sh, fso, pf, pd, agent, cfg, path, wmi, svcClass, svc, rc, n
Set sh = CreateObject("WScript.Shell")
Set fso = CreateObject("Scripting.FileSystemObject")
pf = sh.ExpandEnvironmentStrings("%ProgramFiles%")
pd = sh.ExpandEnvironmentStrings("%ProgramData%")
agent = pf & "\EDR Agent\edr-agent.exe"
cfg = pd & "\EDR Agent\config.yml"
If Not fso.FileExists(agent) Then
  WScript.Quit 1
End If
If Not fso.FolderExists(pd & "\EDR Agent") Then
  fso.CreateFolder pd & "\EDR Agent"
End If
path = """" & agent & """ --config """ & cfg & """"

Set wmi = GetObject("winmgmts:\\.\root\cimv2")
Set svc = wmi.Get("Win32_Service.Name='EDRAgent'")
If Err.Number = 0 Then
  ' Already present: update path and Automatic start.
  rc = svc.Change(, , path, , , "Automatic")
  Err.Clear
Else
  Err.Clear
  Set svcClass = wmi.Get("Win32_Service")
  ' Name, DisplayName, PathName, ServiceType(own=16), ErrorControl(normal=1),
  ' StartMode, DesktopInteract, StartName (LocalSystem)
  rc = svcClass.Create("EDRAgent", "EDR Agent", path, 16, 1, "Automatic", False, "LocalSystem")
  If rc <> 0 And rc <> 22 Then
    ' 22 = service already exists. Retry open/update a few times for
    ' marked-for-delete races after upgrade.
    For n = 1 To 20
      WScript.Sleep 500
      Err.Clear
      Set svc = wmi.Get("Win32_Service.Name='EDRAgent'")
      If Err.Number = 0 Then
        rc = svc.Change(, , path, , , "Automatic")
        Exit For
      End If
      Err.Clear
      rc = svcClass.Create("EDRAgent", "EDR Agent", path, 16, 1, "Automatic", False, "LocalSystem")
      If rc = 0 Or rc = 22 Then Exit For
    Next
  End If
End If

' Delayed auto-start (matches Go installer).
sh.RegWrite "HKLM\SYSTEM\CurrentControlSet\Services\EDRAgent\DelayedAutostart", 1, "REG_DWORD"
sh.Run """" & sh.ExpandEnvironmentStrings("%SystemRoot%\System32") & "\sc.exe"" description EDRAgent ""Endpoint Detection and Response Agent""", 0, True
WScript.Quit 0
