' Full ARP uninstall cleanup (enterprise): kill tray/sensor, drop Run key,
' delete service, wipe ProgramData identity/queue/logs, remove firewall rule.
' MSI RemoveFiles still removes component-tracked Program Files / configs.
' Do NOT set start=disabled before delete — if sc delete fails (handle open),
' the next install would inherit Disabled and StartService returns 1058.
Option Explicit
On Error Resume Next
Dim sh, sys, fso, pd, agent, n, wsh
Set sh = CreateObject("WScript.Shell")
Set fso = CreateObject("Scripting.FileSystemObject")
sys = sh.ExpandEnvironmentStrings("%SystemRoot%\System32")
pd = sh.ExpandEnvironmentStrings("%ProgramData%")
agent = sh.ExpandEnvironmentStrings("%ProgramFiles%") & "\EDR Agent\edr-agent.exe"

If fso.FileExists(agent) Then
  sh.Run """" & agent & """ --msi-stop", 0, True
End If
sh.Run """" & sys & "\sc.exe"" stop EDRAgent", 0, True
sh.Run """" & sys & "\taskkill.exe"" /F /IM edr-agent-ui.exe /T", 0, True
sh.Run """" & sys & "\taskkill.exe"" /F /IM edr-agent.exe /T", 0, True
For n = 1 To 6
  sh.Run """" & sys & "\sc.exe"" delete EDRAgent", 0, True
  sh.Run """" & sys & "\ping.exe"" -n 2 127.0.0.1", 0, True
Next

' HKLM Run tray autostart (left behind when only MSI RemoveFiles ran)
sh.RegDelete "HKLM\Software\Microsoft\Windows\CurrentVersion\Run\EDR Agent"

' Runtime data not authored as MSI KeyPath files
If fso.FolderExists(pd & "\EDR Agent\xdr-tls") Then fso.DeleteFolder pd & "\EDR Agent\xdr-tls", True
If fso.FolderExists(pd & "\EDR Agent\telemetry-queue") Then fso.DeleteFolder pd & "\EDR Agent\telemetry-queue", True
If fso.FolderExists(pd & "\EDR Agent\alert-spool") Then fso.DeleteFolder pd & "\EDR Agent\alert-spool", True
If fso.FolderExists(pd & "\EDR Agent\forensics") Then fso.DeleteFolder pd & "\EDR Agent\forensics", True
If fso.FolderExists(pd & "\EDR Agent\quarantine") Then fso.DeleteFolder pd & "\EDR Agent\quarantine", True
If fso.FolderExists(pd & "\EDR Agent\logs") Then fso.DeleteFolder pd & "\EDR Agent\logs", True
If fso.FolderExists(pd & "\EDR Agent\alerts") Then fso.DeleteFolder pd & "\EDR Agent\alerts", True
If fso.FolderExists(pd & "\EDR\setup") Then fso.DeleteFolder pd & "\EDR\setup", True
If fso.FolderExists(pd & "\EDR") Then fso.DeleteFolder pd & "\EDR", True
If fso.FileExists(pd & "\EDR Agent\enrollment.json") Then fso.DeleteFile pd & "\EDR Agent\enrollment.json", True
If fso.FileExists(pd & "\EDR Agent\agent_id") Then fso.DeleteFile pd & "\EDR Agent\agent_id", True
If fso.FileExists(pd & "\EDR Agent\enrollment.token") Then fso.DeleteFile pd & "\EDR Agent\enrollment.token", True

sh.Run """" & sys & "\netsh.exe"" advfirewall firewall delete rule name=""EDR Agent""", 0, True
