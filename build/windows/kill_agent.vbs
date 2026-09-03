' Hidden MSI helper: stop EDR processes before upgrade/install.
' Do NOT sc delete here — that races CreateService (marked for deletion)
' and leaves "EDRAgent service registered" red after MSI. --install updates
' an existing service entry; uninstall uses msi_purge.vbs for sc delete.
Option Explicit
On Error Resume Next
Dim sh, sys, fso, agent
Set sh = CreateObject("WScript.Shell")
Set fso = CreateObject("Scripting.FileSystemObject")
sys = sh.ExpandEnvironmentStrings("%SystemRoot%\System32")
agent = sh.ExpandEnvironmentStrings("%ProgramFiles%") & "\EDR Agent\edr-agent.exe"
If fso.FileExists(agent) Then
  sh.Run """" & agent & """ --msi-stop", 0, True
End If
sh.Run """" & sys & "\sc.exe"" stop EDRAgent", 0, True
sh.Run """" & sys & "\taskkill.exe"" /F /IM edr-agent-ui.exe /T", 0, True
sh.Run """" & sys & "\taskkill.exe"" /F /IM edr-agent.exe /T", 0, True
sh.Run """" & sys & "\ping.exe"" -n 2 127.0.0.1", 0, True
