' Hidden MSI helper: tear down EDRAgent before RemoveExistingProducts.
' Must run elevated (Impersonate=no on the WiX custom action).
Option Explicit
On Error Resume Next
Dim sh, sys, fso, agent, i, n
Set sh = CreateObject("WScript.Shell")
Set fso = CreateObject("Scripting.FileSystemObject")
sys = sh.ExpandEnvironmentStrings("%SystemRoot%\System32")
agent = sh.ExpandEnvironmentStrings("%ProgramFiles%") & "\EDR Agent\edr-agent.exe"
If fso.FileExists(agent) Then
  sh.Run """" & agent & """ --msi-stop", 0, True
End If
sh.Run """" & sys & "\sc.exe"" config EDRAgent start= disabled", 0, True
sh.Run """" & sys & "\sc.exe"" failure EDRAgent reset= 0 actions= //", 0, True
sh.Run """" & sys & "\sc.exe"" stop EDRAgent", 0, True
sh.Run """" & sys & "\taskkill.exe"" /F /IM edr-agent-ui.exe /T", 0, True
sh.Run """" & sys & "\taskkill.exe"" /F /IM edr-agent.exe /T", 0, True
For n = 1 To 8
  sh.Run """" & sys & "\sc.exe"" delete EDRAgent", 0, True
  sh.Run """" & sys & "\ping.exe"" -n 2 127.0.0.1", 0, True
Next
