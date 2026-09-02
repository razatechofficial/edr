' Hidden MSI helper: stop leftover EDRAgent without a console.
' taskkill of a missing process is ignored (On Error Resume Next).
Option Explicit
On Error Resume Next
Dim sh, sys
Set sh = CreateObject("WScript.Shell")
sys = sh.ExpandEnvironmentStrings("%SystemRoot%\System32")
sh.Run """" & sys & "\sc.exe"" config EDRAgent start= demand", 0, True
sh.Run """" & sys & "\sc.exe"" failure EDRAgent reset= 0 actions= //", 0, True
sh.Run """" & sys & "\taskkill.exe"" /F /IM edr-agent-ui.exe /T", 0, True
sh.Run """" & sys & "\taskkill.exe"" /F /IM edr-agent.exe /T", 0, True
