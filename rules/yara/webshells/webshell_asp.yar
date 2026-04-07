rule Webshell_ASP_Generic
{
    meta:
        description = "Detects generic ASP/ASPX web shells"
        author = "EDR Research Team"
        date = "2025-01-15"
        reference = "https://attack.mitre.org/techniques/T1505.003/"
        severity = "critical"
        mitre_attack = "T1505.003"

    strings:
        $asp1 = "<%@ " ascii nocase
        $asp2 = "<script language" ascii nocase
        $asp3 = "<%@Page" ascii nocase
        $aspx1 = "System.Diagnostics.Process" ascii wide nocase
        $aspx2 = "System.IO" ascii wide nocase

        $exec1 = "wscript.shell" ascii nocase
        $exec2 = "cmd.exe" ascii nocase
        $exec3 = "Process.Start" ascii nocase
        $exec4 = "ProcessStartInfo" ascii nocase
        $exec5 = "CreateObject" ascii nocase
        $exec6 = "Scripting.FileSystemObject" ascii nocase

        $eval1 = "eval(" ascii nocase
        $eval2 = "Execute(" ascii nocase
        $eval3 = "ExecuteGlobal(" ascii nocase
        $eval4 = "Eval(Request" ascii nocase

        $input1 = "Request(" ascii nocase
        $input2 = "Request.Form" ascii nocase
        $input3 = "Request.QueryString" ascii nocase
        $input4 = "Request.Item" ascii nocase

    condition:
        (1 of ($asp*)) and
        (1 of ($exec*) or 1 of ($eval*)) and
        1 of ($input*)
}

rule Webshell_ASPX_Cmd
{
    meta:
        description = "Detects ASPX command execution web shells"
        author = "EDR Research Team"
        date = "2025-01-15"
        reference = "https://attack.mitre.org/techniques/T1505.003/"
        severity = "critical"
        mitre_attack = "T1505.003, T1059"

    strings:
        $aspx = "<%@ Page" ascii nocase
        $import1 = "System.Diagnostics" ascii wide nocase
        $import2 = "System.Runtime.InteropServices" ascii wide nocase

        $process1 = "Process.Start" ascii nocase
        $process2 = "ProcessStartInfo" ascii nocase
        $process3 = "RedirectStandardOutput" ascii nocase
        $process4 = "StandardOutput.ReadToEnd" ascii nocase

        $cmd1 = "cmd.exe /c" ascii wide nocase
        $cmd2 = "/bin/bash" ascii wide
        $cmd3 = "powershell" ascii wide nocase

    condition:
        $aspx and
        $import1 and
        (2 of ($process*)) and
        1 of ($cmd*)
}

rule Webshell_ASP_CmdShell
{
    meta:
        description = "Detects classic ASP command shell web shells"
        author = "EDR Research Team"
        date = "2025-01-15"
        reference = "https://attack.mitre.org/techniques/T1505.003/"
        severity = "critical"
        mitre_attack = "T1505.003"

    strings:
        $asp_tag = "<%" ascii
        $shell1 = "Set oS = Server.CreateObject(\"WSCRIPT.SHELL\")" ascii nocase
        $shell2 = "oS.Exec(\"cmd /c \" &" ascii nocase
        $shell3 = "CreateObject(\"WScript.Shell\")" ascii nocase
        $shell4 = ".exec(" ascii nocase
        $shell5 = ".Run(" ascii nocase
        $request = "Request(" ascii nocase
        $response = "Response.Write" ascii nocase

    condition:
        $asp_tag and
        (1 of ($shell1, $shell2, $shell3)) or
        ($asp_tag and 1 of ($shell4, $shell5) and $request and $response)
}
