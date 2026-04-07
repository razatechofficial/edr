rule Webshell_Generic_Eval_With_Input
{
    meta:
        description = "Detects generic web shell patterns: eval/exec with HTTP parameter input"
        author = "EDR Research Team"
        date = "2025-01-15"
        reference = "https://attack.mitre.org/techniques/T1505.003/"
        severity = "high"
        mitre_attack = "T1505.003"

    strings:
        $eval1 = "eval(" ascii nocase
        $eval2 = "exec(" ascii nocase
        $eval3 = "system(" ascii nocase
        $eval4 = "passthru(" ascii nocase
        $eval5 = "shell_exec(" ascii nocase
        $eval6 = "Execute(" ascii nocase
        $eval7 = "Runtime.getRuntime().exec(" ascii nocase
        $eval8 = "Process.Start(" ascii nocase
        $eval9 = "os.system(" ascii nocase
        $eval10 = "subprocess.call(" ascii nocase
        $eval11 = "subprocess.Popen(" ascii nocase

        $input1 = "$_POST" ascii nocase
        $input2 = "$_GET" ascii nocase
        $input3 = "$_REQUEST" ascii nocase
        $input4 = "request.getParameter" ascii nocase
        $input5 = "Request.Form" ascii nocase
        $input6 = "Request.QueryString" ascii nocase
        $input7 = "request.form" ascii nocase
        $input8 = "request.args" ascii nocase

    condition:
        1 of ($eval*) and 1 of ($input*) and filesize < 500KB
}

rule Webshell_Generic_System_Commands
{
    meta:
        description = "Detects web shell patterns with system command execution"
        author = "EDR Research Team"
        date = "2025-01-15"
        reference = "https://attack.mitre.org/techniques/T1505.003/"
        severity = "high"
        mitre_attack = "T1505.003, T1059"

    strings:
        $cmd1 = "uname -a" ascii nocase
        $cmd2 = "cat /etc/passwd" ascii nocase
        $cmd3 = "id" ascii nocase
        $cmd4 = "whoami" ascii nocase
        $cmd5 = "ifconfig" ascii nocase
        $cmd6 = "netstat -an" ascii nocase
        $cmd7 = "net user" ascii nocase
        $cmd8 = "ipconfig" ascii nocase
        $cmd9 = "systeminfo" ascii nocase
        $cmd10 = "cat /etc/shadow" ascii nocase

        $web_lang1 = "<?php" ascii nocase
        $web_lang2 = "<%@" ascii nocase
        $web_lang3 = "<script" ascii nocase
        $web_lang4 = "import os" ascii

        $exec1 = "exec" ascii nocase
        $exec2 = "system" ascii nocase
        $exec3 = "popen" ascii nocase

    condition:
        1 of ($web_lang*) and 3 of ($cmd*) and 1 of ($exec*)
}
