rule Webshell_Backdoor_Authentication
{
    meta:
        description = "Detects web shell backdoors with authentication/password mechanisms"
        author = "EDR Research Team"
        date = "2025-01-15"
        reference = "https://attack.mitre.org/techniques/T1505.003/"
        severity = "critical"
        mitre_attack = "T1505.003, T1078"

    strings:
        $php = "<?php" ascii nocase

        $auth1 = "md5($_POST[" ascii nocase
        $auth2 = "md5($_GET[" ascii nocase
        $auth3 = "md5($_COOKIE[" ascii nocase
        $auth4 = "sha1($_POST[" ascii nocase
        $auth5 = "$password" ascii nocase
        $auth6 = "$pass" ascii nocase
        $auth7 = "md5($pass)" ascii nocase

        $exec1 = "eval(" ascii nocase
        $exec2 = "system(" ascii nocase
        $exec3 = "exec(" ascii nocase
        $exec4 = "shell_exec(" ascii nocase
        $exec5 = "passthru(" ascii nocase

        $session1 = "session_start()" ascii nocase
        $session2 = "$_SESSION[" ascii nocase

    condition:
        $php and
        1 of ($auth*) and
        1 of ($exec*) and
        filesize < 100KB
}

rule Webshell_Backdoor_File_Manager
{
    meta:
        description = "Detects web shell backdoor with file manager capabilities"
        author = "EDR Research Team"
        date = "2025-01-15"
        reference = "https://attack.mitre.org/techniques/T1505.003/"
        severity = "high"
        mitre_attack = "T1505.003, T1083"

    strings:
        $php = "<?php" ascii nocase

        $fm1 = "scandir(" ascii nocase
        $fm2 = "opendir(" ascii nocase
        $fm3 = "readdir(" ascii nocase
        $fm4 = "file_get_contents(" ascii nocase
        $fm5 = "file_put_contents(" ascii nocase
        $fm6 = "fopen(" ascii nocase
        $fm7 = "fwrite(" ascii nocase
        $fm8 = "unlink(" ascii nocase
        $fm9 = "rename(" ascii nocase
        $fm10 = "mkdir(" ascii nocase
        $fm11 = "rmdir(" ascii nocase
        $fm12 = "chmod(" ascii nocase
        $fm13 = "copy(" ascii nocase

        $exec1 = "exec(" ascii nocase
        $exec2 = "system(" ascii nocase
        $exec3 = "shell_exec(" ascii nocase

        $input1 = "$_POST" ascii nocase
        $input2 = "$_GET" ascii nocase

    condition:
        $php and
        5 of ($fm*) and
        1 of ($exec*) and
        1 of ($input*)
}

rule Webshell_Backdoor_Reverse_Shell
{
    meta:
        description = "Detects web-based reverse shell backdoor"
        author = "EDR Research Team"
        date = "2025-01-15"
        reference = "https://attack.mitre.org/techniques/T1505.003/"
        severity = "critical"
        mitre_attack = "T1505.003, T1059"

    strings:
        $php = "<?php" ascii nocase

        $sock1 = "fsockopen(" ascii nocase
        $sock2 = "socket_create(" ascii nocase
        $sock3 = "stream_socket_client(" ascii nocase
        $sock4 = "pfsockopen(" ascii nocase

        $exec1 = "exec(" ascii nocase
        $exec2 = "shell_exec(" ascii nocase
        $exec3 = "proc_open(" ascii nocase
        $exec4 = "/bin/sh" ascii
        $exec5 = "/bin/bash" ascii
        $exec6 = "cmd.exe" ascii wide nocase

        $connect = /\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/ ascii
        $port = /[0-9]{4,5}/ ascii

    condition:
        $php and
        1 of ($sock*) and
        2 of ($exec*) and
        filesize < 50KB
}
