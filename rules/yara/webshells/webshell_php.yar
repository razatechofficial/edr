rule Webshell_PHP_C99
{
    meta:
        description = "Detects C99 PHP web shell"
        author = "EDR Research Team"
        date = "2025-01-15"
        reference = "https://attack.mitre.org/techniques/T1505.003/"
        severity = "critical"
        mitre_attack = "T1505.003, T1059.004"

    strings:
        $php = "<?php" ascii nocase
        $c99_1 = "c99shell" ascii nocase
        $c99_2 = "c99madshell" ascii nocase
        $c99_3 = "c99_sess_put" ascii nocase
        $c99_4 = "c99ftpbrutecheck" ascii nocase
        $c99_5 = "c99sh_sqlquery" ascii nocase
        $c99_6 = "c99sh_filesman" ascii nocase
        $c99_7 = "c99sh_backconn" ascii nocase

    condition:
        $php and 2 of ($c99_*)
}

rule Webshell_PHP_R57
{
    meta:
        description = "Detects R57 PHP web shell"
        author = "EDR Research Team"
        date = "2025-01-15"
        reference = "https://attack.mitre.org/techniques/T1505.003/"
        severity = "critical"
        mitre_attack = "T1505.003"

    strings:
        $php = "<?php" ascii nocase
        $r57_1 = "r57shell" ascii nocase
        $r57_2 = "r57_logo" ascii nocase
        $r57_3 = "r57_language" ascii nocase
        $r57_4 = "uname -a" ascii
        $r57_5 = "safe_mode" ascii
        $r57_6 = "open_basedir" ascii
        $r57_7 = "mysql_connect" ascii
        $r57_8 = "passthru" ascii

    condition:
        $php and (1 of ($r57_1, $r57_2, $r57_3) or (4 of ($r57_*)))
}

rule Webshell_PHP_B374K
{
    meta:
        description = "Detects B374K PHP web shell"
        author = "EDR Research Team"
        date = "2025-01-15"
        reference = "https://attack.mitre.org/techniques/T1505.003/"
        severity = "critical"
        mitre_attack = "T1505.003"

    strings:
        $php = "<?php" ascii nocase
        $b374k_1 = "b374k" ascii nocase
        $b374k_2 = "b374k shell" ascii nocase
        $b374k_3 = "$s_pass" ascii
        $b374k_4 = "eval(gzinflate(base64_decode" ascii nocase
        $b374k_5 = "preg_replace" ascii
        $b374k_6 = "$_POST['pass']" ascii

    condition:
        $php and (1 of ($b374k_1, $b374k_2) or ($b374k_4 and 1 of ($b374k_3, $b374k_5, $b374k_6)))
}

rule Webshell_PHP_WSO
{
    meta:
        description = "Detects WSO (Web Shell by Orb) PHP web shell"
        author = "EDR Research Team"
        date = "2025-01-15"
        reference = "https://attack.mitre.org/techniques/T1505.003/"
        severity = "critical"
        mitre_attack = "T1505.003"

    strings:
        $php = "<?php" ascii nocase
        $wso1 = "WSO " ascii nocase
        $wso2 = "Web Shell by" ascii nocase
        $wso3 = "wso_version" ascii nocase
        $wso4 = "FilesTools" ascii nocase
        $wso5 = "StringTools" ascii nocase
        $wso6 = "BruteForce" ascii nocase
        $wso7 = "Databases" ascii nocase
        $wso8 = "backdoor" ascii nocase

        $func1 = "shell_exec" ascii nocase
        $func2 = "passthru" ascii nocase
        $func3 = "proc_open" ascii nocase

    condition:
        $php and (2 of ($wso*) or (1 of ($wso*) and 2 of ($func*)))
}

rule Webshell_PHP_ChinaChopper
{
    meta:
        description = "Detects China Chopper PHP web shell (one-liner variant)"
        author = "EDR Research Team"
        date = "2025-01-15"
        reference = "https://attack.mitre.org/software/S0020/"
        severity = "critical"
        mitre_attack = "T1505.003, T1059.004"

    strings:
        $php = "<?php" ascii nocase
        $chopper1 = "eval($_POST[" ascii nocase
        $chopper2 = "assert($_POST[" ascii nocase
        $chopper3 = "eval($_REQUEST[" ascii nocase
        $chopper4 = "assert($_REQUEST[" ascii nocase
        $chopper5 = "@eval(base64_decode($_POST[" ascii nocase
        $chopper6 = "@eval(base64_decode($_REQUEST[" ascii nocase

        $oneliner = /\<\?php\s+@?(eval|assert)\s*\(\s*\$_(POST|GET|REQUEST|COOKIE)\s*\[/ nocase

    condition:
        $php and (1 of ($chopper*) or $oneliner)
}

rule Webshell_PHP_Generic_Functions
{
    meta:
        description = "Detects generic PHP web shells via dangerous function combinations"
        author = "EDR Research Team"
        date = "2025-01-15"
        reference = "https://attack.mitre.org/techniques/T1505.003/"
        severity = "high"
        mitre_attack = "T1505.003"

    strings:
        $php = "<?php" ascii nocase

        $exec1 = "system(" ascii nocase
        $exec2 = "exec(" ascii nocase
        $exec3 = "shell_exec(" ascii nocase
        $exec4 = "passthru(" ascii nocase
        $exec5 = "popen(" ascii nocase
        $exec6 = "proc_open(" ascii nocase
        $exec7 = "pcntl_exec(" ascii nocase

        $eval1 = "eval(" ascii nocase
        $eval2 = "assert(" ascii nocase
        $eval3 = "preg_replace" ascii nocase
        $eval4 = "create_function(" ascii nocase
        $eval5 = "call_user_func(" ascii nocase

        $input1 = "$_POST" ascii nocase
        $input2 = "$_GET" ascii nocase
        $input3 = "$_REQUEST" ascii nocase
        $input4 = "$_COOKIE" ascii nocase
        $input5 = "php://input" ascii nocase

    condition:
        $php and
        1 of ($exec*) and
        1 of ($eval*) and
        1 of ($input*)
}
