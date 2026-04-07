rule Webshell_JSP_Generic
{
    meta:
        description = "Detects generic JSP web shells"
        author = "EDR Research Team"
        date = "2025-01-15"
        reference = "https://attack.mitre.org/techniques/T1505.003/"
        severity = "critical"
        mitre_attack = "T1505.003, T1059"

    strings:
        $jsp = "<%@" ascii nocase
        $jsp2 = "<%=" ascii
        $jsp3 = "<jsp:" ascii nocase

        $runtime1 = "Runtime.getRuntime()" ascii nocase
        $runtime2 = "Runtime.getRuntime().exec(" ascii nocase
        $runtime3 = "ProcessBuilder" ascii nocase
        $runtime4 = "getRuntime" ascii nocase

        $cmd1 = "cmd.exe" ascii wide nocase
        $cmd2 = "/bin/sh" ascii
        $cmd3 = "/bin/bash" ascii

        $input1 = "request.getParameter" ascii nocase
        $input2 = "request.getInputStream" ascii nocase

        $output1 = "getInputStream()" ascii nocase
        $output2 = "BufferedReader" ascii nocase
        $output3 = "InputStreamReader" ascii nocase

    condition:
        (1 of ($jsp*)) and
        1 of ($runtime*) and
        (1 of ($cmd*) or 1 of ($input*)) and
        1 of ($output*)
}

rule Webshell_JSP_Chopper
{
    meta:
        description = "Detects JSP variant of China Chopper web shell"
        author = "EDR Research Team"
        date = "2025-01-15"
        reference = "https://attack.mitre.org/software/S0020/"
        severity = "critical"
        mitre_attack = "T1505.003"

    strings:
        $chopper1 = "Runtime.getRuntime().exec(request.getParameter(" ascii nocase
        $chopper2 = /Runtime\.getRuntime\(\)\.exec\(\s*request\.getParameter\(\"[a-z]{1,5}\"\)\s*\)/ nocase
        $chopper3 = "defineClass" ascii nocase
        $chopper4 = "ClassLoader" ascii nocase
        $chopper5 = "base64Decode" ascii nocase

        $jsp_tag = "<%" ascii

        $minimal = /<%\s*(if\s*\()?request\.getParameter.{0,30}Runtime/ nocase

    condition:
        $jsp_tag and
        (1 of ($chopper1, $chopper2, $minimal) or
         ($chopper3 and $chopper4 and $chopper5))
}

rule Webshell_JSP_Upload_Exec
{
    meta:
        description = "Detects JSP web shells with file upload and execution capabilities"
        author = "EDR Research Team"
        date = "2025-01-15"
        reference = "https://attack.mitre.org/techniques/T1505.003/"
        severity = "high"
        mitre_attack = "T1505.003, T1105"

    strings:
        $jsp_tag = "<%" ascii
        $upload1 = "FileOutputStream" ascii nocase
        $upload2 = "MultipartRequest" ascii nocase
        $upload3 = "FileItem" ascii nocase
        $upload4 = "transferTo" ascii nocase

        $exec1 = "Runtime.getRuntime().exec" ascii nocase
        $exec2 = "ProcessBuilder" ascii nocase
        $exec3 = "ScriptEngineManager" ascii nocase

        $write1 = "FileWriter" ascii nocase
        $write2 = "BufferedWriter" ascii nocase

    condition:
        $jsp_tag and
        (1 of ($upload*) and 1 of ($exec*)) or
        (1 of ($upload*) and 1 of ($write*) and 1 of ($exec*))
}
