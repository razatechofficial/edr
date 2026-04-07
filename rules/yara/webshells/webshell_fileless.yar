rule Webshell_Fileless_Memory_Resident
{
    meta:
        description = "Detects memory-resident/fileless web shell patterns"
        author = "EDR Research Team"
        date = "2025-01-15"
        reference = "https://attack.mitre.org/techniques/T1505.003/"
        severity = "critical"
        mitre_attack = "T1505.003, T1620"

    strings:
        $php = "<?php" ascii nocase

        $stream1 = "php://input" ascii nocase
        $stream2 = "php://filter" ascii nocase
        $stream3 = "data://text/plain" ascii nocase
        $stream4 = "expect://" ascii nocase
        $stream5 = "php://memory" ascii nocase
        $stream6 = "php://temp" ascii nocase

        $eval1 = "eval(" ascii nocase
        $eval2 = "assert(" ascii nocase
        $eval3 = "preg_replace" ascii nocase

        $file_get = "file_get_contents(\"php://input\")" ascii nocase
        $filter = /php:\/\/filter\/convert\.base64-(encode|decode)\/resource=/ nocase

    condition:
        $php and
        (1 of ($stream*) and 1 of ($eval*)) or
        $file_get or $filter
}

rule Webshell_ASPX_Memory_Only
{
    meta:
        description = "Detects ASPX memory-only web shell patterns (no file on disk)"
        author = "EDR Research Team"
        date = "2025-01-15"
        reference = "https://attack.mitre.org/techniques/T1505.003/"
        severity = "critical"
        mitre_attack = "T1505.003, T1620"

    strings:
        $aspx = "<%@" ascii nocase
        $page = "Page" ascii nocase

        $reflection1 = "System.Reflection" ascii wide nocase
        $reflection2 = "Assembly.Load(" ascii wide nocase
        $reflection3 = "Activator.CreateInstance" ascii wide nocase

        $compile1 = "CSharpCodeProvider" ascii wide nocase
        $compile2 = "CompileAssemblyFromSource" ascii wide nocase
        $compile3 = "GenerateInMemory" ascii wide nocase

        $byte_array = /new\s+byte\[\]\s*\{(\s*0x[0-9a-fA-F]{1,2}\s*,?\s*){20,}/ ascii nocase

    condition:
        $aspx and
        (2 of ($reflection*) or (2 of ($compile*)) or
         ($byte_array and 1 of ($reflection*)))
}
