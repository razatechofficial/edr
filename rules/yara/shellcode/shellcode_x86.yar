rule Shellcode_x86_GetProcAddress_Resolution
{
    meta:
        description = "Detects x86 shellcode with GetProcAddress resolution via PEB walking"
        author = "EDR Research Team"
        date = "2025-01-15"
        reference = "https://attack.mitre.org/techniques/T1055/"
        severity = "high"
        mitre_attack = "T1055, T1106"

    strings:
        $peb_walk = { 64 8B 35 30 00 00 00 8B 76 0C 8B 76 1C 8B 46 08 }
        $peb_walk2 = { 64 A1 30 00 00 00 8B 40 0C 8B 40 1C 8B 00 8B 40 08 }
        $peb_walk3 = { 31 C0 64 8B 40 30 8B 40 0C 8B 70 14 AD 96 AD }
        $peb_walk4 = { 64 8B 52 30 8B 52 0C 8B 52 14 8B 72 28 0F B7 4A 26 31 FF }

        $hash_ror13 = { AC 3C 61 7C 02 2C 20 C1 CF 0D 01 C7 }
        $hash_ror13_2 = { 0F B6 0C 06 31 C9 AC C1 C1 05 01 C8 }

        $api_resolve = { 51 8B 52 20 8B 34 8A 01 D6 31 FF }
        $api_resolve2 = { 8B 34 8B 01 EE 31 FF AC C1 CF 0D 01 C7 }

    condition:
        1 of ($peb_walk*) and 1 of ($hash_ror13*) or
        1 of ($peb_walk*) and 1 of ($api_resolve*)
}

rule Shellcode_x86_Stack_Pivot
{
    meta:
        description = "Detects x86 shellcode with stack pivot patterns"
        author = "EDR Research Team"
        date = "2025-01-15"
        reference = "https://attack.mitre.org/techniques/T1055/"
        severity = "high"
        mitre_attack = "T1055"

    strings:
        $pivot1 = { 94 }
        $pivot2 = { 87 E4 }
        $pivot3 = { 8B E0 }
        $pivot4 = { 89 C4 }
        $pivot5 = { 81 C4 ?? ?? FF FF }
        $pivot6 = { 83 EC ?? 54 }

        $setup = { 60 89 E5 31 }
        $shellcode_start = { FC E8 }
        $cld_pushad = { FC 60 }

    condition:
        ($setup or $shellcode_start or $cld_pushad) and 2 of ($pivot*)
}

rule Shellcode_x86_Egg_Hunter
{
    meta:
        description = "Detects x86 egg hunter shellcode patterns"
        author = "EDR Research Team"
        date = "2025-01-15"
        reference = "https://www.hick.org/code/skape/papers/egghunt-shellcode.pdf"
        severity = "high"
        mitre_attack = "T1055"

    strings:
        $ntaccess = { 66 81 CA FF 0F 42 52 6A 02 58 CD 2E 3C 05 5A 74 EF B8 ?? ?? ?? ?? 8B FA AF 75 EA AF 75 E7 FF E7 }
        $seh_egg = { EB 21 59 B8 ?? ?? ?? ?? 51 6A FF 33 D2 64 89 22 6A 02 58 CD 2E 3C 05 5A 74 EF B8 ?? ?? ?? ?? 8B FA AF 75 EA AF 75 E7 FF E7 }
        $ntdisplay = { 66 81 CA FF 0F 42 52 31 C0 66 05 ?? 00 CD 2E 3C 05 5A 74 EF }
        $seh_hunt = { 31 D2 66 81 CA FF 0F 42 52 6A 43 58 CD 2E 3C 05 5A 74 }

    condition:
        any of them
}

rule Shellcode_x86_WinExec_Download
{
    meta:
        description = "Detects x86 download-and-execute shellcode patterns"
        author = "EDR Research Team"
        date = "2025-01-15"
        reference = "https://attack.mitre.org/techniques/T1059/"
        severity = "critical"
        mitre_attack = "T1059, T1105"

    strings:
        $winexec_hash = { E0 1D 2A 0A }
        $urlmon_hash = { 36 1A 2F 70 }
        $download_hash = { E2 FA 1B 01 }
        $loadlib_hash = { 07 26 77 4C }

        $call_pattern = { 68 ?? ?? ?? ?? FF D? }
        $push_url = { 68 68 74 74 70 }
        $get_temp = "GetTempPath" ascii
        $url_download = "URLDownloadToFile" ascii

    condition:
        (2 of ($winexec_hash, $urlmon_hash, $download_hash, $loadlib_hash) and $call_pattern) or
        ($push_url and ($winexec_hash or $url_download))
}
