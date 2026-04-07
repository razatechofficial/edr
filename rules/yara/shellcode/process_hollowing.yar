import "pe"

rule Shellcode_Process_Hollowing
{
    meta:
        description = "Detects process hollowing (RunPE) injection patterns"
        author = "EDR Research Team"
        date = "2025-01-15"
        reference = "https://attack.mitre.org/techniques/T1055.012/"
        severity = "critical"
        mitre_attack = "T1055.012"

    strings:
        $create_suspended = { 6A 04 }
        $api1 = "CreateProcessA" ascii
        $api1w = "CreateProcessW" ascii
        $api2 = "NtUnmapViewOfSection" ascii
        $api3 = "ZwUnmapViewOfSection" ascii
        $api4 = "VirtualAllocEx" ascii
        $api5 = "WriteProcessMemory" ascii
        $api6 = "SetThreadContext" ascii
        $api7 = "ResumeThread" ascii
        $api8 = "GetThreadContext" ascii
        $api9 = "NtResumeThread" ascii
        $api10 = "NtSetContextThread" ascii
        $api11 = "NtGetContextThread" ascii

        $target1 = "svchost.exe" ascii wide nocase
        $target2 = "explorer.exe" ascii wide nocase
        $target3 = "rundll32.exe" ascii wide nocase
        $target4 = "notepad.exe" ascii wide nocase
        $target5 = "RegAsm.exe" ascii wide nocase

    condition:
        uint16(0) == 0x5A4D and
        (1 of ($api1, $api1w)) and
        (1 of ($api2, $api3)) and
        $api4 and $api5 and
        (1 of ($api6, $api10)) and
        (1 of ($api7, $api9))
}

rule Shellcode_Process_Hollowing_NtAPI
{
    meta:
        description = "Detects process hollowing using NT API calls"
        author = "EDR Research Team"
        date = "2025-01-15"
        reference = "https://attack.mitre.org/techniques/T1055.012/"
        severity = "critical"
        mitre_attack = "T1055.012"

    strings:
        $nt1 = "NtCreateProcess" ascii
        $nt2 = "NtCreateSection" ascii
        $nt3 = "NtMapViewOfSection" ascii
        $nt4 = "NtUnmapViewOfSection" ascii
        $nt5 = "NtWriteVirtualMemory" ascii
        $nt6 = "NtSetContextThread" ascii
        $nt7 = "NtResumeThread" ascii
        $nt8 = "NtAllocateVirtualMemory" ascii
        $nt9 = "NtProtectVirtualMemory" ascii

        $pe_magic = { 4D 5A }
        $pe_read = { 8B 46 3C }

        $context_flag = { C7 ?? 00 01 00 10 00 00 }

    condition:
        uint16(0) == 0x5A4D and
        4 of ($nt*) and
        ($pe_read or $context_flag)
}
