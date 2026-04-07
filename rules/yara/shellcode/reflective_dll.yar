import "pe"

rule Shellcode_Reflective_DLL_Injection
{
    meta:
        description = "Detects reflective DLL injection patterns"
        author = "EDR Research Team"
        date = "2025-01-15"
        reference = "https://attack.mitre.org/techniques/T1055.001/"
        severity = "critical"
        mitre_attack = "T1055.001, T1620"

    strings:
        $reflective1 = "ReflectiveLoader" ascii wide
        $reflective2 = "_ReflectiveLoader@4" ascii
        $reflective3 = "reflective_dll" ascii wide

        $pe_header_parse = { 8B 46 3C 8B 44 06 78 01 F0 }
        $pe_reloc = { 8B 46 3C 03 C6 0F B7 48 06 0F B7 40 14 }

        $manual_map = { 8B 43 3C 8B 84 03 88 00 00 00 85 C0 74 }

        $api_hash_kernel32 = { 6A 00 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6A 00 FF 15 }

        $virtualalloc_rwx = { 68 40 00 00 00 68 00 30 00 00 }
        $memcpy_sections = { 8B 4E 08 03 CE 8B 46 0C 03 C7 8B 56 10 52 50 51 E8 }

    condition:
        uint16(0) == 0x5A4D and
        (1 of ($reflective*)) or
        ($pe_header_parse and $virtualalloc_rwx) or
        ($manual_map and $memcpy_sections) or
        ($pe_reloc and $virtualalloc_rwx and $memcpy_sections)
}

rule Shellcode_Reflective_DLL_x64
{
    meta:
        description = "Detects x64 reflective DLL loading patterns"
        author = "EDR Research Team"
        date = "2025-01-15"
        reference = "https://attack.mitre.org/techniques/T1055.001/"
        severity = "critical"
        mitre_attack = "T1055.001"

    strings:
        $rdll_func = "ReflectiveLoader" ascii
        $rdll_export = { 52 65 66 6C 65 63 74 69 76 65 4C 6F 61 64 65 72 }

        $x64_pe_parse = { 48 63 41 3C 44 8B 84 01 88 00 00 00 }
        $x64_reloc = { 48 63 43 3C 44 0F B7 44 03 06 4C 8D 0C 03 }
        $x64_import_resolve = { 48 8D 0C 01 48 8B 01 48 85 C0 74 }

        $x64_alloc = { 41 B9 40 00 00 00 41 B8 00 30 00 00 }
        $x64_ntflush = "NtFlushInstructionCache" ascii

    condition:
        uint16(0) == 0x5A4D and
        ($rdll_func or $rdll_export) or
        ($x64_pe_parse and $x64_alloc) or
        ($x64_reloc and $x64_import_resolve and $x64_ntflush)
}
