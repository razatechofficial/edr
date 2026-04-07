rule Shellcode_x64_PEB_Walking
{
    meta:
        description = "Detects x64 shellcode with PEB walking for API resolution"
        author = "EDR Research Team"
        date = "2025-01-15"
        reference = "https://attack.mitre.org/techniques/T1055/"
        severity = "high"
        mitre_attack = "T1055, T1106"

    strings:
        $peb_x64_1 = { 65 48 8B 04 25 60 00 00 00 48 8B 40 18 48 8B 40 20 }
        $peb_x64_2 = { 65 4C 8B 04 25 60 00 00 00 4D 8B 40 18 4D 8B 40 20 }
        $peb_x64_3 = { 65 48 8B 52 60 48 8B 52 18 48 8B 52 20 48 8B 72 50 }
        $peb_x64_4 = { 48 31 D2 65 48 8B 52 60 48 8B 52 18 48 8B 52 20 }

        $hash_ror13_x64 = { 48 31 C0 AC 41 C1 C9 0D 41 01 C1 }
        $hash_djb2_x64 = { 48 31 C0 AC 41 6B C9 21 41 01 C1 }

    condition:
        1 of ($peb_x64_*) and ($hash_ror13_x64 or $hash_djb2_x64)
}

rule Shellcode_x64_Syscall_Stub
{
    meta:
        description = "Detects x64 shellcode using direct syscall stubs"
        author = "EDR Research Team"
        date = "2025-01-15"
        reference = "https://attack.mitre.org/techniques/T1106/"
        severity = "critical"
        mitre_attack = "T1106, T1055"

    strings:
        $syscall_NtAllocateVirtualMemory = { 4C 8B D1 B8 18 00 00 00 0F 05 C3 }
        $syscall_NtWriteVirtualMemory = { 4C 8B D1 B8 3A 00 00 00 0F 05 C3 }
        $syscall_NtCreateThreadEx = { 4C 8B D1 B8 C1 00 00 00 0F 05 C3 }
        $syscall_NtProtectVirtualMemory = { 4C 8B D1 B8 50 00 00 00 0F 05 C3 }
        $syscall_NtQueueApcThread = { 4C 8B D1 B8 45 00 00 00 0F 05 C3 }

        $generic_syscall = { 4C 8B D1 B8 ?? 00 00 00 0F 05 C3 }
        $indirect_syscall = { 4C 8B D1 B8 ?? 00 00 00 FF 25 }

        $hell_gate = { 4C 8B D1 B8 ?? 00 00 00 49 89 CA 0F 05 C3 }

    condition:
        2 of ($syscall_*) or
        (#generic_syscall > 3) or
        $indirect_syscall or
        $hell_gate
}

rule Shellcode_x64_Reverse_Shell
{
    meta:
        description = "Detects common x64 reverse shell shellcode"
        author = "EDR Research Team"
        date = "2025-01-15"
        reference = "https://attack.mitre.org/techniques/T1059/"
        severity = "critical"
        mitre_attack = "T1059"

    strings:
        $msfvenom_x64 = { FC 48 83 E4 F0 E8 C0 00 00 00 41 51 41 50 52 51 56 48 31 D2 65 48 8B 52 60 }
        $cobalt_x64 = { FC 48 83 E4 F0 E8 C8 00 00 00 41 51 41 50 52 51 56 48 31 D2 65 48 8B 52 60 }

        $ws2_init = { 48 89 E6 48 81 EC 00 01 00 00 }
        $connect_call = { 41 FF D5 48 85 C0 74 }
        $cmd_exec = { 48 8D 0D ?? ?? 00 00 41 FF D5 }

        $socket_setup = { 6A 06 6A 01 6A 02 }
        $socket_connect = { 49 BE ?? ?? ?? ?? ?? ?? 00 00 41 56 }

    condition:
        ($msfvenom_x64 or $cobalt_x64) or
        ($ws2_init and $connect_call and $socket_setup)
}
