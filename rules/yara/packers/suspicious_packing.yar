import "pe"
import "math"

rule Suspicious_High_Entropy_PE
{
    meta:
        description = "Detects PE files with suspiciously high entropy indicating packing or encryption"
        author = "EDR Research Team"
        date = "2025-01-15"
        reference = "https://attack.mitre.org/techniques/T1027.002/"
        severity = "medium"
        mitre_attack = "T1027.002"

    strings:
        $mz = { 4D 5A }

    condition:
        $mz at 0 and
        math.entropy(0, filesize) > 7.0 and
        filesize < 10MB
}

rule Suspicious_Small_IAT
{
    meta:
        description = "Detects PE with abnormally small import table suggesting packed/obfuscated binary"
        author = "EDR Research Team"
        date = "2025-01-15"
        reference = "https://attack.mitre.org/techniques/T1027.002/"
        severity = "medium"
        mitre_attack = "T1027.002"

    strings:
        $loadlib = "LoadLibraryA" ascii
        $getproc = "GetProcAddress" ascii
        $virtualprotect = "VirtualProtect" ascii
        $virtualalloc = "VirtualAlloc" ascii

    condition:
        uint16(0) == 0x5A4D and
        pe.number_of_imports <= 3 and
        pe.number_of_sections >= 1 and
        ($loadlib and $getproc) and
        filesize > 50KB
}

rule Suspicious_Anti_Debug_Strings
{
    meta:
        description = "Detects PE with multiple anti-debugging and anti-analysis indicators"
        author = "EDR Research Team"
        date = "2025-01-15"
        reference = "https://attack.mitre.org/techniques/T1497/"
        severity = "medium"
        mitre_attack = "T1497.001, T1027.002"

    strings:
        $anti1 = "IsDebuggerPresent" ascii
        $anti2 = "CheckRemoteDebuggerPresent" ascii
        $anti3 = "NtQueryInformationProcess" ascii
        $anti4 = "OutputDebugStringA" ascii
        $anti5 = "GetTickCount" ascii
        $anti6 = "QueryPerformanceCounter" ascii

        $vm1 = "vmware" ascii wide nocase
        $vm2 = "virtualbox" ascii wide nocase
        $vm3 = "vbox" ascii wide nocase
        $vm4 = "qemu" ascii wide nocase
        $vm5 = "xen" ascii wide nocase
        $vm6 = "SBIECTL.SYS" ascii wide nocase
        $vm7 = "SbieDll.dll" ascii wide nocase

        $sandbox1 = "SbieDll" ascii wide
        $sandbox2 = "snxhk.dll" ascii wide
        $sandbox3 = "avghooka.dll" ascii wide
        $sandbox4 = "api_log.dll" ascii wide
        $sandbox5 = "dbghelp.dll" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        (3 of ($anti*) and 2 of ($vm*)) or
        (2 of ($anti*) and 3 of ($sandbox*)) or
        (4 of ($anti*) and 3 of ($vm*))
}

rule Suspicious_Self_Modifying_Code
{
    meta:
        description = "Detects PE with indicators of self-modifying or self-decrypting code"
        author = "EDR Research Team"
        date = "2025-01-15"
        reference = "https://attack.mitre.org/techniques/T1027/"
        severity = "medium"
        mitre_attack = "T1027, T1027.002"

    strings:
        $vp = "VirtualProtect" ascii
        $va = "VirtualAlloc" ascii
        $wpm = "WriteProcessMemory" ascii
        $flush = "FlushInstructionCache" ascii

        $rwx_alloc = { 68 40 00 00 00 6A ?? 6A 00 }
        $page_rwx = { 68 40 00 00 00 }

        $xor_loop1 = { 80 34 ?? ?? 40 3B C? 72 F? }
        $xor_loop2 = { 31 ?? 83 C? 04 3B ?? 72 }
        $xor_loop3 = { 80 30 ?? 40 49 75 F? }

    condition:
        uint16(0) == 0x5A4D and
        ($vp or $va) and
        ($wpm or $flush) and
        1 of ($xor_loop*)
}
