import "pe"
import "math"

rule Packer_VMProtect
{
    meta:
        description = "Detects executables protected with VMProtect"
        author = "EDR Research Team"
        date = "2025-01-15"
        reference = "https://vmpsoft.com/"
        severity = "medium"
        mitre_attack = "T1027.002"

    strings:
        $vmp_section1 = ".vmp0" ascii
        $vmp_section2 = ".vmp1" ascii
        $vmp_section3 = ".vmp2" ascii
        $vmp_section4 = ".VMProtect" ascii

        $vmp_str1 = "VMProtect" ascii wide
        $vmp_str2 = "VMProtectSDK" ascii wide
        $vmp_str3 = "VMProtectBegin" ascii
        $vmp_str4 = "VMProtectEnd" ascii
        $vmp_str5 = "VMProtectDecryptStringA" ascii
        $vmp_str6 = "VMProtectDecryptStringW" ascii

    condition:
        uint16(0) == 0x5A4D and
        (1 of ($vmp_section*) or 2 of ($vmp_str*))
}

rule Packer_VMProtect_Virtualized
{
    meta:
        description = "Detects VMProtect code virtualization via bytecode interpreter patterns"
        author = "EDR Research Team"
        date = "2025-01-15"
        reference = "https://vmpsoft.com/"
        severity = "medium"
        mitre_attack = "T1027.002"

    strings:
        $vm_entry = { 9C 60 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? }
        $vm_dispatch = { 8B 06 83 C6 04 FF E0 }
        $vm_push = { 89 45 00 83 ED 04 }
        $vm_pop = { 8B 45 00 83 C5 04 }
        $vm_nand = { 8B 45 00 F7 D0 23 45 04 }

        $mutex_pattern = { 68 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 85 C0 0F 84 }

    condition:
        uint16(0) == 0x5A4D and
        ($vm_entry and 2 of ($vm_dispatch, $vm_push, $vm_pop, $vm_nand)) or
        (for any i in (0..pe.number_of_sections - 1): (pe.sections[i].name matches /\.vmp[0-9]/))
}
