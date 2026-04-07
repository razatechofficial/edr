import "pe"

rule Packer_Themida_WinLicense
{
    meta:
        description = "Detects executables protected with Themida or WinLicense"
        author = "EDR Research Team"
        date = "2025-01-15"
        reference = "https://www.oreans.com/Themida.php"
        severity = "medium"
        mitre_attack = "T1027.002"

    strings:
        $themida1 = ".themida" ascii
        $themida2 = ".Themida" ascii
        $winlicense1 = "WinLicense" ascii wide
        $winlicense2 = ".winlice" ascii

        $section1 = ".themida" ascii
        $section2 = ".Themida" ascii
        $section3 = "Themida" ascii

        $oreans = "Oreans Technologies" ascii wide
        $oreans2 = "oreans.com" ascii wide

        $anti_vm1 = { 0F 3F 07 0B }
        $anti_dbg1 = { 64 A1 30 00 00 00 0F B6 40 02 }
        $anti_dbg2 = { EB 02 ?? ?? 50 EB 02 ?? ?? 0F 31 }

    condition:
        uint16(0) == 0x5A4D and
        (1 of ($themida*, $winlicense*) or
         1 of ($section*) or
         1 of ($oreans*) or
         (2 of ($anti_vm1, $anti_dbg1, $anti_dbg2)))
}

rule Packer_Themida_Virtual_Machine
{
    meta:
        description = "Detects Themida VM-based code virtualization"
        author = "EDR Research Team"
        date = "2025-01-15"
        reference = "https://www.oreans.com/Themida.php"
        severity = "medium"
        mitre_attack = "T1027.002"

    strings:
        $vm_handler = { 8B 45 00 83 C5 04 FF E0 }
        $vm_dispatch = { 0F B6 06 46 FF 24 85 }
        $vm_init = { 89 E5 81 EC ?? ?? 00 00 89 45 ?? 89 5D ?? 89 4D ?? 89 55 }

        $vm_section = ".vlizer" ascii
        $vm_section2 = ".perplex" ascii

    condition:
        uint16(0) == 0x5A4D and
        (2 of ($vm_handler, $vm_dispatch, $vm_init) or 1 of ($vm_section, $vm_section2))
}
