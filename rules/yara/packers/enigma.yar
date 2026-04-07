import "pe"

rule Packer_Enigma_Protector
{
    meta:
        description = "Detects executables protected with Enigma Protector"
        author = "EDR Research Team"
        date = "2025-01-15"
        reference = "https://enigmaprotector.com/"
        severity = "medium"
        mitre_attack = "T1027.002"

    strings:
        $enigma1 = "Enigma Protector" ascii wide
        $enigma2 = "enigma protector" ascii wide nocase
        $enigma3 = "The Enigma Protector" ascii wide
        $enigma4 = ".enigma1" ascii
        $enigma5 = ".enigma2" ascii

        $ep_stub = { 60 E8 00 00 00 00 5D 83 ED 06 81 ED ?? ?? ?? ?? }
        $vbox_check = { 0F 3F 07 0B 66 ?? ?? 75 }
        $anti_debug = { 64 A1 30 00 00 00 0F B6 40 02 84 C0 75 }

        $registration = "ENIGMA_REGISTRATION" ascii wide
        $virtual_box = ".enigma_vbox" ascii
        $ep_section = ".enigma" ascii

    condition:
        uint16(0) == 0x5A4D and
        (2 of ($enigma*) or $ep_stub or $ep_section or $virtual_box or
         ($anti_debug and 1 of ($enigma*)))
}
