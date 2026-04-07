import "pe"
import "math"

rule Packer_UPX
{
    meta:
        description = "Detects executables packed with UPX (Ultimate Packer for eXecutables)"
        author = "EDR Research Team"
        date = "2025-01-15"
        reference = "https://upx.github.io/"
        severity = "low"
        mitre_attack = "T1027.002"

    strings:
        $upx_magic = "UPX!" ascii
        $upx0 = "UPX0" ascii
        $upx1 = "UPX1" ascii
        $upx2 = "UPX2" ascii
        $upx_header = { 55 50 58 21 0D ?? ?? ?? }

        $section_name0 = ".UPX0" ascii
        $section_name1 = ".UPX1" ascii
        $section_name2 = ".UPX2" ascii

    condition:
        uint16(0) == 0x5A4D and
        ($upx_magic or $upx_header or ($upx0 and $upx1) or ($section_name0 and $section_name1))
}

rule Packer_UPX_Modified
{
    meta:
        description = "Detects executables packed with modified/tampered UPX (section names altered)"
        author = "EDR Research Team"
        date = "2025-01-15"
        reference = "https://upx.github.io/"
        severity = "medium"
        mitre_attack = "T1027.002"

    strings:
        $upx_stub_x86 = { 60 BE ?? ?? ?? ?? 8D BE ?? ?? ?? ?? 57 83 CD FF EB 10 }
        $upx_stub_x64 = { 53 56 57 55 48 8D 35 ?? ?? ?? ?? 48 8D 3D }
        $nrv2b = { 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB }
        $nrv2e = { 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB 72 }
        $lzma_stub = { 56 83 C3 04 53 50 C7 03 03 00 02 00 }

    condition:
        uint16(0) == 0x5A4D and
        not ($upx_stub_x86 and for any i in (0..pe.number_of_sections - 1): (pe.sections[i].name == "UPX0")) and
        ($upx_stub_x86 or $upx_stub_x64 or $nrv2b or $nrv2e or $lzma_stub)
}
