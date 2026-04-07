import "pe"

rule Packer_ASPack
{
    meta:
        description = "Detects executables compressed with ASPack"
        author = "EDR Research Team"
        date = "2025-01-15"
        reference = "http://www.aspack.com/"
        severity = "low"
        mitre_attack = "T1027.002"

    strings:
        $aspack1 = ".aspack" ascii
        $aspack2 = ".adata" ascii
        $aspack3 = "ASPack" ascii wide

        $stub_v212 = { 60 E8 00 00 00 00 5D 81 ED ?? ?? ?? ?? BB ?? ?? ?? ?? 03 DD 2B 9D }
        $stub_v224 = { 60 E8 03 00 00 00 E9 EB 04 5D 45 55 C3 E8 01 00 00 00 EB 5D BB ED FF FF FF 03 DD }
        $stub_v242 = { 60 E8 ?? 00 00 00 5D 81 ED ?? ?? ?? ?? BB ?? ?? ?? ?? 03 DD }

    condition:
        uint16(0) == 0x5A4D and
        (1 of ($aspack*) or 1 of ($stub_v212, $stub_v224, $stub_v242))
}
