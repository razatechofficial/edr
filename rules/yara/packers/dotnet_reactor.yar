import "pe"

rule Packer_DotNET_Reactor
{
    meta:
        description = "Detects .NET assemblies obfuscated with .NET Reactor"
        author = "EDR Research Team"
        date = "2025-01-15"
        reference = "https://www.eziriz.com/dotnet_reactor.htm"
        severity = "medium"
        mitre_attack = "T1027.002"

    strings:
        $reactor1 = ".NET Reactor" ascii wide
        $reactor2 = "Eziriz" ascii wide
        $reactor3 = "ReactorHelper" ascii wide

        $dotnet = "mscoree.dll" ascii
        $cor = "_CorExeMain" ascii

        $native_stub = { 56 57 53 E8 00 00 00 00 5B 81 EB ?? ?? ?? ?? 8B 73 }
        $decrypt_call = { 7E ?? ?? ?? 04 28 ?? ?? ?? 06 80 ?? ?? ?? 04 }

        $anti_decompile = { 1F 08 1F 00 1F 00 1F 00 FE 01 }
        $strong_name_removal = "StrongNameSignature" ascii wide

        $embedded = "__reactor_" ascii
        $embedded2 = "{" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        ($dotnet or $cor) and
        (1 of ($reactor*) or $native_stub or ($decrypt_call and $anti_decompile) or $embedded)
}
