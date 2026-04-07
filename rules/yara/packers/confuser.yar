import "pe"

rule Packer_ConfuserEx
{
    meta:
        description = "Detects .NET assemblies obfuscated with ConfuserEx"
        author = "EDR Research Team"
        date = "2025-01-15"
        reference = "https://github.com/yck1509/ConfuserEx"
        severity = "medium"
        mitre_attack = "T1027.002"

    strings:
        $confuser1 = "ConfuserEx" ascii wide
        $confuser2 = "Confuser.Core" ascii wide
        $confuser3 = "ConfusedBy" ascii wide
        $confuser4 = "Confuser" ascii wide

        $koi_stub = { 28 ?? ?? ?? 06 00 28 ?? ?? ?? 06 00 28 ?? ?? ?? 06 00 28 ?? ?? ?? 06 00 }
        $resource_prot = "costura." ascii wide nocase
        $anti_tamper = { 11 00 6F ?? ?? ?? 0A 11 01 6F ?? ?? ?? 0A }

        $dotnet_marker = "_CorExeMain" ascii
        $dotnet_marker2 = "mscoree.dll" ascii
        $dotnet_runtime = "v4.0.30319" ascii wide

        $invalid_meta = { 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 5F ?? ?? ?? }

    condition:
        uint16(0) == 0x5A4D and
        ($dotnet_marker or $dotnet_marker2) and
        (1 of ($confuser*) or $koi_stub or ($anti_tamper and $invalid_meta))
}

rule Packer_ConfuserEx_Unpacker_Stub
{
    meta:
        description = "Detects ConfuserEx runtime decryption/decompression stubs"
        author = "EDR Research Team"
        date = "2025-01-15"
        reference = "https://github.com/yck1509/ConfuserEx"
        severity = "medium"
        mitre_attack = "T1027.002"

    strings:
        $gzip = "System.IO.Compression.GZipStream" ascii wide
        $deflate = "System.IO.Compression.DeflateStream" ascii wide
        $lzma = "SevenZip.Compression.LZMA" ascii wide
        $aes_decrypt = "System.Security.Cryptography.RijndaelManaged" ascii wide
        $derive_key = "System.Security.Cryptography.Rfc2898DeriveBytes" ascii wide
        $assembly_load = "System.Reflection.Assembly::Load" ascii
        $module_resolve = "ModuleResolve" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        (1 of ($gzip, $deflate, $lzma) and $aes_decrypt and $derive_key) or
        ($assembly_load and $module_resolve and 1 of ($gzip, $deflate, $lzma))
}
