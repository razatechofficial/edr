import "pe"

rule Shellcode_Donut_Loader
{
    meta:
        description = "Detects Donut shellcode loader framework output"
        author = "EDR Research Team"
        date = "2025-01-15"
        reference = "https://github.com/TheWover/donut"
        severity = "critical"
        mitre_attack = "T1055, T1620, T1027"

    strings:
        $donut_str1 = "DONUT_INSTANCE" ascii wide
        $donut_str2 = "TheWover" ascii
        $donut_str3 = "donut" ascii wide
        $donut_str4 = "AMSI" ascii wide
        $donut_str5 = "WLDP" ascii wide

        $api1 = "CLRCreateInstance" ascii
        $api2 = "CorBindToRuntime" ascii
        $api3 = "ICLRMetaHost" ascii wide
        $api4 = "ICLRRuntimeInfo" ascii wide
        $api5 = "ICorRuntimeHost" ascii wide

        $clr_load = { 48 8D 0D ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 48 85 C0 74 }
        $amsi_patch = { B8 57 00 07 80 C3 }
        $etw_patch = { 33 C0 C3 }

    condition:
        (2 of ($donut_str*)) or
        (3 of ($api*) and ($clr_load or $amsi_patch)) or
        (2 of ($api*) and $amsi_patch and $etw_patch)
}

rule Shellcode_Donut_Instance_Header
{
    meta:
        description = "Detects Donut shellcode instance header structure"
        author = "EDR Research Team"
        date = "2025-01-15"
        reference = "https://github.com/TheWover/donut"
        severity = "critical"
        mitre_attack = "T1055, T1620"

    strings:
        $instance_sig = { 44 4F 4E 55 54 5F 49 4E 53 54 41 4E 43 45 }
        $module_sig = { 44 4F 4E 55 54 5F 4D 4F 44 55 4C 45 }

        $chaskey_init = { 48 8D ?? ?? ?? ?? ?? 48 8D ?? ?? ?? ?? ?? 41 B8 10 00 00 00 }
        $decrypt_loop = { 48 FF C9 48 85 C9 0F 85 }

        $resolve_api = "RtlExitUserThread" ascii
        $resolve_api2 = "NtContinue" ascii
        $resolve_api3 = "NtFlushInstructionCache" ascii

    condition:
        ($instance_sig or $module_sig) or
        ($chaskey_init and $decrypt_loop) or
        (2 of ($resolve_api*) and ($chaskey_init or $decrypt_loop))
}
