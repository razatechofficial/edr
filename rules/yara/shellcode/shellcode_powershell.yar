rule Shellcode_PowerShell_Loader
{
    meta:
        description = "Detects PowerShell-based shellcode loaders"
        author = "EDR Research Team"
        date = "2025-01-15"
        reference = "https://attack.mitre.org/techniques/T1059.001/"
        severity = "critical"
        mitre_attack = "T1059.001, T1055, T1620"

    strings:
        $alloc1 = "[System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer" ascii wide nocase
        $alloc2 = "VirtualAlloc" ascii wide nocase
        $alloc3 = "kernel32.dll" ascii wide nocase
        $alloc4 = "[Runtime.InteropServices.Marshal]::Copy" ascii wide nocase

        $inject1 = "Invoke-Shellcode" ascii wide nocase
        $inject2 = "Invoke-ReflectivePEInjection" ascii wide nocase
        $inject3 = "[Byte[]]$buf" ascii wide nocase
        $inject4 = "[Byte[]]$shellcode" ascii wide nocase

        $pinvoke1 = "DllImport" ascii wide nocase
        $pinvoke2 = "Add-Type -MemberDefinition" ascii wide nocase
        $pinvoke3 = "EntryPoint" ascii wide nocase
        $pinvoke4 = "CallingConvention" ascii wide nocase

        $b64_decode = "[System.Convert]::FromBase64String" ascii wide nocase
        $xor_decode = /\-bxor\s+0x[0-9a-fA-F]{1,2}/ nocase

    condition:
        (2 of ($alloc*) and 1 of ($inject*)) or
        (2 of ($pinvoke*) and 1 of ($inject*)) or
        (2 of ($alloc*) and $b64_decode) or
        (1 of ($inject1, $inject2) and ($b64_decode or $xor_decode))
}

rule Shellcode_PowerShell_Cradle
{
    meta:
        description = "Detects PowerShell download cradles for shellcode delivery"
        author = "EDR Research Team"
        date = "2025-01-15"
        reference = "https://attack.mitre.org/techniques/T1059.001/"
        severity = "high"
        mitre_attack = "T1059.001, T1105"

    strings:
        $dl1 = "IEX(New-Object Net.WebClient).DownloadString" ascii wide nocase
        $dl2 = "Invoke-Expression" ascii wide nocase
        $dl3 = "IWR" ascii wide nocase
        $dl4 = "Invoke-WebRequest" ascii wide nocase
        $dl5 = "Start-BitsTransfer" ascii wide nocase
        $dl6 = "(New-Object System.Net.WebClient).DownloadData" ascii wide nocase

        $exec1 = "IEX" ascii wide nocase
        $exec2 = "Invoke-Expression" ascii wide nocase
        $exec3 = "[ScriptBlock]::Create" ascii wide nocase

        $obfusc1 = /\-[Jj][Oo][Ii][Nn]\s*['"]/ ascii wide
        $obfusc2 = "-replace" ascii wide nocase
        $obfusc3 = "[char]" ascii wide nocase

    condition:
        (1 of ($dl*) and 1 of ($exec*)) or
        (1 of ($dl*) and 2 of ($obfusc*))
}
