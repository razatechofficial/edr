rule Shellcode_DotNet_Runner
{
    meta:
        description = "Detects .NET shellcode runner assemblies"
        author = "EDR Research Team"
        date = "2025-01-15"
        reference = "https://attack.mitre.org/techniques/T1055/"
        severity = "critical"
        mitre_attack = "T1055, T1620"

    strings:
        $dotnet = "mscoree.dll" ascii
        $cor = "_CorExeMain" ascii

        $marshal1 = "System.Runtime.InteropServices.Marshal" ascii wide
        $marshal2 = "Copy" ascii wide
        $marshal3 = "AllocHGlobal" ascii wide

        $pinvoke_va = "VirtualAlloc" ascii wide
        $pinvoke_vp = "VirtualProtect" ascii wide
        $pinvoke_ct = "CreateThread" ascii wide
        $pinvoke_wfso = "WaitForSingleObject" ascii wide

        $dllimport1 = "[DllImport(\"kernel32\")]" ascii wide
        $dllimport2 = "[DllImport(\"kernel32.dll\")]" ascii wide

        $byte_arr = /new\s+byte\s*\[\s*\]\s*\{(\s*0x[0-9a-fA-F]{1,2}\s*,?\s*){10,}/ ascii wide

    condition:
        ($dotnet or $cor) and
        (($pinvoke_va and $pinvoke_ct) or ($marshal1 and $pinvoke_va)) and
        (1 of ($dllimport*) or $byte_arr)
}

rule Shellcode_DotNet_Injection
{
    meta:
        description = "Detects .NET process injection for shellcode execution"
        author = "EDR Research Team"
        date = "2025-01-15"
        reference = "https://attack.mitre.org/techniques/T1055/"
        severity = "critical"
        mitre_attack = "T1055.001, T1055.002"

    strings:
        $dotnet = "mscoree.dll" ascii

        $inject1 = "OpenProcess" ascii wide
        $inject2 = "VirtualAllocEx" ascii wide
        $inject3 = "WriteProcessMemory" ascii wide
        $inject4 = "CreateRemoteThread" ascii wide
        $inject5 = "NtCreateThreadEx" ascii wide
        $inject6 = "QueueUserAPC" ascii wide
        $inject7 = "NtQueueApcThread" ascii wide

        $target1 = "Process.GetProcessesByName" ascii wide
        $target2 = "Process.Start" ascii wide
        $target3 = "svchost" ascii wide
        $target4 = "explorer" ascii wide
        $target5 = "notepad" ascii wide

    condition:
        $dotnet and
        ($inject1 and $inject2 and $inject3 and ($inject4 or $inject5 or $inject6 or $inject7)) and
        1 of ($target*)
}
