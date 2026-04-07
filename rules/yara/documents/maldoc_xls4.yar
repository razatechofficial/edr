rule Maldoc_XLS4_Macro
{
    meta:
        description = "Detects XLS 4.0 (Excel 4.0) macro sheets used for malware delivery"
        author = "EDR Research Team"
        date = "2025-01-15"
        reference = "https://attack.mitre.org/techniques/T1059.005/"
        severity = "high"
        mitre_attack = "T1059.005, T1204.002"

    strings:
        $ole_magic = { D0 CF 11 E0 A1 B1 1A E1 }

        $macro_sheet = { 01 01 }
        $excel4 = "Excel 4.0" ascii wide nocase

        $formula1 = "EXEC(" ascii wide nocase
        $formula2 = "CALL(" ascii wide nocase
        $formula3 = "RUN(" ascii wide nocase
        $formula4 = "REGISTER(" ascii wide nocase
        $formula5 = "FOPEN(" ascii wide nocase
        $formula6 = "FWRITE(" ascii wide nocase
        $formula7 = "FCLOSE(" ascii wide nocase
        $formula8 = "HALT()" ascii wide nocase
        $formula9 = "CHAR(" ascii wide nocase
        $formula10 = "NOW()" ascii wide nocase

        $api1 = "URLDownloadToFileA" ascii wide
        $api2 = "ShellExecuteA" ascii wide
        $api3 = "WinExec" ascii wide
        $api4 = "kernel32" ascii wide
        $api5 = "urlmon" ascii wide

    condition:
        $ole_magic at 0 and
        (3 of ($formula*) or
         (1 of ($formula1, $formula2, $formula3, $formula4) and 1 of ($api*)) or
         ($excel4 and 2 of ($formula*)))
}

rule Maldoc_XLS4_Auto_Open_Hidden
{
    meta:
        description = "Detects XLS 4.0 macros with Auto_Open in hidden sheets"
        author = "EDR Research Team"
        date = "2025-01-15"
        reference = "https://attack.mitre.org/techniques/T1564.001/"
        severity = "high"
        mitre_attack = "T1059.005, T1564.001"

    strings:
        $ole_magic = { D0 CF 11 E0 A1 B1 1A E1 }

        $auto_open = "Auto_Open" ascii wide nocase
        $hidden_sheet = { 85 00 }
        $very_hidden = { 02 01 }

        $formula_exec = "EXEC(" ascii wide nocase
        $formula_call = "CALL(" ascii wide nocase
        $formula_alert = "ALERT(" ascii wide nocase
        $formula_goto = "GOTO(" ascii wide nocase

    condition:
        $ole_magic at 0 and
        $auto_open and
        1 of ($formula_exec, $formula_call) and
        filesize < 5MB
}
