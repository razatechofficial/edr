rule Maldoc_OLE_Suspicious_VBA
{
    meta:
        description = "Detects malicious OLE documents with suspicious VBA macro content"
        author = "EDR Research Team"
        date = "2025-01-15"
        reference = "https://attack.mitre.org/techniques/T1059.005/"
        severity = "high"
        mitre_attack = "T1059.005, T1204.002"

    strings:
        $ole_magic = { D0 CF 11 E0 A1 B1 1A E1 }

        $vba_attr = "Attribute VB_Name" ascii
        $vba_proj = "VBAProject" ascii wide

        $auto1 = "AutoOpen" ascii wide nocase
        $auto2 = "Auto_Open" ascii wide nocase
        $auto3 = "AutoExec" ascii wide nocase
        $auto4 = "AutoExit" ascii wide nocase
        $auto5 = "AutoClose" ascii wide nocase
        $auto6 = "Auto_Close" ascii wide nocase
        $auto7 = "Document_Open" ascii wide nocase
        $auto8 = "Document_Close" ascii wide nocase
        $auto9 = "Workbook_Open" ascii wide nocase
        $auto10 = "Workbook_Activate" ascii wide nocase

        $danger1 = "Shell(" ascii wide nocase
        $danger2 = "Shell " ascii wide nocase
        $danger3 = "WScript.Shell" ascii wide nocase
        $danger4 = "Scripting.FileSystemObject" ascii wide nocase
        $danger5 = "CreateObject(" ascii wide nocase
        $danger6 = "GetObject(" ascii wide nocase
        $danger7 = "CallByName" ascii wide nocase
        $danger8 = "Environ(" ascii wide nocase

        $susp1 = "powershell" ascii wide nocase
        $susp2 = "cmd.exe" ascii wide nocase
        $susp3 = "certutil" ascii wide nocase
        $susp4 = "mshta" ascii wide nocase
        $susp5 = "cscript" ascii wide nocase
        $susp6 = "wscript" ascii wide nocase
        $susp7 = "regsvr32" ascii wide nocase
        $susp8 = "rundll32" ascii wide nocase

    condition:
        $ole_magic at 0 and
        ($vba_attr or $vba_proj) and
        1 of ($auto*) and
        (2 of ($danger*) or (1 of ($danger*) and 1 of ($susp*)))
}

rule Maldoc_OLE_Obfuscated_VBA
{
    meta:
        description = "Detects OLE documents with obfuscated VBA macros"
        author = "EDR Research Team"
        date = "2025-01-15"
        reference = "https://attack.mitre.org/techniques/T1027/"
        severity = "high"
        mitre_attack = "T1027, T1059.005"

    strings:
        $ole_magic = { D0 CF 11 E0 A1 B1 1A E1 }

        $obfusc1 = "Chr(" ascii wide nocase
        $obfusc2 = "ChrW(" ascii wide nocase
        $obfusc3 = "ChrB(" ascii wide nocase
        $obfusc4 = "StrReverse(" ascii wide nocase
        $obfusc5 = "Replace(" ascii wide nocase
        $obfusc6 = "Mid(" ascii wide nocase
        $obfusc7 = "Join(" ascii wide nocase
        $obfusc8 = "Split(" ascii wide nocase

        $concat = /[a-zA-Z]+\s*&\s*[a-zA-Z]+\s*&\s*[a-zA-Z]+\s*&\s*[a-zA-Z]+/ ascii

        $b64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/" ascii

        $exec_obfusc = /[Ss][Hh][Ee][Ll][Ll]|[Ee][Xx][Ee][Cc]|[Ss][Yy][Ss][Tt][Ee][Mm]/ ascii

    condition:
        $ole_magic at 0 and
        (4 of ($obfusc*) or ($concat and 2 of ($obfusc*)) or
         ($b64 and 2 of ($obfusc*)))
}

rule Maldoc_OLE_DDE_Attack
{
    meta:
        description = "Detects OLE documents with DDE (Dynamic Data Exchange) attack payloads"
        author = "EDR Research Team"
        date = "2025-01-15"
        reference = "https://attack.mitre.org/techniques/T1559.002/"
        severity = "high"
        mitre_attack = "T1559.002"

    strings:
        $ole_magic = { D0 CF 11 E0 A1 B1 1A E1 }

        $dde1 = "DDE" ascii wide
        $dde2 = "DDEAUTO" ascii wide nocase
        $dde3 = /DDE(AUTO)?\s+[a-zA-Z]+\s+['"\\]/ ascii wide nocase

        $cmd1 = "cmd.exe" ascii wide nocase
        $cmd2 = "powershell" ascii wide nocase
        $cmd3 = "mshta" ascii wide nocase
        $cmd4 = "certutil" ascii wide nocase

        $field = "QUOTE" ascii wide

    condition:
        $ole_magic at 0 and
        (1 of ($dde*) and 1 of ($cmd*)) or
        ($field and 1 of ($dde*))
}
