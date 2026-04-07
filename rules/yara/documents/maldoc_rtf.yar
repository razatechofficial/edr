rule Maldoc_RTF_Embedded_Object
{
    meta:
        description = "Detects malicious RTF documents with embedded OLE objects"
        author = "EDR Research Team"
        date = "2025-01-15"
        reference = "https://attack.mitre.org/techniques/T1204.002/"
        severity = "high"
        mitre_attack = "T1204.002, T1027"

    strings:
        $rtf_magic = "{\\rtf" ascii

        $obj1 = "\\object" ascii nocase
        $obj2 = "\\objdata" ascii nocase
        $obj3 = "\\objemb" ascii nocase
        $obj4 = "\\objocx" ascii nocase
        $obj5 = "\\objupdate" ascii nocase

        $ole_hex = "d0cf11e0a1b1" ascii nocase
        $pe_hex = "4d5a90000300" ascii nocase

        $equation1 = "Equation.3" ascii nocase
        $equation2 = "Equation.DSMT" ascii nocase
        $equation3 = "00021700-0000-0000-c000-000000000046" ascii nocase
        $equation4 = "{0002CE02-0000-0000-C000-000000000046}" ascii nocase

    condition:
        $rtf_magic at 0 and
        (1 of ($obj*) and ($ole_hex or $pe_hex)) or
        (1 of ($equation*) and 1 of ($obj*))
}

rule Maldoc_RTF_CVE_2017_11882
{
    meta:
        description = "Detects RTF documents exploiting CVE-2017-11882 (Equation Editor)"
        author = "EDR Research Team"
        date = "2025-01-15"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2017-11882"
        severity = "critical"
        mitre_attack = "T1203"

    strings:
        $rtf_magic = "{\\rtf" ascii

        $eqnedt = "Equation.3" ascii nocase
        $eqnedt_clsid = "0002CE02-0000-0000-C000-000000000046" ascii nocase

        $obj = "\\objdata" ascii nocase

        $exploit_sig1 = { 02 CE 02 00 00 00 00 00 C0 00 00 00 00 00 00 46 }
        $exploit_sig2 = { 03 01 01 03 0A 0A 01 08 5A 5A }
        $overflow = /[0-9a-fA-F]{200,}/ ascii

    condition:
        $rtf_magic at 0 and
        $obj and
        ($eqnedt or $eqnedt_clsid) and
        ($exploit_sig1 or $exploit_sig2 or $overflow)
}

rule Maldoc_RTF_Obfuscated
{
    meta:
        description = "Detects RTF documents with obfuscation techniques (inserted junk, hex encoding)"
        author = "EDR Research Team"
        date = "2025-01-15"
        reference = "https://attack.mitre.org/techniques/T1027/"
        severity = "medium"
        mitre_attack = "T1027, T1204.002"

    strings:
        $rtf_magic = "{\\rtf" ascii

        $hex_obj = /\\objdata\s+[0-9a-fA-F\s\r\n]{500,}/ ascii nocase
        $many_groups = /\{[^}]{0,10}\{[^}]{0,10}\{[^}]{0,10}\{/ ascii
        $junk_control = /\\[a-z]+\-?[0-9]{5,}\s/ ascii

        $bin_embed = "\\bin" ascii
        $objdata = "\\objdata" ascii nocase

    condition:
        $rtf_magic at 0 and
        (($hex_obj and $objdata) or
         ($many_groups and $bin_embed) or
         ($junk_control and $objdata))
}
