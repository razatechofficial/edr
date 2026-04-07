rule Maldoc_OOXML_External_Relationship
{
    meta:
        description = "Detects OOXML documents with external relationship URLs (template injection)"
        author = "EDR Research Team"
        date = "2025-01-15"
        reference = "https://attack.mitre.org/techniques/T1221/"
        severity = "high"
        mitre_attack = "T1221, T1204.002"

    strings:
        $pk_magic = { 50 4B 03 04 }

        $rel1 = "Target=\"http" ascii wide nocase
        $rel2 = "Target=\"https" ascii wide nocase
        $rel3 = "TargetMode=\"External\"" ascii wide nocase

        $template1 = "attachedTemplate" ascii wide nocase
        $template2 = "oleObject" ascii wide nocase
        $template3 = "frame" ascii wide nocase
        $template4 = "subDocument" ascii wide nocase

        $url_susp1 = ".php" ascii wide nocase
        $url_susp2 = ".asp" ascii wide nocase
        $url_susp3 = ".jsp" ascii wide nocase
        $url_susp4 = ".exe" ascii wide nocase
        $url_susp5 = ".dll" ascii wide nocase
        $url_susp6 = ".hta" ascii wide nocase

    condition:
        $pk_magic at 0 and
        $rel3 and
        1 of ($template*) and
        (1 of ($rel1, $rel2) and 1 of ($url_susp*))
}

rule Maldoc_OOXML_Macro_With_External_Content
{
    meta:
        description = "Detects OOXML documents with macros and external content references"
        author = "EDR Research Team"
        date = "2025-01-15"
        reference = "https://attack.mitre.org/techniques/T1204.002/"
        severity = "high"
        mitre_attack = "T1204.002, T1059.005"

    strings:
        $pk_magic = { 50 4B 03 04 }

        $vba_proj = "vbaProject.bin" ascii wide
        $vba_data = "vbaData.xml" ascii wide
        $macro = "[Content_Types].xml" ascii wide

        $content_type1 = "application/vnd.ms-office.vbaProject" ascii wide
        $content_type2 = "application/vnd.ms-excel.sheet.macroEnabled" ascii wide
        $content_type3 = "application/vnd.ms-word.document.macroEnabled" ascii wide

        $external1 = "Target=\"http" ascii wide nocase
        $external2 = "TargetMode=\"External\"" ascii wide nocase

    condition:
        $pk_magic at 0 and
        ($vba_proj or $vba_data) and
        1 of ($content_type*) and
        ($external1 or $external2)
}

rule Maldoc_OOXML_MSHTML_Exploit
{
    meta:
        description = "Detects OOXML documents exploiting MSHTML vulnerabilities (CVE-2021-40444)"
        author = "EDR Research Team"
        date = "2025-01-15"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-40444"
        severity = "critical"
        mitre_attack = "T1203, T1221"

    strings:
        $pk_magic = { 50 4B 03 04 }

        $rel_ext = "TargetMode=\"External\"" ascii wide nocase
        $rel_mhtml = "mhtml:" ascii wide nocase
        $rel_type = "http://schemas.openxmlformats.org/officeDocument/2006/relationships/oleObject" ascii wide

        $cab_ref = ".cab" ascii wide nocase
        $inf_ref = ".inf" ascii wide nocase
        $dll_ref = ".dll" ascii wide nocase

        $html_payload = "<html" ascii wide nocase
        $script_tag = "<script" ascii wide nocase
        $activex = "ActiveXObject" ascii wide nocase

    condition:
        $pk_magic at 0 and
        $rel_ext and
        ($rel_mhtml or $rel_type) and
        (1 of ($cab_ref, $inf_ref, $dll_ref) or ($html_payload and $script_tag))
}
