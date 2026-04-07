rule Maldoc_PDF_JavaScript_Exploit
{
    meta:
        description = "Detects PDF documents with embedded JavaScript exploits"
        author = "EDR Research Team"
        date = "2025-01-15"
        reference = "https://attack.mitre.org/techniques/T1204.002/"
        severity = "high"
        mitre_attack = "T1204.002, T1059.007"

    strings:
        $pdf_magic = "%PDF-" ascii

        $js1 = "/JavaScript" ascii nocase
        $js2 = "/JS " ascii
        $js3 = "/JS(" ascii
        $js4 = "/JS<" ascii

        $action1 = "/OpenAction" ascii
        $action2 = "/AA" ascii
        $action3 = "/Names" ascii

        $exploit1 = "util.printf" ascii nocase
        $exploit2 = "Collab.collectEmailInfo" ascii nocase
        $exploit3 = "util.printd" ascii nocase
        $exploit4 = "app.doc.Collab" ascii nocase
        $exploit5 = "spell.customDictionaryOpen" ascii nocase
        $exploit6 = "media.newPlayer" ascii nocase
        $exploit7 = "getAnnots" ascii nocase
        $exploit8 = "getIcon" ascii nocase
        $exploit9 = "this.info" ascii nocase

        $heap1 = "unescape(" ascii nocase
        $heap2 = /%u[0-9A-Fa-f]{4}/ ascii
        $heap3 = "String.fromCharCode" ascii nocase
        $heap4 = /var\s+[a-z]+\s*=\s*unescape\(/ nocase

    condition:
        $pdf_magic at 0 and
        1 of ($js*) and
        1 of ($action*) and
        (1 of ($exploit*) or 2 of ($heap*))
}

rule Maldoc_PDF_Embedded_File_Execution
{
    meta:
        description = "Detects PDF documents with embedded files designed for execution"
        author = "EDR Research Team"
        date = "2025-01-15"
        reference = "https://attack.mitre.org/techniques/T1204.002/"
        severity = "high"
        mitre_attack = "T1204.002"

    strings:
        $pdf_magic = "%PDF-" ascii

        $embed1 = "/EmbeddedFile" ascii
        $embed2 = "/Filespec" ascii
        $embed3 = "/Type /Filespec" ascii

        $launch1 = "/Launch" ascii
        $launch2 = "/Win" ascii
        $launch3 = "/F (" ascii
        $launch4 = "/URI" ascii

        $exe1 = ".exe" ascii nocase
        $exe2 = ".bat" ascii nocase
        $exe3 = ".cmd" ascii nocase
        $exe4 = ".vbs" ascii nocase
        $exe5 = ".ps1" ascii nocase
        $exe6 = ".hta" ascii nocase

        $action = "/OpenAction" ascii

    condition:
        $pdf_magic at 0 and
        (1 of ($embed*) and 1 of ($launch*) and 1 of ($exe*)) or
        ($action and 1 of ($launch*) and 1 of ($exe*))
}

rule Maldoc_PDF_Encrypted_JavaScript
{
    meta:
        description = "Detects PDF documents with encrypted/obfuscated JavaScript payload"
        author = "EDR Research Team"
        date = "2025-01-15"
        reference = "https://attack.mitre.org/techniques/T1027/"
        severity = "high"
        mitre_attack = "T1027, T1059.007"

    strings:
        $pdf_magic = "%PDF-" ascii

        $encrypt1 = "/Encrypt" ascii
        $encrypt2 = "/StmF" ascii
        $encrypt3 = "/StrF" ascii
        $encrypt4 = "/V 2" ascii
        $encrypt5 = "/Filter /Standard" ascii

        $js_action = "/JavaScript" ascii
        $open_action = "/OpenAction" ascii
        $auto_action = "/AA" ascii

        $filter1 = "/FlateDecode" ascii
        $filter2 = "/ASCIIHexDecode" ascii
        $filter3 = "/ASCII85Decode" ascii
        $filter4 = "/LZWDecode" ascii
        $filter5 = "/RunLengthDecode" ascii

        $multi_filter = /\/Filter\s*\[\s*\/[A-Za-z]+Decode\s+\/[A-Za-z]+Decode/ ascii

    condition:
        $pdf_magic at 0 and
        (1 of ($encrypt*) and ($js_action or $open_action or $auto_action)) or
        ($multi_filter and ($js_action or $open_action)) or
        (2 of ($filter*) and $js_action and $open_action)
}
