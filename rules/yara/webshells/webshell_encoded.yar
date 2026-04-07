rule Webshell_PHP_Base64_Encoded
{
    meta:
        description = "Detects Base64-encoded PHP web shells"
        author = "EDR Research Team"
        date = "2025-01-15"
        reference = "https://attack.mitre.org/techniques/T1027/"
        severity = "high"
        mitre_attack = "T1505.003, T1027"

    strings:
        $php = "<?php" ascii nocase

        $decode1 = "base64_decode(" ascii nocase
        $decode2 = "gzinflate(" ascii nocase
        $decode3 = "gzuncompress(" ascii nocase
        $decode4 = "gzdecode(" ascii nocase
        $decode5 = "str_rot13(" ascii nocase
        $decode6 = "strrev(" ascii nocase

        $eval1 = "eval(" ascii nocase
        $eval2 = "assert(" ascii nocase
        $eval3 = "preg_replace" ascii nocase
        $eval4 = "create_function" ascii nocase

        $nested1 = "eval(gzinflate(base64_decode(" ascii nocase
        $nested2 = "eval(base64_decode(" ascii nocase
        $nested3 = "eval(gzuncompress(base64_decode(" ascii nocase
        $nested4 = "assert(base64_decode(" ascii nocase

        $long_b64 = /[A-Za-z0-9\+\/=]{500,}/ ascii

    condition:
        $php and
        (1 of ($nested*) or
         (1 of ($eval*) and 1 of ($decode*) and $long_b64) or
         (2 of ($decode*) and 1 of ($eval*)))
}

rule Webshell_Hex_Encoded
{
    meta:
        description = "Detects hex-encoded web shell payloads"
        author = "EDR Research Team"
        date = "2025-01-15"
        reference = "https://attack.mitre.org/techniques/T1027/"
        severity = "high"
        mitre_attack = "T1505.003, T1027"

    strings:
        $php = "<?php" ascii nocase

        $hex_decode1 = "hex2bin(" ascii nocase
        $hex_decode2 = "pack(\"H*\"" ascii nocase
        $hex_decode3 = "\\x" ascii
        $chr_build = /chr\s*\(\s*0x[0-9a-fA-F]{2}\s*\)/ nocase

        $eval1 = "eval(" ascii nocase
        $eval2 = "assert(" ascii nocase

        $hex_str = /([0-9a-fA-F]{2}){50,}/ ascii

    condition:
        $php and
        (1 of ($hex_decode*) or $chr_build) and
        1 of ($eval*) and
        $hex_str
}

rule Webshell_Obfuscated_Variable_Function
{
    meta:
        description = "Detects web shells using variable function name obfuscation"
        author = "EDR Research Team"
        date = "2025-01-15"
        reference = "https://attack.mitre.org/techniques/T1027/"
        severity = "high"
        mitre_attack = "T1505.003, T1027"

    strings:
        $php = "<?php" ascii nocase

        $var_func1 = /\$[a-zA-Z_]{1,20}\s*=\s*['"](eval|system|exec|passthru|shell_exec)['"]/ nocase
        $var_func2 = /\$[a-zA-Z_]{1,20}\s*\(\s*\$_(POST|GET|REQUEST|COOKIE)/ nocase
        $var_func3 = /\$[a-zA-Z_]{1,20}\s*=\s*str_rot13\s*\(/ nocase
        $var_func4 = /\$[a-zA-Z_]{1,20}\s*=\s*base64_decode\s*\(/ nocase

        $concat1 = /\$[a-z]\s*=\s*['"][a-z]{1,5}['"]\s*\.\s*['"][a-z]{1,5}['"]/ nocase
        $concat2 = /\$[a-z]\s*\.=\s*['"][a-z]{1,3}['"]/ nocase

    condition:
        $php and (2 of ($var_func*) or (1 of ($var_func*) and 2 of ($concat*)))
}
