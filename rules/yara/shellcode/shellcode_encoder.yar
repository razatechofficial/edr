rule Shellcode_Encoder_Shikata_Ga_Nai
{
    meta:
        description = "Detects shikata_ga_nai polymorphic XOR encoder shellcode"
        author = "EDR Research Team"
        date = "2025-01-15"
        reference = "https://attack.mitre.org/techniques/T1027/"
        severity = "critical"
        mitre_attack = "T1027, T1055"

    strings:
        $sgn_x86_1 = { D9 74 24 F4 5? 29 C9 B1 ?? 31 ?? 17 83 ?? 04 03 }
        $sgn_x86_2 = { DA C? D9 74 24 F4 5? 29 C9 B1 ?? 31 }
        $sgn_x86_3 = { D9 E8 D9 74 24 F4 5? 29 C9 B1 ?? 31 }
        $sgn_x86_4 = { D9 74 24 F4 5? B? ?? ?? ?? ?? 29 C9 B1 ?? 83 ?? 04 31 }

        $fnstenv = { D9 74 24 F4 }
        $counter_set = { 29 C9 B1 }

    condition:
        1 of ($sgn_x86_*) or
        ($fnstenv and $counter_set and filesize < 100KB)
}

rule Shellcode_Encoder_XOR_Loop
{
    meta:
        description = "Detects XOR-encoded shellcode with decoder stub"
        author = "EDR Research Team"
        date = "2025-01-15"
        reference = "https://attack.mitre.org/techniques/T1027/"
        severity = "high"
        mitre_attack = "T1027"

    strings:
        $xor_byte_loop = { 80 34 ?? ?? 40 3B C? 72 F? }
        $xor_byte_loop2 = { 80 30 ?? 40 49 75 F? }
        $xor_byte_loop3 = { 8A 04 ?? 34 ?? 88 04 ?? 4? 3B ?? 72 }
        $xor_dword_loop = { 31 ?? 83 C? 04 3B ?? 72 }
        $xor_dword_loop2 = { 81 34 ?? ?? ?? ?? ?? 83 C? 04 }
        $sub_loop = { 80 2C ?? ?? 4? 79 F? }

        $get_eip = { E8 00 00 00 00 5? }
        $jmp_fwd = { EB ?? }

    condition:
        ($get_eip or $jmp_fwd) and 1 of ($xor_byte_loop, $xor_byte_loop2, $xor_byte_loop3, $xor_dword_loop, $xor_dword_loop2, $sub_loop) and
        filesize < 500KB
}

rule Shellcode_Encoder_Alpha_Mixed
{
    meta:
        description = "Detects alphanumeric encoded shellcode (alpha_mixed encoder)"
        author = "EDR Research Team"
        date = "2025-01-15"
        reference = "https://attack.mitre.org/techniques/T1027/"
        severity = "high"
        mitre_attack = "T1027"

    strings:
        $alpha_x86 = { 89 E2 DA C1 D9 72 F4 58 50 59 49 49 49 49 43 43 43 43 43 43 51 5A }
        $alpha_mixed_1 = { 56 59 49 49 49 49 49 49 49 49 49 49 49 49 49 49 49 49 }
        $alpha_uni = { 49 49 49 49 49 49 49 49 49 49 49 49 49 49 49 49 37 51 5A 6A 41 58 50 30 }

        $alpha_getpc = /[A-Za-z0-9]{4}jYAIAIAIAIAIAIAIA/ ascii

    condition:
        any of them and filesize < 500KB
}

rule Shellcode_Encoder_Base64_Shellcode
{
    meta:
        description = "Detects Base64-encoded shellcode blobs"
        author = "EDR Research Team"
        date = "2025-01-15"
        reference = "https://attack.mitre.org/techniques/T1140/"
        severity = "medium"
        mitre_attack = "T1140, T1027"

    strings:
        $b64_mz = "TVqQAAMAAAAEAAAA" ascii wide
        $b64_shellcode1 = "/EiD5PDo" ascii wide
        $b64_shellcode2 = "/OiCAAAA" ascii wide
        $b64_shellcode3 = "AAAAAAAAAAAAAAA" ascii wide

        $decode_api = "CryptStringToBinaryA" ascii
        $decode_ps = "FromBase64String" ascii wide
        $decode_python = "base64.b64decode" ascii
        $decode_cs = "Convert.FromBase64String" ascii wide

    condition:
        1 of ($b64_mz, $b64_shellcode1, $b64_shellcode2) and
        1 of ($decode_api, $decode_ps, $decode_python, $decode_cs)
}
