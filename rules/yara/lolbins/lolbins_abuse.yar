rule LOLBin_CertUtil_Download {
    meta:
        description = "CertUtil used for file download (T1105)"
        technique = "T1105"
        severity = "high"
    strings:
        $s1 = "certutil" nocase
        $s2 = "-urlcache" nocase
        $s3 = "-split" nocase
        $url = /https?:\/\// nocase
    condition:
        ($s1 and $s2 and $url) or ($s1 and $s3 and $url)
}

rule LOLBin_MSHTA_Execution {
    meta:
        description = "MSHTA executing remote content (T1218.005)"
        technique = "T1218.005"
    strings:
        $s1 = "mshta" nocase
        $r1 = /https?:\/\/[^\s]{10,}/ nocase
        $s2 = "javascript:" nocase
        $s3 = "vbscript:" nocase
    condition:
        $s1 and ($r1 or $s2 or $s3)
}

rule LOLBin_Regsvr32_Squiblydoo {
    meta:
        description = "Regsvr32 SCT execution (T1218.010)"
        technique = "T1218.010"
    strings:
        $s1 = "regsvr32" nocase
        $s2 = "/s" nocase
        $s3 = "/i:" nocase
        $r1 = /https?:\/\//
    condition:
        $s1 and $s2 and $s3 and $r1
}
