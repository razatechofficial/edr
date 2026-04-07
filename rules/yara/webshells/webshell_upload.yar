rule Webshell_Upload_PHP
{
    meta:
        description = "Detects PHP file upload web shells"
        author = "EDR Research Team"
        date = "2025-01-15"
        reference = "https://attack.mitre.org/techniques/T1505.003/"
        severity = "high"
        mitre_attack = "T1505.003, T1105"

    strings:
        $php = "<?php" ascii nocase

        $upload1 = "move_uploaded_file(" ascii nocase
        $upload2 = "$_FILES[" ascii nocase
        $upload3 = "tmp_name" ascii nocase
        $upload4 = "is_uploaded_file(" ascii nocase
        $upload5 = "copy($_FILES" ascii nocase

        $no_check1 = /move_uploaded_file\s*\(\s*\$_FILES\s*\[/ nocase
        $no_check2 = /\$_FILES\s*\[\s*['"][a-z]+['"]\s*\]\s*\[\s*['"]tmp_name['"]\s*\]/ nocase

        $exec1 = "eval(" ascii nocase
        $exec2 = "system(" ascii nocase
        $exec3 = "exec(" ascii nocase
        $exec4 = "include(" ascii nocase
        $exec5 = "include_once(" ascii nocase
        $exec6 = "require(" ascii nocase

        $ext_bypass1 = ".php" ascii nocase
        $ext_bypass2 = "Content-Type" ascii nocase
        $ext_bypass3 = "UPLOAD_ERR_OK" ascii nocase

    condition:
        $php and
        (2 of ($upload*) and 1 of ($exec*)) or
        ($no_check1 and 1 of ($exec*)) or
        (2 of ($upload*) and 2 of ($ext_bypass*) and filesize < 50KB)
}

rule Webshell_Upload_ASPX
{
    meta:
        description = "Detects ASPX file upload web shells"
        author = "EDR Research Team"
        date = "2025-01-15"
        reference = "https://attack.mitre.org/techniques/T1505.003/"
        severity = "high"
        mitre_attack = "T1505.003, T1105"

    strings:
        $aspx = "<%@" ascii nocase

        $upload1 = "FileUpload" ascii wide nocase
        $upload2 = "SaveAs(" ascii wide nocase
        $upload3 = "PostedFile" ascii wide nocase
        $upload4 = "HttpPostedFile" ascii wide nocase
        $upload5 = "Server.MapPath" ascii wide nocase

        $exec1 = "Process.Start" ascii wide nocase
        $exec2 = "System.Diagnostics" ascii wide nocase
        $exec3 = "cmd.exe" ascii wide nocase

        $write1 = "File.WriteAllBytes" ascii wide nocase
        $write2 = "FileStream" ascii wide nocase
        $write3 = "BinaryWriter" ascii wide nocase

    condition:
        $aspx and
        2 of ($upload*) and
        (1 of ($exec*) or 1 of ($write*))
}

rule Webshell_Upload_JSP
{
    meta:
        description = "Detects JSP file upload web shells"
        author = "EDR Research Team"
        date = "2025-01-15"
        reference = "https://attack.mitre.org/techniques/T1505.003/"
        severity = "high"
        mitre_attack = "T1505.003, T1105"

    strings:
        $jsp = "<%" ascii

        $upload1 = "MultipartRequest" ascii nocase
        $upload2 = "FileItem" ascii nocase
        $upload3 = "DiskFileItemFactory" ascii nocase
        $upload4 = "getInputStream" ascii nocase
        $upload5 = "FileOutputStream" ascii nocase

        $exec1 = "Runtime.getRuntime().exec" ascii nocase
        $exec2 = "ProcessBuilder" ascii nocase
        $exec3 = "cmd.exe" ascii wide nocase
        $exec4 = "/bin/sh" ascii

        $write1 = "FileWriter" ascii nocase
        $write2 = "BufferedWriter" ascii nocase
        $write3 = "transferTo" ascii nocase

    condition:
        $jsp and
        2 of ($upload*) and
        (1 of ($exec*) or 1 of ($write*))
}
