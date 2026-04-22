rule Cloud_AWS_Credentials {
    meta:
        description = "AWS credentials in file (T1552.001)"
        technique = "T1552.001"
    strings:
        $key = /AKIA[0-9A-Z]{16}/
        $secret = "aws_secret_access_key"
        $creds_file = ".aws/credentials"
    condition:
        $key or ($secret and $creds_file)
}

rule Cloud_GCP_ServiceAccount {
    meta:
        description = "GCP service account key file"
        technique = "T1552.001"
    strings:
        $s1 = "\"type\": \"service_account\""
        $s2 = "\"private_key_id\""
        $s3 = "\"private_key\""
    condition:
        all of them
}
