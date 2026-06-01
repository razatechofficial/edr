# Validate a code-signing PFX before uploading to GitHub Actions secrets.
param(
	[Parameter(Mandatory = $true)]
	[string]$PfxPath,
	[string]$Password = ''
)

$ErrorActionPreference = 'Stop'

if (-not (Test-Path -LiteralPath $PfxPath)) {
	throw "PFX not found: $PfxPath"
}

$securePass = if ($Password) { ConvertTo-SSecureString $Password -AsPlainText -Force } else { $null }
try {
	$cert = if ($securePass) {
		New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($PfxPath, $securePass)
	} else {
		New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($PfxPath)
	}
} catch {
	throw "Failed to load PFX (check password): $($_.Exception.Message)"
}

$now = Get-Date
Write-Host "Subject: $($cert.Subject)"
Write-Host "Issuer:  $($cert.Issuer)"
Write-Host "NotBefore: $($cert.NotBefore.ToUniversalTime().ToString('o'))"
Write-Host "NotAfter:  $($cert.NotAfter.ToUniversalTime().ToString('o'))"
Write-Host "HasPrivateKey: $($cert.HasPrivateKey)"
Write-Host "Thumbprint: $($cert.Thumbprint)"

if (-not $cert.HasPrivateKey) {
	throw "PFX does not contain a private key"
}
if ($now -lt $cert.NotBefore) {
	throw "Certificate is not yet valid"
}
if ($now -gt $cert.NotAfter) {
	throw "Certificate is expired"
}

Write-Host "PFX validation OK"
