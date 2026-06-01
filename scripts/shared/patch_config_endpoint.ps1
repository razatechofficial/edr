param(
	[Parameter(Mandatory = $true)]
	[string]$ConfigPath,
	[Parameter(Mandatory = $true)]
	[string]$Endpoint
)

$ErrorActionPreference = 'Stop'

if (-not (Test-Path -LiteralPath $ConfigPath)) {
	throw "config not found: $ConfigPath"
}
$endpoint = $Endpoint.Trim()
if ([string]::IsNullOrWhiteSpace($endpoint)) {
	throw "endpoint required"
}
if ($endpoint -match '\s') {
	throw "endpoint must not contain whitespace"
}

$content = Get-Content -LiteralPath $ConfigPath -Raw
$updated = $content -replace 'YOUR_CONTROL_PLANE_HOST', $endpoint
if ($updated -eq $content) {
	Write-Warning "placeholder YOUR_CONTROL_PLANE_HOST not found in $ConfigPath"
}
Set-Content -LiteralPath $ConfigPath -Value $updated -NoNewline
