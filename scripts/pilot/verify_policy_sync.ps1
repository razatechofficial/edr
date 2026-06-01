# Compare control plane and local agent policy hashes.
param(
	[string]$ControlPlaneHost = $env:EDR_CONTROL_PLANE_HOST,
	[string]$DataDir = $env:EDR_AGENT_DATA_DIR,
	[int]$HttpPort = $(if ($env:EDR_CONTROLPLANE_HTTP_PORT) { [int]$env:EDR_CONTROLPLANE_HTTP_PORT } else { 8080 })
)

$ErrorActionPreference = 'Stop'

if ([string]::IsNullOrWhiteSpace($ControlPlaneHost)) {
	throw 'usage: verify_policy_sync.ps1 -ControlPlaneHost <host> [-DataDir path]'
}

if ([string]::IsNullOrWhiteSpace($DataDir)) {
	$DataDir = Join-Path $env:ProgramData 'EDR Agent'
}

$scheme = 'http'
if ($env:EDR_CONTROLPLANE_HTTPS -eq '1' -or $env:EDR_CONTROLPLANE_HTTPS -eq 'true') {
	$scheme = 'https'
}

$url = "$scheme://${ControlPlaneHost}:$HttpPort/v1/policy"
$curlArgs = @('-fsS')
if ($scheme -eq 'https') {
	$caCert = $env:EDR_CONTROLPLANE_CA
	if (-not $caCert) {
		$caCert = Join-Path $env:ProgramData 'EDR Agent\tls\ca.crt'
	}
	if (Test-Path -LiteralPath $caCert) {
		$curlArgs += @('--cacert', $caCert)
	}
}
if ($env:EDR_CONTROLPLANE_API_TOKEN) {
	$curlArgs += @('-H', "Authorization: Bearer $($env:EDR_CONTROLPLANE_API_TOKEN)")
}

$json = & curl.exe @curlArgs $url
$response = $json | ConvertFrom-Json
$cpHash = [string]$response.policy_hash

$hashFile = Join-Path $DataDir 'controlplane-policy.hash'
if (-not (Test-Path -LiteralPath $hashFile)) {
	throw "missing agent policy hash: $hashFile"
}
$agentHash = ((Get-Content -LiteralPath $hashFile -Raw).Trim())

if ([string]::IsNullOrWhiteSpace($cpHash) -or $cpHash -eq 'local-default') {
	throw 'control plane has no staged policy bundles'
}
if ([string]::IsNullOrWhiteSpace($agentHash) -or $agentHash -eq 'local-default') {
	throw "invalid agent policy hash: $agentHash"
}
if ($cpHash -ne $agentHash) {
	throw "policy hash mismatch`n  control plane: $cpHash`n  agent:         $agentHash"
}

Write-Host "policy hash matched: $cpHash"
Write-Host "policy sync verification OK"
