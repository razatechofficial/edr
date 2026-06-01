# Verify local agent applied a control-plane policy hash.
param(
	[string]$DataDir = $env:EDR_AGENT_DATA_DIR
)

$ErrorActionPreference = 'Stop'

if ([string]::IsNullOrWhiteSpace($DataDir)) {
	$DataDir = Join-Path $env:ProgramData 'EDR Agent'
}

$hashFile = Join-Path $DataDir 'controlplane-policy.hash'
if (-not (Test-Path -LiteralPath $hashFile)) {
	throw "no control plane policy hash at $hashFile (agent may not have synced yet)"
}

$hash = ((Get-Content -LiteralPath $hashFile -Raw).Trim())
if ([string]::IsNullOrWhiteSpace($hash) -or $hash -eq 'local-default') {
	throw "invalid policy hash in ${hashFile}: $hash"
}

Write-Host "agent policy hash: $hash"
Write-Host 'agent policy sync OK'
