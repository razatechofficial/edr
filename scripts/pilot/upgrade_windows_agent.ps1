# Upgrade an installed Windows agent MSI while preserving config and agent_id.
param(
	[Parameter(Mandatory = $true)]
	[string]$MsiPath
)

$ErrorActionPreference = 'Stop'
$root = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent

if (-not (Test-Path -LiteralPath $MsiPath)) {
	throw "MSI not found: $MsiPath"
}

& "$root/scripts/ci/verify_windows_msi.ps1" -MsiPath $MsiPath

Write-Host "==> upgrade EDRAgent from $MsiPath"
$proc = Start-Process -FilePath msiexec.exe -ArgumentList @('/i', $MsiPath, '/qn', '/norestart') -Wait -PassThru
if ($proc.ExitCode -ne 0 -and $proc.ExitCode -ne 3010) {
	throw "msiexec failed with exit code $($proc.ExitCode)"
}

Start-Sleep -Seconds 5
$svc = Get-Service -Name EDRAgent -ErrorAction SilentlyContinue
if (-not $svc -or $svc.Status -ne 'Running') {
	if ($svc) { Start-Service EDRAgent }
	Start-Sleep -Seconds 3
	$svc = Get-Service -Name EDRAgent
}
if ($svc.Status -ne 'Running') {
	throw 'EDRAgent service is not running after upgrade'
}

& "$PSScriptRoot/verify_windows_tenant.ps1" -ControlPlaneHost $env:EDR_CONTROL_PLANE_HOST
Write-Host 'Windows agent upgrade OK'
