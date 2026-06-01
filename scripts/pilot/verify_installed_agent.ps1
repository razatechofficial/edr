# Post-install smoke on a Windows fleet endpoint.
param(
	[string]$ControlPlaneHost = $env:EDR_CONTROL_PLANE_HOST
)

$ErrorActionPreference = 'Stop'
& "$PSScriptRoot\verify_windows_tenant.ps1" -ControlPlaneHost $ControlPlaneHost
