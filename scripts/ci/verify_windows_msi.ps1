# Verify a built Windows MSI includes fleet rollout profiles and core agent files.
param(
	[Parameter(Mandatory = $true)]
	[string]$MsiPath
)

$ErrorActionPreference = 'Stop'

if (-not (Test-Path -LiteralPath $MsiPath)) {
	throw "MSI not found: $MsiPath"
}

function Get-MsiFileNames {
	param([string]$Path)
	$installer = New-Object -ComObject WindowsInstaller.Installer
	$db = $installer.GetType().InvokeMember('OpenDatabase', 'InvokeMethod', $null, $installer, @($Path, 0))
	$view = $db.GetType().InvokeMember('OpenView', 'InvokeMethod', $null, $db, @('SELECT File FROM File'))
	$view.GetType().InvokeMember('Execute', 'InvokeMethod', $null, $view, $null) | Out-Null
	$names = New-Object System.Collections.Generic.List[string]
	while ($true) {
		$record = $view.GetType().InvokeMember('Fetch', 'InvokeMethod', $null, $view, $null)
		if ($null -eq $record) { break }
		$names.Add([string]$record.StringData(1)) | Out-Null
	}
	return $names
}

$files = Get-MsiFileNames -Path $MsiPath
$required = @(
	'edr-agent.exe',
	'config.yml',
	'config.tenant.yml',
	'config.tenant.tls.yml',
	'config.fleet.tls.yml',
	'apply_tenant_config.bat',
	'apply_tenant_tls_config.bat'
)

foreach ($name in $required) {
	if ($files -notcontains $name) {
		throw "MSI missing required file: $name"
	}
}

Write-Host "MSI verification passed: $MsiPath ($($files.Count) files)"
