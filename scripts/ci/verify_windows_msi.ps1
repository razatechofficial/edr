# Verify a built Windows MSI includes fleet rollout profiles and core agent files.
param(
	[Parameter(Mandatory = $true)]
	[string]$MsiPath
)

$ErrorActionPreference = 'Stop'

if (-not (Test-Path -LiteralPath $MsiPath)) {
	throw "MSI not found: $MsiPath"
}

function Expand-MsiFileName {
	param([string]$Raw)
	if ([string]::IsNullOrWhiteSpace($Raw)) { return @() }
	# MSI FileName: "shortname|longname" or "longname" only.
	if ($Raw -match '\|') {
		$parts = $Raw -split '\|', 2
		$out = @()
		foreach ($p in $parts) {
			$p = $p.Trim()
			if ($p) { $out += $p }
		}
		return $out
	}
	return @($Raw.Trim())
}

function Get-MsiInstalledFileNames {
	param([string]$Path)
	$installer = New-Object -ComObject WindowsInstaller.Installer
	$db = $installer.GetType().InvokeMember('OpenDatabase', 'InvokeMethod', $null, $installer, @($Path, 0))
	# File column is the row key (e.g. AgentExe); FileName is the deployed name (e.g. edr-agent.exe).
	$view = $db.GetType().InvokeMember('OpenView', 'InvokeMethod', $null, $db, @('SELECT File, FileName FROM File'))
	$view.GetType().InvokeMember('Execute', 'InvokeMethod', $null, $view, $null) | Out-Null
	$names = New-Object System.Collections.Generic.HashSet[string]([StringComparer]::OrdinalIgnoreCase)
	while ($true) {
		$record = $view.GetType().InvokeMember('Fetch', 'InvokeMethod', $null, $view, $null)
		if ($null -eq $record) { break }
		$fileKey = [string]$record.StringData(1)
		$fileName = [string]$record.StringData(2)
		if ($fileKey) { [void]$names.Add($fileKey) }
		foreach ($n in (Expand-MsiFileName $fileName)) {
			[void]$names.Add($n)
		}
	}
	return $names
}

$files = Get-MsiInstalledFileNames -Path $MsiPath
$required = @(
	'edr-agent.exe',
	'edrctl.exe',
	'config.yml',
	'config.tenant.yml',
	'config.tenant.tls.yml',
	'config.fleet.tls.yml',
	'apply_tenant_config.bat',
	'apply_tenant_tls_config.bat'
)

# WiX File row keys when FileName is stored only as short 8.3 form.
$knownFileKeys = @{
	'edr-agent.exe' = @('AgentExe')
	'edrctl.exe'    = @('EdrCtlExe')
}

foreach ($name in $required) {
	if ($files.Contains($name)) { continue }
	$found = $false
	if ($knownFileKeys.ContainsKey($name)) {
		foreach ($key in $knownFileKeys[$name]) {
			if ($files.Contains($key)) { $found = $true; break }
		}
	}
	if (-not $found) {
		throw "MSI missing required file: $name"
	}
}

Write-Host "MSI verification passed: $MsiPath ($($files.Count) file entries)"
