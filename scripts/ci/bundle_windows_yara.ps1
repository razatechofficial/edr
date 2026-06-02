# Copy libyara runtime DLLs next to edr-agent.exe for service load path.
param(
	[string]$Root = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
)

$ErrorActionPreference = 'Stop'
$dist = Join-Path $Root 'dist/windows-amd64'
if (-not (Test-Path (Join-Path $dist 'edr-agent.exe'))) {
	Write-Host "skip bundle: edr-agent.exe missing"
	exit 0
}

$triplet = if ($env:EDR_VCPKG_TRIPLET) { $env:EDR_VCPKG_TRIPLET } else { 'x64-mingw-dynamic' }
$searchRoots = @(
	Join-Path $env:RUNNER_TEMP "vcpkg-edr/installed/$triplet/bin"
)
if (-not [string]::IsNullOrWhiteSpace($env:PKG_CONFIG_PATH)) {
	$libRoot = Split-Path -Parent $env:PKG_CONFIG_PATH
	$searchRoots += (Join-Path $libRoot '..\bin' | Resolve-Path -ErrorAction SilentlyContinue)
}

$copied = 0
foreach ($root in $searchRoots) {
	if (-not $root -or -not (Test-Path -LiteralPath $root)) { continue }
	Get-ChildItem -LiteralPath $root -Filter 'libyara*.dll' -ErrorAction SilentlyContinue | ForEach-Object {
		Copy-Item -LiteralPath $_.FullName -Destination (Join-Path $dist $_.Name) -Force
		Write-Host "bundled $($_.Name)"
		$copied++
	}
}
if ($copied -eq 0) {
	Write-Host "warning: no libyara DLL found to bundle"
}
