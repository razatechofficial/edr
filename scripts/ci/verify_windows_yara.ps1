# Verify Windows release build includes live YARA (CGO + libyara DLL).
param(
    [string]$Root = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
)

$ErrorActionPreference = 'Stop'
$dist = Join-Path $Root 'dist/windows-amd64'
$agent = Join-Path $dist 'edr-agent.exe'

if (-not (Test-Path -LiteralPath $agent)) {
    throw "missing Windows agent binary: $agent"
}

$dlls = @(Get-ChildItem -LiteralPath $dist -Filter 'libyara*.dll' -ErrorAction SilentlyContinue)
if ($dlls.Count -eq 0) {
    throw "libyara DLL missing next to edr-agent.exe; YARA toolchain step failed or bundle_windows_yara.ps1 found nothing"
}

Write-Host "Windows YARA OK: $($dlls.Count) libyara DLL(s) bundled with edr-agent.exe"
