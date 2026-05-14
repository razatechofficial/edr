# Build MSI using WiX v3 (candle/light). Requires candle on PATH (see ensure_wix_path.ps1).
param(
    [Parameter(Mandatory = $true)]
    [string]$Version
)

$ErrorActionPreference = 'Stop'
$root = $env:GITHUB_WORKSPACE
if ([string]::IsNullOrWhiteSpace($root)) {
    $root = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
}
Set-Location $root

$Version = $Version.Trim().Trim([char]0x0D)
if ([string]::IsNullOrWhiteSpace($Version)) {
    $Version = '1.0.0.0'
}

if (-not (Get-Command candle -ErrorAction SilentlyContinue)) {
    throw "candle.exe not on PATH; run ensure_wix_path.ps1 first"
}
if (-not (Get-Command light -ErrorAction SilentlyContinue)) {
    throw "light.exe not on PATH; run ensure_wix_path.ps1 first"
}

New-Item -ItemType Directory -Force -Path 'dist' | Out-Null
New-Item -ItemType Directory -Force -Path 'build/windows' | Out-Null

$wxs = Join-Path $root 'build/windows/installer.wxs'
$wixobj = Join-Path $root 'build/windows/installer.wixobj'
$msi = Join-Path $root "dist/edr-agent_${Version}_amd64.msi"

Write-Host "==> candle (WiX) Version=$Version"
& candle -nologo -arch x64 "-dVersion=$Version" $wxs -o $wixobj
if ($LASTEXITCODE -ne 0) { throw "candle failed with exit $LASTEXITCODE" }

Write-Host "==> light (WiX)"
# -sval: skip ICE validation (CI runners often fail ICE on service installers; MSI still installs).
# -sw1076: suppress duplicate-file warnings when harmless.
& light -nologo -sval -sw1076 $wixobj -o $msi
if ($LASTEXITCODE -ne 0) { throw "light failed with exit $LASTEXITCODE" }

Write-Host "Built: $msi"
