# Build MSI using WiX v3 (candle/light). Requires candle on PATH or EDR_WIX_BIN (see ensure_wix_path.ps1).
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

function Normalize-WiXProductVersion([string]$raw) {
    $s = ($raw -replace '[\r\n]', '').Trim().TrimStart('v', 'V')
    if ([string]::IsNullOrWhiteSpace($s)) { return '1.0.0.0' }
    $nums = [System.Collections.Generic.List[int]]::new()
    foreach ($part in ($s -split '\.')) {
        if ($part -match '^(\d{1,5})') {
            $v = [int]$Matches[1]
            if ($v -gt 65535) { $v = 65535 }
            $nums.Add($v) | Out-Null
        }
    }
    while ($nums.Count -lt 4) { $nums.Add(0) | Out-Null }
    if ($nums.Count -gt 4) { $nums = $nums.GetRange(0, 4) }
    return ($nums -join '.')
}

$Version = Normalize-WiXProductVersion $Version
Write-Host "WiX Product Version (normalized): $Version"

$candleExe = 'candle'
$lightExe = 'light'
if (-not [string]::IsNullOrWhiteSpace($env:EDR_WIX_BIN)) {
    $candleExe = Join-Path $env:EDR_WIX_BIN 'candle.exe'
    $lightExe = Join-Path $env:EDR_WIX_BIN 'light.exe'
    if (-not (Test-Path -LiteralPath $candleExe)) { throw "candle.exe not found at $candleExe (EDR_WIX_BIN)" }
    if (-not (Test-Path -LiteralPath $lightExe)) { throw "light.exe not found at $lightExe (EDR_WIX_BIN)" }
} else {
    if (-not (Get-Command candle -ErrorAction SilentlyContinue)) {
        throw "candle.exe not on PATH; run ensure_wix_path.ps1 first or set EDR_WIX_BIN"
    }
    if (-not (Get-Command light -ErrorAction SilentlyContinue)) {
        throw "light.exe not on PATH; run ensure_wix_path.ps1 first or set EDR_WIX_BIN"
    }
}

$agentExe = Join-Path $root 'dist/windows-amd64/edr-agent.exe'
if (-not (Test-Path -LiteralPath $agentExe)) {
    throw "Missing Windows agent binary (build it first): $agentExe"
}

New-Item -ItemType Directory -Force -Path 'dist' | Out-Null
New-Item -ItemType Directory -Force -Path 'build/windows' | Out-Null

$wxs = Join-Path $root 'build/windows/installer.wxs'
$wixobj = Join-Path $root 'build/windows/installer.wixobj'
$msi = Join-Path $root "dist/edr-agent_${Version}_amd64.msi"

Write-Host "==> candle (WiX) Version=$Version"
& $candleExe -nologo -arch x64 "-dVersion=$Version" $wxs -o $wixobj
if ($LASTEXITCODE -ne 0) { throw "candle failed with exit $LASTEXITCODE" }

Write-Host "==> light (WiX)"
# -sval: skip ICE validation (CI often fails ICE on service installers; MSI still installs).
# -sw1076: suppress duplicate-file warnings when harmless.
& $lightExe -nologo -sval -sw1076 $wixobj -o $msi
if ($LASTEXITCODE -ne 0) { throw "light failed with exit $LASTEXITCODE" }

Write-Host "Built: $msi"
