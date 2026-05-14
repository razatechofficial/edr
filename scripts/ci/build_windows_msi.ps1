# Build MSI using WiX v3 (candle/light). Requires candle on PATH or EDR_WIX_BIN (see ensure_wix_path.ps1).
param(
    [Parameter(Mandatory = $true)]
    [string]$Version
)

$ErrorActionPreference = 'Stop'
# candle.exe/light.exe write normal progress to stderr. PS 7.2+ can surface native stderr as a
# terminating error when $PSNativeCommandUseErrorActionPreference is true; keep legacy behavior.
if ($PSVersionTable.PSVersion.Major -ge 7) {
    $PSNativeCommandUseErrorActionPreference = $false
}
$root = $env:GITHUB_WORKSPACE
if ([string]::IsNullOrWhiteSpace($root)) {
    $root = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
}
Set-Location $root

function Normalize-WiXProductVersion([string]$raw) {
    $s = (($raw -replace '[\r\n]', '').Trim() -replace '^[vV]+', '')
    if ([string]::IsNullOrWhiteSpace($s)) { return '1.0.0.0' }
    $nums = @()
    foreach ($part in ($s -split '\.')) {
        if ($part -match '^(\d{1,5})') {
            $v = [int]$Matches[1]
            if ($v -gt 65535) { $v = 65535 }
            $nums += $v
        }
    }
    while ($nums.Count -lt 4) { $nums += 0 }
    if ($nums.Count -gt 4) { $nums = $nums[0..3] }
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

function Invoke-WiXTool {
    param(
        [string]$Label,
        [string]$ExePath,
        [string[]]$ArgList,
        [string]$OutLog,
        [string]$ErrLog
    )
    Write-Host "==> $Label"
    Write-Host "$ExePath $($ArgList -join ' ')"
    $p = Start-Process -WorkingDirectory $root -FilePath $ExePath -ArgumentList $ArgList `
        -Wait -PassThru -NoNewWindow `
        -RedirectStandardOutput $OutLog -RedirectStandardError $ErrLog
    if ($null -eq $p -or $p.ExitCode -ne 0) {
        $code = if ($null -eq $p) { 'null' } else { $p.ExitCode }
        Write-Host "---- $Label stdout (tail) ----"
        if (Test-Path -LiteralPath $OutLog) { Get-Content -LiteralPath $OutLog -Tail 80 | Write-Host }
        Write-Host "---- $Label stderr (tail) ----"
        if (Test-Path -LiteralPath $ErrLog) { Get-Content -LiteralPath $ErrLog -Tail 80 | Write-Host }
        throw "$Label failed with exit $code"
    }
}

$candleOut = Join-Path $root 'build/windows/candle-out.log'
$candleErr = Join-Path $root 'build/windows/candle-err.log'
$lightOut = Join-Path $root 'build/windows/light-out.log'
$lightErr = Join-Path $root 'build/windows/light-err.log'

Invoke-WiXTool -Label 'candle (WiX)' -ExePath $candleExe `
    -ArgList @('-nologo', '-arch', 'x64', "-dVersion=$Version", $wxs, '-o', $wixobj) `
    -OutLog $candleOut -ErrLog $candleErr

# -sval: skip ICE validation (CI often fails ICE on service installers; MSI still installs).
# -sw1076: suppress duplicate-file warnings when harmless.
Invoke-WiXTool -Label 'light (WiX)' -ExePath $lightExe `
    -ArgList @('-nologo', '-sval', '-sw1076', $wixobj, '-o', $msi) `
    -OutLog $lightOut -ErrLog $lightErr

Write-Host "Built: $msi"
