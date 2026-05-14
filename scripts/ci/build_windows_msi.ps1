# Build MSI using WiX v3 (candle/light). Requires candle on PATH or EDR_WIX_BIN (see ensure_wix_path.ps1).
param(
    [Parameter(Mandatory = $true)]
    [string]$Version
)

$ErrorActionPreference = 'Stop'
if ($PSVersionTable.PSVersion.Major -ge 7) {
    $PSNativeCommandUseErrorActionPreference = $false
}
$root = $env:GITHUB_WORKSPACE
if ([string]::IsNullOrWhiteSpace($root)) {
    $root = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
}
$root = [System.IO.Path]::GetFullPath($root.TrimEnd('\', '/'))
Set-Location -LiteralPath $root

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

function Invoke-WiXTool {
    param(
        [string]$Label,
        [string]$ExePath,
        [string[]]$ArgList,
        [string]$LogPath
    )
    Write-Host "==> $Label"
    Write-Host ("$ExePath " + ($ArgList -join ' '))
    # Start-Process + file redirects: avoids PS pipeline/LASTEXITCODE quirks and stderr→success-stream issues.
    $outF = Join-Path $env:TEMP ("edr-wix-{0}-stdout.log" -f [guid]::NewGuid().ToString('n'))
    $errF = Join-Path $env:TEMP ("edr-wix-{0}-stderr.log" -f [guid]::NewGuid().ToString('n'))
    try {
        # Use List<string> so Windows PowerShell 5.1 Start-Process forwards argv correctly (plain arrays can flatten wrong).
        $argColl = [System.Collections.Generic.List[string]]::new()
        foreach ($a in $ArgList) { $argColl.Add($a) }
        $p = Start-Process -FilePath $ExePath -ArgumentList $argColl -WorkingDirectory $root -Wait -PassThru -NoNewWindow `
            -RedirectStandardOutput $outF -RedirectStandardError $errF
        if ($null -eq $p) {
            throw "$Label failed to start process"
        }
        $code = $p.ExitCode
        $merged = @(
            (Get-Content -LiteralPath $outF -Raw -ErrorAction SilentlyContinue)
            (Get-Content -LiteralPath $errF -Raw -ErrorAction SilentlyContinue)
        ) -join "`n"
        if ([string]::IsNullOrWhiteSpace($merged)) { $merged = '(no output)' }
        Set-Content -LiteralPath $LogPath -Value $merged -NoNewline
        if ($code -ne 0) {
            Write-Host "---- $Label log ----"
            Write-Host $merged
            throw "$Label failed with exit $code"
        }
    }
    finally {
        Remove-Item -LiteralPath $outF, $errF -Force -ErrorAction SilentlyContinue
    }
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

$agentExe = [System.IO.Path]::GetFullPath((Join-Path $root 'dist/windows-amd64/edr-agent.exe'))
if (-not (Test-Path -LiteralPath $agentExe)) {
    throw "Missing Windows agent binary (build it first): $agentExe"
}
$configYml = [System.IO.Path]::GetFullPath((Join-Path $root 'build/windows/config.yml'))
if (-not (Test-Path -LiteralPath $configYml)) {
    throw "Missing build/windows/config.yml (WiX source file)"
}

New-Item -ItemType Directory -Force -Path 'dist' | Out-Null
New-Item -ItemType Directory -Force -Path 'build/windows' | Out-Null

$wxs = [System.IO.Path]::GetFullPath((Join-Path $root 'build/windows/installer.wxs'))
$wixobj = [System.IO.Path]::GetFullPath((Join-Path $root 'build/windows/installer.wixobj'))
$msi = [System.IO.Path]::GetFullPath((Join-Path $root "dist/edr-agent_${Version}_amd64.msi"))

$candleLog = Join-Path $root 'build/windows/candle.log'
$lightLog = Join-Path $root 'build/windows/light.log'

$candleArgList = @(
    '-nologo', '-arch', 'x64',
    "-dMsiProductVersion=$Version",
    "-dEdrAgentExe=$agentExe",
    "-dEdrConfigYml=$configYml",
    $wxs,
    '-o', $wixobj
)
Invoke-WiXTool -Label 'candle (WiX)' -ExePath $candleExe -ArgList $candleArgList -LogPath $candleLog

$lightArgList = @('-nologo', '-sval', '-sw1076', $wixobj, '-o', $msi)
Invoke-WiXTool -Label 'light (WiX)' -ExePath $lightExe -ArgList $lightArgList -LogPath $lightLog

Write-Host "Built: $msi"
