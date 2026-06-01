# Stage detection rules and generate WiX fragment for MSI packaging.
param(
    [Parameter(Mandatory = $true)]
    [string]$Root
)

$ErrorActionPreference = 'Stop'
$root = [System.IO.Path]::GetFullPath($Root.TrimEnd('\', '/'))
$rulesStage = Join-Path $root 'build/windows/msi-rules'
$rulesWxs = Join-Path $root 'build/windows/rules.wxs'

if (Test-Path -LiteralPath $rulesStage) {
    Remove-Item -LiteralPath $rulesStage -Recurse -Force
}
New-Item -ItemType Directory -Force -Path $rulesStage | Out-Null

function Copy-RuleTree {
    param(
        [string]$SourceRelative,
        [string]$DestRelative
    )
    $src = Join-Path $root $SourceRelative
    if (-not (Test-Path -LiteralPath $src)) {
        Write-Host "skip missing rules tree: $SourceRelative"
        return
    }
    $dest = Join-Path $rulesStage $DestRelative
    New-Item -ItemType Directory -Force -Path (Split-Path -Parent $dest) | Out-Null
    Copy-Item -LiteralPath $src -Destination $dest -Recurse -Force
}

Copy-RuleTree 'rules/sigma' 'sigma'
Copy-RuleTree 'rules/yara' 'yara'
Copy-RuleTree 'rules/ioc' 'ioc'
Copy-RuleTree 'rules/playbooks' 'playbooks'
Copy-RuleTree 'rules/custom' 'custom'
Copy-RuleTree 'rules/compliance/sca/windows' 'compliance/sca'

$configSrc = Join-Path $root 'configs/windows/config.yml'
$configDest = Join-Path $root 'build/windows/config.yml'
New-Item -ItemType Directory -Force -Path (Split-Path -Parent $configDest) | Out-Null
Copy-Item -LiteralPath $configSrc -Destination $configDest -Force

$heatExe = 'heat.exe'
if (-not [string]::IsNullOrWhiteSpace($env:EDR_WIX_BIN)) {
    $heatExe = Join-Path $env:EDR_WIX_BIN 'heat.exe'
}
if (-not (Get-Command $heatExe -ErrorAction SilentlyContinue)) {
    throw "heat.exe not on PATH; run ensure_wix_path.ps1 first or set EDR_WIX_BIN"
}

Write-Host "==> heat rules fragment"
& $heatExe dir $rulesStage `
    -cg RulesComponents `
    -dr RULESROOT `
    -var var.RulesStage `
    -srd `
    -scom `
    -sreg `
    -gg `
    -out $rulesWxs `
    -nologo
if ($LASTEXITCODE -ne 0) {
    throw "heat failed with exit $LASTEXITCODE"
}
Write-Host "Staged rules -> $rulesWxs"
