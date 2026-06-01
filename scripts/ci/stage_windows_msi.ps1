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

$configHardenedSrc = Join-Path $root 'configs/windows/config.hardened.yml'
$configHardenedDest = Join-Path $root 'build/windows/config.hardened.yml'
if (Test-Path -LiteralPath $configHardenedSrc) {
    Copy-Item -LiteralPath $configHardenedSrc -Destination $configHardenedDest -Force
}

$configEnterpriseSrc = Join-Path $root 'configs/windows/config.enterprise.yml'
$configEnterpriseDest = Join-Path $root 'build/windows/config.enterprise.yml'
if (Test-Path -LiteralPath $configEnterpriseSrc) {
    Copy-Item -LiteralPath $configEnterpriseSrc -Destination $configEnterpriseDest -Force
}

$configFleetSrc = Join-Path $root 'configs/windows/config.fleet.yml'
$configFleetDest = Join-Path $root 'build/windows/config.fleet.yml'
if (Test-Path -LiteralPath $configFleetSrc) {
    Copy-Item -LiteralPath $configFleetSrc -Destination $configFleetDest -Force
}

$configTenantSrc = Join-Path $root 'configs/windows/config.tenant.yml'
$configTenantDest = Join-Path $root 'build/windows/config.tenant.yml'
if (Test-Path -LiteralPath $configTenantSrc) {
    Copy-Item -LiteralPath $configTenantSrc -Destination $configTenantDest -Force
}

$configFleetTlsSrc = Join-Path $root 'configs/windows/config.fleet.tls.yml'
$configFleetTlsDest = Join-Path $root 'build/windows/config.fleet.tls.yml'
if (Test-Path -LiteralPath $configFleetTlsSrc) {
    Copy-Item -LiteralPath $configFleetTlsSrc -Destination $configFleetTlsDest -Force
}

$configTenantTlsSrc = Join-Path $root 'configs/windows/config.tenant.tls.yml'
$configTenantTlsDest = Join-Path $root 'build/windows/config.tenant.tls.yml'
if (Test-Path -LiteralPath $configTenantTlsSrc) {
    Copy-Item -LiteralPath $configTenantTlsSrc -Destination $configTenantTlsDest -Force
}

$configPPLSrc = Join-Path $root 'configs/windows/config.ppl.yml'
$configPPLDest = Join-Path $root 'build/windows/config.ppl.yml'
if (Test-Path -LiteralPath $configPPLSrc) {
    Copy-Item -LiteralPath $configPPLSrc -Destination $configPPLDest -Force
}

foreach ($scriptName in @(
        'apply_tenant_config.bat',
        'apply_tenant_tls_config.bat',
        'apply_am_ppl_config.bat',
        'apply_hardened_config.bat',
        'apply_enterprise_config.bat',
        'apply_fleet_config.bat'
    )) {
    $src = Join-Path $root ("scripts/windows/$scriptName")
    $dest = Join-Path $root ("build/windows/$scriptName")
    if (Test-Path -LiteralPath $src) {
        Copy-Item -LiteralPath $src -Destination $dest -Force
    }
}

$heatExe = 'heat.exe'
if (-not [string]::IsNullOrWhiteSpace($env:EDR_WIX_BIN)) {
    $heatExe = Join-Path $env:EDR_WIX_BIN 'heat.exe'
}
if (-not (Get-Command $heatExe -ErrorAction SilentlyContinue)) {
    throw "heat.exe not on PATH; run ensure_wix_path.ps1 first or set EDR_WIX_BIN"
}

$modelsStage = Join-Path $root 'build/windows/msi-models'
$modelsWxs = Join-Path $root 'build/windows/models.wxs'
if (Test-Path -LiteralPath $modelsStage) {
    Remove-Item -LiteralPath $modelsStage -Recurse -Force
}
New-Item -ItemType Directory -Force -Path $modelsStage | Out-Null

$modelsSrc = Join-Path $root 'models'
$modelFiles = @(Get-ChildItem -LiteralPath $modelsSrc -Filter '*.onnx' -ErrorAction SilentlyContinue)
if ($modelFiles.Count -gt 0) {
    foreach ($model in $modelFiles) {
        Copy-Item -LiteralPath $model.FullName -Destination (Join-Path $modelsStage $model.Name) -Force
    }
    $manifest = Join-Path $modelsSrc 'manifest.json'
    if (Test-Path -LiteralPath $manifest) {
        Copy-Item -LiteralPath $manifest -Destination (Join-Path $modelsStage 'manifest.json') -Force
    }
    foreach ($sig in (Get-ChildItem -LiteralPath $modelsSrc -Filter '*.onnx.sig' -ErrorAction SilentlyContinue)) {
        Copy-Item -LiteralPath $sig.FullName -Destination (Join-Path $modelsStage $sig.Name) -Force
    }

    Write-Host "==> heat models fragment"
    & $heatExe dir $modelsStage `
        -cg ModelsComponents `
        -dr MODELSROOT `
        -var var.ModelsStage `
        -srd `
        -scom `
        -sreg `
        -gg `
        -out $modelsWxs `
        -nologo
    if ($LASTEXITCODE -ne 0) {
        throw "heat models failed with exit $LASTEXITCODE"
    }
    Write-Host "Staged models -> $modelsWxs"
} else {
    Write-Host "skip models MSI fragment (no models/*.onnx)"
    if (Test-Path -LiteralPath $modelsWxs) {
        Remove-Item -LiteralPath $modelsWxs -Force
    }
    @(
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<Wix xmlns="http://schemas.microsoft.com/wix/2006/wi">'
        '  <Fragment>'
        '    <ComponentGroup Id="ModelsComponents"/>'
        '  </Fragment>'
        '</Wix>'
    ) -join "`n" | Set-Content -LiteralPath $modelsWxs -Encoding UTF8
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
