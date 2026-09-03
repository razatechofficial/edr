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

$baselineSrc = Join-Path $root 'rules/baseline.yaml'
if (Test-Path -LiteralPath $baselineSrc) {
    Copy-Item -LiteralPath $baselineSrc -Destination (Join-Path $rulesStage 'baseline.yaml') -Force
} else {
    throw "missing rules/baseline.yaml (Windows config requires it)"
}

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

$ensureOnnx = Join-Path $root 'scripts/ci/ensure_onnx_models.sh'
$stageModels = Join-Path $root 'scripts/ci/stage_os_models.sh'
$bash = Get-Command bash -ErrorAction SilentlyContinue
if ($bash -and (Test-Path -LiteralPath $ensureOnnx)) {
    & $bash.Source $ensureOnnx
    if ($LASTEXITCODE -ne 0) { throw "ensure_onnx_models.sh failed with exit $LASTEXITCODE" }
}
if ($bash -and (Test-Path -LiteralPath $stageModels)) {
    & $bash.Source $stageModels 'windows' $modelsStage
    if ($LASTEXITCODE -ne 0) { throw "stage_os_models.sh failed with exit $LASTEXITCODE" }
} else {
    $modelsSrc = Join-Path $root 'models'
    $allow = @(
        'behavior_lstm.onnx', 'network_anomaly.onnx', 'ransomware.onnx',
        'network_lgbm.onnx', 'rat_c2_detector.onnx', 'pe_classifier.onnx'
    )
    foreach ($name in $allow) {
        $src = Join-Path $modelsSrc $name
        if (Test-Path -LiteralPath $src) {
            Copy-Item -LiteralPath $src -Destination (Join-Path $modelsStage $name) -Force
            $sig = "$src.sig"
            if (Test-Path -LiteralPath $sig) {
                Copy-Item -LiteralPath $sig -Destination (Join-Path $modelsStage "$name.sig") -Force
            }
        }
    }
    $manifest = Join-Path $modelsSrc 'manifest.json'
    if (Test-Path -LiteralPath $manifest) {
        Copy-Item -LiteralPath $manifest -Destination (Join-Path $modelsStage 'manifest.json') -Force
    }
}
$modelFiles = @(Get-ChildItem -LiteralPath $modelsStage -Filter '*.onnx' -ErrorAction SilentlyContinue)
if ($modelFiles.Count -gt 0) {
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
    throw "ML models not found in models/ (need *.onnx). Run 'make models-bootstrap' or wait for prepare_release_assets."
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
