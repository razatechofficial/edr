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
    $outF = Join-Path $env:TEMP ("edr-wix-{0}-stdout.log" -f [guid]::NewGuid().ToString('n'))
    $errF = Join-Path $env:TEMP ("edr-wix-{0}-stderr.log" -f [guid]::NewGuid().ToString('n'))
    try {
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
$edrCtlExe = [System.IO.Path]::GetFullPath((Join-Path $root 'dist/windows-amd64/edrctl.exe'))
$edrUIExe = [System.IO.Path]::GetFullPath((Join-Path $root 'dist/windows-amd64/edr-agent-ui.exe'))
$edrInstallerExe = [System.IO.Path]::GetFullPath((Join-Path $root 'dist/windows-amd64/edr-installer.exe'))
$edrSvcRegExe = [System.IO.Path]::GetFullPath((Join-Path $root 'dist/windows-amd64/edr-svcreg.exe'))
if (-not (Test-Path -LiteralPath $agentExe)) {
    throw "Missing Windows agent binary (build it first): $agentExe"
}
if (-not (Test-Path -LiteralPath $edrCtlExe)) {
    throw "Missing Windows edrctl binary (build it first): $edrCtlExe"
}
if (-not (Test-Path -LiteralPath $edrUIExe)) {
    throw "Missing Windows UI binary (build it first): $edrUIExe"
}
if (-not (Test-Path -LiteralPath $edrInstallerExe)) {
    throw "Missing Windows installer binary (build it first): $edrInstallerExe"
}
if (-not (Test-Path -LiteralPath $edrSvcRegExe)) {
    throw "Missing Windows svcreg binary (build it first): $edrSvcRegExe"
}

& (Join-Path $PSScriptRoot 'stage_windows_msi.ps1') -Root $root

$configYml = [System.IO.Path]::GetFullPath((Join-Path $root 'build/windows/config.yml'))
$configHardenedYml = [System.IO.Path]::GetFullPath((Join-Path $root 'build/windows/config.hardened.yml'))
$configEnterpriseYml = [System.IO.Path]::GetFullPath((Join-Path $root 'build/windows/config.enterprise.yml'))
$configFleetYml = [System.IO.Path]::GetFullPath((Join-Path $root 'build/windows/config.fleet.yml'))
$configTenantYml = [System.IO.Path]::GetFullPath((Join-Path $root 'build/windows/config.tenant.yml'))
$configFleetTlsYml = [System.IO.Path]::GetFullPath((Join-Path $root 'build/windows/config.fleet.tls.yml'))
$configTenantTlsYml = [System.IO.Path]::GetFullPath((Join-Path $root 'build/windows/config.tenant.tls.yml'))
$configPPLYml = [System.IO.Path]::GetFullPath((Join-Path $root 'build/windows/config.ppl.yml'))
$applyTenantBat = [System.IO.Path]::GetFullPath((Join-Path $root 'build/windows/apply_tenant_config.bat'))
$applyTenantTlsBat = [System.IO.Path]::GetFullPath((Join-Path $root 'build/windows/apply_tenant_tls_config.bat'))
$applyPPLBat = [System.IO.Path]::GetFullPath((Join-Path $root 'build/windows/apply_am_ppl_config.bat'))
$licenseRtf = [System.IO.Path]::GetFullPath((Join-Path $root 'build/windows/License.rtf'))
$killAgentVbs = [System.IO.Path]::GetFullPath((Join-Path $root 'build/windows/kill_agent.vbs'))
$msiPurgeVbs = [System.IO.Path]::GetFullPath((Join-Path $root 'build/windows/msi_purge.vbs'))
$registerServiceVbs = [System.IO.Path]::GetFullPath((Join-Path $root 'build/windows/register_service.vbs'))
$rulesWxs = [System.IO.Path]::GetFullPath((Join-Path $root 'build/windows/rules.wxs'))
$modelsWxs = [System.IO.Path]::GetFullPath((Join-Path $root 'build/windows/models.wxs'))
$rulesStage = [System.IO.Path]::GetFullPath((Join-Path $root 'build/windows/msi-rules'))
$modelsStage = [System.IO.Path]::GetFullPath((Join-Path $root 'build/windows/msi-models'))
if (-not (Test-Path -LiteralPath $licenseRtf)) {
    throw "Missing MSI license RTF: $licenseRtf"
}
if (-not (Test-Path -LiteralPath $killAgentVbs)) {
    throw "Missing MSI kill helper: $killAgentVbs"
}
if (-not (Test-Path -LiteralPath $msiPurgeVbs)) {
    throw "Missing MSI purge helper: $msiPurgeVbs"
}
if (-not (Test-Path -LiteralPath $registerServiceVbs)) {
    throw "Missing MSI register helper: $registerServiceVbs"
}
if (-not (Test-Path -LiteralPath $configYml)) {
    throw "Missing staged config: $configYml"
}
if (-not (Test-Path -LiteralPath $configHardenedYml)) {
    throw "Missing staged hardened config: $configHardenedYml"
}
if (-not (Test-Path -LiteralPath $configEnterpriseYml)) {
    throw "Missing staged enterprise config: $configEnterpriseYml"
}
if (-not (Test-Path -LiteralPath $configFleetYml)) {
    throw "Missing staged fleet config: $configFleetYml"
}
if (-not (Test-Path -LiteralPath $configTenantYml)) {
    throw "Missing staged tenant config: $configTenantYml"
}
if (-not (Test-Path -LiteralPath $configFleetTlsYml)) {
    throw "Missing staged fleet TLS config: $configFleetTlsYml"
}
if (-not (Test-Path -LiteralPath $configTenantTlsYml)) {
    throw "Missing staged tenant TLS config: $configTenantTlsYml"
}
if (-not (Test-Path -LiteralPath $configPPLYml)) {
    throw "Missing staged PPL config: $configPPLYml"
}
if (-not (Test-Path -LiteralPath $applyTenantBat)) {
    throw "Missing staged apply_tenant_config.bat: $applyTenantBat"
}
if (-not (Test-Path -LiteralPath $applyTenantTlsBat)) {
    throw "Missing staged apply_tenant_tls_config.bat: $applyTenantTlsBat"
}
if (-not (Test-Path -LiteralPath $applyPPLBat)) {
    throw "Missing staged apply_am_ppl_config.bat: $applyPPLBat"
}
if (-not (Test-Path -LiteralPath $rulesWxs)) {
    throw "Missing rules WiX fragment: $rulesWxs"
}
if (-not (Test-Path -LiteralPath $modelsWxs)) {
    throw "Missing models WiX fragment: $modelsWxs"
}

New-Item -ItemType Directory -Force -Path 'dist' | Out-Null
New-Item -ItemType Directory -Force -Path 'build/windows' | Out-Null

$wxs = [System.IO.Path]::GetFullPath((Join-Path $root 'build/windows/installer.wxs'))
$wixobj = [System.IO.Path]::GetFullPath((Join-Path $root 'build/windows/installer.wixobj'))
$rulesWixobj = [System.IO.Path]::GetFullPath((Join-Path $root 'build/windows/rules.wixobj'))
$modelsWixobj = [System.IO.Path]::GetFullPath((Join-Path $root 'build/windows/models.wixobj'))
$msi = [System.IO.Path]::GetFullPath((Join-Path $root "dist/edr-agent_${Version}_amd64.msi"))

$candleLog = Join-Path $root 'build/windows/candle.log'
$lightLog = Join-Path $root 'build/windows/light.log'

$candleArgList = @(
    '-nologo', '-arch', 'x64',
    "-dMsiProductVersion=$Version",
    "-dEdrAgentExe=$agentExe",
    "-dEdrCtlExe=$edrCtlExe",
    "-dEdrUIExe=$edrUIExe",
    "-dEdrInstallerExe=$edrInstallerExe",
    "-dEdrSvcRegExe=$edrSvcRegExe",
    "-dEdrConfigYml=$configYml",
    "-dEdrConfigHardenedYml=$configHardenedYml",
    "-dEdrConfigEnterpriseYml=$configEnterpriseYml",
    "-dEdrConfigFleetYml=$configFleetYml",
    "-dEdrConfigTenantYml=$configTenantYml",
    "-dEdrConfigFleetTlsYml=$configFleetTlsYml",
    "-dEdrConfigTenantTlsYml=$configTenantTlsYml",
    "-dEdrConfigPPLYml=$configPPLYml",
    "-dEdrApplyTenantBat=$applyTenantBat",
    "-dEdrApplyTenantTlsBat=$applyTenantTlsBat",
    "-dEdrApplyPPLBat=$applyPPLBat",
    "-dEdrLicenseRtf=$licenseRtf",
    "-dKillAgentVbs=$killAgentVbs",
    "-dMsiPurgeVbs=$msiPurgeVbs",
    "-dRegisterServiceVbs=$registerServiceVbs",
    "-dRulesStage=$rulesStage",
    "-dModelsStage=$modelsStage",
    $wxs,
    '-out', (Join-Path $root 'build/windows/')
)
Invoke-WiXTool -Label 'candle installer.wxs' -ExePath $candleExe -ArgList $candleArgList -LogPath $candleLog

$candleRulesArgList = @(
    '-nologo', '-arch', 'x64',
    "-dRulesStage=$rulesStage",
    $rulesWxs,
    '-out', (Join-Path $root 'build/windows/')
)
Invoke-WiXTool -Label 'candle rules.wxs' -ExePath $candleExe -ArgList $candleRulesArgList -LogPath $candleLog

$candleModelsArgList = @(
    '-nologo', '-arch', 'x64',
    "-dModelsStage=$modelsStage",
    $modelsWxs,
    '-out', (Join-Path $root 'build/windows/')
)
Invoke-WiXTool -Label 'candle models.wxs' -ExePath $candleExe -ArgList $candleModelsArgList -LogPath $candleLog

$wixobj = Join-Path $root 'build/windows/installer.wixobj'
$rulesWixobj = Join-Path $root 'build/windows/rules.wixobj'
$modelsWixobj = Join-Path $root 'build/windows/models.wixobj'
$lightInputs = @($wixobj, $rulesWixobj, $modelsWixobj)

$agentDist = Join-Path $root 'dist/windows-amd64'
$yaraDlls = @(Get-ChildItem -LiteralPath $agentDist -Filter 'libyara*.dll' -ErrorAction SilentlyContinue)
if ($yaraDlls.Count -gt 0) {
    $yaraWxs = Join-Path $root 'build/windows/yara_dll.wxs'
    $yaraLines = @(
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<Wix xmlns="http://schemas.microsoft.com/wix/2006/wi">'
        '  <Fragment>'
        '    <DirectoryRef Id="INSTALLFOLDER">'
    )
    $groupRefs = @()
    $idx = 0
    foreach ($dll in $yaraDlls) {
        $idx++
        $cmpId = "cmpLibYara$idx"
        $fileId = "LibYaraDll$idx"
        $full = [System.IO.Path]::GetFullPath($dll.FullName)
        $yaraLines += @(
            "      <Component Id=""$cmpId"" Guid=""*"" Directory=""INSTALLFOLDER"" Win64=""yes"">"
            "        <File Id=""$fileId"" Source=""$full"" Name=""$($dll.Name)"" KeyPath=""yes""/>"
            '      </Component>'
        )
        $groupRefs += "      <ComponentRef Id=""$cmpId""/>"
    }
    $yaraLines += @(
        '    </DirectoryRef>'
        '    <ComponentGroup Id="YaraDllComponents">'
    )
    $yaraLines += $groupRefs
    $yaraLines += @(
        '    </ComponentGroup>'
        '    <Feature Id="ProductFeature" Level="1">'
        '      <ComponentGroupRef Id="YaraDllComponents"/>'
        '    </Feature>'
        '  </Fragment>'
        '</Wix>'
    )
    Set-Content -LiteralPath $yaraWxs -Value ($yaraLines -join "`n") -Encoding UTF8
    $yaraWixobj = Join-Path $root 'build/windows/yara_dll.wixobj'
    Invoke-WiXTool -Label 'candle yara_dll.wxs' -ExePath $candleExe -ArgList @(
        '-nologo', '-arch', 'x64', $yaraWxs, '-out', (Join-Path $root 'build/windows/')
    ) -LogPath $candleLog
    $lightInputs += $yaraWixobj
    Write-Host "Including $($yaraDlls.Count) libyara DLL(s) in MSI"
}

$wixBinDir = $env:EDR_WIX_BIN
if ([string]::IsNullOrWhiteSpace($wixBinDir)) {
    $lightCmd = Get-Command $lightExe -ErrorAction SilentlyContinue
    if ($null -ne $lightCmd) {
        $wixBinDir = [System.IO.Path]::GetDirectoryName($lightCmd.Source)
    }
}
$uiExt = if (-not [string]::IsNullOrWhiteSpace($wixBinDir)) {
    Join-Path $wixBinDir 'WixUIExtension.dll'
} else {
    'WixUIExtension'
}
if ($uiExt -ne 'WixUIExtension' -and -not (Test-Path -LiteralPath $uiExt)) {
    throw "WixUIExtension.dll not found at $uiExt (needed for the license dialog)"
}

$lightArgList = @(
    '-nologo', '-sval', '-sw1076',
    '-ext', $uiExt,
    '-cultures:en-us',
    "-dRulesStage=$rulesStage",
    "-dModelsStage=$modelsStage",
    $lightInputs,
    '-o', $msi
)
Invoke-WiXTool -Label 'light (WiX)' -ExePath $lightExe -ArgList $lightArgList -LogPath $lightLog

Write-Host "Built: $msi"
