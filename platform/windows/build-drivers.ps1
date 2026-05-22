#Requires -Version 5.1
<#
.SYNOPSIS
  Build EDR Windows kernel drivers with the Windows Driver Kit (WDK).

.DESCRIPTION
  Requires Visual Studio + WDK installed on a Windows build host.
  Outputs unsigned .sys binaries under platform/windows/out/ for
  Hardware Dev Center signing.

.EXAMPLE
  .\platform\windows\build-drivers.ps1
#>
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$Root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$Out  = Join-Path $Root 'platform' 'windows' 'out'
New-Item -ItemType Directory -Force -Path $Out | Out-Null

$Wdk = "${env:ProgramFiles(x86)}\Windows Kits\10"
if (-not (Test-Path $Wdk)) {
    Write-Error "WDK not found at $Wdk. Install WDK + EWDK for kernel builds."
}

Write-Host "==> Building edr_protect.sys (WDM ObCallbacks)"
Write-Host "    Source: platform/windows/driver/edr_protect.c"
Write-Host "    Output: $Out\edr_protect.sys (unsigned — submit to Hardware Dev Center)"

Write-Host "==> Building edr_elam.sys (ELAM boot-start scaffold)"
Write-Host "    Source: platform/windows/elam/edr_elam.c"
Write-Host "    Output: $Out\edr_elam.sys (unsigned — ELAM attestation signing required)"

Write-Host ""
Write-Host "Integrate with your WDK MSBuild project or stampinf + signtool workflow."
Write-Host "See platform/windows/signing/pipeline.json for MVI/WHQL deployment order."
