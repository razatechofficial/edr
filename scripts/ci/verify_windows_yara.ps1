# Verify Windows release build includes live YARA (CGO + libyara).
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
if ($dlls.Count -gt 0) {
    Write-Host "Windows YARA OK: $($dlls.Count) libyara DLL(s) bundled with edr-agent.exe"
    exit 0
}

# Static libyara (vcpkg ONLY_STATIC_LIBRARY): confirm go-yara is linked into the agent.
if (Get-Command go -ErrorAction SilentlyContinue) {
    $meta = (& go version -m $agent 2>&1) | Out-String
    if ($meta -match 'hillu/go-yara') {
        Write-Host "Windows YARA OK: agent statically linked with go-yara (no libyara DLL required)"
        exit 0
    }
}

throw "YARA not detected: no libyara DLL next to edr-agent.exe and go version -m shows no go-yara dependency"
