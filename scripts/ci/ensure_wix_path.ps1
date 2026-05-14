# Ensure WiX v3 candle.exe / light.exe are on PATH (GITHUB_PATH for later steps).
# Chocolatey package names/versions drift; official WiX binaries zip is deterministic for CI.
$ErrorActionPreference = 'Stop'

function Add-WixBinToPath {
    param([string]$BinDir)
    if (-not (Test-Path (Join-Path $BinDir 'candle.exe'))) { return $false }
    Add-Content -Path $env:GITHUB_PATH -Value $BinDir
    Write-Host "WiX bin added to GITHUB_PATH: $BinDir"
    return $true
}

if (Get-Command candle -ErrorAction SilentlyContinue) {
    Write-Host "candle already on PATH: $((Get-Command candle).Source)"
    exit 0
}

$candidates = @()
if (${env:ProgramFiles(x86)}) {
    $candidates += Get-ChildItem -Path "${env:ProgramFiles(x86)}\WiX Toolset*" -Directory -ErrorAction SilentlyContinue
}
if ($env:ProgramFiles) {
    $candidates += Get-ChildItem -Path "$env:ProgramFiles\WiX Toolset*" -Directory -ErrorAction SilentlyContinue
}
foreach ($dir in $candidates) {
    $bin = Join-Path $dir.FullName 'bin'
    if (Add-WixBinToPath $bin) { exit 0 }
}

Write-Host "WiX not preinstalled; downloading WiX v3.14.1 binaries (official release)..."
$zipUrl = 'https://github.com/wixtoolset/wix3/releases/download/wix3141rtm/wix314-binaries.zip'
$zipPath = Join-Path $env:RUNNER_TEMP 'wix314-binaries.zip'
$dest = Join-Path $env:RUNNER_TEMP 'wix314-binaries'
if (Get-Command curl.exe -ErrorAction SilentlyContinue) {
    & curl.exe -fsSL -o $zipPath $zipUrl
} else {
    Invoke-WebRequest -Uri $zipUrl -OutFile $zipPath -UseBasicParsing
}
if (Test-Path $dest) { Remove-Item -Recurse -Force $dest }
Expand-Archive -Path $zipPath -DestinationPath $dest -Force

$candlePath = Join-Path $dest 'candle.exe'
if (Test-Path -LiteralPath $candlePath) {
    $binDir = $dest
} else {
    $candle = Get-ChildItem -Path $dest -Recurse -Filter 'candle.exe' -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $candle) {
        throw "candle.exe not found inside extracted WiX binaries (wix314-binaries.zip)"
    }
    $binDir = $candle.Directory.FullName
}
if (-not (Add-WixBinToPath $binDir)) {
    throw "Failed to add WiX bin directory"
}
Write-Host "Using WiX from: $binDir"
