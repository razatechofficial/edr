# Ensure WiX v3 candle.exe / light.exe are on PATH (GITHUB_PATH + current session PATH).
#
# On GitHub Actions we *always* install pinned WiX v3.14.1 binaries: runners may expose a
# different "candle" first on PATH (or WiX v4 tooling), which breaks v3 .wxs builds.
$ErrorActionPreference = 'Stop'
# Native tools (curl.exe, WiX) may write non-errors to stderr; PS 7.2+ can treat that as fatal with Stop.
if ($PSVersionTable.PSVersion.Major -ge 7) {
    $PSNativeCommandUseErrorActionPreference = $false
}

function Add-WixBinToPath {
    param([string]$BinDir)
    if (-not (Test-Path (Join-Path $BinDir 'candle.exe'))) { return $false }
    if (-not [string]::IsNullOrWhiteSpace($env:GITHUB_PATH)) {
        $ghPathFile = $env:GITHUB_PATH
        $parent = Split-Path -LiteralPath $ghPathFile -Parent
        if ($parent -and -not (Test-Path -LiteralPath $parent)) {
            New-Item -ItemType Directory -Path $parent -Force | Out-Null
        }
        if (-not (Test-Path -LiteralPath $ghPathFile)) {
            New-Item -ItemType File -Path $ghPathFile -Force | Out-Null
        }
        Add-Content -Path $ghPathFile -Value $BinDir
    }
    $env:PATH = "$BinDir;$env:PATH"
    $env:EDR_WIX_BIN = $BinDir
    if (-not [string]::IsNullOrWhiteSpace($env:GITHUB_ENV)) {
        Add-Content -Path $env:GITHUB_ENV -Value "EDR_WIX_BIN=$BinDir"
    }
    Write-Host "WiX bin on PATH: $BinDir"
    return $true
}

function Install-PinnedWix314 {
    Write-Host "Installing pinned WiX v3.14.1 binaries..."
    $tmp = if (-not [string]::IsNullOrWhiteSpace($env:RUNNER_TEMP)) { $env:RUNNER_TEMP } else { [System.IO.Path]::GetTempPath().TrimEnd('\', '/') }
    $zipUrl = 'https://github.com/wixtoolset/wix3/releases/download/wix3141rtm/wix314-binaries.zip'
    $zipPath = Join-Path $tmp 'wix314-binaries.zip'
    $dest = Join-Path $tmp 'wix314-binaries'

    if (Get-Command curl.exe -ErrorAction SilentlyContinue) {
        & curl.exe -fsSL -o $zipPath $zipUrl
    } else {
        Invoke-WebRequest -Uri $zipUrl -OutFile $zipPath -UseBasicParsing
    }

    # Internet-downloaded zip/exes carry MOTW; headless runners can block execution (candle/light exit immediately).
    Unblock-File -LiteralPath $zipPath -ErrorAction SilentlyContinue

    if (Test-Path $dest) { Remove-Item -Recurse -Force $dest }
    New-Item -ItemType Directory -Force -Path $dest | Out-Null
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    [System.IO.Compression.ZipFile]::ExtractToDirectory($zipPath, $dest)

    Get-ChildItem -LiteralPath $dest -Recurse -File -ErrorAction SilentlyContinue | ForEach-Object {
        Unblock-File -LiteralPath $_.FullName -ErrorAction SilentlyContinue
    }

    $candlePath = Join-Path $dest 'candle.exe'
    if (-not (Test-Path -LiteralPath $candlePath)) {
        $found = Get-ChildItem -Path $dest -Recurse -Filter 'candle.exe' -ErrorAction SilentlyContinue | Select-Object -First 1
        if (-not $found) { throw "candle.exe not found after extracting wix314-binaries.zip" }
        $binDir = $found.Directory.FullName
    } else {
        $binDir = $dest
    }

    if (-not (Add-WixBinToPath $binDir)) {
        throw "Failed to add WiX bin directory: $binDir"
    }
    Write-Host "Pinned WiX ready."
}

if ($env:GITHUB_ACTIONS -eq 'true') {
    Install-PinnedWix314
    return
}

if (Get-Command candle -ErrorAction SilentlyContinue) {
    $src = (Get-Command candle).Source
    Write-Host "candle already on PATH: $src"
    $binDir = Split-Path -Parent $src
    $env:EDR_WIX_BIN = $binDir
    if (-not [string]::IsNullOrWhiteSpace($env:GITHUB_ENV)) {
        Add-Content -Path $env:GITHUB_ENV -Value "EDR_WIX_BIN=$binDir"
    }
    return
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
    if (Add-WixBinToPath $bin) { return }
}

Install-PinnedWix314
