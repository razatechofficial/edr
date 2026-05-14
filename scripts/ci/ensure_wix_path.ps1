# Add WiX Toolset v3 bin (candle.exe / light.exe) to GITHUB_PATH for subsequent steps.
$ErrorActionPreference = 'Stop'

if (Get-Command candle -ErrorAction SilentlyContinue) {
    Write-Host "candle already on PATH"
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
    $candle = Join-Path $bin 'candle.exe'
    if (Test-Path -LiteralPath $candle) {
        Add-Content -Path $env:GITHUB_PATH -Value $bin
        Write-Host "Added WiX to PATH: $bin"
        exit 0
    }
}

Write-Host "WiX Toolset not found; installing via Chocolatey..."
choco install wixtoolset -y --no-progress

$machine = [Environment]::GetEnvironmentVariable('Path', 'Machine')
$user = [Environment]::GetEnvironmentVariable('Path', 'User')
$env:PATH = "$machine;$user"

if (Get-Command candle -ErrorAction SilentlyContinue) {
    Write-Host "WiX available after choco: $( (Get-Command candle).Source )"
    exit 0
}

# choco may install without updating current process PATH; add common install dir.
$candidates = @()
if (${env:ProgramFiles(x86)}) {
    $candidates += Get-ChildItem -Path "${env:ProgramFiles(x86)}\WiX Toolset*" -Directory -ErrorAction SilentlyContinue
}
foreach ($dir in $candidates) {
    $bin = Join-Path $dir.FullName 'bin'
    if (Test-Path -LiteralPath (Join-Path $bin 'candle.exe')) {
        Add-Content -Path $env:GITHUB_PATH -Value $bin
        Write-Host "Added WiX to GITHUB_PATH: $bin"
        exit 0
    }
}

throw "candle.exe not found after choco install wixtoolset"
