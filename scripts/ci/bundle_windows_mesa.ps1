# Bundle Mesa software OpenGL (opengl32.dll) next to edr-agent-ui.exe.
# Required for Fyne on Windows Server / Hyper-V / RDP (no WGL driver).
# Fails the build if no DLL can be obtained — do not ship a console that
# exits with no window on Server.
param(
	[string]$Root = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path,
	[switch]$Required
)

$ErrorActionPreference = 'Stop'
$dist = Join-Path $Root 'dist/windows-amd64'
$dest = Join-Path $dist 'opengl32.dll'
$ui = Join-Path $dist 'edr-agent-ui.exe'
if (-not (Test-Path -LiteralPath $ui)) {
	if ($Required) { throw "edr-agent-ui.exe missing; cannot bundle Mesa" }
	Write-Host "skip mesa: edr-agent-ui.exe missing"
	exit 0
}

function Test-MesaDll([string]$Path) {
	if (-not (Test-Path -LiteralPath $Path)) { return $false }
	$len = (Get-Item -LiteralPath $Path).Length
	# Real Mesa x64 opengl32.dll is several MB; reject stubs.
	return ($len -gt 1MB)
}

if (Test-MesaDll $dest) {
	Write-Host "mesa opengl32.dll already present ($([math]::Round((Get-Item $dest).Length/1MB,1)) MiB)"
	exit 0
}

# Prefer pinned GitHub raw/release mirrors, then fdossena latest.
$urls = @()
if ($env:EDR_MESA_URL) { $urls += $env:EDR_MESA_URL }
$urls += @(
	# fdossena Mesa64 zip (single opengl32.dll) — used by Fyne community for Server/RDP
	'https://downloads.fdossena.com/geth.php?r=mesa64-latest',
	'https://downloads.fdossena.com/geth.php?r=mesa/latest'
)

$tmp = Join-Path $env:TEMP ("edr-mesa-" + [guid]::NewGuid().ToString('n'))
New-Item -ItemType Directory -Force -Path $tmp | Out-Null
$lastErr = $null
try {
	foreach ($url in $urls) {
		$zip = Join-Path $tmp ('mesa-' + [guid]::NewGuid().ToString('n') + '.zip')
		try {
			Write-Host "Downloading Mesa software OpenGL from $url"
			Invoke-WebRequest -Uri $url -OutFile $zip -UseBasicParsing -TimeoutSec 180
			if ((Get-Item $zip).Length -lt 100KB) { throw "download too small" }
			$extract = Join-Path $tmp ([guid]::NewGuid().ToString('n'))
			New-Item -ItemType Directory -Force -Path $extract | Out-Null
			Expand-Archive -LiteralPath $zip -DestinationPath $extract -Force
			$dll = Get-ChildItem -LiteralPath $extract -Recurse -Filter 'opengl32.dll' -File -ErrorAction SilentlyContinue |
				Where-Object { $_.Length -gt 1MB } |
				Sort-Object Length -Descending |
				Select-Object -First 1
			if (-not $dll) { throw "opengl32.dll not found in archive" }
			Copy-Item -LiteralPath $dll.FullName -Destination $dest -Force
			if (-not (Test-MesaDll $dest)) { throw "copied dll failed size check" }
			Write-Host "bundled $($dll.Name) ($([math]::Round($dll.Length/1MB,1)) MiB) -> $dest"
			exit 0
		}
		catch {
			$lastErr = $_
			Write-Host "mesa mirror failed: $($_.Exception.Message)"
		}
	}
	$msg = "failed to bundle Mesa opengl32.dll (Server/RDP console will not open): $lastErr"
	if ($Required) { throw $msg }
	Write-Host "warning: $msg"
	exit 1
}
finally {
	Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue
}
