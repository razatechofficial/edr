# Bundle Mesa software OpenGL (opengl32.dll) next to edr-agent-ui.exe.
# Fyne requires OpenGL; Windows Server / Hyper-V / RDP often have none, so the
# console exits with no window. Application-directory opengl32.dll is loaded first.
param(
	[string]$Root = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
)

$ErrorActionPreference = 'Stop'
$dist = Join-Path $Root 'dist/windows-amd64'
$dest = Join-Path $dist 'opengl32.dll'
if (-not (Test-Path -LiteralPath (Join-Path $dist 'edr-agent-ui.exe'))) {
	Write-Host "skip mesa: edr-agent-ui.exe missing"
	exit 0
}
if (Test-Path -LiteralPath $dest) {
	Write-Host "mesa opengl32.dll already present"
	exit 0
}

# Pinned fdossena Mesa64 (single opengl32.dll zip). MIT/X11 Mesa license.
$url = if ($env:EDR_MESA_URL) { $env:EDR_MESA_URL } else {
	'https://downloads.fdossena.com/geth.php?r=mesa64-latest'
}
$tmp = Join-Path $env:TEMP ("edr-mesa-" + [guid]::NewGuid().ToString('n'))
New-Item -ItemType Directory -Force -Path $tmp | Out-Null
$zip = Join-Path $tmp 'mesa.zip'
try {
	Write-Host "Downloading Mesa software OpenGL..."
	Invoke-WebRequest -Uri $url -OutFile $zip -UseBasicParsing
	Expand-Archive -LiteralPath $zip -DestinationPath $tmp -Force
	$dll = Get-ChildItem -LiteralPath $tmp -Recurse -Filter 'opengl32.dll' -File |
		Where-Object { $_.Length -gt 100KB } |
		Select-Object -First 1
	if (-not $dll) {
		throw "opengl32.dll not found in Mesa archive"
	}
	Copy-Item -LiteralPath $dll.FullName -Destination $dest -Force
	Write-Host "bundled $($dll.Name) ($([math]::Round($dll.Length/1MB,1)) MiB) -> $dest"
}
finally {
	Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue
}
