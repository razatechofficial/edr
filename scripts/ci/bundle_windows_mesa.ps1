# Bundle Mesa software OpenGL next to edr-agent-ui.exe.
# Required for Fyne on Windows Server / Hyper-V / RDP (no WGL driver).
# Downloads with curl.exe -L (Invoke-WebRequest does not follow fdossena 301s).
param(
	[string]$Root = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path,
	[switch]$Required
)

$ErrorActionPreference = 'Stop'
$dist = Join-Path $Root 'dist/windows-amd64'
$destGl = Join-Path $dist 'opengl32.dll'
$destGallium = Join-Path $dist 'libgallium_wgl.dll'
$ui = Join-Path $dist 'edr-agent-ui.exe'
if (-not (Test-Path -LiteralPath $ui)) {
	if ($Required) { throw "edr-agent-ui.exe missing; cannot bundle Mesa" }
	Write-Host "skip mesa: edr-agent-ui.exe missing"
	exit 0
}

function Test-MesaReady {
	if (-not (Test-Path -LiteralPath $destGl)) { return $false }
	$glLen = (Get-Item -LiteralPath $destGl).Length
	# Fat single-DLL builds (fdossena) are several MB.
	if ($glLen -gt 1MB) { return $true }
	# Modern Mesa: thin opengl32.dll + libgallium_wgl.dll megadriver.
	if ((Test-Path -LiteralPath $destGallium) -and ((Get-Item -LiteralPath $destGallium).Length -gt 1MB)) {
		return $true
	}
	return $false
}

if (Test-MesaReady) {
	Write-Host "mesa already present: $destGl"
	exit 0
}

function Invoke-CurlDownload([string]$Url, [string]$OutFile) {
	$curl = Get-Command curl.exe -ErrorAction SilentlyContinue
	if (-not $curl) { throw "curl.exe not found" }
	# -L follows 301/302; -f fails on HTTP errors; avoid PowerShell curl alias.
	& $curl.Source -fsSL --retry 3 --retry-delay 2 --max-time 300 --connect-timeout 30 -o $OutFile $Url
	if ($LASTEXITCODE -ne 0) { throw "curl failed ($LASTEXITCODE) for $Url" }
	if (-not (Test-Path -LiteralPath $OutFile) -or ((Get-Item -LiteralPath $OutFile).Length -lt 50KB)) {
		throw "download too small from $Url"
	}
}

function Expand-MesaArchive([string]$Archive, [string]$DestDir) {
	New-Item -ItemType Directory -Force -Path $DestDir | Out-Null
	$hdr = New-Object byte[] 4
	$fs = [System.IO.File]::OpenRead($Archive)
	try { [void]$fs.Read($hdr, 0, 4) } finally { $fs.Close() }
	$isZip = ($hdr[0] -eq 0x50 -and $hdr[1] -eq 0x4B)
	if ($isZip) {
		Expand-Archive -LiteralPath $Archive -DestinationPath $DestDir -Force
		return
	}
	$seven = $null
	foreach ($c in @(
		(Get-Command 7z.exe -ErrorAction SilentlyContinue),
		(Get-Command 7zr.exe -ErrorAction SilentlyContinue)
	)) {
		if ($c) { $seven = $c.Source; break }
	}
	foreach ($p in @(
		"${env:ProgramFiles}\7-Zip\7z.exe",
		"${env:ProgramFiles(x86)}\7-Zip\7z.exe"
	)) {
		if (-not $seven -and (Test-Path -LiteralPath $p)) { $seven = $p }
	}
	if (-not $seven) {
		$seven = Join-Path $DestDir '7zr.exe'
		Invoke-CurlDownload 'https://www.7-zip.org/a/7zr.exe' $seven
	}
	& $seven x -y "-o$DestDir" $Archive | Out-Null
	if ($LASTEXITCODE -ne 0) { throw "7z extract failed ($LASTEXITCODE)" }
}

function Copy-MesaFromTree([string]$ExtractDir) {
	$x64 = Get-ChildItem -LiteralPath $ExtractDir -Recurse -Directory -ErrorAction SilentlyContinue |
		Where-Object { $_.Name -ieq 'x64' } |
		Select-Object -First 1
	$search = if ($x64) { $x64.FullName } else { $ExtractDir }
	$gl = Get-ChildItem -LiteralPath $search -Recurse -Filter 'opengl32.dll' -File -ErrorAction SilentlyContinue |
		Sort-Object Length -Descending |
		Select-Object -First 1
	if (-not $gl) { throw "opengl32.dll not found under $search" }
	Copy-Item -LiteralPath $gl.FullName -Destination $destGl -Force
	$glDir = $gl.DirectoryName
	$companions = @(
		'libgallium_wgl.dll',
		'libglapi.dll',
		'zlib.dll',
		'zstd.dll',
		'libwinpthread-1.dll'
	)
	foreach ($name in $companions) {
		$hit = Get-ChildItem -LiteralPath $glDir -Filter $name -File -ErrorAction SilentlyContinue | Select-Object -First 1
		if (-not $hit) {
			$hit = Get-ChildItem -LiteralPath $search -Recurse -Filter $name -File -ErrorAction SilentlyContinue |
				Sort-Object Length -Descending |
				Select-Object -First 1
		}
		if ($hit) {
			Copy-Item -LiteralPath $hit.FullName -Destination (Join-Path $dist $hit.Name) -Force
			Write-Host "bundled $($hit.Name) ($([math]::Round($hit.Length/1MB,1)) MiB)"
		}
	}
	Write-Host "bundled $($gl.Name) ($([math]::Round($gl.Length/1MB,1)) MiB) -> $destGl"
}

function Get-Pal1000MesaUrl {
	$api = 'https://api.github.com/repos/pal1000/mesa-dist-win/releases/latest'
	$rel = Invoke-RestMethod -Uri $api -Headers @{ 'User-Agent' = 'edr-ci' }
	$asset = $rel.assets | Where-Object { $_.name -match 'release-msvc\.7z$' } | Select-Object -First 1
	if (-not $asset) { throw "no release-msvc.7z on pal1000/mesa-dist-win $($rel.tag_name)" }
	return [string]$asset.browser_download_url
}

$urls = New-Object System.Collections.Generic.List[string]
if ($env:EDR_MESA_URL) { $urls.Add($env:EDR_MESA_URL) }
# GitHub is stable on GHA (no 301 HTML). pal1000 ships x64 opengl32 + libgallium_wgl.
try { $urls.Add((Get-Pal1000MesaUrl)) } catch { Write-Host "github latest lookup: $($_.Exception.Message)" }
$urls.Add('https://github.com/pal1000/mesa-dist-win/releases/download/26.2.0/mesa3d-26.2.0-release-msvc.7z')
# Community single-DLL zip (needs curl -L; Invoke-WebRequest fails on 301).
$urls.Add('https://downloads.fdossena.com/geth.php?r=mesa64-latest')

$tmp = Join-Path $env:TEMP ("edr-mesa-" + [guid]::NewGuid().ToString('n'))
New-Item -ItemType Directory -Force -Path $tmp | Out-Null
$lastErr = $null
try {
	foreach ($url in $urls) {
		if ([string]::IsNullOrWhiteSpace($url)) { continue }
		$archive = Join-Path $tmp ('mesa-' + [guid]::NewGuid().ToString('n') + '.bin')
		$extract = Join-Path $tmp ([guid]::NewGuid().ToString('n'))
		try {
			Write-Host "Downloading Mesa software OpenGL from $url"
			Invoke-CurlDownload $url $archive
			Expand-MesaArchive $archive $extract
			Copy-MesaFromTree $extract
			if (-not (Test-MesaReady)) { throw "copied Mesa files failed readiness check" }
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
