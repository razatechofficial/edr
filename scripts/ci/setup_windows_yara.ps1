# Install libyara via vcpkg for Windows amd64 CGO builds (go-yara / YARA layer).
# vcpkg's yara port is ONLY_STATIC_LIBRARY; use x64-mingw-static (not -dynamic).
# vcpkg does not ship yara.pc — use yara_no_pkg_config + explicit CGO flags.
param(
	[switch]$SkipIfPresent
)

$ErrorActionPreference = 'Stop'

$vcpkgRoot = Join-Path $env:RUNNER_TEMP 'vcpkg-edr'
# Static MinGW libs match yara's ONLY_STATIC_LIBRARY port; -dynamic leaves lib/ empty.
$triplet = 'x64-mingw-static'
$installed = Join-Path $vcpkgRoot "installed\$triplet"

function Set-GhEnv([string]$Name, [string]$Value) {
	if ([string]::IsNullOrWhiteSpace($env:GITHUB_ENV)) {
		Set-Item -Path "env:$Name" -Value $Value
		return
	}
	$escaped = $Value -replace "`r`n", '%0A'
	Add-Content -LiteralPath $env:GITHUB_ENV -Value "${Name}=${escaped}"
}

function Find-LibYaraArtifact([string]$Root) {
	$libDirs = @(
		(Join-Path $Root 'lib'),
		(Join-Path $Root 'debug\lib'),
		(Join-Path $Root 'lib\manual-link')
	)
	# vcpkg CMake target is "libyara" -> MinGW archive is liblibyara.a (not libyara.a).
	$names = @('liblibyara.a', 'libyara.a', 'libyara.dll.a', 'libyara.lib', 'yara.lib')
	foreach ($dir in $libDirs) {
		if (-not (Test-Path -LiteralPath $dir)) { continue }
		foreach ($name in $names) {
			$p = Join-Path $dir $name
			if (Test-Path -LiteralPath $p) { return $p }
		}
	}
	$found = Get-ChildItem -LiteralPath $Root -Recurse -File -ErrorAction SilentlyContinue |
		Where-Object { $_.Name -match '^lib(lib)?yara\.(a|lib|dll\.a)$' } |
		Select-Object -First 1
	if ($found) { return $found.FullName }
	return $null
}

function Ensure-MingwYaraLinkName([string]$LibFile) {
	$dir = Split-Path -Parent $LibFile
	$linkPath = Join-Path $dir 'libyara.a'
	if ((Split-Path -Leaf $LibFile) -eq 'libyara.a') {
		return $linkPath
	}
	if (Test-Path -LiteralPath $linkPath) {
		return $linkPath
	}
	try {
		New-Item -ItemType HardLink -Path $linkPath -Target $LibFile | Out-Null
	} catch {
		Copy-Item -LiteralPath $LibFile -Destination $linkPath -Force
	}
	Write-Host "Created libyara.a link for go-yara (-lyara): $linkPath"
	return $linkPath
}

function Find-YaraHeaderDir([string]$Root) {
	$direct = Join-Path $Root 'include\yara.h'
	if (Test-Path -LiteralPath $direct) {
		return (Join-Path $Root 'include')
	}
	$nested = Get-ChildItem -LiteralPath (Join-Path $Root 'include') -Recurse -Filter 'yara.h' -File -ErrorAction SilentlyContinue |
		Select-Object -First 1
	if ($nested) {
		return $nested.Directory.FullName
	}
	return $null
}

if ($SkipIfPresent -and (Find-LibYaraArtifact $installed)) {
	Write-Host "vcpkg yara already installed at $installed"
} else {
	if (-not (Test-Path $vcpkgRoot)) {
		Write-Host "==> Cloning vcpkg"
		git clone --depth 1 https://github.com/microsoft/vcpkg $vcpkgRoot
	}
	$bootstrap = Join-Path $vcpkgRoot 'bootstrap-vcpkg.bat'
	if (-not (Test-Path (Join-Path $vcpkgRoot 'vcpkg.exe'))) {
		Write-Host "==> Bootstrapping vcpkg"
		& $bootstrap -disableMetrics
		if ($LASTEXITCODE -ne 0) { throw "vcpkg bootstrap failed" }
	}
	Write-Host "==> vcpkg install yara ($triplet)"
	& (Join-Path $vcpkgRoot 'vcpkg.exe') install yara --triplet $triplet --clean-after-build
	if ($LASTEXITCODE -ne 0) { throw "vcpkg install failed" }
}

$libYara = Find-LibYaraArtifact $installed
if (-not $libYara) {
	Write-Host "==> lib/ contents (diagnostic):"
	$libPath = Join-Path $installed 'lib'
	if (Test-Path -LiteralPath $libPath) {
		Get-ChildItem -LiteralPath $libPath -Recurse -ErrorAction SilentlyContinue | ForEach-Object { Write-Host $_.FullName }
	} else {
		Write-Host "(no lib directory)"
	}
	throw "libyara library not found under $installed (triplet=$triplet)"
}

$includeDir = Find-YaraHeaderDir $installed
if (-not $includeDir) {
	throw "yara.h not found under $installed/include"
}

$libDir = Split-Path -Parent $libYara
Ensure-MingwYaraLinkName $libYara | Out-Null

$prefix = $installed -replace '\\', '/'
$includePrefix = $includeDir -replace '\\', '/'
$libPrefix = $libDir -replace '\\', '/'
$cgoCflags = "-I$includePrefix"
# go-yara (yara_no_pkg_config) links with -lyara; alias libyara.a is created from liblibyara.a.
$cgoLdflags = "-L$libPrefix -lyara -lssl -lcrypto -lws2_32 -lcrypt32"

Set-GhEnv 'EDR_WINDOWS_YARA' '1'
Set-GhEnv 'EDR_VCPKG_TRIPLET' $triplet
Set-GhEnv 'EDR_GO_BUILD_TAGS' 'yara_no_pkg_config,yara_static'
Set-GhEnv 'CGO_ENABLED' '1'
Set-GhEnv 'CGO_CFLAGS' $cgoCflags
Set-GhEnv 'CGO_LDFLAGS' $cgoLdflags

$binDir = Join-Path $installed 'bin'
if (Test-Path -LiteralPath $binDir) {
	Set-GhEnv 'PATH' "$binDir;$env:PATH"
}

Write-Host "Windows YARA toolchain ready (triplet=$triplet)"
Write-Host "  libyara: $libYara"
Write-Host "  include: $includeDir"
Write-Host "  CGO_CFLAGS=$cgoCflags"
Write-Host "  CGO_LDFLAGS=$cgoLdflags"
