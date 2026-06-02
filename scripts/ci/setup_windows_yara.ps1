# Install libyara via vcpkg for Windows amd64 CGO builds (go-yara / YARA layer).
# vcpkg's yara port does not ship yara.pc; we use yara_no_pkg_config + explicit CGO flags.
# Sets GITHUB_ENV: EDR_WINDOWS_YARA, CGO_CFLAGS, CGO_LDFLAGS, EDR_GO_BUILD_TAGS, PATH.
param(
	[switch]$SkipIfPresent
)

$ErrorActionPreference = 'Stop'

$vcpkgRoot = Join-Path $env:RUNNER_TEMP 'vcpkg-edr'
# MinGW triplet: Go CGO on GHA Windows uses gcc; matches MSVC .lib less reliably.
$triplet = 'x64-mingw-dynamic'
$installed = Join-Path $vcpkgRoot "installed\$triplet"

function Set-GhEnv([string]$Name, [string]$Value) {
	if ([string]::IsNullOrWhiteSpace($env:GITHUB_ENV)) {
		Set-Item -Path "env:$Name" -Value $Value
		return
	}
	# Multiline-safe for GITHUB_ENV (rarely needed here).
	$escaped = $Value -replace "`r`n", '%0A'
	Add-Content -LiteralPath $env:GITHUB_ENV -Value "${Name}=${escaped}"
}

function Find-LibYaraArtifact([string]$Root) {
	$candidates = @(
		(Join-Path $Root 'lib\libyara.a'),
		(Join-Path $Root 'lib\libyara.dll.a'),
		(Join-Path $Root 'lib\yara.lib'),
		(Join-Path $Root 'lib\libyara.lib')
	)
	foreach ($p in $candidates) {
		if (Test-Path -LiteralPath $p) { return $p }
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
	Write-Host "==> vcpkg install yara pkgconf ($triplet)"
	& (Join-Path $vcpkgRoot 'vcpkg.exe') install yara pkgconf --triplet $triplet --clean-after-build
	if ($LASTEXITCODE -ne 0) { throw "vcpkg install failed" }
}

$libYara = Find-LibYaraArtifact $installed
if (-not $libYara) {
	throw "libyara library not found under $installed/lib"
}

$includeDir = Join-Path $installed 'include'
$libDir = Join-Path $installed 'lib'
$binDir = Join-Path $installed 'bin'
if (-not (Test-Path (Join-Path $includeDir 'yara.h'))) {
	throw "yara.h not found under $includeDir"
}

# go-yara: skip pkg-config (vcpkg does not install yara.pc) and link static libyara.
$prefix = $installed -replace '\\', '/'
$cgoCflags = "-I$prefix/include"
$cgoLdflags = "-L$prefix/lib -lyara -lssl -lcrypto -lcrypt32 -lws2_32"

Set-GhEnv 'EDR_WINDOWS_YARA' '1'
Set-GhEnv 'EDR_VCPKG_TRIPLET' $triplet
Set-GhEnv 'EDR_GO_BUILD_TAGS' 'yara_no_pkg_config,yara_static'
Set-GhEnv 'CGO_ENABLED' '1'
Set-GhEnv 'CGO_CFLAGS' $cgoCflags
Set-GhEnv 'CGO_LDFLAGS' $cgoLdflags
if (Test-Path -LiteralPath $binDir) {
	Set-GhEnv 'PATH' "$binDir;$env:PATH"
}
Write-Host "Windows YARA toolchain ready (triplet=$triplet, lib=$libYara)"
Write-Host "CGO_CFLAGS=$cgoCflags"
Write-Host "CGO_LDFLAGS=$cgoLdflags"
