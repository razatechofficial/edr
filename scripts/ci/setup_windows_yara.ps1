# Install libyara via vcpkg for Windows amd64 CGO builds (go-yara / YARA layer).
# Sets GITHUB_ENV: EDR_WINDOWS_YARA, PKG_CONFIG, PKG_CONFIG_PATH, CGO_ENABLED, PATH.
param(
	[switch]$SkipIfPresent
)

$ErrorActionPreference = 'Stop'

$vcpkgRoot = Join-Path $env:RUNNER_TEMP 'vcpkg-edr'
$triplet = 'x64-windows'
$installed = Join-Path $vcpkgRoot "installed\$triplet"

function Set-GhEnv([string]$Name, [string]$Value) {
	if ([string]::IsNullOrWhiteSpace($env:GITHUB_ENV)) {
		Set-Item -Path "env:$Name" -Value $Value
		return
	}
	Add-Content -LiteralPath $env:GITHUB_ENV -Value "${Name}=${Value}"
}

if ($SkipIfPresent -and (Test-Path (Join-Path $installed 'lib\yara.lib'))) {
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

$pkgconf = Join-Path $installed 'tools\pkgconf\pkgconf.exe'
if (-not (Test-Path $pkgconf)) {
	throw "pkgconf not found at $pkgconf"
}
$pkgConfigPath = Join-Path $installed 'lib\pkgconfig'
$binDir = Join-Path $installed 'bin'

Set-GhEnv 'EDR_WINDOWS_YARA' '1'
Set-GhEnv 'CGO_ENABLED' '1'
Set-GhEnv 'PKG_CONFIG' $pkgconf
Set-GhEnv 'PKG_CONFIG_PATH' $pkgConfigPath
Set-GhEnv 'PATH' "$binDir;$env:PATH"
Write-Host "Windows YARA toolchain ready (PKG_CONFIG_PATH=$pkgConfigPath)"
