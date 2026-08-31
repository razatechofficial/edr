# Optional Authenticode signing for Windows release artifacts (agent exe + MSI).
# Skips cleanly when signing secrets are not configured.
param(
	[string]$Root = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path,
	[switch]$MsiOnly,
	[switch]$VerifyOnly
)

$ErrorActionPreference = 'Stop'
$root = [System.IO.Path]::GetFullPath($Root.TrimEnd('\', '/'))

function Find-SignTool {
	if (-not [string]::IsNullOrWhiteSpace($env:EDR_SIGNTOOL_PATH) -and (Test-Path -LiteralPath $env:EDR_SIGNTOOL_PATH)) {
		return $env:EDR_SIGNTOOL_PATH
	}
	$candidates = @(
		"${env:ProgramFiles(x86)}\Windows Kits\10\bin\*\x64\signtool.exe",
		"${env:ProgramFiles}\Windows Kits\10\bin\*\x64\signtool.exe"
	)
	foreach ($pattern in $candidates) {
		$hit = Get-ChildItem -Path $pattern -ErrorAction SilentlyContinue | Sort-Object FullName -Descending | Select-Object -First 1
		if ($hit) { return $hit.FullName }
	}
	throw "signtool.exe not found; install Windows SDK or set EDR_SIGNTOOL_PATH"
}

function Test-AuthenticodeSigned([string]$Path) {
	$sig = Get-AuthenticodeSignature -LiteralPath $Path
	return ($sig.Status -eq 'Valid')
}

$agentExe = Join-Path $root 'dist/windows-amd64/edr-agent.exe'
$extraExes = @(
	(Join-Path $root 'dist/windows-amd64/edr-installer.exe'),
	(Join-Path $root 'dist/windows-amd64/edr-agent-ui.exe'),
	(Join-Path $root 'dist/windows-amd64/edrctl.exe')
)
$msiFiles = @(Get-ChildItem -LiteralPath (Join-Path $root 'dist') -Filter 'edr-agent_*.msi' -ErrorAction SilentlyContinue)

if ($VerifyOnly) {
	if (-not (Test-Path -LiteralPath $agentExe)) {
		throw "missing agent binary for verify: $agentExe"
	}
	if (-not (Test-AuthenticodeSigned $agentExe)) {
		throw "edr-agent.exe is not Authenticode signed (Valid)"
	}
	foreach ($msi in $msiFiles) {
		if (-not (Test-AuthenticodeSigned $msi.FullName)) {
			throw "MSI not Authenticode signed: $($msi.Name)"
		}
	}
	Write-Host "Authenticode verify OK: edr-agent.exe + $($msiFiles.Count) MSI(s)"
	exit 0
}

$pfxB64 = $env:WINDOWS_SIGN_PFX_BASE64
$pfxPass = $env:WINDOWS_SIGN_PFX_PASSWORD
if ([string]::IsNullOrWhiteSpace($pfxB64)) {
	Write-Host "skip Authenticode signing (WINDOWS_SIGN_PFX_BASE64 not set)"
	exit 0
}

$signtool = Find-SignTool
$ts = if ([string]::IsNullOrWhiteSpace($env:WINDOWS_SIGN_TIMESTAMP_URL)) { 'http://timestamp.digicert.com' } else { $env:WINDOWS_SIGN_TIMESTAMP_URL }
$pfxPath = Join-Path $env:RUNNER_TEMP 'edr-sign.pfx'
[System.IO.File]::WriteAllBytes($pfxPath, [Convert]::FromBase64String($pfxB64))

function Invoke-SignFile([string]$Target) {
	if (-not (Test-Path -LiteralPath $Target)) {
		Write-Host "skip missing: $Target"
		return
	}
	Write-Host "==> signtool $Target"
	& $signtool sign `
		/f $pfxPath `
		/p $pfxPass `
		/tr $ts `
		/td sha256 `
		/fd sha256 `
		$Target
	if ($LASTEXITCODE -ne 0) {
		throw "signtool failed for $Target (exit $LASTEXITCODE)"
	}
}

try {
	if (-not $MsiOnly) {
		Invoke-SignFile $agentExe
		foreach ($exe in $extraExes) {
			Invoke-SignFile $exe
		}
	}
	foreach ($msi in $msiFiles) {
		Invoke-SignFile $msi.FullName
	}
}
finally {
	Remove-Item -LiteralPath $pfxPath -Force -ErrorAction SilentlyContinue
}

Write-Host "Authenticode signing complete"
