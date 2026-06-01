# Smoke-test local detection and optional control-plane alert forwarding (Windows).
param(
	[string]$ControlPlaneHost = $env:EDR_CONTROL_PLANE_HOST
)

$ErrorActionPreference = 'Stop'

$alertFile = if ($env:EDR_ALERT_FILE) { $env:EDR_ALERT_FILE } else { Join-Path $env:ProgramData 'EDR Agent\alerts.jsonl' }
$timeoutSec = if ($env:EDR_PILOT_ALERT_TIMEOUT) { [int]$env:EDR_PILOT_ALERT_TIMEOUT } else { 30 }
$httpPort = if ($env:EDR_CONTROLPLANE_HTTP_PORT) { $env:EDR_CONTROLPLANE_HTTP_PORT } else { '8080' }
$https = $env:EDR_CONTROLPLANE_HTTPS -eq '1' -or $env:EDR_CONTROLPLANE_HTTPS -eq 'true'
$apiToken = $env:EDR_CONTROLPLANE_API_TOKEN
$caCert = if ($env:EDR_CONTROLPLANE_CA) { $env:EDR_CONTROLPLANE_CA } else { Join-Path $env:ProgramData 'EDR Agent\tls\ca.crt' }

function Get-CpAlertCount {
	param([string]$HostName)
	$scheme = if ($https) { 'https' } else { 'http' }
	$curlArgs = @('-fsS')
	if ($https) {
		if (-not (Test-Path -LiteralPath $caCert)) {
			throw "missing CA cert for HTTPS: $caCert (set EDR_CONTROLPLANE_CA)"
		}
		$curlArgs += @('--cacert', $caCert)
	}
	if ($apiToken) {
		$curlArgs += @('-H', "Authorization: Bearer $apiToken")
	}
	$url = "${scheme}://${HostName}:${httpPort}/v1/alerts?limit=500"
	$json = & curl.exe @curlArgs $url
	$data = $json | ConvertFrom-Json
	return @($data.alerts).Count
}

$probeDir = Join-Path $env:TEMP ("edr-pilot-probe-{0}" -f [guid]::NewGuid().ToString('N').Substring(0, 8))
New-Item -ItemType Directory -Path $probeDir -Force | Out-Null
$probeFile = Join-Path $probeDir 'log4j_yara_probe.txt'
$baselineCp = 0

if ($ControlPlaneHost) {
	try {
		$baselineCp = Get-CpAlertCount -HostName $ControlPlaneHost
	} catch {
		$baselineCp = 0
	}
}

Write-Host '==> trigger Log4Shell YARA probe'
Set-Content -LiteralPath $probeFile -Value '${jndi:ldap://127.0.0.1/edr-pilot-probe}' -NoNewline

Write-Host "==> wait for local alert ($alertFile)"
$deadline = (Get-Date).AddSeconds($timeoutSec)
$found = $false
while ((Get-Date) -lt $deadline) {
	if (Test-Path -LiteralPath $alertFile) {
		$tail = Get-Content -LiteralPath $alertFile -Tail 50 -ErrorAction SilentlyContinue
		if ($tail -match 'Log4Shell|log4j|jndi') {
			$found = $true
			break
		}
	}
	Start-Sleep -Seconds 2
}
if (-not $found) {
	Remove-Item -LiteralPath $probeDir -Recurse -Force -ErrorAction SilentlyContinue
	throw "no local detection alert observed within ${timeoutSec}s"
}
Write-Host 'local detection alert observed'

if ($ControlPlaneHost) {
	Write-Host '==> wait for control plane alert forwarding'
	$target = $baselineCp + 1
	$deadline = (Get-Date).AddSeconds($timeoutSec)
	$count = 0
	while ((Get-Date) -lt $deadline) {
		try {
			$count = Get-CpAlertCount -HostName $ControlPlaneHost
		} catch {
			$count = 0
		}
		if ($count -ge $target) {
			Write-Host "control plane alerts: $count (target >= $target)"
			break
		}
		Write-Host "waiting for alerts ($count/$target)..."
		Start-Sleep -Seconds 5
	}
	if ($count -lt $target) {
		throw "timed out waiting for control plane alert forwarding"
	}
}

Remove-Item -LiteralPath $probeDir -Recurse -Force -ErrorAction SilentlyContinue
Write-Host 'detection pipeline pilot check OK'
