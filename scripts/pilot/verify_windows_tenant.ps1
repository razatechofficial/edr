# Verify Windows tenant profile + control plane connectivity after MSI install.
param(
	[string]$ControlPlaneHost = $env:EDR_CONTROL_PLANE_HOST
)

$ErrorActionPreference = 'Stop'

$dataRoot = Join-Path $env:ProgramData 'EDR Agent'
$active = Join-Path $dataRoot 'config.yml'
$agentID = Join-Path $dataRoot 'agent_id'
$grpcPort = 50051

function Test-TcpPort([string]$HostName, [int]$Port) {
	try {
		$client = New-Object System.Net.Sockets.TcpClient
		$async = $client.BeginConnect($HostName, $Port, $null, $null)
		$ok = $async.AsyncWaitHandle.WaitOne(3000, $false)
		if ($ok -and $client.Connected) {
			$client.EndConnect($async) | Out-Null
			$client.Close()
			return $true
		}
		$client.Close()
	} catch {}
	return $false
}

Write-Host "==> EDRAgent service"
$svc = Get-Service -Name EDRAgent -ErrorAction SilentlyContinue
if (-not $svc) {
	throw "EDRAgent service not installed"
}
Write-Host "status: $($svc.Status)"
if ($svc.Status -ne 'Running') {
	throw "EDRAgent service is not running"
}

Write-Host "==> active config"
if (-not (Test-Path -LiteralPath $active)) {
	throw "missing active config: $active"
}
$cfgText = Get-Content -LiteralPath $active -Raw
if ($cfgText -match 'YOUR_CONTROL_PLANE_HOST') {
	throw "config still contains YOUR_CONTROL_PLANE_HOST; run apply_tenant_config.bat <host>"
}

if ($cfgText -match '(?m)^\s*endpoint:\s*"?([^"\r\n]+)"?') {
	$endpoint = $Matches[1].Trim()
	Write-Host "server.endpoint: $endpoint"
	if ($endpoint -eq 'YOUR_CONTROL_PLANE_HOST') {
		throw "server.endpoint not configured"
	}
	if (-not $ControlPlaneHost) {
		$ControlPlaneHost = $endpoint
	}
} else {
	Write-Warning "could not parse server.endpoint from config"
}

Write-Host "==> agent identity"
if (-not (Test-Path -LiteralPath $agentID)) {
	throw "missing agent_id file (agent has not initialized): $agentID"
}
Write-Host "agent_id: $((Get-Content -LiteralPath $agentID -Raw).Trim())"

if ($cfgText -match '(?m)^\s*mutual_tls:\s*true\s*$') {
	$tlsDir = Join-Path $dataRoot 'tls'
	Write-Host "==> mTLS client material ($tlsDir)"
	foreach ($f in @('ca.crt', 'agent-client.crt', 'agent-client.key')) {
		$path = Join-Path $tlsDir $f
		if (-not (Test-Path -LiteralPath $path)) {
			throw "missing mTLS file: $path"
		}
	}
	Write-Host 'mTLS material present'
}

$edrctl = Get-Command edrctl -ErrorAction SilentlyContinue
if ($edrctl) {
	Write-Host '==> edrctl fleet local'
	& edrctl --config $active fleet local
}

if ($ControlPlaneHost) {
	Write-Host "==> control plane gRPC $ControlPlaneHost`:$grpcPort"
	if (-not (Test-TcpPort $ControlPlaneHost $grpcPort)) {
		throw "cannot reach control plane gRPC port ${ControlPlaneHost}:${grpcPort}"
	}
	Write-Host "gRPC port reachable"
}

Write-Host "Windows tenant pilot check OK"
