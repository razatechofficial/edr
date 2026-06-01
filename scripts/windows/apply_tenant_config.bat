@echo off
setlocal EnableExtensions

net session >nul 2>&1
if errorlevel 1 (
	echo ERROR: Run as Administrator.
	exit /b 1
)

set "HOST=%~1"
if not defined HOST set "HOST=%EDR_CONTROL_PLANE_HOST%"

set "INSTALLDIR=%ProgramFiles%\EDR Agent"
set "AGENT=%INSTALLDIR%\edr-agent.exe"
set "DATAROOT=%ProgramData%\EDR Agent"
set "TENANT=%DATAROOT%\config.tenant.yml"
set "ACTIVE=%DATAROOT%\config.yml"

if not exist "%TENANT%" (
	echo ERROR: Missing "%TENANT%". Reinstall the MSI or copy configs\windows\config.tenant.yml.
	exit /b 1
)
if not exist "%AGENT%" (
	echo ERROR: Missing "%AGENT%".
	exit /b 1
)

copy /Y "%TENANT%" "%ACTIVE%" >nul || exit /b 1

if defined HOST (
	powershell -NoProfile -ExecutionPolicy Bypass -Command ^
		"$p='%ACTIVE%'; $h='%HOST%'; $c=Get-Content -LiteralPath $p -Raw; $u=$c -replace 'YOUR_CONTROL_PLANE_HOST',$h; if ($u -eq $c) { Write-Warning 'placeholder YOUR_CONTROL_PLANE_HOST not found' }; Set-Content -LiteralPath $p -Value $u -NoNewline" || exit /b 1
	echo Patched server.endpoint=%HOST%
) else (
	echo WARNING: No control plane host set. Pass host as arg or set EDR_CONTROL_PLANE_HOST.
)

net stop EDRAgent >nul 2>&1
"%AGENT%" --install || exit /b 1

echo Applied enterprise tenant config (hardened ETW + service hardening) and reinstalled EDRAgent.
exit /b 0
