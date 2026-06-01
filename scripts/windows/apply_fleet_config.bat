@echo off
setlocal EnableExtensions

net session >nul 2>&1
if errorlevel 1 (
	echo ERROR: Run as Administrator.
	exit /b 1
)

set "HOST=%~1"
if not defined HOST set "HOST=%EDR_CONTROL_PLANE_HOST%"

set "DATAROOT=%ProgramData%\EDR Agent"
set "FLEET=%DATAROOT%\config.fleet.yml"
set "ACTIVE=%DATAROOT%\config.yml"

if not exist "%FLEET%" (
	echo ERROR: Missing "%FLEET%". Reinstall the MSI or copy configs\windows\config.fleet.yml.
	exit /b 1
)

copy /Y "%FLEET%" "%ACTIVE%" >nul || exit /b 1

if defined HOST (
	powershell -NoProfile -ExecutionPolicy Bypass -Command ^
		"$p='%ACTIVE%'; $h='%HOST%'; $c=Get-Content -LiteralPath $p -Raw; $u=$c -replace 'YOUR_CONTROL_PLANE_HOST',$h; if ($u -eq $c) { Write-Warning 'placeholder YOUR_CONTROL_PLANE_HOST not found' }; Set-Content -LiteralPath $p -Value $u -NoNewline" || exit /b 1
	echo Patched server.endpoint=%HOST%
) else (
	echo WARNING: No control plane host set. Pass host as arg or set EDR_CONTROL_PLANE_HOST.
)

sc query EDRAgent >nul 2>&1
if errorlevel 1 (
	echo Applied fleet config to "%ACTIVE%". Start the EDRAgent service to take effect.
	exit /b 0
)

net stop EDRAgent >nul 2>&1
net start EDRAgent >nul 2>&1
if errorlevel 1 (
	echo WARNING: Fleet config applied but EDRAgent service failed to restart.
	exit /b 1
)

echo Applied fleet config and restarted EDRAgent.
exit /b 0
