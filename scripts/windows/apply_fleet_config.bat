@echo off
setlocal EnableExtensions

net session >nul 2>&1
if errorlevel 1 (
	echo ERROR: Run as Administrator.
	exit /b 1
)

set "DATAROOT=%ProgramData%\EDR Agent"
set "FLEET=%DATAROOT%\config.fleet.yml"
set "ACTIVE=%DATAROOT%\config.yml"

if not exist "%FLEET%" (
	echo ERROR: Missing "%FLEET%". Reinstall the MSI or copy configs\windows\config.fleet.yml.
	exit /b 1
)

copy /Y "%FLEET%" "%ACTIVE%" >nul || exit /b 1

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
