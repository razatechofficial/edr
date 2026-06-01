@echo off
setlocal EnableExtensions

net session >nul 2>&1
if errorlevel 1 (
	echo ERROR: Run as Administrator.
	exit /b 1
)

set "DATAROOT=%ProgramData%\EDR Agent"
set "ENTERPRISE=%DATAROOT%\config.enterprise.yml"
set "ACTIVE=%DATAROOT%\config.yml"

if not exist "%ENTERPRISE%" (
	echo ERROR: Missing "%ENTERPRISE%". Reinstall the MSI or copy configs\windows\config.enterprise.yml.
	exit /b 1
)

copy /Y "%ENTERPRISE%" "%ACTIVE%" >nul || exit /b 1

sc query EDRAgent >nul 2>&1
if errorlevel 1 (
	echo Applied enterprise config (ML enabled) to "%ACTIVE%". Start the EDRAgent service to take effect.
	exit /b 0
)

net stop EDRAgent >nul 2>&1
net start EDRAgent >nul 2>&1
if errorlevel 1 (
	echo WARNING: Enterprise config applied but EDRAgent service failed to restart.
	exit /b 1
)

echo Applied enterprise config (ML enabled) and restarted EDRAgent.
exit /b 0
