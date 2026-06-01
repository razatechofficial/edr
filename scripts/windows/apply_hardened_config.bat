@echo off
setlocal EnableExtensions

net session >nul 2>&1
if errorlevel 1 (
	echo ERROR: Run as Administrator.
	exit /b 1
)

set "DATAROOT=%ProgramData%\EDR Agent"
set "HARDENED=%DATAROOT%\config.hardened.yml"
set "ACTIVE=%DATAROOT%\config.yml"

if not exist "%HARDENED%" (
	echo ERROR: Missing "%HARDENED%". Reinstall the MSI or copy configs\windows\config.hardened.yml.
	exit /b 1
)

copy /Y "%HARDENED%" "%ACTIVE%" >nul || exit /b 1

sc query EDRAgent >nul 2>&1
if errorlevel 1 (
	echo Applied hardened config to "%ACTIVE%". Start the EDRAgent service to take effect.
	exit /b 0
)

net stop EDRAgent >nul 2>&1
net start EDRAgent >nul 2>&1
if errorlevel 1 (
	echo WARNING: Hardened config applied but EDRAgent service failed to restart.
	exit /b 1
)

echo Applied hardened config and restarted EDRAgent.
exit /b 0
