@echo off
setlocal EnableExtensions

net session >nul 2>&1
if errorlevel 1 (
	echo ERROR: Run as Administrator.
	exit /b 1
)

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

net stop EDRAgent >nul 2>&1
"%AGENT%" --install || exit /b 1

echo Applied enterprise tenant config (hardened ETW + service hardening) and reinstalled EDRAgent.
exit /b 0
