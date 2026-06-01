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
set "PPL=%DATAROOT%\config.ppl.yml"
set "ACTIVE=%DATAROOT%\config.yml"

if not exist "%PPL%" (
	echo ERROR: Missing "%PPL%". Reinstall the MSI or copy configs\windows\config.ppl.yml.
	exit /b 1
)
if not exist "%AGENT%" (
	echo ERROR: Missing "%AGENT%".
	exit /b 1
)

copy /Y "%PPL%" "%ACTIVE%" >nul || exit /b 1

net stop EDRAgent >nul 2>&1
"%AGENT%" --install || exit /b 1

echo Applied AM-PPL production config. Verify service_hardening_posture.json for ppl_is_antimalware=true.
exit /b 0
