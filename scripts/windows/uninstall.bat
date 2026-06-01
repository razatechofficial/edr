@echo off
setlocal EnableExtensions

net session >nul 2>&1
if errorlevel 1 (
	echo ERROR: Run as Administrator.
	exit /b 1
)

set "INSTALLDIR=%ProgramFiles%\EDR Agent"
set "AGENT_EXE=%INSTALLDIR%\edr-agent.exe"

if exist "%AGENT_EXE%" (
	"%AGENT_EXE%" --uninstall >nul 2>&1
)

if exist "%AGENT_EXE%" del /f /q "%AGENT_EXE%" >nul 2>&1
if exist "%INSTALLDIR%\edrctl.exe" del /f /q "%INSTALLDIR%\edrctl.exe" >nul 2>&1
if exist "%INSTALLDIR%" rmdir "%INSTALLDIR%" >nul 2>&1

netsh advfirewall firewall delete rule name="EDR Agent" >nul 2>&1

echo Uninstall complete. Config and data remain under "%ProgramData%\EDR Agent".
exit /b 0
