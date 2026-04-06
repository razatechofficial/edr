@echo off
setlocal EnableExtensions

net session >nul 2>&1
if errorlevel 1 (
	echo ERROR: Run as Administrator.
	exit /b 1
)

set "BINDIR=%ProgramFiles%\EDR\bin"

sc query EDRAgent >nul 2>&1
if not errorlevel 1 (
	net stop EDRAgent >nul 2>&1
	sc delete EDRAgent >nul 2>&1
	ping -n 3 127.0.0.1 >nul
)

if exist "%BINDIR%\edr-agent.exe" del /f /q "%BINDIR%\edr-agent.exe" >nul 2>&1
if exist "%BINDIR%\edrctl.exe" del /f /q "%BINDIR%\edrctl.exe" >nul 2>&1
if exist "%BINDIR%" rmdir "%BINDIR%" >nul 2>&1
if exist "%ProgramFiles%\EDR" rmdir "%ProgramFiles%\EDR" >nul 2>&1

netsh advfirewall firewall delete rule name="EDR Agent" >nul 2>&1

echo Uninstall complete. Configuration and data under "%ProgramData%\EDR" were not removed.
exit /b 0
