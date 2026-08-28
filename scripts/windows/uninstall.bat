@echo off
setlocal EnableExtensions

net session >nul 2>&1
if errorlevel 1 (
	echo ERROR: Run as Administrator.
	exit /b 1
)

set "INSTALLDIR=%ProgramFiles%\EDR Agent"
set "INSTALLER=%INSTALLDIR%\edr-installer.exe"
set "AGENT_EXE=%INSTALLDIR%\edr-agent.exe"

if exist "%INSTALLER%" (
	"%INSTALLER%" uninstall
	exit /b %ERRORLEVEL%
)

if exist "%AGENT_EXE%" (
	"%AGENT_EXE%" --uninstall >nul 2>&1
)

sc stop EDRAgent >nul 2>&1
sc delete EDRAgent >nul 2>&1
reg delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" /v "EDR Agent" /f >nul 2>&1

if exist "%INSTALLDIR%" rmdir /s /q "%INSTALLDIR%" >nul 2>&1
if exist "%ProgramData%\EDR Agent" rmdir /s /q "%ProgramData%\EDR Agent" >nul 2>&1

netsh advfirewall firewall delete rule name="EDR Agent" >nul 2>&1

echo Uninstall complete. EDR Agent files, service, firewall rule, and data were removed.
exit /b 0
