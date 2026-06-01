@echo off
setlocal EnableExtensions

net session >nul 2>&1
if errorlevel 1 (
	echo ERROR: Run as Administrator.
	exit /b 1
)

set "ROOT=%~dp0"
set "REPO=%ROOT%..\.."
set "INSTALLDIR=%ProgramFiles%\EDR Agent"
set "DATAROOT=%ProgramData%\EDR Agent"
set "AGENT_EXE=%INSTALLDIR%\edr-agent.exe"

mkdir "%INSTALLDIR%" 2>nul
mkdir "%DATAROOT%" 2>nul

copy /Y "%ROOT%edr-agent-windows-amd64.exe" "%AGENT_EXE%" >nul || exit /b 1
if exist "%ROOT%edrctl-windows-amd64.exe" (
	copy /Y "%ROOT%edrctl-windows-amd64.exe" "%INSTALLDIR%\edrctl.exe" >nul || exit /b 1
)

if exist "%REPO%\configs\windows\config.yml" (
	copy /Y "%REPO%\configs\windows\config.yml" "%DATAROOT%\config.yml" >nul || exit /b 1
) else if exist "%ROOT%config\agent.yaml" (
	copy /Y "%ROOT%config\agent.yaml" "%DATAROOT%\config.yml" >nul || exit /b 1
)

xcopy /E /I /Y "%REPO%\rules\sigma" "%DATAROOT%\rules\sigma\" >nul 2>&1
xcopy /E /I /Y "%REPO%\rules\yara" "%DATAROOT%\rules\yara\" >nul 2>&1
xcopy /E /I /Y "%REPO%\rules\playbooks" "%DATAROOT%\rules\playbooks\" >nul 2>&1
xcopy /E /I /Y "%REPO%\rules\custom" "%DATAROOT%\rules\custom\" >nul 2>&1
xcopy /E /I /Y "%REPO%\rules\ioc" "%DATAROOT%\rules\ioc\" >nul 2>&1
xcopy /E /I /Y "%REPO%\rules\compliance\sca\windows" "%DATAROOT%\rules\compliance\sca\" >nul 2>&1

"%AGENT_EXE%" --install || exit /b 1

netsh advfirewall firewall show rule name="EDR Agent" >nul 2>&1
if errorlevel 1 (
	netsh advfirewall firewall add rule name="EDR Agent" dir=out action=allow program="%AGENT_EXE%" enable=yes >nul || exit /b 1
)

echo EDR Agent installed to "%INSTALLDIR%" and started as service EDRAgent.
exit /b 0
