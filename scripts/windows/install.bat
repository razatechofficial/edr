@echo off
setlocal EnableExtensions

net session >nul 2>&1
if errorlevel 1 (
	echo ERROR: Run as Administrator.
	exit /b 1
)

set "ROOT=%~dp0"
set "CFGDIR=%ProgramData%\EDR\config"
set "BINDIR=%ProgramFiles%\EDR\bin"
set "AGENT_EXE=%BINDIR%\edr-agent.exe"
set "CFG=%CFGDIR%\agent.yaml"

mkdir "%ProgramData%\EDR\config" 2>nul
mkdir "%ProgramData%\EDR\data" 2>nul
mkdir "%ProgramData%\EDR\logs" 2>nul
mkdir "%ProgramData%\EDR\rules" 2>nul
mkdir "%ProgramData%\EDR\quarantine" 2>nul
mkdir "%BINDIR%" 2>nul

copy /Y "%ROOT%edr-agent-windows-amd64.exe" "%AGENT_EXE%" >nul || exit /b 1
copy /Y "%ROOT%edrctl-windows-amd64.exe" "%BINDIR%\edrctl.exe" >nul || exit /b 1

if not exist "%CFG%" (
	if exist "%ROOT%config\agent.yaml" (
		copy /Y "%ROOT%config\agent.yaml" "%CFG%" >nul || exit /b 1
	) else (
		echo ERROR: Missing template "%ROOT%config\agent.yaml"
		exit /b 1
	)
)

sc query EDRAgent >nul 2>&1
if not errorlevel 1 (
	net stop EDRAgent >nul 2>&1
	sc delete EDRAgent >nul 2>&1
	ping -n 3 127.0.0.1 >nul
)

sc create EDRAgent binPath= "\"%AGENT_EXE%\" run --config \"%CFG%\"" start= auto DisplayName= "EDR Agent" || exit /b 1
sc description EDRAgent "EDR endpoint detection and response agent" >nul 2>&1

sc failure EDRAgent reset= 86400 actions= restart/5000/restart/10000/restart/30000 >nul 2>&1
sc failureflag EDRAgent 1 >nul 2>&1

netsh advfirewall firewall show rule name="EDR Agent" >nul 2>&1
if errorlevel 1 (
	netsh advfirewall firewall add rule name="EDR Agent" dir=out action=allow program="%AGENT_EXE%" enable=yes >nul || exit /b 1
)

sc start EDRAgent || exit /b 1
echo EDR Agent installed and started.
exit /b 0
