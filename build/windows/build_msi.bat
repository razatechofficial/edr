@echo off
setlocal
REM WiX Product/@Version must be numeric a.b.c.d (each 0-65535). Do not pass git describe strings here.
set VERSION=%1
if "%VERSION%"=="" set VERSION=1.0.0.0
REM Run from repo root. Absolute -d paths so light.exe bind phase always finds payload (see WiX binder docs).
set "ROOT=%CD%"
set "AGENT=%ROOT%\dist\windows-amd64\edr-agent.exe"
set "CONF=%ROOT%\build\windows\config.yml"
REM Logs consumed by CI (release.yml) on failure.
candle -nologo -arch x64 -dVersion=%VERSION% "-dAgentExe=%AGENT%" "-dConfigYml=%CONF%" build\windows\installer.wxs -o build\windows\installer.wixobj >build\windows\candle.log 2>&1
if errorlevel 1 (
  echo candle failed, see build\windows\candle.log
  type build\windows\candle.log
  exit /b 1
)
light -nologo -sval -sw1076 build\windows\installer.wixobj -o dist\edr-agent_%VERSION%_amd64.msi >build\windows\light.log 2>&1
if errorlevel 1 (
  echo light failed, see build\windows\light.log
  type build\windows\light.log
  exit /b 1
)
echo Built: dist\edr-agent_%VERSION%_amd64.msi
exit /b 0
