@echo off
REM Thin wrapper: real build logic is scripts\ci\build_windows_msi.ps1 (same as CI).
setlocal
set "VERSION=%~1"
if "%VERSION%"=="" set "VERSION=1.0.0.0"
pushd "%~dp0..\.."
powershell -NoProfile -ExecutionPolicy Bypass -File "scripts\ci\build_windows_msi.ps1" -Version "%VERSION%"
set "ERR=%ERRORLEVEL%"
popd
exit /b %ERR%
