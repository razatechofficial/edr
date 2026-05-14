@echo off
REM WiX Product/@Version must be numeric a.b.c.d (each 0-65535). Do not pass git describe strings here.
set VERSION=%1
if "%VERSION%"=="" set VERSION=1.0.0.0
candle -arch x64 -dVersion=%VERSION% build\windows\installer.wxs -o build\windows\installer.wixobj
light -sw1076 build\windows\installer.wixobj -o dist\edr-agent_%VERSION%_amd64.msi
echo Built: dist\edr-agent_%VERSION%_amd64.msi
