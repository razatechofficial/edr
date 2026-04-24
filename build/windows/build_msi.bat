@echo off
set VERSION=%1
if "%VERSION%"=="" set VERSION=dev
candle -dVersion=%VERSION% build\windows\installer.wxs -o build\windows\installer.wixobj
light build\windows\installer.wixobj -o dist\edr-agent_%VERSION%_amd64.msi
echo Built: dist\edr-agent_%VERSION%_amd64.msi
