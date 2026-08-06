@echo off
setlocal
chcp 65001 >nul
title AegisScope Control Plane

powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\windows\Start-AegisScope.ps1"
set "AEGIS_EXIT=%ERRORLEVEL%"

if not "%AEGIS_EXIT%"=="0" (
  echo.
  echo AegisScope exited with code %AEGIS_EXIT%.
  echo AegisScope 已退出，错误码：%AEGIS_EXIT%。
  pause
)

exit /b %AEGIS_EXIT%
