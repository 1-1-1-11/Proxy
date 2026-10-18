@echo off
rem Desktop "network check": check first; when something fails, offer the repair once.
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%~dp0Repair-ClaudeProxy.ps1" -OfferRepair %*
set "checkExit=%ERRORLEVEL%"
echo.
pause
exit /b %checkExit%
