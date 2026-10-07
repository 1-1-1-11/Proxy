@echo off
rem All public check entries use the same current checker. No automatic repair.
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%~dp0Repair-ClaudeProxy.ps1" -Full -Output "%~dp0reports\desktop-last-check.json" %*
set "auditExit=%ERRORLEVEL%"
echo.
echo %~dp0reports\desktop-last-check.json
echo claude-proxy -Full -Details
pause
exit /b %auditExit%
