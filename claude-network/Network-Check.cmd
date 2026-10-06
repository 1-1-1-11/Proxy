@echo off
rem All public check entries use the same current checker. No automatic repair.
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%~dp0Repair-ClaudeProxy.ps1" -Full -Output "%~dp0reports\desktop-last-check.json" %*
set "auditExit=%ERRORLEVEL%"
echo.
echo Check complete. No automatic repair was performed.
echo Report: %~dp0reports\desktop-last-check.json
echo Explicit repair: claude-proxy -Repair
pause
exit /b %auditExit%
