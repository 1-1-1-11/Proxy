@echo off
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%USERPROFILE%\.codex\ClaudeNetwork\Repair-ClaudeProxy.ps1" %*
exit /b %ERRORLEVEL%
