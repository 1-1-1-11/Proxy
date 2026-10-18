@echo off
setlocal
"C:\Tools\Python\python.exe" -X utf8 -B "%~dp0check.py" --launch --workspace "%CD%"
if errorlevel 1 (
  echo Launch stopped: the fixed exit is not confirmed. See the reasons above.
  exit /b 2
)
set "HTTP_PROXY=http://127.0.0.1:17892"
set "HTTPS_PROXY=http://127.0.0.1:17892"
set "ALL_PROXY=http://127.0.0.1:17892"
set "NO_PROXY=localhost,127.0.0.1,::1"
set "BROWSER=C:\Users\example\.codex\ClaudeNetwork\ClaudeBrowser.exe"
rem Do not override account credentials, provider settings, project scope or history.
rem The CLI may come from npm, the native installer or bun; the first one present is used.
set "CLAUDE_CLI="
for %%P in ("%APPDATA%\npm\claude.cmd" "%USERPROFILE%\.local\bin\claude.exe" "%USERPROFILE%\.bun\bin\claude.exe") do if not defined CLAUDE_CLI if exist %%P set "CLAUDE_CLI=%%~P"
if not defined CLAUDE_CLI (
  echo Claude CLI was not found. Install it, then start again.
  exit /b 3
)
call "%CLAUDE_CLI%" %*
exit /b %errorlevel%
