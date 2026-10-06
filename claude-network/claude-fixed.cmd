@echo off
setlocal
"C:\Tools\Python\python.exe" -X utf8 -B "%~dp0audit_proxy.py" --launch-check --workspace "%CD%"
if errorlevel 1 (
  echo Claude fixed proxy unavailable or public IP changed. Launch stopped.
  echo Run claude-proxy for details, or claude-proxy -Repair for explicit repair.
  exit /b 2
)
set "HTTP_PROXY=http://127.0.0.1:17892"
set "HTTPS_PROXY=http://127.0.0.1:17892"
set "ALL_PROXY=http://127.0.0.1:17892"
set "NO_PROXY=localhost,127.0.0.1,::1"
set "BROWSER=C:\Users\example\.codex\ClaudeNetwork\ClaudeBrowser.exe"
rem Do not override account credentials, provider settings, project scope or history.
call "C:\Users\example\AppData\Roaming\npm\claude.cmd" %*
exit /b %errorlevel%
