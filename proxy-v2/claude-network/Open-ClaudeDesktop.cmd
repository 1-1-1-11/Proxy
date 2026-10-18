@echo off
rem Desktop "Claude client (fixed exit)": check first, then start the app pinned to the dedicated port.
"C:\Tools\Python\python.exe" -X utf8 -B "%~dp0check.py" --open-desktop --workspace "%USERPROFILE%"
if errorlevel 1 (
  echo.
  pause
  exit /b 2
)
exit /b 0
