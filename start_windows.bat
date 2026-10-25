@echo off
setlocal
cd /d "%~dp0"
if not exist ".venv\Scripts\python.exe" (
    py -3 -m venv .venv
    if errorlevel 1 goto :failed
)
".venv\Scripts\python.exe" -m pip install -r requirements.txt
if errorlevel 1 goto :failed
".venv\Scripts\python.exe" run_local.py
if errorlevel 1 goto :failed
exit /b 0
:failed
echo NoxCipher could not start. Check Python installation and the error above.
pause
exit /b 1
