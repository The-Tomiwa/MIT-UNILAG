@echo off
REM GPON Malware Framework Generator - one-click start (Windows)
cd /d "%~dp0"

where python >nul 2>nul
if errorlevel 1 (
  echo Python 3.10+ is required. Install it from https://www.python.org/downloads/
  echo and tick "Add python.exe to PATH" during setup, then run this file again.
  pause
  exit /b 1
)

REM A .venv copied from another computer points at that computer's Python and
REM will not start here - detect that and rebuild it.
set NEEDS_SETUP=0
if not exist ".venv\Scripts\python.exe" set NEEDS_SETUP=1
if "%NEEDS_SETUP%"=="0" (
  ".venv\Scripts\python.exe" -c "import flask, fitz" >nul 2>nul || set NEEDS_SETUP=1
)

if "%NEEDS_SETUP%"=="1" (
  echo First run on this computer: setting up Python environment and dependencies...
  if exist ".venv" rmdir /s /q ".venv"
  python -m venv .venv || goto :fail
  ".venv\Scripts\python.exe" -m pip install --quiet --upgrade pip
  ".venv\Scripts\python.exe" -m pip install --quiet flask pymupdf || goto :fail
  REM optional, only used by the tests to compile-check YARA rules
  ".venv\Scripts\python.exe" -m pip install --quiet yara-python >nul 2>nul
)

echo.
echo Starting on http://127.0.0.1:5057  (close this window or press Ctrl+C to stop)
start "" "http://127.0.0.1:5057"
".venv\Scripts\python.exe" app.py
pause
exit /b 0

:fail
echo Setup failed - check your internet connection and try again.
pause
exit /b 1
