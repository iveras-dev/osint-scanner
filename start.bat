@echo off
REM OSINT Scanner starten
set SCRIPT_DIR=%~dp0
if exist "%SCRIPT_DIR%.venv\Scripts\activate.bat" (
    call "%SCRIPT_DIR%.venv\Scripts\activate.bat"
)
python "%SCRIPT_DIR%osint_scanner.py" %*
pause
