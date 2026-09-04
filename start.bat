@echo off
REM OSINT Scanner starten
set SCRIPT_DIR=%~dp0
cd /d "%SCRIPT_DIR%"

REM Python bepalen: venv heeft voorrang
set PYTHON=python
if exist "%SCRIPT_DIR%.venv\Scripts\python.exe" (
    set PYTHON=%SCRIPT_DIR%.venv\Scripts\python.exe
)

REM Installatie-check: dependencies aanwezig? Zo niet, installeer automatisch.
%PYTHON% -c "import requests, rich" >nul 2>&1
if errorlevel 1 (
    echo.
    echo [!] Dependencies ontbreken - eerste keer starten^?
    echo ^>^> Installatie wordt automatisch gestart...
    if exist "%SCRIPT_DIR%install_windows.bat" (
        call "%SCRIPT_DIR%install_windows.bat"
    ) else (
        echo FOUT: install_windows.bat niet gevonden. Installeer handmatig:
        echo   pip install -r requirements.txt
        pause
        exit /b 1
    )
)

%PYTHON% "%SCRIPT_DIR%osint_scanner.py" %*
pause
