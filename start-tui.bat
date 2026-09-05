@echo off
REM OSINT Scanner - Textual desktop-versie
REM Zelfhelend: installeert textual automatisch als die ontbreekt.
set SCRIPT_DIR=%~dp0
cd /d "%SCRIPT_DIR%"

REM Python bepalen: venv heeft voorrang
set PYTHON=python
if exist "%SCRIPT_DIR%.venv\Scripts\python.exe" (
    set PYTHON=%SCRIPT_DIR%.venv\Scripts\python.exe
)

REM Installatie-check: basisfunctionaliteit aanwezig? Zo niet, installeer.
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

REM Textual (TUI-modus) zelfhelend installeren
%PYTHON% -c "import textual" >nul 2>&1
if errorlevel 1 (
    echo.
    echo [!] Textual ontbreekt - nodig voor de desktop-versie.
    echo ^>^> Textual wordt geinstalleerd...
    %PYTHON% -m pip install --quiet --upgrade textual
    if errorlevel 1 (
        echo FOUT: textual kon niet geinstalleerd worden. Probeer handmatig:
        echo   %PYTHON% -m pip install textual
        pause
        exit /b 1
    )
    echo [OK] Textual gereed
)

%PYTHON% "%SCRIPT_DIR%osint_tui.py" %*
pause