@echo off
REM =============================================================================
REM OSINT Scanner - Bouw standalone app (Windows)
REM =============================================================================

set SCRIPT_DIR=%~dp0

REM Activeer venv
if exist "%SCRIPT_DIR%.venv\Scripts\activate.bat" (
    call "%SCRIPT_DIR%.venv\Scripts\activate.bat"
)

REM Check PyInstaller
where pyinstaller >nul 2>&1
if %errorlevel% neq 0 (
    echo PyInstaller niet gevonden. Installeren...
    pip install pyinstaller
)

echo ^>^> Bouwen van standalone OSINT Scanner...
echo.

cd /d "%SCRIPT_DIR%"

pyinstaller ^
    --name "OSINT-Scanner" ^
    --onefile ^
    --console ^
    --clean ^
    --noconfirm ^
    --collect-submodules holehe ^
    --collect-submodules ddgs ^
    --collect-submodules duckduckgo_search ^
    --collect-submodules socid_extractor ^
    --collect-submodules maigret ^
    --collect-data maigret ^
    --hidden-import harvest_client ^
    --hidden-import pycountry ^
    --hidden-import certifi ^
    --hidden-import httpx ^
    --hidden-import trio ^
    --hidden-import rich ^
    --hidden-import requests ^
    --add-data "requirements.txt;." ^
    --add-data ".env.example;." ^
    osint_scanner.py

echo.
echo =================================================================
echo   BUILD VOLTOOID!
echo.
echo   Executable:  %SCRIPT_DIR%dist\OSINT-Scanner.exe
echo.
echo   Kopieer naar een nieuwe map samen met:
echo     - .env.example (template voor API-keys)
echo.
echo   Of deel de hele gdorks/ map.
echo =================================================================
pause
