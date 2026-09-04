@echo off
REM =============================================================================
REM OSINT Scanner - Installatie Windows
REM =============================================================================

set SCRIPT_DIR=%~dp0
set PYTHON=
set VENV_DIR=%SCRIPT_DIR%.venv

REM --- Zoek Python ---
for %%V in (python3.13 python3.12 python3.11 python3.10 python) do (
    where %%V >nul 2>&1
    if %errorlevel%==0 (
        set PYTHON=%%V
        goto :found_python
    )
)

REM Probeer py alias
where py >nul 2>&1
if %errorlevel%==0 (
    py -3 --version >nul 2>&1
    if %errorlevel%==0 (
        set PYTHON=py -3
        goto :found_python
    )
)

echo FOUT: Geen Python 3.10+ gevonden.
echo Installeer Python via: https://www.python.org/downloads/
echo   (Vink "Add Python to PATH" aan tijdens installatie!)
pause
exit /b 1

:found_python
echo Python gevonden: %PYTHON%
echo.

REM --- Maak virtual environment ---
if not exist "%VENV_DIR%" (
    echo ^>^> Virtual environment aanmaken...
    %PYTHON% -m venv "%VENV_DIR%"
)

REM --- Activeer venv ---
call "%VENV_DIR%\Scripts\activate.bat"

REM --- Installeer dependencies ---
echo ^>^> Dependencies installeren...
pip install --upgrade pip --quiet
pip install -r "%SCRIPT_DIR%requirements.txt" --quiet
pip install pyinstaller --quiet 2>nul

REM Playwright-browser (optioneel; nodig voor de WAF-tolerantie laag "Playwright")
python -c "import playwright" >nul 2>&1
if %errorlevel%==0 (
    echo ^>^> Playwright-browser installeren (optioneel; kan een moment duren)...
    python -m playwright install chromium >nul 2>&1
)

echo.
echo ^>^> Installatie voltooid!
echo.

REM --- Kopieer .env.example naar .env als die niet bestaat ---
if not exist "%SCRIPT_DIR%.env" (
    copy "%SCRIPT_DIR%.env.example" "%SCRIPT_DIR%.env" >nul
    echo ^>^> .env aangemaakt vanuit .env.example
    echo    Vul je API-keys in: %SCRIPT_DIR%.env
    echo.
)

REM --- Chrome check ---
echo ^>^> Chrome checken voor PDF-ondersteuning...
set CHROME_FOUND=0
for %%P in (
    "%ProgramFiles%\Google\Chrome\Application\chrome.exe"
    "%ProgramFiles(x86)%\Google\Chrome\Application\chrome.exe"
    "%ProgramFiles%\Microsoft\Edge\Application\msedge.exe"
) do (
    if exist %%P set CHROME_FOUND=1
)

if %CHROME_FOUND%==1 (
    echo    Chrome gevonden - PDF-export werkt.
) else (
    echo    Chrome niet gevonden - PDF-export werkt niet.
    echo    Installeer Chrome: https://www.google.com/chrome/
)
echo.

echo =================================================================
echo   Starten:    start.bat
echo   Bouwen:     bouw_standalone.bat
echo =================================================================
pause
