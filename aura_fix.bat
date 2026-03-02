@echo off
title Aura Self-Repair Tool v19.4
color 0A
echo.
echo  ╔════════════════════════════════════╗
echo  ║   AURA Self-Repair v19.4          ║
echo  ║   Restoring Aura to Peak State    ║
echo  ╚════════════════════════════════════╝
echo.

cd /d "%~dp0"

echo [1/5] Ensuring Python dependencies...
pip install -q aiohttp python-dotenv requests rich playwright google-genai aiofiles
echo [OK] Dependencies

echo.
echo [2/5] Ensuring Playwright browsers...
python -m playwright install chromium --quiet 2>nul
echo [OK] Playwright

echo.
echo [3/5] Restoring Gemini API Key to environment...
setx GEMINI_API_KEY "%GEMINI_API_KEY%" >nul 2>&1
setx AURA_GEMINI_API_KEY "%AURA_GEMINI_API_KEY%" >nul 2>&1
echo [OK] Environment Variables

echo.
echo [4/5] Creating required directories...
if not exist reports mkdir reports
if not exist screenshots mkdir screenshots
if not exist logs mkdir logs
echo [OK] Directories

echo.
echo [5/5] Running health check...
python aura_health.py
if %ERRORLEVEL% EQU 0 (
    echo.
    echo  ✅ Aura is FULLY OPERATIONAL!
    echo  Run: aura zenith ^<target^>
) else (
    echo.
    echo  ⚠️  Some issues remain. Check output above.
)

echo.
pause
