@echo off
setlocal enabledelayedexpansion

:: Aura v33.2 - Simplified Runner
cd /d "c:\Users\User\.gemini\antigravity\scratch\aura"

if "%~1"=="" (
    echo.
    echo [!] Aura Sentinel - Simplified Runner
    echo ------------------------------------
    echo Usage:   .\run_aura.bat ^<target_domain^> [options]
    echo.
    echo Examples:
    echo   .\run_aura.bat example.com                      (Uses default Gemini)
    echo   .\run_aura.bat example.com --ai-provider gemini  (Force Gemini)
    echo   .\run_aura.bat example.com --ai-model anthropic/claude-3.5-sonnet (OpenRouter)
    echo.
    pause
    exit /b
)

:: Check if user provided provider/model, if not, default to gemini for stability
set ARGS=%*
echo %ARGS% | findstr /i "--ai-provider" >nul
if errorlevel 1 (
    echo %ARGS% | findstr /i "--ai-model" >nul
    if errorlevel 1 (
        set ARGS=%ARGS% --ai-provider gemini
    )
)

echo [🚀] Engaging Zenith Protocol for: %~1
python aura_main.py %ARGS%
pause
