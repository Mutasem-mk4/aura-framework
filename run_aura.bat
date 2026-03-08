@echo off
setlocal enabledelayedexpansion

:: Aura v25.0 - Hybrid Runner
cd /d "%~dp0"

:: Auto-detect Python command
set PY_CMD=python
where python >nul 2>nul
if errorlevel 1 (
    where py >nul 2>nul
    if not errorlevel 1 (
        set PY_CMD=py
    ) else (
        echo [!] ERROR: Python not found. Please install Python or use the absolute path.
        exit /b 1
    )
)

if "%~1"=="" (
    echo.
    echo [!] Aura Sentinel - Tactical Runner
    echo ------------------------------------
    echo Usage:   aura ^<target_domain^> [options]
    echo.
    echo Examples:
    echo   aura intel.com
    echo   aura intel.com --ai-provider gemini
    echo   aura intel.com --ai-model anthropic/claude-3.5-sonnet
    echo.
    exit /b
)

:: Check AI options
set ARGS=%*
set HAS_AI=0
echo !ARGS! | findstr /i "--ai-provider" >nul && set HAS_AI=1
echo !ARGS! | findstr /i "--ai-model" >nul && set HAS_AI=1

if !HAS_AI!==0 (
    set ARGS=!ARGS! --ai-provider gemini
)

echo [🚀] Engaging Zenith Protocol via !PY_CMD! for: %~1
!PY_CMD! aura_main.py !ARGS!

