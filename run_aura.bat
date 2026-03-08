@echo off
setlocal enabledelayedexpansion

:: Aura v25.0 - Ultimate Runner
cd /d "%~dp0"

:: 1. Auto-detect Python command
set "PY_CMD=python"
where !PY_CMD! >nul 2>nul
if errorlevel 1 (
    set "PY_CMD=py"
    where !PY_CMD! >nul 2>nul
    if errorlevel 1 (
        :: Fallback: Try standard AppData location (latest first)
        for /f "delims=" %%D in ('dir /b /ad /o-n "%LOCALAPPDATA%\Programs\Python\Python*" 2^>nul') do (
            if exist "%LOCALAPPDATA%\Programs\Python\%%D\python.exe" (
                set "PY_CMD=%LOCALAPPDATA%\Programs\Python\%%D\python.exe"
                goto :found_py
            )
        )
        echo [!] ERROR: Python not found in PATH or standard AppData locations.
        echo Please ensure Python 3.10+ is installed and 'python' is in your PATH.
        exit /b 1
    )
)
:found_py

if "%~1" == "" (
    echo.
    echo [!] Aura Sentinel - Tactical Runner
    echo ------------------------------------
    echo Usage:   aura ^<target_domain^> [options]
    echo.
    echo Examples:
    echo   aura intel.com
    echo   aura intel.com --ai-provider gemini
    echo   aura intel.com --free-ai
    echo   aura intel.com --ai-model anthropic/claude-3.5-sonnet
    echo.
    exit /b
)

:: 2. Launch Mission
set "ARGS=%*"

echo [🚀] Engaging Zenith Protocol via "!PY_CMD!" for: %1
"!PY_CMD!" aura_main.py !ARGS!
if errorlevel 1 (
    echo.
    echo [!] Mission aborted. If you see 'ModuleNotFoundError', please run:
    echo     pip install rich aiohttp httpx curl_cffi google-generativeai beautifulsoup4 lxml PyYAML jinja2
)

