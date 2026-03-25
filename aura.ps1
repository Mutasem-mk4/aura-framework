# Aura v33 Zenith - Windows UTF-8 Launcher
# Usage: .\aura.ps1 [args...]
# Example: .\aura.ps1 --status
#          .\aura.ps1 --setup
#          .\aura.ps1 target.com --auto

$host.UI.RawUI.WindowTitle = "Aura v33 Zenith"

# Force UTF-8 codepage for Rich/Unicode support
$null = chcp 65001 2>&1

# Set environment variables for clean output
$env:PYTHONIOENCODING = "utf-8"
$env:TERM = "xterm-256color"

# Run Aura with all passed arguments
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
python "$scriptDir\aura_main.py" @args
