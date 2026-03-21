import os, glob, re

count = 0
for filepath in glob.glob(r"C:\Users\User\.gemini\antigravity\scratch\aura\**\*.py", recursive=True):
    if "formatter.py" in filepath: continue
    if "nexus_zenith" in filepath: continue
    
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            text = f.read()
    except UnicodeDecodeError:
        try:
            with open(filepath, "r", encoding="latin-1") as f:
                text = f.read()
        except Exception: continue
            
    original = text
    # Replace any `console = Console(...)`
    text = re.sub(r"^[ \t]*console\s*=\s*Console\([^\)]*\)", "from aura.ui.formatter import console", text, flags=re.MULTILINE)
    
    if text != original:
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(text)
        count += 1

print(f"Patched {count} files.")
