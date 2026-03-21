import os, glob

count = 0
for filepath in glob.glob(r"C:\Users\User\.gemini\antigravity\scratch\aura\**\*.py", recursive=True):
    if "formatter.py" in filepath: continue
    if "nexus_zenith" in filepath: continue
    
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            text = f.read()
    except Exception: continue
            
    original = text
    
    # 1. Exact string replace for the generic console instantiation
    text = text.replace("    from aura.ui.formatter import console", "    from aura.ui.formatter import console")
    text = text.replace("        from aura.ui.formatter import console", "        from aura.ui.formatter import console")
    text = text.replace("from aura.ui.formatter import console", "from aura.ui.formatter import console")
    
    # 2. Advanced forms
    text = text.replace("from aura.ui.formatter import console", "from aura.ui.formatter import console")
    text = text.replace("from aura.ui.formatter import console", "from aura.ui.formatter import console")
    
    if text != original:
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(text)
        count += 1

print(f"Bruteforce Patched {count} files.")
