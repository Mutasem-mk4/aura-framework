import os, glob
import re

count = 0
for filepath in glob.glob(r"C:\Users\User\.gemini\antigravity\scratch\aura\**\*.py", recursive=True):
    if "formatter.py" in filepath: continue
    if "nexus_zenith" in filepath: continue
    
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            text = f.read()
    except Exception: continue
    
    if re.search(r"console\s*=\s*Console\(", text):
        print(f"FOUND IN: {filepath}")
        for line in text.split("\n"):
            if "console = Console(" in line:
                print(f"  {line}")
