import os
import re

def check_files(start_dir):
    for root, dirs, files in os.walk(start_dir):
        for file in files:
            if file.endswith(".py"):
                path = os.path.join(root, file)
                with open(path, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
                    if "os." in content and "import os" not in content and "from os import" not in content:
                        print(f"Missing import os in: {path}")

if __name__ == "__main__":
    check_files(r"C:\Users\User\.gemini\antigravity\scratch\aura\aura")
