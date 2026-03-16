import os

def check_files(start_dir):
    missing = []
    for root, dirs, files in os.walk(start_dir):
        for file in files:
            if file.endswith(".py"):
                path = os.path.join(root, file)
                try:
                    with open(path, "r", encoding="utf-8", errors="ignore") as f:
                        lines = f.readlines()
                        has_os_use = any("os." in line for line in lines)
                        has_os_import = any("import os" in line or "from os import" in line for line in lines)
                        if has_os_use and not has_os_import:
                            missing.append(path)
                except Exception:
                    pass
    return missing

if __name__ == "__main__":
    aura_dir = r"C:\Users\User\.gemini\antigravity\scratch\aura\aura"
    results = check_files(aura_dir)
    print("COUNT=" + str(len(results)))
    for r in results:
        print("MISSING:" + r)
