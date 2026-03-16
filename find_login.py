import sqlite3
import os

db_path = 'C:/Users/User/.gemini/antigravity\scratch/aura/aura_intel.db'
if not os.path.exists(db_path):
    print(f"DB not found at {db_path}")
    exit()

conn = sqlite3.connect(db_path)
cur = conn.cursor()

print("Searching for login/auth URLs for alscotoday.com...")
# Correct schema: targets.value, findings.content
cur.execute("SELECT value FROM targets WHERE value LIKE '%alscotoday%'")
targets = cur.fetchall()
for t in targets:
    print(f"Target: {t[0]}")

cur.execute("SELECT finding_type, content FROM findings WHERE content LIKE '%alscotoday%' AND (content LIKE '%login%' OR content LIKE '%auth%' OR content LIKE '%sign%')")
findings = cur.fetchall()
for f in findings:
    print(f"Finding Type: {f[0]} | Content: {f[1][:200]}...")

if not findings:
    print("No specific login URLs found in findings. Checking common paths manually...")
    import requests
    common_paths = ["/login", "/signin", "/auth", "/administrator", "/admin", "/wp-login.php"]
    for path in common_paths:
        url = f"http://alscotoday.com{path}"
        try:
            r = requests.get(url, timeout=5, verify=False)
            if r.status_code == 200:
                print(f"FOUND (HTTP 200): {url}")
        except:
            pass
