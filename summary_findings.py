
import sqlite3

try:
    conn = sqlite3.connect("aura_intel.db")
    cur = conn.cursor()
    print("--- 🎯 Intigriti Campaign Summary ---")
    cur.execute("SELECT type, severity, target FROM findings WHERE target LIKE '%intigriti%' ORDER BY rowid DESC LIMIT 5;")
    results = cur.fetchall()
    if results:
        for r in results:
            print(f"[*] Found: {r[0]} ({r[1]}) on {r[2]}")
    else:
        print("[!] No findings yet for Intigriti.")
    
    cur.execute("SELECT count(*) FROM findings WHERE target LIKE '%intigriti%';")
    count = cur.fetchone()[0]
    print(f"\nTotal Intigriti findings: {count}")
    conn.close()
except Exception as e:
    print(f"Error: {e}")
