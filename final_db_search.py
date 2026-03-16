import sqlite3
import os

db_path = r'C:\Users\User\.gemini\antigravity\scratch\aura\scripts\aura_intel.db'
if os.path.exists(db_path):
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    print(f"--- Searching {db_path} ---")
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
    tables = [t[0] for t in cursor.fetchall()]
    print(f"Tables: {tables}")
    
    for table in tables:
        cursor.execute(f"PRAGMA table_info(\"{table}\")")
        cols = [c[1] for c in cursor.fetchall()]
        for col in cols:
            try:
                cursor.execute(f"SELECT * FROM \"{table}\" WHERE \"{col}\" LIKE '%arc.net%'")
                rows = cursor.fetchall()
                if rows:
                    print(f"[{table}.{col}] Matches: {len(rows)}")
                    for r in rows[:10]:
                        print(r)
            except:
                pass
    conn.close()
else:
    print(f"DB not found at {db_path}")
