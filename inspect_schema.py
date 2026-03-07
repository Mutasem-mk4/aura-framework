
import sqlite3

try:
    conn = sqlite3.connect("aura_intel.db")
    cur = conn.cursor()
    cur.execute("SELECT name FROM sqlite_master WHERE type='table';")
    tables = [t[0] for t in cur.fetchall()]
    print("Tables:", tables)
    for table in tables:
        print(f"\nSchema for {table}:")
        cur.execute(f"PRAGMA table_info({table});")
        print([c[1] for c in cur.fetchall()])
    conn.close()
except Exception as e:
    print(f"Error: {e}")
