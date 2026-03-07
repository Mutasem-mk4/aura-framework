import sqlite3
conn = sqlite3.connect("aura_intel.db")
c = conn.cursor()
c.execute("PRAGMA table_info(findings)")
cols = [r[1] for r in c.fetchall()]
print("findings cols:", cols)
c.execute("SELECT COUNT(*) FROM findings")
print("total findings:", c.fetchone()[0])
# Sample a row to understand structure
c.execute("SELECT * FROM findings LIMIT 1")
row = c.fetchone()
if row:
    for i, val in enumerate(row):
        print(f"  {cols[i]}: {str(val)[:80]}")
conn.close()
