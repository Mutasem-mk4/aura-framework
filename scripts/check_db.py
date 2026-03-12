import sqlite3, json
conn = sqlite3.connect('aura_intel.db')
# Check targets schema
print("=== TARGETS TABLE COLUMNS ===")
cols = conn.execute("PRAGMA table_info(targets)").fetchall()
for c in cols:
    print(f"  {c[1]} ({c[2]})")
print()

# Check all tables
print("=== ALL TABLES ===")
for name, in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall():
    cnt = conn.execute(f"SELECT COUNT(*) FROM [{name}]").fetchone()[0]
    print(f"  {name}: {cnt} rows")
print()

# Sample target data
print("=== SAMPLE TARGETS ===")
rows = conn.execute("SELECT * FROM targets LIMIT 3").fetchall()
cols = [c[1] for c in conn.execute("PRAGMA table_info(targets)").fetchall()]
for row in rows:
    print({cols[i]: str(v)[:200] for i, v in enumerate(row)})
    print()

conn.close()
