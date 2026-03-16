import sqlite3
import os

db_path = 'scripts/aura_intel.db'
if os.path.exists(db_path):
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
    tables = [t[0] for t in cursor.fetchall()]
    print(f"Tables in {db_path}: {tables}")
    for table in tables:
        cursor.execute(f"SELECT COUNT(*) FROM {table}")
        print(f"Table {table} has {cursor.fetchone()[0]} rows.")
    conn.close()
else:
    print(f"{db_path} not found.")
