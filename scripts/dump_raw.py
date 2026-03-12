import sqlite3

def dump_raw_findings(db_path):
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    try:
        # Get all table names
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
        tables = cursor.fetchall()
        print(f"Tables: {tables}")
        
        # Dump findings table info
        cursor.execute("PRAGMA table_info(findings);")
        print("Findings Table Info:", cursor.fetchall())
        
        # Dump first 5 rows
        cursor.execute("SELECT * FROM findings LIMIT 5;")
        print("First 5 Rows:", cursor.fetchall())
    except Exception as e:
        print(f"Error: {e}")
    finally:
        conn.close()

if __name__ == "__main__":
    dump_raw_findings("aura_intel.db")
