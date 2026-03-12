import sqlite3
import json

def check_findings():
    db_path = "aura_intel.db"
    try:
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        cursor.execute("SELECT * FROM findings ORDER BY id DESC LIMIT 5")
        rows = cursor.fetchall()
        
        print(f"--- Latest 5 Findings ---")
        for row in rows:
            print(dict(row))
            
    except Exception as e:
        print(f"Error: {e}")
    finally:
        conn.close()

if __name__ == "__main__":
    check_findings()
