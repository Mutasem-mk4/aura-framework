import sqlite3

def get_findings_info(db_path):
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    try:
        cursor.execute("PRAGMA table_info(findings);")
        columns = cursor.fetchall()
        print("Findings Columns:")
        for col in columns:
            print(col)
        
        cursor.execute("SELECT * FROM findings LIMIT 1;")
        row = cursor.fetchone()
        print("\nFirst Row Data:")
        print(row)
    except Exception as e:
        print(f"Error: {e}")
    finally:
        conn.close()

if __name__ == "__main__":
    get_findings_info("aura_intel.db")
