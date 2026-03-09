import sqlite3

def find_logic_finding(db_path):
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    try:
        # Get column names
        cursor.execute("PRAGMA table_info(findings);")
        columns = [col[1] for col in cursor.fetchall()]
        
        # Search all columns for the specific finding
        cursor.execute("SELECT * FROM findings;")
        rows = cursor.fetchall()
        for row in rows:
            row_str = str(row)
            if "State Skip" in row_str or "checkout" in row_str:
                finding = dict(zip(columns, row))
                print(f"MATCH FOUND:")
                for k, v in finding.items():
                    if v: # Only print non-empty fields
                        print(f"{k}: {v}")
                print("-" * 50)
    except Exception as e:
        print(f"Error: {e}")
    finally:
        conn.close()

if __name__ == "__main__":
    find_logic_finding("aura_intel.db")
