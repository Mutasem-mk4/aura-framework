import sqlite3

def find_targets(db_path):
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    try:
        cursor.execute("PRAGMA table_info(targets);")
        columns = [col[1] for col in cursor.fetchall()]
        print(f"Targets Columns: {columns}")
        
        # Search all columns in targets for checkout/success
        cursor.execute("SELECT * FROM targets;")
        rows = cursor.fetchall()
        for row in rows:
            row_str = str(row)
            if "checkout" in row_str or "success" in row_str:
                target = dict(zip(columns, row))
                print(f"TARGET MATCH: {target}")
    except Exception as e:
        print(f"Error: {e}")
    finally:
        conn.close()

if __name__ == "__main__":
    find_targets("aura_intel.db")
