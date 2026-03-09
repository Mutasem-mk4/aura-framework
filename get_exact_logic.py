import sqlite3

def get_logic_details(db_path):
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    try:
        # Get column names for findings table
        cursor.execute("PRAGMA table_info(findings);")
        columns = [col[1] for col in cursor.fetchall()]
        print(f"Columns in 'findings': {columns}")
        
        # Search for logic findings
        query = "SELECT * FROM findings WHERE type LIKE '%Logic%' OR description LIKE '%checkout%';"
        cursor.execute(query)
        rows = cursor.fetchall()
        for row in rows:
            result = dict(zip(columns, row))
            print(f"Finding Found: {result}")
            print("-" * 30)
    except Exception as e:
        print(f"Error: {e}")
    finally:
        conn.close()

if __name__ == "__main__":
    get_logic_details("aura_intel.db")
