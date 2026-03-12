import sqlite3

def inspect_schema(db_path):
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
        tables = cursor.fetchall()
        for table in tables:
            t_name = table[0]
            print(f"\nTable: {t_name}")
            cursor.execute(f"PRAGMA table_info({t_name});")
            columns = cursor.fetchall()
            for col in columns:
                print(col)
    except Exception as e:
        print(f"Error: {e}")
    finally:
        conn.close()

if __name__ == "__main__":
    inspect_schema("aura_intel.db")
