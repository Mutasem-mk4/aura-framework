import sqlite3

def get_exact_logic_finding(db_path):
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    try:
        # Search for the business logic finding in the findings table
        cursor.execute("SELECT url, description, extra_data FROM findings WHERE type LIKE '%Logic%' OR description LIKE '%checkout%';")
        rows = cursor.fetchall()
        for row in rows:
            print(f"URL: {row[0]}")
            print(f"Description: {row[1]}")
            print(f"Extra Data: {row[2]}")
            print("-" * 30)
    except Exception as e:
        print(f"Error: {e}")
    finally:
        conn.close()

if __name__ == "__main__":
    get_exact_logic_finding("aura_intel.db")
