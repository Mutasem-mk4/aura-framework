import sqlite3

def find_crawled_urls(db_path):
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    try:
        # Get column names for targets table
        cursor.execute("PRAGMA table_info(targets);")
        columns = [col[1] for col in cursor.fetchall()]
        
        # Search for checkout/success in targets
        cursor.execute("SELECT * FROM targets WHERE url LIKE '%checkout%' OR url LIKE '%success%';")
        rows = cursor.fetchall()
        for row in rows:
            target = dict(zip(columns, row))
            print(f"URL Found: {target.get('url')}")
    except Exception as e:
        print(f"Error: {e}")
    finally:
        conn.close()

if __name__ == "__main__":
    find_crawled_urls("aura_intel.db")
