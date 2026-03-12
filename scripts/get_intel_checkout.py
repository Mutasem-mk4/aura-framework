import sqlite3

def get_intel_checkout_urls(db_path):
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    try:
        query = "SELECT url FROM targets WHERE url LIKE '%intel%' AND url LIKE '%checkout%';"
        cursor.execute(query)
        rows = cursor.fetchall()
        print("Intel Checkout URLs Found:")
        for row in rows:
            print(row[0])
    except Exception as e:
        print(f"Error: {e}")
    finally:
        conn.close()

if __name__ == "__main__":
    get_intel_checkout_urls("aura_intel.db")
