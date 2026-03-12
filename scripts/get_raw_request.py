import sqlite3

def get_raw_request(db_path):
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    try:
        cursor.execute("PRAGMA table_info(findings);")
        columns = [col[1] for col in cursor.fetchall()]
        
        cursor.execute("SELECT * FROM findings WHERE content LIKE '%State Skip%' AND content LIKE '%intel%';")
        row = cursor.fetchone()
        if row:
            finding = dict(zip(columns, row))
            print("RAW REQUEST:")
            print(finding.get('raw_request'))
            print("\nURL:")
            print(finding.get('url') or finding.get('content'))
        else:
            print("No matching finding found.")
    except Exception as e:
        print(f"Error: {e}")
    finally:
        conn.close()

if __name__ == "__main__":
    get_raw_request("aura_intel.db")
