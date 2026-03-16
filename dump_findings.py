import sqlite3
import json

db_path = 'aura_intel.db'
conn = sqlite3.connect(db_path)
cursor = conn.cursor()

print(f"\n=== SOVEREIGN INTELLIGENCE FROM {db_path} ===")
try:
    cursor.execute("SELECT * FROM sovereign_intelligence WHERE data LIKE '%arc.net%'")
    rows = cursor.fetchall()
    print(f"Total Matches: {len(rows)}")

    for row in rows:
        # id, type, data, confidence, ...
        data = row[2]
        if data.strip().startswith('{'):
            try:
                parsed_data = json.loads(data)
                print(json.dumps(parsed_data, indent=2))
            except:
                print(data)
        else:
            print(data)

except Exception as e:
    print(f"Error: {e}")

conn.close()
