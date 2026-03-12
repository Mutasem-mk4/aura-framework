import sqlite3
import json
import os

def harvest():
    db_path = "aura_intel.db"
    if not os.path.exists(db_path):
        print(f"Error: {db_path} not found.")
        return

    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    # 1. Severity Distribution
    print("--- Severity Distribution ---")
    cursor.execute("SELECT severity, count(*) FROM findings GROUP BY severity ORDER BY count(*) DESC")
    rows = cursor.fetchall()
    for row in rows:
        print(f"{row[0]}: {row[1]}")

    # 2. Top Findings (CRITICAL/HIGH)
    print("\n--- Top Findings (Gems) ---")
    cursor.execute("""
        SELECT finding_type, severity, content 
        FROM findings 
        WHERE severity IN ('CRITICAL', 'HIGH') 
        LIMIT 20
    """)
    gems = cursor.fetchall()
    for gem in gems:
        print(f"[{gem[1]}] {gem[0]}: {gem[2][:100]}...")

    conn.close()

if __name__ == "__main__":
    harvest()
