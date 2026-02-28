import sqlite3
import os

def clean_db():
    project_db = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'aura_intel.db')
    home_db = os.path.join(os.path.expanduser("~"), 'aura_intel.db')
    
    for db_path in [project_db, home_db]:
        if not os.path.exists(db_path): continue
        try:
            conn = sqlite3.connect(db_path)
            c = conn.cursor()
            # Aggressive cleaning
            c.execute("DELETE FROM findings WHERE content LIKE '%Example%' OR content LIKE '%test%' OR finding_type LIKE '%Example%' OR finding_type = 'Forge-ExampleScanner';")
            c.execute("DELETE FROM targets WHERE risk_score = 0;")
            conn.commit()
            print(f"Purged records from {db_path}.")
            conn.close()
            # If it's the home DB, maybe just delete the file to avoid future confusion?
            if db_path == home_db:
                # keep it for safety but clear it.
                pass
        except Exception as e:
            print(f"Error cleaning {db_path}: {e}")

if __name__ == '__main__':
    clean_db()
