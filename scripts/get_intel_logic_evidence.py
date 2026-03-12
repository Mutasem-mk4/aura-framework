import sqlite3
import json

def get_intel_logic_evidence():
    conn = sqlite3.connect('aura_intel.db')
    cursor = conn.cursor()
    
    # Get column names for findings
    cursor.execute("PRAGMA table_info(findings);")
    columns = [col[1] for col in cursor.fetchall()]
    print(f"Columns: {columns}")
    
    # Search for the specific finding
    query = "SELECT * FROM findings WHERE content LIKE '%intel%' AND content LIKE '%State Skip%';"
    cursor.execute(query)
    rows = cursor.fetchall()
    
    with open('intel_logic_evidence.txt', 'w', encoding='utf-8') as f:
        for row in rows:
            f.write("="*50 + "\n")
            for col_name, val in zip(columns, row):
                f.write(f"{col_name}: {val}\n")
            f.write("\n")
            
    conn.close()

if __name__ == "__main__":
    get_intel_logic_evidence()
