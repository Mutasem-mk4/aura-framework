import sqlite3

def find_logic_finding(db_path, log_path):
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    try:
        cursor.execute("PRAGMA table_info(findings);")
        columns = [col[1] for col in cursor.fetchall()]
        
        cursor.execute("SELECT * FROM findings;")
        rows = cursor.fetchall()
        with open(log_path, "w", encoding="utf-8") as f:
            for row in rows:
                if "State Skip" in str(row) or "checkout" in str(row):
                    finding = dict(zip(columns, row))
                    f.write("MATCH FOUND:\n")
                    for k, v in finding.items():
                        if v:
                            f.write(f"{k}: {v}\n")
                    f.write("-" * 50 + "\n")
        print(f"Results written to {log_path}")
    except Exception as e:
        print(f"Error: {e}")
    finally:
        conn.close()

if __name__ == "__main__":
    find_logic_finding("aura_intel.db", "logic_finding_log.txt")
