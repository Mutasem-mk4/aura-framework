import sqlite3

def dump_targets(db_path, output_path):
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT * FROM targets LIMIT 50;")
        rows = cursor.fetchall()
        with open(output_path, "w", encoding="utf-8") as f:
            for row in rows:
                f.write(str(row) + "\n")
        print(f"Dumped 50 targets to {output_path}")
    except Exception as e:
        print(f"Error: {e}")
    finally:
        conn.close()

if __name__ == "__main__":
    dump_targets("aura_intel.db", "targets_dump.txt")
