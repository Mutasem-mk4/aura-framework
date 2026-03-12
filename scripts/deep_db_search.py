import sqlite3

def deep_search():
    conn = sqlite3.connect('aura_intel.db')
    cursor = conn.cursor()
    
    # Get all tables
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
    tables = [t[0] for t in cursor.fetchall()]
    
    search_terms = ['bloombees', 'api-backup', 'storage.googleapis.com']
    
    with open('deep_search_results.txt', 'w', encoding='utf-8') as f:
        for table in tables:
            f.write(f"\n--- TABLE: {table} ---\n")
            cursor.execute(f"PRAGMA table_info({table});")
            columns = [col[1] for col in cursor.fetchall()]
            
            for term in search_terms:
                for col in columns:
                    query = f"SELECT * FROM {table} WHERE {col} LIKE ?"
                    cursor.execute(query, (f'%{term}%',))
                    rows = cursor.fetchall()
                    if rows:
                        f.write(f"Match for '{term}' in column '{col}':\n")
                        for row in rows:
                            f.write(str(row) + "\n")
                            
    conn.close()

if __name__ == "__main__":
    deep_search()
