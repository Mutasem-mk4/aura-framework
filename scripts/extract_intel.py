import sqlite3

def extract_valid_intel_findings():
    conn = sqlite3.connect('aura_intel.db')
    cursor = conn.cursor()
    
    # We want things that:
    # 1. Are actually on an intel.com subdomain
    # 2. Are NOT the generic buckets found for everyone
    
    query = """
    SELECT content, finding_type, severity 
    FROM findings 
    WHERE content LIKE '%intel.com%' 
    AND content NOT LIKE '%storage.googleapis.com%'
    AND content NOT LIKE '%s3.amazonaws.com%'
    ORDER BY CASE severity 
        WHEN 'CRITICAL' THEN 1 
        WHEN 'HIGH' THEN 2 
        WHEN 'MEDIUM' THEN 3 
        ELSE 4 END;
    """
    
    cursor.execute(query)
    rows = cursor.fetchall()
    
    with open('valid_intel_findings.txt', 'w', encoding='utf-8') as f:
        f.write("--- VALID INTEL FINDINGS (FILTERED) ---\n\n")
        for row in rows:
            f.write(f"Type: {row[1]} | Severity: {row[2]}\n")
            f.write(f"Content: {row[0]}\n")
            f.write("-" * 30 + "\n")
            
    conn.close()

if __name__ == "__main__":
    extract_valid_intel_findings()
