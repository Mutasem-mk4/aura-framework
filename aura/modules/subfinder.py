import json

def parse(data):
    """
    Parses Subfinder output. 
    Subfinder can output raw domains per line or JSON.
    """
    results = []
    lines = data.strip().split("\n")
    
    for line in lines:
        line = line.strip()
        if not line:
            continue
            
        try:
            # Try JSON format
            item = json.loads(line)
            if "host" in item:
                results.append({"type": "subdomain", "value": item["host"], "source": "subfinder"})
            else:
                results.append({"type": "subdomain", "value": line, "source": "subfinder"})
        except json.JSONDecodeError:
            # Fallback to raw text
            results.append({"type": "subdomain", "value": line, "source": "subfinder"})
            
    return results
