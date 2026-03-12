import json

with open('data/chaos_index.json') as f:
    d = json.load(f)

# Programs with some subdomains
filtered = [p for p in d if p.get('count', 0) > 0]
filtered.sort(key=lambda x: (x.get('change', 0), -x.get('count', 0)), reverse=True)

for p in filtered[:15]:
    print(f"{p['name']} (+{p.get('change', 0)}) (total: {p.get('count', 0)}) | {p.get('platform', 'independent')}")
