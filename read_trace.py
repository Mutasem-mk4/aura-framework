try:
    with open('error_trace.log', 'r', encoding='utf-8') as f:
        print(f.read().encode('ascii', 'replace').decode('ascii'))
except Exception as e:
    print("Failed to read log:", e)
