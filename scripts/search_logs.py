import os

def search_logs(log_dir, query):
    if not os.path.exists(log_dir):
        print(f"Log directory {log_dir} does not exist.")
        return
    
    print(f"Searching in {log_dir} for '{query}'...")
    for root, dirs, files in os.walk(log_dir):
        for file in files:
            path = os.path.join(root, file)
            try:
                with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                    if query in f.read():
                        print(f"Match found in: {path}")
            except Exception as e:
                pass

if __name__ == "__main__":
    search_logs("logs", "checkout")
    search_logs("logs", "success")
