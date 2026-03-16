import os

file_path = 'targets.txt'
if os.path.exists(file_path):
    with open(file_path, 'r', encoding='utf-16le', errors='ignore') as f:
        print(f.read())
else:
    print(f"File {file_path} not found.")
