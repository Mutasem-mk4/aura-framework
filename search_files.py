import os

files = ['valid_intel_findings.txt', 'aura_output.txt']
search_term = 'arc.net'

print(f"Searching for '{search_term}' in text files...\n")

for file in files:
    if os.path.exists(file):
        print(f"--- File: {file} ---")
        matches = 0
        with open(file, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                if search_term.lower() in line.lower():
                    print(line.strip())
                    matches += 1
                    if matches > 50:
                        print("... Too many matches, stopping for this file.")
                        break
        print(f"Found {matches} matches.\n")
    else:
        print(f"File {file} not found.\n")
