with open('aura/core/stealth.py', 'r', encoding='utf-8') as f:
    lines = f.readlines()

new_lines = []
for i, line in enumerate(lines):
    if 'Singularity: Block detected' in line and 'print(' in line:
        print(f'Removing line {i+1}: {line.strip()[:60]}')
        # Skip this line (remove it)
        continue
    new_lines.append(line)

with open('aura/core/stealth.py', 'w', encoding='utf-8') as f:
    f.writelines(new_lines)

print(f'Done. Removed spam print. Total lines: {len(lines)} -> {len(new_lines)}')
