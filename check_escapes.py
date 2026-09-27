import json

with open('/mnt/c/hybrid-soc-lab/vm1_wazuh_soar/workflows/soc_soar_workflow.json', 'r', encoding='utf-8') as f:
    content = f.read()

# Try to find the actual escape issue by checking each backslash
for i, ch in enumerate(content):
    if ch == '\\':
        if i+1 < len(content):
            next_ch = content[i+1]
            if next_ch not in ['"', '\\', '/', 'b', 'f', 'n', 'r', 't', 'u']:
                print(f'Char {i}: \\{next_ch}')