import json

with open('/mnt/c/hybrid-soc-lab/vm1_wazuh_soar/workflows/soc_soar_workflow.json') as f:
    content = f.read()

# Find all backslashes that might be invalid
for i, ch in enumerate(content):
    if ch == '\\':
        if i+1 < len(content):
            next_ch = content[i+1]
            if next_ch not in ['"', '\\', '/', 'b', 'f', 'n', 'r', 't', 'u']:
                print(f'Position {i}: \\{next_ch} (context: ...{content[max(0,i-20):i+20]}...)')