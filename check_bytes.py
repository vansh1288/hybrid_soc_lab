with open('/mnt/c/hybrid-soc-lab/vm1_wazuh_soar/workflows/soc_soar_workflow.json', 'rb') as f:
    content = f.read()

for i in range(10040, 10070):
    if i < len(content):
        c = content[i]
        ch = chr(c) if 32 <= c < 127 else '?'
        print(f'{i}: {c:02x} ({ch})')