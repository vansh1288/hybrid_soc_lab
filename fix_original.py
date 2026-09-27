# Read raw bytes
with open('/mnt/c/hybrid-soc-lab/vm1_wazuh_soar/workflows/soc_soar_workflow.json', 'rb') as f:
    content = f.read()

# Replace \` with \\` (in bytes: 0x5c 0x60 -> 0x5c 0x5c 0x60)
# Replace \$ with \\$ (in bytes: 0x5c 0x24 -> 0x5c 0x5c 0x24)
# This makes them valid JSON escapes: \\ = literal backslash, then ` or $

content = content.replace(b'\\`', b'\\\\`')
content = content.replace(b'\\$', b'\\\\$')

with open('/mnt/c/hybrid-soc-lab/vm1_wazuh_soar/workflows/soc_soar_workflow.json', 'wb') as f:
    f.write(content)

print("Fixed original file")