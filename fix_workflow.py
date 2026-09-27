import json

# Read the current workflow
with open('/mnt/c/hybrid-soc-lab/vm1_wazuh_soar/workflows/soc_soar_workflow.json') as f:
    workflow = json.load(f)

# The workflow is already parsed, so the functionCode strings are correctly decoded
# Now we need to re-serialize with proper escaping
# The issue is that when we write JSON, the backslashes in the strings need to be escaped

# Write it back with proper JSON serialization
with open('/mnt/c/hybrid-soc-lab/vm1_wazuh_soar/workflows/soc_soar_workflow.json', 'w') as f:
    json.dump(workflow, f, indent=2)

print("Workflow re-serialized with proper JSON escaping")
PYEOF