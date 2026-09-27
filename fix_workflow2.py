import re

# Read the raw file
with open('/mnt/c/hybrid-soc-lab/vm1_wazuh_soar/workflows/soc_soar_workflow.json', 'r') as f:
    content = f.read()

# The issue: in functionCode strings, we have `\`` and `\$` which are invalid JSON escapes
# We need to replace `\`` with `\\`` and `\$` with `\\$` but only inside JSON string values

# Simple approach: Find all functionCode values and fix the escapes
# Pattern: "functionCode": " ... " (with escaped content)

# Since the JSON is almost valid except for these escapes, let's do a targeted fix
# Replace `\`` with `\\`` (but only when it's an escape in a string)
# Replace `\$` with `\\$` (but only when it's an escape in a string)

# Actually, the correct fix for JSON:
# In JSON, to represent a literal backslash followed by `, we need \\\\`
# To represent a literal backslash followed by $, we need \\\\$

# The current file has single backslash before ` and $ in the JavaScript code
# We need to double them for JSON

# Let's do a more careful replacement using regex to find string values
# But this is complex. Simpler: just fix the known problematic patterns globally

# The patterns that are invalid:
# \` -> should be \\` in JSON (so JS gets \`)
# \$ -> should be \\$ in JSON (so JS gets \$)

# But we must be careful not to break valid escapes like \n, \t, etc.

# Since the file is mostly valid JSON except these, let's do targeted replacements
# We know the functionCode strings contain JavaScript with template literals
# In those, `\`` appears for markdown code formatting
# And `\$` appears for escaping $ in Slack markdown

# Fix: replace \` with \\` and \$ with \\$ throughout the file
# This is safe because \` and \$ are never valid JSON escapes

content = content.replace('\\`', '\\\\`')
content = content.replace('\\$', '\\\\$')

# Write back
with open('/mnt/c/hybrid-soc-lab/vm1_wazuh_soar/workflows/soc_soar_workflow.json', 'w') as f:
    f.write(content)

print("Fixed escape sequences")
PYEOF