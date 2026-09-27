import subprocess
result = subprocess.run(['grep', '-r', 'StrongPassword123\|Changeme123', '--exclude-dir=.git', '--exclude=*.md', '/mnt/c/hybrid-soc-lab'], capture_output=True, text=True)
if result.stdout:
    print(result.stdout)
else:
    print("No hardcoded passwords found")