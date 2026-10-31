import re

with open('specs/project.md', 'r') as f:
    content = f.read()

config_match = re.search(r'### 1.4\s*(.*?)(?=---)', content, re.DOTALL)
if config_match:
    print(config_match.group(1))
else:
    print("Could not find section 1.4")
