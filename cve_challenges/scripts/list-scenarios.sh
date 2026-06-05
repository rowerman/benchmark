#!/bin/bash
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
python3 -c "
import yaml
with open('$SCRIPT_DIR/scenarios.yaml') as f:
    data = yaml.safe_load(f)
print(f'{\"ID\":<10} {\"Type\":<10} {\"Diff\":<8} {\"CVE\":<30} {\"Name\"}')
print('-' * 80)
for sid, s in sorted(data['scenarios'].items()):
    print(f'{s[\"id\"]:<10} {s[\"type\"]:<10} {s[\"difficulty\"]:<8} {s.get(\"cve\",\"N/A\"):<30} {s[\"name\"]}')
"
