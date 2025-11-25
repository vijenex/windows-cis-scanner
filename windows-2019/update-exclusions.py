#!/usr/bin/env python3
import re
import os

# Read exclusions
exclusions = set()
with open('EXCLUSIONS_2019.txt', 'r') as f:
    for line in f:
        line = line.strip()
        if line and not line.startswith('#') and '.' in line:
            exclusions.add(line)

print(f"Loaded {len(exclusions)} exclusions")

# Update each milestone file
milestone_dir = 'milestones'
for filename in os.listdir(milestone_dir):
    if not filename.startswith('milestone-') or not filename.endswith('.ps1'):
        continue
    
    filepath = os.path.join(milestone_dir, filename)
    with open(filepath, 'r', encoding='utf-8') as f:
        content = f.read()
    
    changes = []
    for control_id in exclusions:
        # Match control definition and add AppliesTo if not present
        pattern = rf"(\$Global:Rules\s*\+=\s*@\{{[^}}]*Id\s*=\s*['\"]" + re.escape(control_id) + r"['\"][^}}]*)(}})"
        
        def add_applies_to(match):
            rule_content = match.group(1)
            if 'AppliesTo' not in rule_content:
                changes.append(control_id)
                return rule_content + "\n  AppliesTo='NotApplicable'\n" + match.group(2)
            return match.group(0)
        
        content = re.sub(pattern, add_applies_to, content, flags=re.DOTALL)
    
    if changes:
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(content)
        print(f"✅ Updated {filename}")

print("\n✅ All milestone files updated with exclusions")
