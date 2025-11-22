#!/usr/bin/env python3
import re

mss_controls = [f"18.5.{i}" for i in range(1, 13)]

with open('windows-2025/milestones/milestone-18.ps1', 'r') as f:
    content = f.read()

# Add Tags field after Section line for MSS controls
for control_id in mss_controls:
    pattern = rf'(  Id = "{control_id}"\n  Title = .*?\n  Section = "Section 18"\n)'
    replacement = r'\1  Tags = "MSS-Legacy"\n'
    content = re.sub(pattern, replacement, content)

with open('windows-2025/milestones/milestone-18.ps1', 'w') as f:
    f.write(content)

print(f"Added MSS-Legacy tags to {len(mss_controls)} controls")
