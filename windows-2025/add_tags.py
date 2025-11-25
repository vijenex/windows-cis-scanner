import re
import os

# Load CSV controls
csv_path = "windows_CIS-Hardening_lIST.csv"
applicable_controls = []

with open(csv_path, 'r') as f:
    for line in f:
        match = re.match(r'^(\d+\.\d+\.?\d*\.?\d*):', line)
        if match:
            applicable_controls.append(match.group(1))

print(f"Loaded {len(applicable_controls)} applicable controls from CSV")

# Process milestone files
milestones_path = "milestones"
for filename in sorted(os.listdir(milestones_path)):
    if filename.startswith("milestone-") and filename.endswith(".ps1") and ".backup" not in filename:
        filepath = os.path.join(milestones_path, filename)
        print(f"\nProcessing {filename}...")
        
        with open(filepath, 'r') as f:
            content = f.read()
        
        # Find all rule definitions
        pattern = r'(\$Global:Rules\s*\+=\s*@\{[^}]+Id\s*=\s*[\'"](\d+\.\d+\.?\d*\.?\d*)[\'"][^}]+\})'
        
        def replace_rule(match):
            full_rule = match.group(1)
            control_id = match.group(2)
            
            # Check if AppliesTo already exists
            if 'AppliesTo' in full_rule:
                return full_rule
            
            # Determine AppliesTo value
            if control_id in applicable_controls:
                if control_id.startswith('2.3.'):
                    applies_to = "'DefaultEnabled'"
                else:
                    applies_to = "'Applicable'"
            else:
                applies_to = "'NotApplicable'"
            
            # Insert AppliesTo before closing brace
            new_rule = re.sub(r'\}$', f'; AppliesTo = {applies_to} }}', full_rule)
            return new_rule
        
        new_content = re.sub(pattern, replace_rule, content)
        
        if new_content != content:
            with open(filepath, 'w') as f:
                f.write(new_content)
            print(f"  ✓ Updated {filename}")
        else:
            print(f"  - No changes needed")

print("\n✅ AppliesTo tags added to all milestone files!")
