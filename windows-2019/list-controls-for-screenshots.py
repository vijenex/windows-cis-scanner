#!/usr/bin/env python3
"""
Generate a clean list of controls that need screenshots
Run this after scanning a server to get the exact list
"""
import csv
import sys
from pathlib import Path

# Load exclusions
exclusions = set()
exclusion_file = Path('EXCLUSIONS_2019.txt')
if exclusion_file.exists():
    for line in exclusion_file.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith('#') and '.' in line:
            exclusions.add(line)

print(f"Loaded {len(exclusions)} exclusions\n")

# Find CSV file
csv_file = None
if len(sys.argv) > 1:
    csv_file = Path(sys.argv[1])
else:
    # Look for CSV in reports directory
    reports_dir = Path('reports')
    if reports_dir.exists():
        csv_files = list(reports_dir.glob('*.csv'))
        if csv_files:
            csv_file = sorted(csv_files, key=lambda x: x.stat().st_mtime)[-1]

if not csv_file or not csv_file.exists():
    print("❌ No CSV file found. Please run the scanner first or provide CSV path:")
    print("   python3 list-controls-for-screenshots.py path/to/report.csv")
    sys.exit(1)

print(f"Processing: {csv_file}\n")

# Read and filter
failed_controls = []
passed_controls = []
total_excluded = 0

with open(csv_file, 'r', encoding='utf-8') as f:
    reader = csv.DictReader(f)
    for row in reader:
        control_id = row.get('Control ID', '').strip()
        
        if control_id in exclusions:
            total_excluded += 1
            continue
        
        status = row.get('Status', '').lower()
        title = row.get('Control Title', '')
        
        if status == 'fail':
            failed_controls.append((control_id, title))
        elif status == 'pass':
            passed_controls.append((control_id, title))

# Generate output
output_file = Path('CONTROLS_NEEDING_SCREENSHOTS.txt')
with open(output_file, 'w', encoding='utf-8') as f:
    f.write("="*100 + "\n")
    f.write("WINDOWS SERVER 2019 - CONTROLS NEEDING SCREENSHOTS\n")
    f.write("="*100 + "\n\n")
    
    f.write(f"📊 Summary:\n")
    f.write(f"   Total Controls: {len(failed_controls) + len(passed_controls)}\n")
    f.write(f"   Excluded: {total_excluded}\n")
    f.write(f"   Failed (need screenshots): {len(failed_controls)}\n")
    f.write(f"   Passed: {len(passed_controls)}\n")
    f.write(f"   Compliance: {len(passed_controls)/(len(failed_controls)+len(passed_controls))*100:.1f}%\n\n")
    
    f.write("="*100 + "\n")
    f.write("FAILED CONTROLS - TAKE SCREENSHOTS FOR THESE\n")
    f.write("="*100 + "\n\n")
    
    # Group by section
    sections = {}
    for control_id, title in failed_controls:
        section = control_id.split('.')[0]
        if section not in sections:
            sections[section] = []
        sections[section].append((control_id, title))
    
    for section in sorted(sections.keys(), key=lambda x: int(x) if x.isdigit() else 999):
        f.write(f"\n--- Section {section} ({len(sections[section])} controls) ---\n\n")
        for control_id, title in sections[section]:
            f.write(f"❌ {control_id}\n")
            f.write(f"   {title}\n")
            f.write(f"   Screenshot: {control_id.replace('.', '_')}.png\n\n")

print(f"✅ Generated: {output_file}")
print(f"\n📸 You need screenshots for {len(failed_controls)} controls")
print(f"\nNext steps:")
print(f"1. Open {output_file}")
print(f"2. Go through each failed control")
print(f"3. Take screenshot showing the GPO setting")
print(f"4. Save as: ControlID.png (e.g., 18_10_16_1.png)")
