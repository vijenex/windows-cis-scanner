#!/usr/bin/env python3
"""Generate report template with exclusions applied - ready for Word import"""
import csv
import sys
from pathlib import Path
from collections import defaultdict

# Load exclusions
exclusions = set()
exclusion_file = Path('EXCLUSIONS_2019.txt')
if exclusion_file.exists():
    for line in exclusion_file.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith('#') and '.' in line:
            exclusions.add(line)

print(f"Loaded {len(exclusions)} exclusions")

# Find CSV
csv_file = None
if len(sys.argv) > 1:
    csv_file = Path(sys.argv[1])
else:
    reports_dir = Path('reports')
    if reports_dir.exists():
        csv_files = list(reports_dir.glob('*.csv'))
        if csv_files:
            csv_file = sorted(csv_files, key=lambda x: x.stat().st_mtime)[-1]

if not csv_file or not csv_file.exists():
    print("❌ No CSV file. Run scanner first or provide: python3 generate-report-template.py report.csv")
    sys.exit(1)

print(f"Processing: {csv_file}")

# Read and filter
controls = []
with open(csv_file, 'r', encoding='utf-8') as f:
    reader = csv.DictReader(f)
    for row in reader:
        if row.get('Control ID', '').strip() not in exclusions:
            controls.append(row)

failed = [c for c in controls if c.get('Status', '').lower() == 'fail']
passed = [c for c in controls if c.get('Status', '').lower() == 'pass']

# Group by section
sections = defaultdict(list)
for control in failed:
    section = control.get('Control ID', '').split('.')[0]
    sections[section].append(control)

# Generate template
output = Path('Windows-Server-2019-CIS-Audit-Report-TEMPLATE.txt')
with open(output, 'w', encoding='utf-8') as f:
    f.write("="*100 + "\n")
    f.write("WINDOWS SERVER 2019 - CIS AUDIT REPORT\n")
    f.write("="*100 + "\n\n")
    
    f.write("EXECUTIVE SUMMARY\n")
    f.write("-" * 100 + "\n\n")
    f.write(f"Total Controls Audited: {len(controls)}\n")
    f.write(f"Excluded (Not Applicable): {len(exclusions)}\n")
    f.write(f"Passed: {len(passed)}\n")
    f.write(f"Failed: {len(failed)}\n")
    f.write(f"Compliance Rate: {len(passed)/len(controls)*100:.1f}%\n\n")
    
    f.write("="*100 + "\n")
    f.write("FAILED CONTROLS (REQUIRE REMEDIATION)\n")
    f.write("="*100 + "\n\n")
    
    for section in sorted(sections.keys(), key=lambda x: int(x) if x.isdigit() else 999):
        f.write(f"\n{'='*100}\n")
        f.write(f"SECTION {section} - {len(sections[section])} Failed Controls\n")
        f.write(f"{'='*100}\n\n")
        
        for control in sections[section]:
            control_id = control.get('Control ID', '')
            title = control.get('Control Title', '')
            
            f.write(f"Control ID: {control_id}\n")
            f.write(f"Title: {title}\n")
            f.write(f"Status: FAIL\n")
            f.write(f"Screenshot: [INSERT SCREENSHOT: {control_id.replace('.', '_')}.png]\n")
            f.write(f"Remediation: [TO BE COMPLETED]\n")
            f.write("-" * 100 + "\n\n")
    
    f.write("\n" + "="*100 + "\n")
    f.write("PASSED CONTROLS\n")
    f.write("="*100 + "\n\n")
    
    for control in passed:
        f.write(f"✓ {control.get('Control ID', '')}: {control.get('Control Title', '')}\n")
    
    f.write("\n\n" + "="*100 + "\n")
    f.write("EXCLUDED CONTROLS (NOT APPLICABLE TO SERVER 2019)\n")
    f.write("="*100 + "\n\n")
    
    with open(exclusion_file, 'r') as ex:
        for line in ex:
            line = line.strip()
            if line and not line.startswith('#'):
                f.write(f"{line}\n")

print(f"\n✅ Template generated: {output}")
print(f"\nYou can now:")
print(f"1. Open this file in any text editor")
print(f"2. Copy/paste into Word")
print(f"3. Add screenshots where indicated")
print(f"4. Format as needed")
print(f"\n📊 Summary:")
print(f"   Controls in report: {len(controls)}")
print(f"   Excluded: {len(exclusions)}")
print(f"   Failed (need screenshots): {len(failed)}")
print(f"   Passed: {len(passed)}")
