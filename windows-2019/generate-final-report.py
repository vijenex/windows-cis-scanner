#!/usr/bin/env python3
import csv
import os
from collections import defaultdict

# Read exclusions
exclusions = set()
with open('EXCLUSIONS_2019.txt', 'r') as f:
    for line in f:
        line = line.strip()
        if line and not line.startswith('#') and '.' in line:
            exclusions.add(line)

print(f"Loaded {len(exclusions)} exclusions\n")

# Find latest CSV file
csv_files = [f for f in os.listdir('.') if f.endswith('.csv') and 'server' in f.lower()]
if not csv_files:
    print("No CSV files found")
    exit(1)

latest_csv = sorted(csv_files)[-1]
print(f"Processing: {latest_csv}\n")

# Read CSV and filter
controls = []
excluded_count = 0

with open(latest_csv, 'r', encoding='utf-8') as f:
    reader = csv.DictReader(f)
    for row in reader:
        control_id = row.get('Control ID', '').strip()
        if control_id in exclusions:
            excluded_count += 1
            continue
        controls.append(row)

# Generate summary
total_controls = len(controls)
failed = sum(1 for c in controls if c.get('Status', '').lower() == 'fail')
passed = sum(1 for c in controls if c.get('Status', '').lower() == 'pass')

# Group by section
sections = defaultdict(lambda: {'total': 0, 'fail': 0, 'pass': 0})
for control in controls:
    control_id = control.get('Control ID', '')
    section = control_id.split('.')[0] if '.' in control_id else 'Other'
    status = control.get('Status', '').lower()
    
    sections[section]['total'] += 1
    if status == 'fail':
        sections[section]['fail'] += 1
    elif status == 'pass':
        sections[section]['pass'] += 1

# Write report
report_file = 'FINAL_AUDIT_REPORT.txt'
with open(report_file, 'w', encoding='utf-8') as f:
    f.write("="*100 + "\n")
    f.write("WINDOWS SERVER 2019 - FINAL CIS AUDIT REPORT\n")
    f.write("="*100 + "\n\n")
    
    f.write(f"Total Controls: {total_controls}\n")
    f.write(f"Excluded Controls: {excluded_count}\n")
    f.write(f"Failed: {failed}\n")
    f.write(f"Passed: {passed}\n")
    f.write(f"Compliance Rate: {(passed/total_controls*100):.1f}%\n\n")
    
    f.write("="*100 + "\n")
    f.write("SUMMARY BY SECTION\n")
    f.write("="*100 + "\n\n")
    
    for section in sorted(sections.keys(), key=lambda x: int(x) if x.isdigit() else 999):
        data = sections[section]
        f.write(f"Section {section}: {data['fail']} failed / {data['total']} total\n")
    
    f.write("\n" + "="*100 + "\n")
    f.write("FAILED CONTROLS (NEED SCREENSHOTS)\n")
    f.write("="*100 + "\n\n")
    
    for control in controls:
        if control.get('Status', '').lower() == 'fail':
            control_id = control.get('Control ID', '')
            title = control.get('Control Title', '')
            f.write(f"❌ {control_id}: {title}\n")
    
    f.write("\n" + "="*100 + "\n")
    f.write("PASSED CONTROLS\n")
    f.write("="*100 + "\n\n")
    
    for control in controls:
        if control.get('Status', '').lower() == 'pass':
            control_id = control.get('Control ID', '')
            title = control.get('Control Title', '')
            f.write(f"✅ {control_id}: {title}\n")

print(f"✅ Report generated: {report_file}")
print(f"\n📊 Summary:")
print(f"   Total Controls: {total_controls}")
print(f"   Excluded: {excluded_count}")
print(f"   Failed: {failed}")
print(f"   Passed: {passed}")
print(f"   Compliance: {(passed/total_controls*100):.1f}%")
