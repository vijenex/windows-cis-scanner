# Generate Windows Server 2019 CIS Audit Report

## Quick Start

After running the scanner on your server, generate the audit report:

```bash
# Generate text template (no dependencies needed)
python3 generate-report-template.py reports/YourServerReport.csv
```

This creates: `Windows-Server-2019-CIS-Audit-Report-TEMPLATE.txt`

## What Gets Excluded

The report **automatically excludes** these 62 controls:
- Lock screen features
- Desktop App Installer
- LAPS (not in Server 2019)
- Cloud/Consumer features
- OneSettings/Diagnostics
- And more...

See `EXCLUSIONS_2019.txt` for the complete list.

## Report Contents

### 1. Executive Summary
- Total controls audited (~334)
- Excluded controls (62)
- Pass/Fail counts
- Compliance percentage

### 2. Failed Controls (by Section)
Each failed control includes:
- Control ID and Title
- Status: FAIL
- Screenshot placeholder
- Remediation notes section

### 3. Passed Controls
Simple list of all passing controls

### 4. Excluded Controls
List of 62 N/A controls with reasons

## Convert to Word

### Option 1: Copy/Paste
1. Open the generated `.txt` file
2. Copy all content
3. Paste into Word
4. Format as needed
5. Insert screenshots

### Option 2: Use Word Import
1. Open Word
2. File → Open
3. Select the `.txt` file
4. Choose encoding: UTF-8
5. Format and add screenshots

### Option 3: Use python-docx (if available)
```bash
pip3 install python-docx --break-system-packages
python3 generate-word-report.py reports/YourServerReport.csv
```

This creates: `Windows-Server-2019-CIS-Audit-Report.docx`

## Adding Screenshots

For each failed control, the template shows:
```
Screenshot: [INSERT SCREENSHOT: 18_10_16_1.png]
```

1. Take screenshot of the GPO setting
2. Save as indicated filename
3. Insert into Word document at that location

## Example Workflow

```bash
# 1. Run scanner on Windows Server
# (On the server)
cd C:\Path\To\Scripts
.\vijenex-scanner.ps1

# 2. Copy CSV to your Mac
# Copy from server to: windows-2019/reports/

# 3. Generate report template
cd /path/to/windows-2019
python3 generate-report-template.py reports/ServerName.csv

# 4. Open template
open Windows-Server-2019-CIS-Audit-Report-TEMPLATE.txt

# 5. Copy to Word and format
# 6. Add screenshots for failed controls
```

## Files Generated

| File | Description |
|------|-------------|
| `*-TEMPLATE.txt` | Text template ready for Word |
| `*.docx` | Word document (if using python-docx) |
| `CONTROLS_NEEDING_SCREENSHOTS.txt` | Screenshot checklist |

## Verification

The report should show:
- ✅ ~334 controls (not 396)
- ✅ 62 controls excluded
- ✅ No lock screen, LAPS, or App Installer controls
- ✅ Only Server 2019 applicable controls

If you see 396 controls, the exclusions weren't applied correctly.
