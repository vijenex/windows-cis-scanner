# Windows Server 2019 CIS Audit - Screenshot Collection Guide

## ✅ Setup Complete

All exclusions have been applied to the audit framework:
- **62 controls excluded** (not applicable to Server 2019)
- **Milestone files updated** with AppliesTo='NotApplicable'
- **~334 controls remain** in audit scope

## 🚀 Quick Start - Get Your Screenshot List

### Step 1: Run Scanner on a Server
```powershell
# On the Windows Server 2019 machine
cd C:\Path\To\windows-2019\Scripts
.\vijenex-scanner.ps1
```

This will generate a CSV report in the `reports` folder.

### Step 2: Generate Screenshot List
```bash
# On your Mac (after copying CSV from server)
cd /Users/satish.korra/Desktop/Windows-CIS-Audit-code/Windows-Server-CIS-Audit/windows-2019
python3 list-controls-for-screenshots.py reports/YourReport.csv
```

This creates `CONTROLS_NEEDING_SCREENSHOTS.txt` with the exact list of failed controls.

### Step 3: Take Screenshots
Open `CONTROLS_NEEDING_SCREENSHOTS.txt` and take screenshots for each failed control.

## 📸 Screenshot Guidelines

### What to Capture
For each failed control, capture:
1. **Group Policy Editor** showing the policy setting
2. **Full window** including navigation path
3. **Current value** clearly visible

### How to Take Screenshots
1. Open **Group Policy Editor** (gpedit.msc or gpmc.msc)
2. Navigate to the policy location
3. Use **Windows + Shift + S** (Snip & Sketch)
4. Capture the full window
5. Save as: `ControlID.png`

### Naming Convention
```
Section_Subsection_Control.png

Examples:
1_1_1.png          (Control 1.1.1)
18_10_16_1.png     (Control 18.10.16.1)
17_3_1.png         (Control 17.3.1)
```

### Organization
Create folders by section:
```
screenshots/
├── section_1/      (Account Policies)
├── section_2/      (Local Policies)
├── section_17/     (Advanced Audit Policy)
└── section_18/     (Administrative Templates)
```

## 📋 What's Been Excluded

These 62 controls are **NOT** in your audit scope:

### Desktop/Workstation Features (Not in Server 2019)
- Lock screen features (2)
- Desktop App Installer (5)
- Cloud/Consumer experiences (2)
- Speech recognition (1)
- Bluetooth pairing (1)

### Features Added in Later Versions
- LAPS (8 controls - added in Server 2022)
- Kernel DMA Protection (1)
- OneSettings/Diagnostics (5)

### Environment-Specific (May not apply)
- Printer settings (6)
- Remote Assistance (2)
- Group Policy processing (2)
- Hardened UNC paths (1)

See `EXCLUSIONS_2019.txt` for complete list with reasons.

## 📊 Expected Results

Based on analysis of 21 servers:

| Category | Typical Count |
|----------|---------------|
| Total Controls | ~334 |
| Usually Pass | ~180-200 |
| Usually Fail | ~130-150 |
| **Screenshots Needed** | **~130-150** |

## 🎯 Priority Controls for Screenshots

### High Priority (Security Critical)
1. **Section 1**: Password policies
2. **Section 17**: Audit policies
3. **Section 18.9**: Windows Defender, Firewall, Network security

### Medium Priority
4. **Section 18.10**: Administrative templates
5. **Section 2**: Local policies

### Low Priority (Often pass)
6. **Section 5**: System Services
7. **Section 9**: Windows Firewall rules

## 🔧 Troubleshooting

### "No CSV file found"
- Make sure you've run the scanner first
- Check the `reports` folder for CSV files
- Provide the CSV path explicitly: `python3 list-controls-for-screenshots.py path/to/file.csv`

### "Control not found in GPO"
- Some controls may be registry-based
- Check the milestone file for the exact registry path
- Use Registry Editor (regedit) instead of GPO Editor

### "Too many screenshots"
- Focus on failed controls only
- Passed controls don't need screenshots
- Use the filtered list from `CONTROLS_NEEDING_SCREENSHOTS.txt`

## 📁 Files Reference

| File | Purpose |
|------|---------|
| `EXCLUSIONS_2019.txt` | List of 62 excluded controls |
| `EXCLUSIONS_SUMMARY.md` | Detailed explanation of exclusions |
| `SCREENSHOT_CHECKLIST.md` | Full checklist with categories |
| `list-controls-for-screenshots.py` | Generate screenshot list from CSV |
| `CONTROLS_NEEDING_SCREENSHOTS.txt` | Generated list (after running script) |

## ✨ Tips for Efficiency

1. **Batch by section**: Do all Section 18 controls together
2. **Use GPO templates**: Navigate once, screenshot multiple related policies
3. **Name consistently**: Use the naming convention for easy sorting
4. **Verify as you go**: Check off controls in the list
5. **Save originals**: Keep high-res screenshots, resize for reports later

## 🎉 You're Ready!

1. ✅ Exclusions applied
2. ✅ Milestone files updated
3. ✅ Scripts ready
4. ✅ Documentation complete

**Next step**: Run the scanner and generate your screenshot list!

```bash
python3 list-controls-for-screenshots.py reports/YourServerReport.csv
```

Good luck with your audit! 🚀
