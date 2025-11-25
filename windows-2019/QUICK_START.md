# Quick Start - Windows Server 2019 CIS Audit

## 🎯 Everything is Ready!

✅ 62 controls excluded from audit  
✅ Milestone files updated  
✅ Report generators created  

## 📋 3-Step Process

### 1️⃣ Run Scanner (on Windows Server)
```powershell
cd C:\Path\To\windows-2019\Scripts
.\vijenex-scanner.ps1
```
Output: CSV file in `reports/` folder

### 2️⃣ Generate Report (on Mac)
```bash
cd /path/to/windows-2019
python3 generate-report-template.py reports/YourServer.csv
```
Output: `Windows-Server-2019-CIS-Audit-Report-TEMPLATE.txt`

### 3️⃣ Get Screenshot List
```bash
python3 list-controls-for-screenshots.py reports/YourServer.csv
```
Output: `CONTROLS_NEEDING_SCREENSHOTS.txt`

## 📸 Take Screenshots

Open `CONTROLS_NEEDING_SCREENSHOTS.txt` and take screenshots for each failed control.

## 📄 Create Final Report

1. Open the TEMPLATE.txt file
2. Copy into Microsoft Word
3. Insert screenshots where indicated
4. Format and save

## ✅ What's Excluded

62 controls automatically excluded:
- LAPS (8 controls)
- Desktop App Installer (5 controls)
- Lock screen features (2 controls)
- Cloud/Consumer features (2 controls)
- And 45 more...

See `EXCLUSIONS_2019.txt` for full list.

## 📊 Expected Results

- **Total Controls**: ~334 (not 396)
- **Excluded**: 62
- **Screenshots Needed**: ~130-150 (typical)

## 🆘 Need Help?

- Report generation: See `GENERATE_REPORT.md`
- Screenshots: See `README_SCREENSHOTS.md`
- Exclusions: See `EXCLUSIONS_SUMMARY.md`

## 🎉 That's It!

You're ready to audit your Windows Server 2019 systems with the correct control set.
