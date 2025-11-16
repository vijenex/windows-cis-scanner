# CIS Scanner - Evidence Collection Tool

## Overview
Automated evidence collection tool that reads the CIS scanner CSV output and generates a comprehensive HTML evidence report for all failed controls. **No manual screenshots needed!**

## Features
- ✅ **Automated Evidence Collection** - Runs verification commands automatically
- ✅ **HTML Report Generation** - Professional, searchable evidence report
- ✅ **Timestamp Tracking** - Records when evidence was collected
- ✅ **Audit Trail** - Shows actual system values at scan time
- ✅ **No Screenshots Required** - Text-based evidence is easier to review and search

## Usage

### Step 1: Run the CIS Scanner
```powershell
cd windows-2019\Scripts
.\vijenex-scanner.ps1
```

This generates: `windows-2019\reports\vijenex-cis-results.csv`

### Step 2: Collect Evidence for Failed Controls
```powershell
.\Collect-FailureEvidence.ps1 -CSVPath ".\windows-2019\reports\vijenex-cis-results.csv"
```

This generates: `windows-2019\reports\vijenex-evidence-report.html`

### Step 3: Review Evidence Report
Open `vijenex-evidence-report.html` in any web browser to see:
- Control ID and Title
- Actual system value detected
- Verification command used
- Timestamp of evidence collection

## What Evidence is Collected?

The tool automatically collects evidence for:

### Password Policies
- Password history size
- Maximum/minimum password age
- Minimum password length
- Password complexity requirements
- Reversible encryption settings

### Account Lockout Policies
- Lockout duration
- Lockout threshold
- Lockout observation window

### Audit Policies
- All audit subcategories (using `auditpol` command)
- Credential Validation, Account Lockout, Logon/Logoff, etc.

### User Rights Assignments
- Access this computer from network
- Allow log on locally
- Allow log on through Remote Desktop
- Deny access from network
- All other user rights

### Security Options
- Registry-based security settings
- Domain member settings
- Interactive logon settings
- Network access settings

## Evidence Report Format

The HTML report includes:
- **System Information**: Computer name, timestamp, total failed controls
- **Evidence Table**: 
  - Control ID
  - Control Title
  - Section
  - **Actual Value** (what scanner detected)
  - **Verification Command** (how to manually verify)
  - Timestamp

## Benefits Over Screenshots

| Screenshots | Evidence Collection Tool |
|-------------|-------------------------|
| ❌ Time-consuming (499 screenshots!) | ✅ Automated (runs in seconds) |
| ❌ Not searchable | ✅ Fully searchable HTML |
| ❌ Large file sizes | ✅ Lightweight text report |
| ❌ Hard to review | ✅ Easy to review in browser |
| ❌ Manual work | ✅ Fully automated |

## Requirements
- Windows Server 2019 or 2025
- Administrator privileges
- PowerShell 5.1 or higher
- Scanner CSV output file

## Example Output

```
==============================================================
         CIS SCANNER - EVIDENCE COLLECTION TOOL              
==============================================================
Reading: .\windows-2019\reports\vijenex-cis-results.csv

Total Controls: 533
Failed Controls: 499

Collecting evidence for 499 failed controls...

[*] Exporting security policy...
[1/499] Collecting evidence for 1.1.1...
[2/499] Collecting evidence for 1.1.3...
...

[*] Generating HTML evidence report...

==============================================================
         EVIDENCE COLLECTION COMPLETED                       
==============================================================
Evidence Report: .\windows-2019\reports\vijenex-evidence-report.html
Total Failed Controls: 499

Open the HTML file in a browser to view the evidence report.
==============================================================
```

## Notes
- Evidence collection is **audit-only** - no system changes are made
- The tool reads the same data sources as the scanner (secedit, auditpol, registry)
- Evidence is collected at the time you run the tool (may differ from original scan time)
- For best accuracy, run evidence collection immediately after scanning

## Troubleshooting

**Q: Evidence shows "<not configured>"**  
A: This means the setting is not explicitly configured in the security policy. This is the actual system state.

**Q: Evidence shows "<error: ...>"**  
A: The tool couldn't read that specific setting. Check if you're running as Administrator.

**Q: Can I run this on a different machine?**  
A: No, the evidence collection must run on the same machine that was scanned, as it reads live system settings.

## Support
For issues or questions, refer to the main README.md or CIS Benchmark documentation.
