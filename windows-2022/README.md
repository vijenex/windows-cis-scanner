# Windows Server 2022 CIS Compliance Scanner

## Overview
Automated CIS (Center for Internet Security) compliance scanner for Windows Server 2022 Standalone/Workgroup environments.

## System Requirements
- **Operating System**: Windows Server 2022 (Build 20348)
- **PowerShell**: Version 5.1 or higher
- **Privileges**: Administrator rights required

## Quick Start

### Run Scanner
```powershell
# Navigate to windows-2022 folder
cd windows-2022

# Run comprehensive scan
powershell -NoProfile -ExecutionPolicy Bypass -File .\Scripts\vijenex-scanner.ps1 -OutputDir .\reports -Profile Level1

# Collect evidence for failed controls
powershell -NoProfile -ExecutionPolicy Bypass -File ..\Collect-FailureEvidence.ps1 -CSVPath ".\reports\vijenex-cis-results.csv"
```

### Generate All Report Formats
```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\Scripts\vijenex-scanner.ps1 -OutputDir .\reports -Profile Level1 -OutputFormat All
```

## CIS Controls Coverage

### Implemented Sections
Controls will be added to the `milestones/` folder:

- **Section 1**: Account Policies (Password Policy, Account Lockout Policy)
- **Section 2**: Local Policies (User Rights Assignment, Security Options)
- **Section 5**: System Services
- **Section 9**: Windows Defender Firewall
- **Section 17**: Advanced Audit Policy Configuration
- **Section 18**: Administrative Templates (Computer Configuration)
- **Section 19**: Administrative Templates (User Configuration)

### Adding Controls
Place control definition files in `milestones/` folder:
- `milestone-1.ps1` - Account Policies
- `milestone-2.ps1` - Local Policies
- `milestone-5.ps1` - System Services
- `milestone-9.ps1` - Windows Defender Firewall
- `milestone-17.ps1` - Advanced Audit Policy
- `milestone-18.ps1` - Administrative Templates (Computer)
- `milestone-19.ps1` - Administrative Templates (User)

## Report Outputs

After scanning, you'll find in `reports/` folder:
- `vijenex-cis-results.csv` - Detailed CSV report
- `vijenex-cis-report.html` - Interactive HTML report
- `vijenex-cis-report-pdf.html` - PDF-ready report
- `vijenex-cis-report.docx` - Word document
- `vijenex-evidence-report.html` - Evidence for failed controls

## Parameters

| Parameter | Description | Default | Example |
|-----------|-------------|---------|---------|
| `-OutputDir` | Report output directory | `.\reports` | `-OutputDir "C:\Audit"` |
| `-Profile` | CIS profile level | `Level1` | `-Profile Level2` |
| `-OutputFormat` | Report formats | `HTML,CSV` | `-OutputFormat All` |
| `-Milestones` | Specific milestone files | All files | `-Milestones @("milestone-1.ps1")` |
| `-Include` | Include specific control IDs | None | `-Include @("1.1.1","2.2.1")` |
| `-Exclude` | Exclude specific control IDs | None | `-Exclude @("9.2.1")` |

## Documentation

Place official CIS Benchmark PDF in `documentation/` folder for reference.

## Version Information
- **Scanner Version**: 1.8.3
- **Windows Server**: 2022 (Build 20348)
- **CIS Benchmark**: Based on official CIS Microsoft Windows Server 2022 Benchmark
- **Release Date**: November 2025

## Support
Refer to main repository README for detailed documentation and troubleshooting.
