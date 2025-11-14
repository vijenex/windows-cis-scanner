# Windows Server 2019 CIS Compliance Scanner

## Overview
This directory contains the CIS compliance scanner for Windows Server 2019, evaluating **533 security controls** (431 unique control definitions representing 57% of 751 total CIS benchmark controls) for comprehensive security auditing. All critical security sections are 100% complete.

## Directory Structure
```
windows-2019/
├── Scripts/
│   └── mother-scanner.ps1      # Main scanner engine
├── milestones/                 # CIS control definitions
│   ├── milestone-template.ps1  # Template for new controls
│   └── milestone-*.ps1         # Individual milestone files
├── reports/                    # Generated scan reports
└── documentation/              # CIS benchmark documentation
```

## Usage

### Basic Scan
```powershell
# Run comprehensive CIS audit (HTML + CSV by default)
powershell -NoProfile -ExecutionPolicy Bypass -File .\Scripts\mother-scanner.ps1 -OutputDir .\reports -Profile Level1

# Generate all formats (HTML, CSV, PDF, Word)
powershell -NoProfile -ExecutionPolicy Bypass -File .\Scripts\mother-scanner.ps1 -OutputDir .\reports -Profile Level1 -OutputFormat All
```

### Advanced Options
```powershell
# Specify output directory
.\Scripts\mother-scanner.ps1 -OutputDir "C:\Reports"

# Run specific profile (Level1 or Level2)
.\Scripts\mother-scanner.ps1 -Profile "Level2"

# Run specific milestones
.\Scripts\mother-scanner.ps1 -Milestones @("milestone-1.ps1", "milestone-2.ps1")

# Generate specific formats
.\Scripts\mother-scanner.ps1 -OutputFormat @("HTML", "CSV")
.\Scripts\mother-scanner.ps1 -OutputFormat All  # HTML, CSV, PDF, Word

# Include/Exclude specific controls
.\Scripts\mother-scanner.ps1 -Include @("1.1.1", "2.2.1")
.\Scripts\mother-scanner.ps1 -Exclude @("9.2.1")
```

## Implementation Coverage

**Total Controls Evaluated**: 533 (Level1 profile)
**Unique Control Definitions**: 431 (57% of 751 total CIS controls)

### ✅ Complete Sections (100% Coverage)
- **Section 1**: Account Policies (10 controls)
- **Section 2**: Local Policies (95 controls)
- **Section 5**: System Services (2 controls)
- **Section 9**: Windows Defender Firewall (27 controls)
- **Section 17**: Advanced Audit Policy Configuration (54 controls)

### ⚠️ Partial Coverage
- **Section 18**: Administrative Templates - Computer (230+ controls implemented)
- **Section 19**: Administrative Templates - User (13 controls implemented)

### Control Types Supported
- **SecEdit**: Security policy settings (Password, Account Lockout, Security Options)
- **AuditPolicy**: Advanced audit policy configurations
- **Registry**: Administrative Templates via registry checks
- **PrivRight**: User Rights Assignment automation
- **Composite**: Multi-condition validation
- **Manual**: Manual verification required (Firewall, Services)

## CIS Reference
All controls reference the official CIS Microsoft Windows Server 2019 Benchmark available at:
https://www.cisecurity.org/benchmark/microsoft_windows_server

## Requirements
- Windows Server 2019
- PowerShell 5.1 or later
- Administrator privileges
- Network access for CIS documentation links

## Output Formats
- **HTML**: Visual dashboard with color-coded results
- **CSV**: Structured data for analysis and tracking
- **PDF**: Browser-based PDF generation (print-friendly)
- **Word**: Native DOCX format (requires Microsoft Word)

## Scan Summary Display
After scan completion, displays:
```
=============================================================
                    SCAN COMPLETED                           
=============================================================
Total Checks: 533
Passed: 245
Failed: 288
Success Rate: 45.9%
=============================================================
```

## Notes
- **Audit-only scanner** - makes no system changes
- **Real-time progress** - displays each control as it's evaluated
- **Reports stored** in reports/ directory by default
- **CIS Reference links** included for each control
- **Standardized format** - matches Windows 2025 implementation
- **Enterprise-ready** - 100% coverage of critical security sections