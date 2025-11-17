# Windows Server 2022 CIS Compliance Scanner

## Overview
This directory contains the CIS compliance scanner for Windows Server 2022, evaluating **432 security controls** (432 unique control definitions) for comprehensive security auditing based on official CIS Microsoft Windows Server 2022 Benchmark.

## Directory Structure
```
windows-2022/
├── Scripts/
│   └── vijenex-scanner.ps1      # Main scanner engine
├── milestones/                 # CIS control definitions
│   ├── milestone-1.ps1         # Account Policies
│   ├── milestone-2.ps1         # Local Policies
│   ├── milestone-5.ps1         # System Services
│   ├── milestone-9.ps1         # Windows Defender Firewall
│   ├── milestone-17.ps1        # Advanced Audit Policy
│   ├── milestone-18.ps1        # Administrative Templates (Computer)
│   ├── milestone-19.ps1        # Administrative Templates (User)
│   └── milestone-2022-new-controls.ps1  # New Windows 2022 Controls
├── reports/                    # Generated scan reports
└── documentation/              # CIS benchmark documentation
```

## Usage

### Basic Scan
```powershell
# Run comprehensive CIS audit (HTML + CSV by default)
powershell -NoProfile -ExecutionPolicy Bypass -File .\Scripts\vijenex-scanner.ps1 -OutputDir .\reports -Profile Level1

# Generate all formats (HTML, CSV, PDF, Word)
powershell -NoProfile -ExecutionPolicy Bypass -File .\Scripts\vijenex-scanner.ps1 -OutputDir .\reports -Profile Level1 -OutputFormat All
```

### Advanced Options
```powershell
# Specify output directory
.\Scripts\vijenex-scanner.ps1 -OutputDir "C:\Reports"

# Run specific profile (Level1 or Level2)
.\Scripts\vijenex-scanner.ps1 -Profile "Level2"

# Run specific milestones
.\Scripts\vijenex-scanner.ps1 -Milestones @("milestone-1.ps1", "milestone-2.ps1")

# Generate specific formats
.\Scripts\vijenex-scanner.ps1 -OutputFormat @("HTML", "CSV")
.\Scripts\vijenex-scanner.ps1 -OutputFormat All  # HTML, CSV, PDF, Word

# Include/Exclude specific controls
.\Scripts\vijenex-scanner.ps1 -Include @("1.1.1", "2.2.1")
.\Scripts\vijenex-scanner.ps1 -Exclude @("9.2.1")
```

## Implementation Coverage

### ✅ Implemented Sections
- **Section 1**: Account Policies (11 controls) - Password Policy, Account Lockout Policy
- **Section 2**: Local Policies (122 controls) - User Rights Assignment, Security Options
- **Section 5**: System Services (2 controls) - Service configuration
- **Section 9**: Windows Defender Firewall (27 controls) - Domain/Private/Public profiles
- **Section 17**: Advanced Audit Policy Configuration (34 controls) - Audit policies
- **Section 18**: Administrative Templates - Computer (231 controls) - Registry-based security settings
- **Section 19**: Administrative Templates - User (12 controls) - User configuration policies
- **New 2022 Controls**: (8 controls) - Windows Server 2022 specific security controls

**Total: 432 Security Controls Evaluated** (432 unique control definitions)

### New Windows Server 2022 Controls
- 18.6.7.1 - Mandate the minimum version of SMB
- 18.6.8.2 - Require Encryption
- 18.9.26.1 - Allow Custom SSPs and APs to be loaded into LSASS
- 18.9.39.1 - Configure validation of ROCA-vulnerable WHfB keys
- 18.10.13.3 - Turn off Microsoft consumer experiences
- 18.10.57.3.3.5 - Do not allow LPT port redirection
- 18.10.57.3.3.6 - Do not allow supported Plug and Play device redirection
- 18.10.57.3.3.7 - Do not allow WebAuthn redirection
- 18.10.82.2 - Sign-in and lock last interactive user automatically after a restart

### Control Types Supported
- **SecEdit**: Security policy settings (Password, Account Lockout, Security Options)
- **AuditPolicy**: Advanced audit policy configurations
- **Registry**: Administrative Templates via registry checks
- **PrivRight**: User Rights Assignment automation
- **Composite**: Multi-condition validation
- **Manual**: Manual verification required (Firewall, Services)

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
Total Checks: 432
Passed: XXX
Failed: XXX
Success Rate: XX.X%
=============================================================
```

## CIS Reference
All controls reference the official CIS Microsoft Windows Server 2022 Benchmark available at:
https://www.cisecurity.org/benchmark/microsoft_windows_server

## Requirements
- Windows Server 2022
- PowerShell 5.1 or later
- Administrator privileges
- Network access for CIS documentation links

## Notes
- **Audit-only scanner** - makes no system changes
- **Real-time progress** - displays each control as it's evaluated
- **Reports stored** in reports/ directory by default
- **CIS Reference links** included for each control
- **Standardized format** - matches Windows 2019 and 2025 implementation
- **Enterprise-ready** - comprehensive security baseline for Windows Server 2022
- **Zero duplicates** - 432 unique controls validated
