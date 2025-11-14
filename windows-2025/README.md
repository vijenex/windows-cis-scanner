# Windows Server 2025 CIS Compliance Scanner

## Overview
This directory contains the CIS compliance scanner for Windows Server 2025, implementing **327+ CIS benchmark controls** for comprehensive security auditing based on official CIS Microsoft Windows Server 2025 Benchmark v1.0.0.

## Directory Structure
```
windows-2025/
├── Scripts/
│   └── mother-scanner.ps1      # Main scanner engine
├── milestones/                 # CIS control definitions
│   ├── milestone-1.ps1         # Account Policies
│   ├── milestone-2.ps1         # Local Policies
│   ├── milestone-5.ps1         # System Services
│   ├── milestone-9.ps1         # Windows Defender Firewall
│   ├── milestone-17.ps1        # Advanced Audit Policy
│   ├── milestone-18.ps1        # Administrative Templates (Computer)
│   ├── milestone-19.ps1        # Administrative Templates (User)
│   └── ...                     # Additional milestones
├── reports/                    # Generated scan reports
└── documentation/              # CIS benchmark PDF documentation
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

### ✅ Implemented Sections
- **Section 1**: Account Policies (11 controls) - Password Policy, Account Lockout Policy
- **Section 2**: Local Policies (98 controls) - User Rights Assignment, Security Options
- **Section 5**: System Services (1 control) - Print Spooler configuration
- **Section 9**: Windows Defender Firewall (14 controls) - Private/Public profile settings
- **Section 17**: Advanced Audit Policy (27 controls) - Comprehensive audit logging
- **Section 18**: Administrative Templates - Computer (164+ controls) - Registry-based security settings
- **Section 19**: Administrative Templates - User (12 controls) - User configuration policies

**Total: 327+ Security Controls**

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
Total Checks: 327
Passed: 189
Failed: 138
Success Rate: 57.8%
=============================================================
```

## CIS Reference
All controls reference the official CIS Microsoft Windows Server 2025 Benchmark v1.0.0 available at:
https://www.cisecurity.org/benchmark/microsoft_windows_server

## Requirements
- Windows Server 2025
- PowerShell 5.1 or later
- Administrator privileges
- Network access for CIS documentation links

## Notes
- **Audit-only scanner** - makes no system changes
- **Real-time progress** - displays each control as it's evaluated
- **Reports stored** in reports/ directory by default
- **CIS Reference links** included for each control
- **Standardized format** - matches Windows 2019 implementation
- **Enterprise-ready** - comprehensive security baseline for Windows Server 2025
