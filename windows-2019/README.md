# Windows Server 2019 CIS Compliance Scanner

## Overview
This directory contains the CIS compliance scanner for Windows Server 2019, implementing official CIS benchmark controls for security auditing.

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
# Run from Scripts directory
cd Scripts
.\mother-scanner.ps1
```

### Advanced Options
```powershell
# Specify output directory
.\mother-scanner.ps1 -OutputDir "C:\Reports"

# Run specific profile
.\mother-scanner.ps1 -Profile "Level2"

# Run specific milestones
.\mother-scanner.ps1 -Milestones @("milestone-1.ps1", "milestone-2.ps1")

# Generate specific formats
.\mother-scanner.ps1 -OutputFormat @("HTML", "CSV")
```

## Control Types Supported
- **SecEdit**: Security policy settings
- **AuditPolicy**: Audit policy configurations  
- **Registry**: Registry key/value checks
- **PrivRight**: User rights assignments
- **Composite**: Multi-condition checks
- **Manual**: Manual verification required

## CIS Reference
All controls reference the official CIS Microsoft Windows Server 2019 Benchmark available at:
https://www.cisecurity.org/benchmark/microsoft_windows_server

## Requirements
- Windows Server 2019
- PowerShell 5.1 or later
- Administrator privileges
- Network access for CIS documentation links

## Notes
- Audit-only scanner - makes no system changes
- Reports stored in reports/ directory by default
- All controls include official CIS benchmark references
- Custom descriptions removed to ensure accuracy