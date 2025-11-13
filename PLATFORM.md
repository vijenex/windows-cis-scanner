# Windows CIS Audit Platform Architecture

## Overview

This repository is structured as a **multi-version Windows CIS audit platform** that supports different Windows operating systems with dedicated audit modules. Each Windows version has its own folder containing version-specific CIS benchmark implementations.

## Platform Structure

```
Windows-Server-CIS-Audit/
├── windows-2025/          # Windows Server 2025 audit module
├── windows-2022/          # Windows Server 2022 audit module (planned)
├── windows-2019/          # Windows Server 2019 audit module (planned)
├── windows-11/            # Windows 11 Enterprise audit module (planned)
├── windows-10/            # Windows 10 Enterprise audit module (planned)
├── README.md              # Main platform documentation
├── LICENSE                # MIT License
└── CONTRIBUTING.md        # Contribution guidelines
```

## Version-Specific Modules

Each Windows version folder contains:

```
windows-XXXX/
├── Scripts/
│   └── mother-scanner.ps1     # Main scanner engine
├── milestones/                # CIS control definitions
│   ├── milestone-1.ps1        # Section 1 controls
│   ├── milestone-2.ps1        # Section 2 controls
│   └── ...                    # Additional sections
├── documentation/             # Official CIS benchmark PDF
└── reports/                   # Generated audit reports
```

## CIS Benchmark Compliance

- **Strict Adherence**: All implementations strictly follow official CIS benchmark documentation
- **Version-Specific**: Each module implements controls specific to that Windows version
- **Official Documentation**: Includes official CIS benchmark PDFs for reference
- **No Modifications**: Controls are implemented exactly as specified in CIS documentation

## Usage Pattern

1. **Navigate** to the appropriate Windows version folder
2. **Run** the scanner from within that folder
3. **Review** version-specific reports and documentation

## Development Principles

- **Official CIS Compliance**: Never deviate from official CIS benchmark specifications
- **Version Isolation**: Each Windows version is completely independent
- **Consistent Architecture**: All versions use the same scanner engine architecture
- **Documentation Included**: Official CIS PDFs included with each version

## Roadmap

### Current Status
- ✅ **Windows Server 2025**: Complete implementation (133 controls)

### Planned Releases
- 🔄 **Windows Server 2022**: In development
- 🔄 **Windows Server 2019**: Planned
- 🔄 **Windows 11 Enterprise**: Planned  
- 🔄 **Windows 10 Enterprise**: Planned

## Contributing

When contributing to specific Windows versions:

1. **Follow CIS Documentation**: Strictly adhere to official CIS benchmark specifications
2. **Version-Specific**: Work within the appropriate version folder
3. **Test Thoroughly**: Validate against official CIS documentation
4. **Document Changes**: Reference specific CIS control numbers and sections

## Quality Assurance

- **CIS Validation**: All controls validated against official CIS documentation
- **No Custom Controls**: Only implement controls specified in official benchmarks
- **Version Accuracy**: Ensure controls match the specific Windows version requirements
- **Documentation Sync**: Keep implementation aligned with included CIS PDFs