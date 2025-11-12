# Windows CIS Audit Tool

A comprehensive PowerShell-based security auditing tool for Windows Server systems based on Center for Internet Security (CIS) benchmarks.

## 🔒 **IMPORTANT: PROPRIETARY SOFTWARE**
This repository contains proprietary software. **NO MODIFICATIONS OR REDISTRIBUTION ALLOWED**. See [LICENSE](LICENSE) for full terms.

## 📋 Overview

This tool provides automated security compliance auditing for Windows Server systems against CIS (Center for Internet Security) benchmarks. It performs comprehensive security assessments without making any system changes - **audit-only mode**.

### ✨ Key Features

- **🔍 Comprehensive Coverage**: Covers all 19 sections of CIS Windows Server benchmarks
- **🛡️ Multiple Rule Types**: Supports SecEdit, AuditPolicy, User Rights Assignment, Registry, and Manual checks
- **📊 Detailed Reporting**: Generates HTML and CSV reports with remediation guidance
- **🚫 Audit-Only**: No system modifications - safe to run in production
- **⚡ Automated**: Minimal user interaction required
- **📖 Documentation**: Includes official CIS benchmark documentation

### 🎯 Supported Rule Types

| Type | Description | Coverage |
|------|-------------|----------|
| **SecEdit** | Security policy settings via secedit export | Password policies, Account lockout, Security options |
| **AuditPolicy** | Advanced audit policy configuration | Event logging and monitoring |
| **PrivRight** | User Rights Assignment automation | Privilege and logon rights |
| **Registry** | Administrative Templates via registry | Group Policy settings |
| **Composite** | Multi-condition validation | Complex policy combinations |
| **Manual** | Human verification required | Firewall, services, and UI settings |

## 🗂️ Repository Structure

```
├── windows-2025/           # Windows Server 2025 CIS audit tools
│   ├── Scripts/
│   │   └── mother-scanner.ps1    # Main scanner engine
│   ├── milestones/               # CIS control definitions
│   │   ├── milestone-1.ps1       # Account Policies
│   │   ├── milestone-2.ps1       # Local Policies  
│   │   ├── milestone-5.ps1       # System Services
│   │   ├── milestone-9.ps1       # Windows Defender Firewall
│   │   ├── milestone-17.ps1      # Advanced Audit Policy
│   │   ├── milestone-18.ps1      # Administrative Templates (Computer)
│   │   ├── milestone-19.ps1      # Administrative Templates (User)
│   │   └── ...                   # Additional milestones
│   └── reports/                  # Generated audit reports
├── windows-2022/           # [Future] Windows Server 2022 tools
├── windows-2019/           # [Future] Windows Server 2019 tools
└── LICENSE                 # Proprietary license terms
```

## 🚀 Quick Start

### Prerequisites
- Windows Server 2025 (target system)
- PowerShell 5.1 or later
- **Administrator privileges** (required for security policy access)

### Installation
1. **Download** the repository (DO NOT FORK - see license terms)
2. **Extract** to your preferred location
3. **Navigate** to the `windows-2025` directory

### Usage

#### Basic Scan (All Controls)
```powershell
# Run comprehensive CIS audit
powershell -NoProfile -ExecutionPolicy Bypass -File .\Scripts\mother-scanner.ps1 -OutputDir .\reports -Profile Level1
```

#### Advanced Options
```powershell
# Scan specific milestones only
powershell -NoProfile -ExecutionPolicy Bypass -File .\Scripts\mother-scanner.ps1 -Milestones @("milestone-1.ps1","milestone-2.ps1") -OutputDir .\reports

# Include specific controls
powershell -NoProfile -ExecutionPolicy Bypass -File .\Scripts\mother-scanner.ps1 -Include @("1.1.1","2.2.1") -OutputDir .\reports

# Exclude specific controls  
powershell -NoProfile -ExecutionPolicy Bypass -File .\Scripts\mother-scanner.ps1 -Exclude @("9.2.1","9.3.1") -OutputDir .\reports
```

### Parameters

| Parameter | Description | Default | Example |
|-----------|-------------|---------|---------|
| `-OutputDir` | Report output directory | `.\reports` | `-OutputDir "C:\Audit"` |
| `-Profile` | CIS profile level | `Level1` | `-Profile Level2` |
| `-Milestones` | Specific milestone files | All files | `-Milestones @("milestone-1.ps1")` |
| `-Include` | Include specific control IDs | None | `-Include @("1.1.1","2.2.1")` |
| `-Exclude` | Exclude specific control IDs | None | `-Exclude @("9.2.1")` |

## 📊 Report Output

The tool generates comprehensive reports in multiple formats:

### 📄 HTML Report (`cis-report.html`)
- **Visual dashboard** with pass/fail summary
- **Detailed findings** with descriptions and impact
- **Remediation guidance** for each control
- **Color-coded results** for easy identification

### 📈 CSV Report (`cis-results.csv`)
- **Structured data** for analysis and tracking
- **Import-friendly** format for spreadsheet applications
- **Compliance tracking** over time

### 📚 CIS Documentation
- **Official CIS benchmark guide** included with reports
- **Detailed remediation steps** for each control
- **Best practice recommendations**

## 🎯 CIS Coverage

### Windows Server 2025 Standalone/Workgroup

| Section | Controls | Coverage |
|---------|----------|----------|
| **1** Account Policies | 11 | Password Policy, Account Lockout Policy |
| **2** Local Policies | 98 | User Rights Assignment, Security Options |
| **5** System Services | 1 | Print Spooler configuration |
| **9** Windows Defender Firewall | 14 | Private/Public profile settings |
| **17** Advanced Audit Policy | 27 | Comprehensive audit logging |
| **18** Administrative Templates (Computer) | 164+ | Registry-based security settings |
| **19** Administrative Templates (User) | 12 | User configuration policies |

**Total: 300+ Security Controls**

## 🔧 Understanding Results

### Result Status
- ✅ **Pass**: Control is properly configured
- ❌ **Fail**: Control needs attention or manual verification
- ⚠️ **Manual**: Requires human verification (not a failure)

### Common "Fail" Reasons
1. **Default Windows Settings**: Fresh installations lack security hardening
2. **Manual Verification Required**: Firewall, services, UI settings need human check
3. **Missing Group Policy**: Administrative Templates require GP configuration
4. **Audit Policy Disabled**: Windows default has minimal audit logging

## 🛠️ Troubleshooting

### Common Issues

#### "Access Denied" Errors
```powershell
# Ensure running as Administrator
# Right-click PowerShell → "Run as Administrator"
```

#### "Execution Policy" Errors
```powershell
# Temporarily bypass execution policy
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process
```

#### "No Rules Loaded" 
- Verify milestone files exist in `milestones/` folder
- Check file permissions and paths
- Ensure PowerShell syntax is valid

#### High Failure Rate
- **Expected behavior** for default Windows installations
- Use reports to identify actual security gaps
- Focus on "Pass" vs "Manual" vs genuine "Fail" items

## 📋 Best Practices

### Before Running
1. **Backup system** (recommended for production)
2. **Review scope** - start with specific milestones
3. **Plan remediation** - have change management process ready

### After Running  
1. **Review HTML report** for executive summary
2. **Analyze CSV data** for detailed findings
3. **Prioritize fixes** based on risk and impact
4. **Document exceptions** for accepted risks
5. **Schedule regular scans** for compliance monitoring

## 🤝 Contributing

### 🚫 Code Modifications
**NOT PERMITTED** - This is proprietary software. See [LICENSE](LICENSE).

### 🐛 Issue Reporting
We welcome issue reports and feature requests:

1. **Search existing issues** before creating new ones
2. **Use issue templates** when available  
3. **Provide detailed information**:
   - Windows version and build
   - PowerShell version
   - Error messages (full text)
   - Steps to reproduce
   - Expected vs actual behavior

### 📝 Issue Guidelines
- **Security vulnerabilities**: Contact maintainers privately
- **Feature requests**: Describe use case and business value
- **Bug reports**: Include system information and logs
- **Questions**: Check documentation first

## 📞 Support

- **Issues**: Use GitHub Issues for bug reports and feature requests
- **Documentation**: Refer to included CIS benchmark guide
- **Updates**: Watch repository for new releases

## ⚖️ Legal

### License
This software is proprietary. See [LICENSE](LICENSE) for complete terms.

### Disclaimer
- **No warranty** provided - use at your own risk
- **Audit-only tool** - makes no system changes
- **CIS compliance** - based on official CIS benchmarks
- **Your responsibility** - validate findings in your environment

### CIS Benchmarks
This tool implements controls from CIS (Center for Internet Security) benchmarks. CIS benchmarks are developed by cybersecurity experts and are freely available at [cisecurity.org](https://www.cisecurity.org/).

---

## 🏷️ Version Information

- **Current Version**: 1.0.0
- **Target OS**: Windows Server 2025
- **CIS Benchmark**: Windows Server 2025 Standalone/Workgroup
- **Last Updated**: November 2025

---

**⭐ If this tool helps secure your environment, please star the repository!**

**🔒 Remember: This is proprietary software - see LICENSE for usage terms**