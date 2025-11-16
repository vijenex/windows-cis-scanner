```
██╗   ██╗██╗     ██╗███████╗███╗   ██╗███████╗██╗  ██╗
██║   ██║██║     ██║██╔════╝████╗  ██║██╔════╝╚██╗██╔╝
██║   ██║██║     ██║█████╗  ██╔██╗ ██║█████╗   ╚███╔╝ 
╚██╗ ██╔╝██║██   ██║██╔══╝  ██║╚██╗██║██╔══╝   ██╔██╗ 
 ╚████╔╝ ██║╚█████╔╝███████╗██║ ╚████║███████╗██╔╝ ██╗
  ╚═══╝  ╚═╝ ╚════╝ ╚══════╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝

                    Windows CIS Audit Tool
           Powered by Vijenex Security Platform
```

# Windows CIS Audit Platform

A comprehensive PowerShell-based security auditing platform for Windows systems based on official Center for Internet Security (CIS) benchmarks. Supports multiple Windows versions with dedicated audit modules.

## 🔓 **OPEN SOURCE SOFTWARE**
This repository contains open source software under MIT License. **CONTRIBUTIONS WELCOME**. See [LICENSE](LICENSE) for full terms.

## 📋 Overview

This platform provides automated security compliance auditing for Windows systems against official CIS (Center for Internet Security) benchmarks. It performs comprehensive security assessments without making any system changes - **audit-only mode**.

![Vijenex Security Platform](docs/images/logo.jpeg)

### ✨ Key Features

- **🔍 Multi-Version Support**: Dedicated modules for different Windows versions (2025, 2022, 2019, etc.)
- **📋 Official CIS Compliance**: Strictly follows official CIS benchmark documentation
- **🛡️ Multiple Rule Types**: Supports SecEdit, AuditPolicy, User Rights Assignment, Registry, and Manual checks
- **📊 Detailed Reporting**: Generates HTML and CSV reports with remediation guidance
- **🚫 Audit-Only**: No system modifications - safe to run in production
- **⚡ Automated**: Minimal user interaction required
- **📖 Documentation**: Includes official CIS benchmark documentation for each version

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
├── windows-2025/           # Windows Server 2025 CIS audit tools (COMPLETE)
│   ├── Scripts/
│   │   └── vijenex-scanner.ps1    # Main scanner engine
│   ├── milestones/               # CIS control definitions
│   │   ├── milestone-1.ps1       # Account Policies
│   │   ├── milestone-2.ps1       # Local Policies  
│   │   ├── milestone-5.ps1       # System Services
│   │   ├── milestone-9.ps1       # Windows Defender Firewall
│   │   ├── milestone-17.ps1      # Advanced Audit Policy
│   │   ├── milestone-18.ps1      # Administrative Templates (Computer)
│   │   ├── milestone-19.ps1      # Administrative Templates (User)
│   │   └── ...                   # Additional milestones
│   ├── documentation/            # Official CIS benchmark PDF
│   └── reports/                  # Generated audit reports
├── windows-2019/           # Windows Server 2019 CIS audit tools (COMPLETE)
│   ├── Scripts/
│   │   └── vijenex-scanner.ps1    # Main scanner engine
│   ├── milestones/               # CIS control definitions (431 controls)
│   │   ├── milestone-1.ps1       # Account Policies
│   │   ├── milestone-2.ps1       # Local Policies
│   │   ├── milestone-5.ps1       # System Services
│   │   ├── milestone-9.ps1       # Windows Defender Firewall
│   │   ├── milestone-17.ps1      # Advanced Audit Policy
│   │   ├── milestone-18.ps1      # Administrative Templates (Computer)
│   │   ├── milestone-19.ps1      # Administrative Templates (User)
│   │   └── ...                   # Additional milestones
│   ├── documentation/            # CIS benchmark documentation
│   └── reports/                  # Generated audit reports
├── windows-2022/           # [Planned] Windows Server 2022 tools
├── windows-11/             # [Planned] Windows 11 tools
├── windows-10/             # [Planned] Windows 10 tools
└── LICENSE                 # MIT License
```

## 🚀 Quick Start

### Prerequisites
- Supported Windows system (see version-specific folders)
- PowerShell 5.1 or later
- **Administrator privileges** (required for security policy access)

### Installation

#### System Installation (Recommended)

**Latest Release (Stable):**
```powershell
# Download latest release (v1.7.0)
Invoke-WebRequest -Uri "https://github.com/vijenex/windows-cis-scanner/archive/refs/tags/v1.7.0.zip" -OutFile "vijenex-windows-cis-v1.7.0.zip"
Expand-Archive -Path "vijenex-windows-cis-v1.7.0.zip" -DestinationPath "C:\Tools\"
cd "C:\Tools\Windows-Server-CIS-Audit-1.7.0\windows-2025"

# Or for Windows Server 2019
cd "C:\Tools\Windows-Server-CIS-Audit-1.7.0\windows-2019"
```

**Development Version:**
```powershell
# Clone the repository
git clone https://github.com/vijenex/windows-cis-scanner.git
cd windows-cis-scanner

# Navigate to your Windows version
cd windows-2025  # For Windows Server 2025
# OR
cd windows-2019  # For Windows Server 2019
```

**Specific Version:**
```powershell
# Install specific version (replace v1.7.0 with desired version)
git clone --branch v1.7.0 https://github.com/vijenex/windows-cis-scanner.git
cd windows-cis-scanner\windows-2025  # or windows-2019
```

### Usage

#### Basic Scan (All Controls)
```powershell
# Navigate to your Windows version folder (e.g., windows-2025)
cd windows-2025

# Run comprehensive CIS audit (HTML + CSV by default)
powershell -NoProfile -ExecutionPolicy Bypass -File .\Scripts\vijenex-scanner.ps1 -OutputDir .\reports -Profile Level1

# Generate all formats (HTML, CSV, PDF, Word)
powershell -NoProfile -ExecutionPolicy Bypass -File .\Scripts\vijenex-scanner.ps1 -OutputDir .\reports -Profile Level1 -OutputFormat All
```

### Scanner in Action

**Scan Process:**
![Scanner Process](docs/images/scan-process.png)

**Scan Output with Summary:**
![Scan Output](docs/images/scan-output.png)

#### Advanced Options
```powershell
# From within version-specific folder (e.g., windows-2025)

# Generate only Word document
powershell -NoProfile -ExecutionPolicy Bypass -File .\Scripts\vijenex-scanner.ps1 -OutputFormat Word -OutputDir .\reports

# Generate only PDF report
powershell -NoProfile -ExecutionPolicy Bypass -File .\Scripts\vijenex-scanner.ps1 -OutputFormat PDF -OutputDir .\reports

# Generate multiple formats
powershell -NoProfile -ExecutionPolicy Bypass -File .\Scripts\vijenex-scanner.ps1 -OutputFormat HTML,PDF,Word -OutputDir .\reports

# Scan specific milestones with Word output
powershell -NoProfile -ExecutionPolicy Bypass -File .\Scripts\vijenex-scanner.ps1 -Milestones @("milestone-1.ps1","milestone-2.ps1") -OutputFormat Word -OutputDir .\reports

# Include specific controls with all formats
powershell -NoProfile -ExecutionPolicy Bypass -File .\Scripts\vijenex-scanner.ps1 -Include @("1.1.1","2.2.1") -OutputFormat All -OutputDir .\reports
```

### Parameters

| Parameter | Description | Default | Example |
|-----------|-------------|---------|---------|
| `-OutputDir` | Report output directory | `.\reports` | `-OutputDir "C:\Audit"` |
| `-Profile` | CIS profile level | `Level1` | `-Profile Level2` |
| `-OutputFormat` | Report formats to generate | `HTML,CSV` | `-OutputFormat All` or `-OutputFormat Word,PDF` |
| `-Milestones` | Specific milestone files | All files | `-Milestones @("milestone-1.ps1")` |
| `-Include` | Include specific control IDs | None | `-Include @("1.1.1","2.2.1")` |
| `-Exclude` | Exclude specific control IDs | None | `-Exclude @("9.2.1")` |

## 📊 Report Output

The tool generates comprehensive reports in multiple formats with detailed system information:

### Sample HTML Report
![HTML Report Output](docs/images/html-ouput.png)

### Scan Summary Display
![Scan Summary](docs/images/scan-output.png)

### 📄 HTML Report (`vijenex-cis-report.html`)
- **System Information**: OS version, IP address, machine ID, scan date
- **Visual dashboard** with pass/fail summary
- **Detailed findings** with CIS Reference links
- **Remediation guidance** for each control
- **Color-coded results** for easy identification (green for pass, red for fail)

![HTML Report Sample](docs/images/html-ouput.png)

### 📈 CSV Report (`vijenex-cis-results.csv`)
- **Structured data** for analysis and tracking
- **Import-friendly** format for spreadsheet applications
- **Compliance tracking** over time

### 📑 PDF Report (`vijenex-cis-report-pdf.html`)
- **Browser-based PDF generation** (no additional software needed)
- **Print-friendly HTML** with one-click PDF creation button
- **Clean format** for executive reporting
- **Complete system information** and audit results
- **Usage**: Open in browser → Click "Print to PDF" button → Save as PDF

### 📝 Word Document (`vijenex-cis-report.docx`)
- **Native DOCX format** - Word document
- **Requires Microsoft Word** for generation
- **Structured tables** with all audit findings
- **System details** for audit trail
- **Usage**: Opens directly in Microsoft Word

### 🎯 Output Format Options
- `HTML,CSV` (default)
- `All` (HTML + CSV + PDF + Word)
- `Word` (Word document only)
- `PDF` (PDF report only)
- `HTML,PDF,Word` (custom combination)

### 📚 CIS Documentation
- **Official CIS benchmark guide** included with reports
- **Detailed remediation steps** for each control
- **Best practice recommendations**

## 🎯 CIS Coverage

### Currently Supported Versions

#### Windows Server 2025 Standalone/Workgroup

| Section | Controls | Coverage |
|---------|----------|----------|
| **1** Account Policies | 11 | Password Policy, Account Lockout Policy |
| **2** Local Policies | 98 | User Rights Assignment, Security Options |
| **3-8** System Services & Firewall | 14 | Event Log, Services, Firewall |
| **9** Windows Defender Firewall | 7 | Private/Public profile settings |
| **18** Administrative Templates (Computer) | 29 | Registry-based security settings |
| **19** Administrative Templates (User) | 12 | User configuration policies |

**Total: 212 Security Controls Evaluated** (164 unique control definitions)

#### Windows Server 2019 Standalone/Workgroup ✅ **NEW**

| Section | Controls | Coverage |
|---------|----------|----------|
| **1** Account Policies | 10 | Password Policy, Account Lockout Policy |
| **2** Local Policies | 95 | User Rights Assignment, Security Options |
| **5** System Services | 2 | Print Spooler, Remote Registry |
| **9** Windows Defender Firewall | 27 | Domain, Private, Public profiles |
| **17** Advanced Audit Policy | 54 | Comprehensive audit logging |
| **18** Administrative Templates (Computer) | 230+ | Registry-based security settings |
| **19** Administrative Templates (User) | 13 | User configuration policies |

**Total: 533 Security Controls Evaluated** (Level1 profile)
**Unique Control Definitions: 431** (57% of 751 total CIS controls)

### Planned Versions

- **Windows Server 2022** - Coming soon
- **Windows 11** - Planned
- **Windows 10** - Planned

> All implementations strictly follow official CIS benchmark documentation for each respective version.

## 🔧 Understanding Results

### Result Status
- ✅ **Pass**: Control is properly configured
- ❌ **Fail**: Control needs attention or manual verification
- ⚠️ **Manual**: Requires human verification (not a failure)

### CSV Report Columns
The scanner generates detailed CSV reports with the following columns:

| Column | Description |
|--------|-------------|
| **Id** | CIS control ID (e.g., 17.1.1) |
| **Title** | Control name/description |
| **Section** | CIS section name |
| **Status** | PASS or FAIL |
| **Current** | Current value on your system |
| **Expected** | Expected value per CIS benchmark |
| **Evidence** | How the scanner verified this control |
| **CISReference** | Link to official CIS documentation |
| **Remediation** | Detailed step-by-step fix instructions |
| **Description** | Important notes about the control |

### ⚠️ IMPORTANT: Audit Policy Controls (GUI vs Command Line)

**Why GUI Shows Different Results:**

Windows has **TWO separate audit policy systems**:
1. **Legacy Audit Policy** (9 categories) - Shown in Local Security Policy GUI under "Local Policies → Audit Policy"
2. **Advanced Audit Policy** (53 subcategories) - Shown under "Advanced Audit Policy Configuration"

When **both** are configured, **Advanced Audit Policy OVERRIDES Legacy**.

**What This Means for You:**
- ✅ **Scanner reads**: `auditpol` command (Advanced Audit Policy - the EFFECTIVE policy)
- ❌ **GUI shows**: Legacy Audit Policy (may show "Not Configured" even when Advanced is active)
- 🎯 **Result**: Scanner shows FAIL, but GUI shows "Not Configured" - **THIS IS NORMAL**

**How to Verify Scanner Results (Works on ALL Windows Editions including Server Core):**

```powershell
# Method 1: Check ALL effective audit policies (what scanner reads)
auditpol /get /category:*

# Method 2: Check specific subcategory
auditpol /get /subcategory:"Credential Validation"
auditpol /get /subcategory:"Logon"
auditpol /get /subcategory:"Process Creation"

# Method 3: Export to CSV for analysis
auditpol /get /category:* /r > audit-policy.csv

# Method 4: Check if GPO is overriding local settings
gpresult /r
# Or generate detailed HTML report
gpresult /h gp-report.html

# Method 5: Check Legacy Audit Policy (usually all zeros)
secedit /export /cfg C:\secpol.cfg
notepad C:\secpol.cfg
# Look at [Event Audit] section - will show 0 if Advanced Audit is active
```

**Understanding Your Output:**

When you run `auditpol /get /category:*`, you'll see output like:
```
Credential Validation    Success
Logon                    Success and Failure
Process Creation         No Auditing
```

- **Success** = Only successful events are logged
- **Success and Failure** = Both success and failure events are logged (most secure)
- **Failure** = Only failed events are logged
- **No Auditing** = Nothing is logged (CIS FAIL)

**What This Proves:**
1. If `auditpol` shows values (not all "No Auditing") → Advanced Audit Policy is active
2. If `secedit` export shows `[Event Audit]` all zeros → Legacy policy is disabled
3. If GUI shows "Not Configured" but `auditpol` shows values → **Scanner is correct, GUI is misleading**

**Why Many Show "No Auditing":**
- Windows does NOT enable all audit subcategories by default
- CIS benchmarks require many more to be enabled
- Your scanner correctly identifies these as FAIL
- This is expected on non-hardened servers

**How to Remediate Audit Policy Controls:**

**Method 1 (GUI - If Available): Use Group Policy Editor**

⚠️ **Note**: `gpedit.msc` is NOT available on Windows Server Core editions. If you get "Windows cannot find gpedit.msc", use Method 2 (Command Line) instead.

```
1. Press Win+R, type: gpedit.msc
2. Navigate to:
   Computer Configuration 
     → Windows Settings 
       → Security Settings 
         → Advanced Audit Policy Configuration 
           → System Audit Policies 
             → [Select category, e.g., Logon/Logoff]
3. Double-click the subcategory (e.g., "Logon")
4. Check "Configure the following audit events"
5. Select Success and/or Failure as required
6. Click Apply → OK
7. Verify: auditpol /get /subcategory:"Logon"
```

**Method 2 (Command Line - Works on ALL Editions including Server Core):**

✅ **Recommended for Server Core and automated deployments**

```powershell
# Enable specific audit policy
auditpol /set /subcategory:"Credential Validation" /success:enable /failure:enable
auditpol /set /subcategory:"Logon" /success:enable /failure:enable
auditpol /set /subcategory:"Process Creation" /success:enable

# Verify it was applied
auditpol /get /subcategory:"Credential Validation"

# Enable multiple subcategories at once
auditpol /set /subcategory:"Logon","Logoff","Account Lockout" /success:enable /failure:enable

# View all current settings
auditpol /get /category:*
```

**Method 3 (Domain GPO - For Domain-Joined Servers):**

⚠️ **Note**: Requires `gpmc.msc` on a management workstation (not available on Server Core)

```
1. From a management workstation, open: gpmc.msc
2. Edit the GPO applied to your servers
3. Navigate to:
   Computer Configuration 
     → Policies 
       → Windows Settings 
         → Security Settings 
           → Advanced Audit Policy Configuration
4. Configure required subcategories
5. Run on target server: gpupdate /force
6. Verify: auditpol /get /category:*
```

**Method 4 (Legacy GUI - NOT Recommended):**
```
Navigate to: secpol.msc → Local Policies → Audit Policy
⚠️ WARNING: This configures Legacy Audit Policy (9 categories only)
⚠️ If Advanced Audit Policy is active, these settings are IGNORED
⚠️ Use Methods 1-3 instead
```

**Quick CIS Compliance Script (Copy & Paste):**

```powershell
# Enable all CIS-required audit policies for Windows Server 2019
auditpol /set /subcategory:"Credential Validation" /success:enable /failure:enable
auditpol /set /subcategory:"Application Group Management" /success:enable /failure:enable
auditpol /set /subcategory:"Security Group Management" /success:enable /failure:enable
auditpol /set /subcategory:"User Account Management" /success:enable /failure:enable
auditpol /set /subcategory:"PNP Activity" /success:enable
auditpol /set /subcategory:"Process Creation" /success:enable
auditpol /set /subcategory:"Account Lockout" /success:enable /failure:enable
auditpol /set /subcategory:"Logoff" /success:enable
auditpol /set /subcategory:"Logon" /success:enable /failure:enable
auditpol /set /subcategory:"Special Logon" /success:enable
auditpol /set /subcategory:"Detailed File Share" /failure:enable
auditpol /set /subcategory:"File Share" /success:enable /failure:enable
auditpol /set /subcategory:"Other Object Access Events" /success:enable /failure:enable
auditpol /set /subcategory:"Removable Storage" /success:enable /failure:enable
auditpol /set /subcategory:"Audit Policy Change" /success:enable /failure:enable
auditpol /set /subcategory:"Authentication Policy Change" /success:enable
auditpol /set /subcategory:"Authorization Policy Change" /success:enable
auditpol /set /subcategory:"Sensitive Privilege Use" /success:enable /failure:enable
auditpol /set /subcategory:"IPsec Driver" /success:enable /failure:enable
auditpol /set /subcategory:"Security System Extension" /success:enable /failure:enable
auditpol /set /subcategory:"System Integrity" /success:enable /failure:enable

# Verify all settings
auditpol /get /category:*
```

**Key Takeaways:**

✅ **Scanner is Accurate - Not False Positives:**
- Scanner uses `auditpol` command (same as Method 2 above)
- This reads the ACTUAL effective policy enforced by Windows
- If scanner shows FAIL, run `auditpol /get /category:*` yourself to confirm
- You'll see the same values the scanner sees

❌ **Don't Trust These for Audit Policies:**
- Local Security Policy GUI (`secpol.msc` → Local Policies → Audit Policy) - Shows Legacy policy
- Group Policy Editor Legacy section - Shows 9 categories instead of 53 subcategories
- `secedit` export `[Event Audit]` section - Shows Legacy policy (usually all zeros)

✅ **Trust These for Audit Policies:**
- `auditpol /get /category:*` command - Shows effective Advanced Audit Policy
- Group Policy Editor → Advanced Audit Policy Configuration (if available)
- Scanner CSV output - Reads from `auditpol`

🎯 **Bottom Line:**
- **Scanner reads**: `auditpol` (correct)
- **GUI shows**: Legacy policy (misleading)
- **You should verify using**: `auditpol` (same as scanner)
- **Result**: Scanner and your manual verification will match - proving scanner accuracy

### Common "Fail" Reasons
1. **Default Windows Settings**: Fresh installations lack security hardening
2. **Manual Verification Required**: Firewall, services, UI settings need human check
3. **Missing Group Policy**: Administrative Templates require GP configuration
4. **Audit Policy Disabled**: Windows default has minimal audit logging (most subcategories show "No Auditing")
5. **GUI vs Effective Policy**: Audit policies may show differently in GUI vs actual enforcement

### 🔍 How to Independently Verify Scanner Accuracy

Don't just trust the scanner - verify it yourself! Run these commands to confirm scanner results:

**For Audit Policies:**
```powershell
# See exactly what scanner sees
auditpol /get /category:*

# Compare with scanner CSV output - values will match
```

**For Password Policies:**
```powershell
# Check password settings
net accounts

# Or export full policy
secedit /export /cfg C:\secpol.cfg
Get-Content C:\secpol.cfg | Select-String "Password"
```

**For User Rights:**
```powershell
# Export and check user rights
secedit /export /cfg C:\secpol.cfg
Get-Content C:\secpol.cfg | Select-String "SeNetworkLogonRight"
Get-Content C:\secpol.cfg | Select-String "SeInteractiveLogonRight"
```

**For Registry Settings:**
```powershell
# Check specific registry values
Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name RestrictAnonymousSAM
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name DisableCAD
Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" -Name RequireSignOrSeal
```

**Expected Results:**
- Your manual verification will show the **same values** as scanner CSV output
- This proves scanner accuracy
- If GUI shows different values (especially for audit policies), GUI is wrong, not scanner

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
- Fresh Windows Server typically fails 60-80% of CIS controls
- Use reports to identify actual security gaps
- Focus on "Pass" vs "Manual" vs genuine "Fail" items
- Verify scanner results using commands in "Understanding Results" section

#### "Scanner Shows FAIL but GUI Shows Not Configured"
- **This is NORMAL for audit policies**
- Scanner reads Advanced Audit Policy (correct)
- GUI shows Legacy Audit Policy (misleading)
- Run `auditpol /get /category:*` to verify scanner is correct
- See "Audit Policy Controls (GUI vs Command Line)" section above

## 📋 Best Practices

### Before Running
1. **Backup system** (recommended for production)
2. **Review scope** - start with specific milestones
3. **Plan remediation** - have change management process ready

### After Running  
1. **Review HTML report** for executive summary
2. **Analyze CSV data** for detailed findings
3. **Verify scanner accuracy** (optional but recommended):
   - Run `auditpol /get /category:*` to confirm audit policy results
   - Run `net accounts` to confirm password policy results
   - Compare with scanner CSV output - values will match
4. **Prioritize fixes** based on risk and impact
5. **Document exceptions** for accepted risks
6. **Schedule regular scans** for compliance monitoring

## 🤝 Contributing

### ✅ Code Contributions
**WELCOME** - This is open source software under MIT License. See [LICENSE](LICENSE) for details.

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
This software is open source under MIT License. See [LICENSE](LICENSE) for complete terms.

### Disclaimer
- **No warranty** provided - use at your own risk
- **Audit-only tool** - makes no system changes
- **CIS compliance** - based on official CIS benchmarks
- **Your responsibility** - validate findings in your environment

### CIS Benchmarks
This tool implements controls from CIS (Center for Internet Security) benchmarks. CIS benchmarks are developed by cybersecurity experts and are freely available at [cisecurity.org](https://www.cisecurity.org/).

---

## 🏷️ Releases

### Current Stable Release
- **v1.7.0** - Windows Server 2025 & 2019 CIS Scanner
  - **Windows Server 2025**: 203 controls evaluated (164 unique definitions)
  - **Windows Server 2019**: 533 controls evaluated (431 unique definitions, 57% CIS coverage)
  - Enhanced CSV output with 10 detailed columns
  - Comprehensive remediation guidance for all controls
  - Audit policy GUI vs CLI explanation to prevent false positive perception
  - Multiple report formats (HTML, CSV, PDF, Word)
  - Real-time scan progress display with pass/fail summary

### Download Options
```powershell
# Latest stable release (v1.7.0)
Invoke-WebRequest -Uri "https://github.com/vijenex/windows-cis-scanner/archive/refs/tags/v1.7.0.zip" -OutFile "vijenex-windows-cis-v1.7.0.zip"

# All releases
# Visit: https://github.com/vijenex/windows-cis-scanner/releases
```

### Version Information
- **Current Version**: v1.7.0
- **Supported OS**: Windows Server 2025, Windows Server 2019
- **CIS Compliance**: Based on official CIS benchmark documentation
- **Release Date**: January 2025
- **New Features**: Enhanced CSV output with detailed remediation steps, audit policy GUI vs CLI explanation

---

**⭐ If this tool helps secure your environment, please star the repository!**

**🔓 Remember: This is open source software under MIT License - contributions welcome!**