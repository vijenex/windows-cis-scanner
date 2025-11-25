# Windows Server 2019 CIS Audit - Screenshot Checklist

## Summary
- **Total Controls**: ~334 (after excluding 62 N/A controls)
- **Excluded Controls**: 62 (not applicable to Server 2019)
- **Controls Needing Screenshots**: Run scanner to get exact count

## Exclusions Applied (62 controls)

### Lock Screen Features (2)
- 18.1.1.1 - Prevent enabling lock screen camera
- 18.1.1.2 - Prevent enabling lock screen slide show

### Speech Recognition (1)
- 18.1.2.2 - Allow users to enable online speech recognition services

### Cloud/Consumer Features (2)
- 18.10.13.1 - Turn off cloud consumer account state content
- 18.10.13.2 - Turn off Microsoft consumer experiences

### Credential UI (2)
- 18.10.15.1 - Do not display the password reveal button
- 18.10.15.2 - Enumerate administrator accounts on elevation

### OneSettings/Diagnostics (5)
- 18.10.16.3 - Disable OneSettings Downloads
- 18.10.16.4 - Do not show feedback notifications
- 18.10.16.5 - Enable OneSettings Auditing
- 18.10.16.6 - Limit Diagnostic Log Collection
- 18.10.16.7 - Limit Dump Collection

### Desktop App Installer (5)
- 18.10.18.2 - Enable App Installer Experimental Features
- 18.10.18.3 - Enable App Installer Hash Override
- 18.10.18.4 - Enable App Installer Local Archive Malware Scan Override
- 18.10.18.5 - Enable App Installer ms-appinstaller protocol
- 18.10.18.6 - Enable App Installer Microsoft Store Source Certificate Validation Bypass

### Bluetooth (1)
- 18.10.14.1 - Require pin for pairing

### Windows Defender Advanced (5)
- 18.10.43.6.1.2 - Configure Attack Surface Reduction rules
- 18.10.43.11.1.1.2 - Configure Remote Encryption Protection Mode
- 18.10.43.13.1 - Scan excluded files during quick scans
- 18.10.43.13.4 - Trigger quick scan after X days
- 18.10.43.17 - Control whether exclusions are visible to local users

### RSS Feeds (1)
- 18.10.58.2 - Turn on Basic feed authentication over HTTP

### Sign-in Features (8)
- 18.10.82.1 - Sign-in and lock last interactive user automatically after restart
- 18.9.28.1-7 - Various sign-in features

### Kernel DMA Protection (1)
- 18.9.24.1 - Kernel DMA Protection

### LAPS (8)
- 18.9.25.1-8 - All LAPS settings (not in Server 2019)

### Power Management (2)
- 18.9.33.6.3-4 - Power management settings

### Remote Assistance (2)
- 18.9.35.1-2 - Remote Assistance settings

### MSS Settings (3)
- 18.4.5 - Enable SEHOP
- 18.4.7 - NetBT NodeType configuration
- 18.5.12 - WarningLevel for security event log

### Network Settings (1)
- 18.6.4.2 - Configure NetBIOS settings

### Printer Settings (6)
- 18.7.5-8, 18.7.10-12 - Various printer settings

### Group Policy (2)
- 18.9.19.4-5 - Group Policy processing

### Internet Download (2)
- 18.9.20.1.1, 18.9.20.1.5 - Internet download features

### Hardened UNC Paths (1)
- 18.6.14.1 - Hardened UNC Paths

## Next Steps

1. **Run the scanner with exclusions**:
   ```powershell
   cd Scripts
   .\run-scanner-with-exclusions.ps1
   ```

2. **Review the FINAL report** in the reports folder

3. **Take screenshots** for all FAILED controls

4. **Organize screenshots** by section number (1.x, 2.x, 17.x, 18.x, etc.)

## Screenshot Guidelines

- Use Windows Snipping Tool or Snip & Sketch
- Capture the full GPO editor window showing:
  - Policy path in left pane
  - Policy setting in right pane
  - Current configuration value
- Save as: `ControlID_ShortDescription.png`
  - Example: `18.10.16.1_AllowDiagnosticData.png`
- Group by section in folders

## Compliance Target

After applying exclusions, focus on remediating:
1. Password policies (Section 1)
2. Audit policies (Section 17)
3. Security settings (Section 18)
