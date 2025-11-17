# Windows Server 2022 CIS Control Definitions

## Overview
This folder contains PowerShell scripts that define CIS benchmark controls for Windows Server 2022.

## File Structure

Each milestone file should follow this naming convention:
- `milestone-1.ps1` - Section 1: Account Policies
- `milestone-2.ps1` - Section 2: Local Policies
- `milestone-5.ps1` - Section 5: System Services
- `milestone-9.ps1` - Section 9: Windows Defender Firewall
- `milestone-17.ps1` - Section 17: Advanced Audit Policy
- `milestone-18.ps1` - Section 18: Administrative Templates (Computer)
- `milestone-19.ps1` - Section 19: Administrative Templates (User)

## Control Definition Format

Each control is defined as a hashtable and added to `$Global:Rules`:

```powershell
# Example: Password Policy Control
$Global:Rules += @{
    Id = '1.1.1'
    Title = "(L1) Ensure 'Enforce password history' is set to '24 or more password(s)' (Automated)"
    Section = '1.1 Password Policy'
    Profile = 'Level1'
    Type = 'SecEdit'
    SectionName = 'System Access'
    Key = 'PasswordHistorySize'
    Operator = 'GreaterOrEqual'
    Expected = 24
    CISReference = 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
    Remediation = 'Configure via Local Security Policy or Group Policy'
}

# Example: Audit Policy Control
$Global:Rules += @{
    Id = '17.1.1'
    Title = "(L1) Ensure 'Audit Credential Validation' is set to 'Success and Failure' (Automated)"
    Section = '17.1 Account Logon'
    Profile = 'Level1'
    Type = 'AuditPolicy'
    Subcategory = 'Credential Validation'
    Expected = 'Success and Failure'
    CISReference = 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
    Remediation = 'Configure via Advanced Audit Policy Configuration'
}

# Example: User Rights Assignment
$Global:Rules += @{
    Id = '2.2.1'
    Title = "(L1) Ensure 'Access Credential Manager as a trusted caller' is set to 'No One' (Automated)"
    Section = '2.2 User Rights Assignment'
    Profile = 'Level1'
    Type = 'PrivRight'
    Key = 'SeTrustedCredManAccessPrivilege'
    ExpectedPrincipals = @()
    SetMode = 'Exact'
    CISReference = 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
    Remediation = 'Configure via Local Security Policy'
}

# Example: Registry-based Control
$Global:Rules += @{
    Id = '18.1.1.1'
    Title = "(L1) Ensure 'Prevent enabling lock screen camera' is set to 'Enabled' (Automated)"
    Section = '18.1.1 Lock Screen'
    Profile = 'Level1'
    Type = 'Registry'
    Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization'
    ValueName = 'NoLockScreenCamera'
    Expected = 1
    CISReference = 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
    Remediation = 'Configure via Group Policy'
}

# Example: Manual Review Control
$Global:Rules += @{
    Id = '9.1.1'
    Title = "(L1) Ensure 'Windows Firewall: Domain: Firewall state' is set to 'On' (Manual)"
    Section = '9.1 Domain Profile'
    Profile = 'Level1'
    Type = 'Manual'
    Expected = 'On (recommended)'
    Evidence = 'Check Windows Defender Firewall settings'
    CISReference = 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
    Remediation = 'Enable via Windows Defender Firewall with Advanced Security'
}
```

## Control Types

| Type | Description | Use Case |
|------|-------------|----------|
| `SecEdit` | Security policy via secedit | Password policies, account lockout, security options |
| `AuditPolicy` | Advanced audit policy | Event logging configuration |
| `PrivRight` | User rights assignment | Privilege and logon rights |
| `Registry` | Registry-based settings | Group Policy administrative templates |
| `Composite` | Multiple related checks | Complex multi-condition validations |
| `Manual` | Requires human verification | Firewall, services, UI settings |

## Adding New Controls

1. Create or edit the appropriate milestone file
2. Add control definition using the format above
3. Test the scanner to verify the control works
4. Document any special considerations

## Notes

- All controls must have unique `Id` values
- `Profile` should be either `Level1` or `Level2`
- `CISReference` should link to official CIS documentation
- `Remediation` should provide clear guidance on how to fix failures

## Testing

After adding controls, test with:
```powershell
# Test specific milestone
.\Scripts\vijenex-scanner.ps1 -Milestones @("milestone-1.ps1")

# Test specific control
.\Scripts\vijenex-scanner.ps1 -Include @("1.1.1")
```
