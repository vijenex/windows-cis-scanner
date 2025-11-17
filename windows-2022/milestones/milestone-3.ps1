# 2.3 Security Options (Windows Server 2022) — Audit-only
$Global:Rules += @(
  # 2.3.1 Accounts
  @{
    Id='2.3.1.1'
    Title='(L1) Ensure ''Accounts: Guest account status'' is set to ''Disabled'' (MS only) (Automated)'
    Section='2.3.1 Accounts'
    Profile='Level1'
    Type='SecEdit'
    SectionName='System Access'
    Key='EnableGuestAccount'
    Operator='Equals'
    Expected=0
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='2.3.1.1'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2022 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2022 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='2.3.1.2'
    Title='(L1) Ensure ''Accounts: Limit local account use of blank passwords to console logon only'' is set to ''Enabled'' (Automated)'
    Section='2.3.1 Accounts'
    Profile='Level1'
    Type='SecEdit'
    SectionName='System Access'
    Key='LimitBlankPasswordUse'
    Operator='Equals'
    Expected=1
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='2.3.1.2'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2022 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2022 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='2.3.1.3'
    Title='(L1) Configure ''Accounts: Rename administrator account'' (Automated)'
    Section='2.3.1 Accounts'
    Profile='Level1'
    Type='Manual'
    Expected='Renamed from Administrator'
    Evidence='Check Local Security Policy'
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='2.3.1.3'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2022 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2022 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='2.3.1.4'
    Title='(L1) Configure ''Accounts: Rename guest account'' (Automated)'
    Section='2.3.1 Accounts'
    Profile='Level1'
    Type='Manual'
    Expected='Renamed from Guest'
    Evidence='Check Local Security Policy'
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='2.3.1.4'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2022 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2022 Benchmark documentation for detailed remediation steps.'
  },

  # 2.3.2 Audit
  @{
    Id='2.3.2.1'
    Title='(L1) Ensure ''Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit policy category settings'' is set to ''Enabled'' (Automated)'
    Section='2.3.2 Audit'
    Profile='Level1'
    Type='SecEdit'
    SectionName='System Access'
    Key='SCENoApplyLegacyAuditPolicy'
    Operator='Equals'
    Expected=1
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='2.3.2.1'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2022 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2022 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='2.3.2.2'
    Title='(L1) Ensure ''Audit: Shut down system immediately if unable to log security audits'' is set to ''Disabled'' (Automated)'
    Section='2.3.2 Audit'
    Profile='Level1'
    Type='SecEdit'
    SectionName='System Access'
    Key='CrashOnAuditFail'
    Operator='Equals'
    Expected=0
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='2.3.2.2'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2022 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2022 Benchmark documentation for detailed remediation steps.'
  },

  # 2.3.4 Devices
  @{
    Id='2.3.4.1'
    Title='(L1) Ensure ''Devices: Prevent users from installing printer drivers'' is set to ''Enabled'' (Automated)'
    Section='2.3.4 Devices'
    Profile='Level1'
    Type='SecEdit'
    SectionName='System Access'
    Key='AddPrinterDrivers'
    Operator='Equals'
    Expected=1
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='2.3.4.1'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2022 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2022 Benchmark documentation for detailed remediation steps.'
  },

  # 2.3.6 Domain member
  @{
    Id='2.3.6.1'
    Title='(L1) Ensure ''Domain member: Digitally encrypt or sign secure channel data (always)'' is set to ''Enabled'' (Automated)'
    Section='2.3.6 Domain member'
    Profile='Level1'
    Type='Registry'
    Key='HKLM:/System/CurrentControlSet/Services/Netlogon/Parameters'
    ValueName='RequireSignOrSeal'
    Expected=1
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='2.3.6.1'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2022 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2022 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='2.3.6.2'
    Title='(L1) Ensure ''Domain member: Digitally encrypt secure channel data (when possible)'' is set to ''Enabled'' (Automated)'
    Section='2.3.6 Domain member'
    Profile='Level1'
    Type='Registry'
    Key='HKLM:/System/CurrentControlSet/Services/Netlogon/Parameters'
    ValueName='SealSecureChannel'
    Expected=1
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='2.3.6.2'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2022 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2022 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='2.3.6.3'
    Title='(L1) Ensure ''Domain member: Digitally sign secure channel data (when possible)'' is set to ''Enabled'' (Automated)'
    Section='2.3.6 Domain member'
    Profile='Level1'
    Type='Registry'
    Key='HKLM:/System/CurrentControlSet/Services/Netlogon/Parameters'
    ValueName='SignSecureChannel'
    Expected=1
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='2.3.6.3'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2022 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2022 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='2.3.6.4'
    Title='(L1) Ensure ''Domain member: Disable machine account password changes'' is set to ''Disabled'' (Automated)'
    Section='2.3.6 Domain member'
    Profile='Level1'
    Type='Registry'
    Key='HKLM:/System/CurrentControlSet/Services/Netlogon/Parameters'
    ValueName='DisablePasswordChange'
    Expected=0
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='2.3.6.4'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2022 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2022 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='2.3.6.5'
    Title='(L1) Ensure ''Domain member: Maximum machine account password age'' is set to ''30 or fewer days, but not 0'' (Automated)'
    Section='2.3.6 Domain member'
    Profile='Level1'
    Type='Composite'
    AllOf=@(
        @{ Type='Registry'; Key='HKLM:/System/CurrentControlSet/Services/Netlogon/Parameters'; ValueName='MaximumPasswordAge'; Operator='LessOrEqual'; Expected=30 },
        @{ Type='Registry'; Key='HKLM:/System/CurrentControlSet/Services/Netlogon/Parameters'; ValueName='MaximumPasswordAge'; Operator='NotEquals'; Expected=0 }
    )
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='2.3.6.5'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2022 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2022 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='2.3.6.6'
    Title='(L1) Ensure ''Domain member: Require strong (Windows 2000 or later) session key'' is set to ''Enabled'' (Automated)'
    Section='2.3.6 Domain member'
    Profile='Level1'
    Type='Registry'
    Key='HKLM:/System/CurrentControlSet/Services/Netlogon/Parameters'
    ValueName='RequireStrongKey'
    Expected=1
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='2.3.6.6'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2022 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2022 Benchmark documentation for detailed remediation steps.'
  },

  # 2.3.7 Interactive logon
  @{
    Id='2.3.7.1'
    Title='(L1) Ensure ''Interactive logon: Do not require CTRL+ALT+DEL'' is set to ''Disabled'' (Automated)'
    Section='2.3.7 Interactive logon'
    Profile='Level1'
    Type='SecEdit'
    SectionName='System Access'
    Key='DisableCAD'
    Operator='Equals'
    Expected=0
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='2.3.7.1'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2022 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2022 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='2.3.7.2'
    Title='(L1) Ensure ''Interactive logon: Don''t display last signed-in'' is set to ''Enabled'' (Automated)'
    Section='2.3.7 Interactive logon'
    Profile='Level1'
    Type='SecEdit'
    SectionName='System Access'
    Key='DontDisplayLastUserName'
    Operator='Equals'
    Expected=1
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='2.3.7.2'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2022 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2022 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='2.3.7.3'
    Title='(L1) Ensure ''Interactive logon: Machine inactivity limit'' is set to ''900 or fewer second(s), but not 0'' (Automated)'
    Section='2.3.7 Interactive logon'
    Profile='Level1'
    Type='Composite'
    AllOf=@(
        @{ SectionName='System Access'; Key='InactivityTimeoutSecs'; Operator='LessOrEqual'; Expected=900 },
        @{ SectionName='System Access'; Key='InactivityTimeoutSecs'; Operator='NotEquals'; Expected=0 }
    )
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='2.3.7.3'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2022 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2022 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='2.3.7.4'
    Title='(L1) Configure ''Interactive logon: Message text for users attempting to log on'' (Automated)'
    Section='2.3.7 Interactive logon'
    Profile='Level1'
    Type='Manual'
    Expected='Configured with appropriate message'
    Evidence='Check Local Security Policy'
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='2.3.7.4'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2022 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2022 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='2.3.7.5'
    Title='(L1) Configure ''Interactive logon: Message title for users attempting to log on'' (Automated)'
    Section='2.3.7 Interactive logon'
    Profile='Level1'
    Type='Manual'
    Expected='Configured with appropriate title'
    Evidence='Check Local Security Policy'
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='2.3.7.5'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2022 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2022 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='2.3.7.6'
    Title='(L2) Ensure ''Interactive logon: Number of previous logons to cache (in case domain controller is not available)'' is set to ''4 or fewer logon(s)'' (MS only) (Automated)'
    Section='2.3.7 Interactive logon'
    Profile='Level2'
    Type='Registry'
    Key='HKLM:/Software/Microsoft/Windows NT/CurrentVersion/Winlogon'
    ValueName='CachedLogonsCount'
    Operator='LessOrEqual'
    Expected=4
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='2.3.7.6'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2022 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2022 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='2.3.7.7'
    Title='(L1) Ensure ''Interactive logon: Prompt user to change password before expiration'' is set to ''between 5 and 14 days'' (Automated)'
    Section='2.3.7 Interactive logon'
    Profile='Level1'
    Type='Composite'
    AllOf=@(
        @{ SectionName='System Access'; Key='PasswordExpiryWarning'; Operator='GreaterOrEqual'; Expected=5 },
        @{ SectionName='System Access'; Key='PasswordExpiryWarning'; Operator='LessOrEqual'; Expected=14 }
    )
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='2.3.7.7'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2022 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2022 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='2.3.7.8'
    Title='(L1) Ensure ''Interactive logon: Require Domain Controller Authentication to unlock workstation'' is set to ''Enabled'' (MS only) (Automated)'
    Section='2.3.7 Interactive logon'
    Profile='Level1'
    Type='Registry'
    Key='HKLM:/Software/Microsoft/Windows NT/CurrentVersion/Winlogon'
    ValueName='ForceUnlockLogon'
    Expected=1
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='2.3.7.8'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2022 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2022 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='2.3.7.9'
    Title='(L1) Ensure ''Interactive logon: Smart card removal behavior'' is set to ''Lock Workstation'' or higher (Automated)'
    Section='2.3.7 Interactive logon'
    Profile='Level1'
    Type='Registry'
    Key='HKLM:/Software/Microsoft/Windows NT/CurrentVersion/Winlogon'
    ValueName='ScRemoveOption'
    Operator='GreaterOrEqual'
    Expected=1
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='2.3.7.9'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2022 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2022 Benchmark documentation for detailed remediation steps.'
  },

  # 2.3.8 Microsoft network client
  @{
    Id='2.3.8.1'
    Title='(L1) Ensure ''Microsoft network client: Digitally sign communications (always)'' is set to ''Enabled'' (Automated)'
    Section='2.3.8 Microsoft network client'
    Profile='Level1'
    Type='Registry'
    Key='HKLM:/System/CurrentControlSet/Services/LanmanWorkstation/Parameters'
    ValueName='RequireSecuritySignature'
    Expected=1
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='2.3.8.1'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2022 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2022 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='2.3.8.2'
    Title='(L1) Ensure ''Microsoft network client: Digitally sign communications (if server agrees)'' is set to ''Enabled'' (Automated)'
    Section='2.3.8 Microsoft network client'
    Profile='Level1'
    Type='Registry'
    Key='HKLM:/System/CurrentControlSet/Services/LanmanWorkstation/Parameters'
    ValueName='EnableSecuritySignature'
    Expected=1
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='2.3.8.2'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2022 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2022 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='2.3.8.3'
    Title='(L1) Ensure ''Microsoft network client: Send unencrypted password to third-party SMB servers'' is set to ''Disabled'' (Automated)'
    Section='2.3.8 Microsoft network client'
    Profile='Level1'
    Type='Registry'
    Key='HKLM:/System/CurrentControlSet/Services/LanmanWorkstation/Parameters'
    ValueName='EnablePlainTextPassword'
    Expected=0
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='2.3.8.3'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2022 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2022 Benchmark documentation for detailed remediation steps.'
  }
)