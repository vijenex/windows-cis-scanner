# 1 Account Policies (Windows Server 2016) — Audit-only
$Global:Rules += @(
  # 1.1 Password Policy
  @{ 
    Id='1.1.1'
    Title='(L1) Ensure ''Enforce password history'' is set to ''24 or more password(s)'' (Automated)'
    Section='1.1 Password Policy'
    Profile='Level1'
    Type='SecEdit'
    SectionName='System Access'
    Key='PasswordHistorySize'
    Operator='GreaterOrEqual'
    Expected=24
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='1.1.1'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2016 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2016 Benchmark documentation for detailed remediation steps.'
  },
  @{ 
    Id='1.1.2'
    Title='(L1) Ensure ''Maximum password age'' is set to ''365 or fewer days, but not 0'' (Automated)'
    Section='1.1 Password Policy'
    Profile='Level1'
    Type='Composite'
    AllOf=@(
        @{ Type='SecEdit'; SectionName='System Access'; Key='MaximumPasswordAge'; Operator='LessOrEqual'; Expected=365 },
        @{ Type='SecEdit'; SectionName='System Access'; Key='MaximumPasswordAge'; Operator='NotEquals'; Expected=0 }
    )
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='1.1.2'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2016 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2016 Benchmark documentation for detailed remediation steps.'
  },
  @{ 
    Id='1.1.3'
    Title='(L1) Ensure ''Minimum password age'' is set to ''1 or more day(s)'' (Automated)'
    Section='1.1 Password Policy'
    Profile='Level1'
    Type='SecEdit'
    SectionName='System Access'
    Key='MinimumPasswordAge'
    Operator='GreaterOrEqual'
    Expected=1
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='1.1.3'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2016 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2016 Benchmark documentation for detailed remediation steps.'
  },
  @{ 
    Id='1.1.4'
    Title='(L1) Ensure ''Minimum password length'' is set to ''14 or more character(s)'' (Automated)'
    Section='1.1 Password Policy'
    Profile='Level1'
    Type='SecEdit'
    SectionName='System Access'
    Key='MinimumPasswordLength'
    Operator='GreaterOrEqual'
    Expected=14
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='1.1.4'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2016 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2016 Benchmark documentation for detailed remediation steps.'
  },
  @{ 
    Id='1.1.5'
    Title='(L1) Ensure ''Password must meet complexity requirements'' is set to ''Enabled'' (Automated)'
    Section='1.1 Password Policy'
    Profile='Level1'
    Type='SecEdit'
    SectionName='System Access'
    Key='PasswordComplexity'
    Operator='Equals'
    Expected=1
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='1.1.5'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2016 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2016 Benchmark documentation for detailed remediation steps.'
  },
  @{ 
    Id='1.1.6'
    Title='(L1) Ensure ''Store passwords using reversible encryption'' is set to ''Disabled'' (Automated)'
    Section='1.1 Password Policy'
    Profile='Level1'
    Type='SecEdit'
    SectionName='System Access'
    Key='ClearTextPassword'
    Operator='Equals'
    Expected=0
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='1.1.6'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2016 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2016 Benchmark documentation for detailed remediation steps.'
  },

  # 1.2 Account Lockout Policy
  @{ 
    Id='1.2.1'
    Title='(L1) Ensure ''Account lockout duration'' is set to ''15 or more minute(s)'' (Automated)'
    Section='1.2 Account Lockout Policy'
    Profile='Level1'
    Type='SecEdit'
    SectionName='System Access'
    Key='LockoutDuration'
    Operator='GreaterOrEqual'
    Expected=15
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='1.2.1'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2016 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2016 Benchmark documentation for detailed remediation steps.'
  },
  @{ 
    Id='1.2.2'
    Title='(L1) Ensure ''Account lockout threshold'' is set to ''5 or fewer invalid logon attempt(s), but not 0'' (Automated)'
    Section='1.2 Account Lockout Policy'
    Profile='Level1'
    Type='Composite'
    AllOf=@(
        @{ Type='SecEdit'; SectionName='System Access'; Key='LockoutBadCount'; Operator='LessOrEqual'; Expected=5 },
        @{ Type='SecEdit'; SectionName='System Access'; Key='LockoutBadCount'; Operator='NotEquals'; Expected=0 }
    )
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='1.2.2'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2016 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2016 Benchmark documentation for detailed remediation steps.'
  },
  @{ 
    Id='1.2.3'
    Title='(L1) Ensure ''Allow Administrator account lockout'' is set to ''Enabled'' (MS only) (Manual)'
    Section='1.2 Account Lockout Policy'
    Profile='Level1'
    Type='Manual'
    AppliesTo='MS'
    Expected='Enabled'
    Evidence='Local Security Policy path noted in report'
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='1.2.3'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2016 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2016 Benchmark documentation for detailed remediation steps.'
  },
  @{ 
    Id='1.2.4'
    Title='(L1) Ensure ''Reset account lockout counter after'' is set to ''15 or more minute(s)'' (Automated)'
    Section='1.2 Account Lockout Policy'
    Profile='Level1'
    Type='SecEdit'
    SectionName='System Access'
    Key='ResetLockoutCount'
    Operator='GreaterOrEqual'
    Expected=15
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='1.2.4'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2016 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2016 Benchmark documentation for detailed remediation steps.'
  }
)