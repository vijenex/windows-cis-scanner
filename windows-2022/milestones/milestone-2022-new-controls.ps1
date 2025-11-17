# New Windows Server 2022 Controls (8 controls)
$Global:Rules += @(
  # 18.6.7.1 Lanman Server
  @{
    Id='18.6.7.1'
    Title='(L1) Ensure ''Mandate the minimum version of SMB'' is set to ''Enabled: 3.1.1'' (Automated)'
    Section='18.6.7 Lanman Server'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters'
    ValueName='SMBServerMinProtocol'
    Expected=0x0311
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.6.7.1'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2022 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2022 Benchmark documentation for detailed remediation steps.'
  },

  # 18.6.8.2 Lanman Workstation
  @{
    Id='18.6.8.2'
    Title='(L1) Ensure ''Require Encryption'' is set to ''Enabled'' (Automated)'
    Section='18.6.8 Lanman Workstation'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\\SYSTEM\\CurrentControlSet\\Services\\LanmanWorkstation\\Parameters'
    ValueName='RequireEncryption'
    Expected=1
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.6.8.2'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2022 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2022 Benchmark documentation for detailed remediation steps.'
  },

  # 18.9.26.1 Local Security Authority
  @{
    Id='18.9.26.1'
    Title='(L1) Ensure ''Allow Custom SSPs and APs to be loaded into LSASS'' is set to ''Disabled'' (Automated)'
    Section='18.9.26 Local Security Authority'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\System'
    ValueName='AllowCustomSSPsAPs'
    Expected=0
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.9.26.1'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2022 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2022 Benchmark documentation for detailed remediation steps.'
  },

  # 18.9.39.1 Security Account Manager
  @{
    Id='18.9.39.1'
    Title='(L1) Ensure ''Configure validation of ROCA-vulnerable WHfB keys during authentication'' is set to ''Enabled: Audit'' or higher (DC only) (Automated)'
    Section='18.9.39 Security Account Manager'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\SAM'
    ValueName='ValidateROCAVulnerableWHfBKeys'
    Operator='GreaterOrEqual'
    Expected=1
    AppliesTo='DC'
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.9.39.1'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2022 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2022 Benchmark documentation for detailed remediation steps.'
  },

  # 18.10.57.3.3.5 Remote Desktop Services - Device and Resource Redirection
  @{
    Id='18.10.57.3.3.5'
    Title='(L2) Ensure ''Do not allow LPT port redirection'' is set to ''Enabled'' (Automated)'
    Section='18.10.57 Remote Desktop Services'
    Profile='Level2'
    Type='Registry'
    Key='HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services'
    ValueName='fDisableLPT'
    Expected=1
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.10.57.3.3.5'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2022 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2022 Benchmark documentation for detailed remediation steps.'
  },

  # 18.10.57.3.3.6 Remote Desktop Services - Device and Resource Redirection
  @{
    Id='18.10.57.3.3.6'
    Title='(L2) Ensure ''Do not allow supported Plug and Play device redirection'' is set to ''Enabled'' (Automated)'
    Section='18.10.57 Remote Desktop Services'
    Profile='Level2'
    Type='Registry'
    Key='HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services'
    ValueName='fDisablePNPRedir'
    Expected=1
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.10.57.3.3.6'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2022 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2022 Benchmark documentation for detailed remediation steps.'
  },

  # 18.10.57.3.3.7 Remote Desktop Services - Device and Resource Redirection
  @{
    Id='18.10.57.3.3.7'
    Title='(L2) Ensure ''Do not allow WebAuthn redirection'' is set to ''Enabled'' (Automated)'
    Section='18.10.57 Remote Desktop Services'
    Profile='Level2'
    Type='Registry'
    Key='HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services'
    ValueName='fDisableWebAuthn'
    Expected=1
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.10.57.3.3.7'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2022 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2022 Benchmark documentation for detailed remediation steps.'
  },

  # 18.10.82.2 Windows Logon Options
  @{
    Id='18.10.82.2'
    Title='(L1) Ensure ''Sign-in and lock last interactive user automatically after a restart'' is set to ''Disabled'' (Automated)'
    Section='18.10.82 Windows Logon Options'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System'
    ValueName='DisableAutomaticRestartSignOn'
    Expected=1
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.10.82.2'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2022 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2022 Benchmark documentation for detailed remediation steps.'
  }
)
