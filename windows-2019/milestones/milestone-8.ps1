# 18.7-18.9 Printers, Start Menu, System Controls (Windows Server 2019)
$Global:Rules += @(
  # 18.7 Printers
  @{
    Id='18.7.1'
    Title='(L1) Ensure ''Allow Print Spooler to accept client connections'' is set to ''Disabled'' (Automated)'
    Section='18.7 Printers'
    Profile='Level1'
    Type='Registry'
    Key='HKLM:\Software\Policies\Microsoft\Windows NT\Printers'
    ValueName='RegisterSpoolerRemoteRpcEndPoint'
    Expected=2
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.7.1'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='18.7.2'
    Title='(L1) Ensure ''Configure Redirection Guard'' is set to ''Enabled: Redirection Guard Enabled'' (Automated)'
    Section='18.7 Printers'
    Profile='Level1'
    Type='Registry'
    Key='HKLM:\Software\Policies\Microsoft\Windows NT\Printers'
    ValueName='RedirectionguardPolicy'
    Expected=1
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.7.2'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='18.7.3'
    Title='(L1) Ensure ''Configure RPC connection settings: Protocol to use for outgoing RPC connections'' is set to ''Enabled: RPC over TCP'' (Automated)'
    Section='18.7 Printers'
    Profile='Level1'
    Type='Registry'
    Key='HKLM:\Software\Policies\Microsoft\Windows NT\Printers\RPC'
    ValueName='RpcProtocols'
    Expected=5
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.7.3'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='18.7.4'
    Title='(L1) Ensure ''Configure RPC connection settings: Use authentication for outgoing RPC connections'' is set to ''Enabled: Default'' (Automated)'
    Section='18.7 Printers'
    Profile='Level1'
    Type='Registry'
    Key='HKLM:\Software\Policies\Microsoft\Windows NT\Printers\RPC'
    ValueName='RpcAuthentication'
    Expected=0
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.7.4'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='18.7.9'
    Title='(L1) Ensure ''Limits print driver installation to Administrators'' is set to ''Enabled'' (Automated)'
    Section='18.7 Printers'
    Profile='Level1'
    Type='Registry'
    Key='HKLM:\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint'
    ValueName='RestrictDriverInstallationToAdministrators'
    Expected=1
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.7.9'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },

  # 18.9.3 Audit Process Creation
  @{
    Id='18.9.3.1'
    Title='(L1) Ensure ''Include command line in process creation events'' is set to ''Enabled'' (Automated)'
    Section='18.9.3 Audit Process Creation'
    Profile='Level1'
    Type='Registry'
    Key='HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit'
    ValueName='ProcessCreationIncludeCmdLine_Enabled'
    Expected=1
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.9.3.1'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },

  # 18.9.4 Credentials Delegation
  @{
    Id='18.9.4.1'
    Title='(L1) Ensure ''Encryption Oracle Remediation'' is set to ''Enabled: Force Updated Clients'' (Automated)'
    Section='18.9.4 Credentials Delegation'
    Profile='Level1'
    Type='Registry'
    Key='HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\CredSSP\Parameters'
    ValueName='AllowEncryptionOracle'
    Expected=0
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.9.4.1'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='18.9.4.2'
    Title='(L1) Ensure ''Remote host allows delegation of non-exportable credentials'' is set to ''Enabled'' (Automated)'
    Section='18.9.4 Credentials Delegation'
    Profile='Level1'
    Type='Registry'
    Key='HKLM:\Software\Policies\Microsoft\Windows\CredentialsDelegation'
    ValueName='AllowProtectedCreds'
    Expected=1
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.9.4.2'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },

  # 18.9.7.2 Device Installation
  @{
    Id='18.9.7.2'
    Title='(L1) Ensure ''Prevent device metadata retrieval from the Internet'' is set to ''Enabled'' (Automated)'
    Section='18.9.7 Device Installation'
    Profile='Level1'
    Type='Registry'
    Key='HKLM:\Software\Policies\Microsoft\Windows\Device Metadata'
    ValueName='PreventDeviceMetadataFromNetwork'
    Expected=1
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.9.7.2'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },

  # 18.9.13 Early Launch Antimalware
  @{
    Id='18.9.13.1'
    Title='(L1) Ensure ''Boot-Start Driver Initialization Policy'' is set to ''Enabled: Good, unknown and bad but critical'' (Automated)'
    Section='18.9.13 Early Launch Antimalware'
    Profile='Level1'
    Type='Registry'
    Key='HKLM:\System\CurrentControlSet\Policies\EarlyLaunch'
    ValueName='DriverLoadPolicy'
    Expected=3
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.9.13.1'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },

  # 18.9.19 Group Policy
  @{
    Id='18.9.19.2'
    Title='(L1) Ensure ''Configure registry policy processing: Do not apply during periodic background processing'' is set to ''Enabled: FALSE'' (Automated)'
    Section='18.9.19 Group Policy'
    Profile='Level1'
    Type='Registry'
    Key='HKLM:\Software\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}'
    ValueName='NoBackgroundPolicy'
    Expected=0
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.9.19.2'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='18.9.19.3'
    Title='(L1) Ensure ''Configure registry policy processing: Process even if the Group Policy objects have not changed'' is set to ''Enabled: TRUE'' (Automated)'
    Section='18.9.19 Group Policy'
    Profile='Level1'
    Type='Registry'
    Key='HKLM:\Software\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}'
    ValueName='NoGPOListChanges'
    Expected=0
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.9.19.3'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='18.9.19.6'
    Title='(L1) Ensure ''Continue experiences on this device'' is set to ''Disabled'' (Automated)'
    Section='18.9.19 Group Policy'
    Profile='Level1'
    Type='Registry'
    Key='HKLM:\Software\Policies\Microsoft\Windows\System'
    ValueName='EnableCdp'
    Expected=0
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.9.19.6'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='18.9.19.7'
    Title='(L1) Ensure ''Turn off background refresh of Group Policy'' is set to ''Disabled'' (Automated)'
    Section='18.9.19 Group Policy'
    Profile='Level1'
    Type='Registry'
    Key='HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System'
    ValueName='DisableBkGndGroupPolicy'
    Expected=0
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.9.19.7'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  }
)