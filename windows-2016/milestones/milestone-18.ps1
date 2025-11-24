# 18 Administrative Templates (Computer) (Windows Server 2016) — Audit-only
$Global:Rules += @(
  # 18.1 Control Panel
  # 18.1.1 Personalization
  # EXCLUDED: 18.1.1.1 - Lock screen camera not applicable to Windows Server 2016
  # EXCLUDED: 18.1.1.2 - Lock screen slide show not applicable to Windows Server 2016

  # 18.1.2 Regional and Language Options
  # EXCLUDED: 18.1.2.2 - Speech recognition not applicable to Windows Server 2016
  # EXCLUDED: 18.1.3 - Online Tips not applicable to Windows Server 2016

  # 18.4 MS Security Guide
  # EXCLUDED: 18.4.1-8 - MS Security Guide controls not applicable to Windows Server 2016

  # 18.5 MSS (Legacy)
  # EXCLUDED: 18.5.1-11 - MSS Legacy controls not applicable to Windows Server 2016
  @{
    Id='18.5.12'
    Title='(L1) Ensure ''MSS: (WarningLevel) Percentage threshold for the security event log at which the system will generate a warning'' is set to ''Enabled: 90% or less'' (Automated)'
    Section='18.5 MSS (Legacy)'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SYSTEM\CurrentControlSet\Services\Eventlog\Security'
    ValueName='WarningLevel'
    Operator='LessOrEqual'
    Expected=90
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.5.12'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2016 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2016 Benchmark documentation for detailed remediation steps.'
  },

  # 18.6 Network
  # 18.6.4 DNS Client
  # EXCLUDED: 18.6.4.1-4 - DNS Client policies not applicable to Windows Server 2016

  # 18.6.5 Fonts
  # EXCLUDED: 18.6.5.1 - Font Providers not applicable to Windows Server 2016

  # 18.6.8 Lanman Workstation
  # EXCLUDED: 18.6.8.1 - Lanman Workstation not applicable to Windows Server 2016

  # 18.6.9 Link-Layer Topology Discovery
  # EXCLUDED: 18.6.9.1-2 - Link-Layer Topology Discovery not applicable to Windows Server 2016

  # 18.6.10 Microsoft Peer-to-Peer Networking Services
  # EXCLUDED: 18.6.10.2 - Peer-to-Peer Networking not applicable to Windows Server 2016

  # 18.6.11 Network Connections
  # EXCLUDED: 18.6.11.2-4 - Network Connections policies not applicable to Windows Server 2016

  # 18.6.14 Network Provider
  # EXCLUDED: 18.6.14.1 - Hardened UNC Paths not applicable to Windows Server 2016

  # 18.6.19 TCPIP Settings
  # EXCLUDED: 18.6.19.2.1 - IPv6 disable not applicable to Windows Server 2016

  # 18.6.20 Windows Connect Now
  # EXCLUDED: 18.6.20.1-2 - Windows Connect Now not applicable to Windows Server 2016

  # 18.6.21 Windows Connection Manager
  # EXCLUDED: 18.6.21.1-2 - Windows Connection Manager not applicable to Windows Server 2016

  # 18.7 Printers
  # EXCLUDED: 18.7.1-12 - Printer policies not applicable to Windows Server 2016

  # 18.8 Start Menu and Taskbar
  # 18.8.1 Notifications
  # EXCLUDED: 18.8.1.1 - Notifications not applicable to Windows Server 2016

  # 18.9 System
  # 18.9.3 Audit Process Creation
  # EXCLUDED: 18.9.3.1 - Not applicable to Windows Server 2016

  # 18.9.4 Credentials Delegation
  # EXCLUDED: 18.9.4.1-2 - Credentials Delegation not applicable to Windows Server 2016

  # 18.9.5 Device Guard
  # EXCLUDED: 18.9.5.1-7 - Device Guard not applicable to Windows Server 2016

  # 18.9.7 Device Installation
  @{
    Id='18.9.7.2'
    Title='(NG) Ensure ''Turn On Virtualization Based Security'' is set to ''Enabled'' (Automated)'
    Section='18.9.5 Device Guard'
    Profile='NextGeneration'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard'
    ValueName='EnableVirtualizationBasedSecurity'
    Expected=1
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.9.5.1'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2016 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2016 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='18.9.5.2'
    Title='(NG) Ensure ''Turn On Virtualization Based Security: Select Platform Security Level'' is set to ''Secure Boot'' or higher (Automated)'
    Section='18.9.5 Device Guard'
    Profile='NextGeneration'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard'
    ValueName='RequirePlatformSecurityFeatures'
    Operator='GreaterOrEqual'
    Expected=1
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.9.5.2'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2016 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2016 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='18.9.5.3'
    Title='(NG) Ensure ''Turn On Virtualization Based Security: Virtualization Based Protection of Code Integrity'' is set to ''Enabled with UEFI lock'' (Automated)'
    Section='18.9.5 Device Guard'
    Profile='NextGeneration'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard'
    ValueName='HypervisorEnforcedCodeIntegrity'
    Expected=1
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.9.5.3'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2016 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2016 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='18.9.5.4'
    Title='(NG) Ensure ''Turn On Virtualization Based Security: Require UEFI Memory Attributes Table'' is set to ''True (checked)'' (Automated)'
    Section='18.9.5 Device Guard'
    Profile='NextGeneration'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard'
    ValueName='HVCIMATRequired'
    Expected=1
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.9.5.4'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2016 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2016 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='18.9.5.5'
    Title='(NG) Ensure ''Turn On Virtualization Based Security: Credential Guard Configuration'' is set to ''Enabled with UEFI lock'' (MS Only) (Automated)'
    Section='18.9.5 Device Guard'
    Profile='NextGeneration'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard'
    ValueName='LsaCfgFlags'
    Expected=1
    AppliesTo='MS'
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.9.5.5'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2016 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2016 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='18.9.5.6'
    Title='(NG) Ensure ''Turn On Virtualization Based Security: Credential Guard Configuration'' is set to ''Disabled'' (DC Only) (Automated)'
    Section='18.9.5 Device Guard'
    Profile='NextGeneration'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard'
    ValueName='LsaCfgFlags'
    Expected=0
    AppliesTo='DC'
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.9.5.6'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2016 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2016 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='18.9.5.7'
    Title='(NG) Ensure ''Turn On Virtualization Based Security: Secure Launch Configuration'' is set to ''Enabled'' (Automated)'
    Section='18.9.5 Device Guard'
    Profile='NextGeneration'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard'
    ValueName='ConfigureSystemGuardLaunch'
    Expected=1
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'

  # EXCLUDED: 18.9.7.2 - Device metadata not applicable to Windows Server 2016

  # 18.9.13 Early Launch Antimalware
  # EXCLUDED: 18.9.13.1 - Early Launch Antimalware not applicable to Windows Server 2016

  # 18.9.19 Group Policy
  @{
    Id='18.9.19.2'
    Title='(L1) Ensure ''Configure registry policy processing: Do not apply during periodic background processing'' is set to ''Enabled: FALSE'' (Automated)'
    Section='18.9.19 Group Policy'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}'
    ValueName='NoBackgroundPolicy'
    Expected=0
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.9.19.2'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2016 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2016 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='18.9.19.3'
    Title='(L1) Ensure ''Configure registry policy processing: Process even if the Group Policy objects have not changed'' is set to ''Enabled: TRUE'' (Automated)'
    Section='18.9.19 Group Policy'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}'
    ValueName='NoGPOListChanges'
    Expected=0
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.9.19.3'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2016 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2016 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='18.9.19.4'
    Title='(L1) Ensure ''Configure security policy processing: Do not apply during periodic background processing'' is set to ''Enabled: FALSE'' (Automated)'
    Section='18.9.19 Group Policy'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{827D319E-6EAC-11D2-A4EA-00C04F79F83A}'
    ValueName='NoBackgroundPolicy'
    Expected=0
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.9.19.4'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2016 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2016 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='18.9.19.5'
    Title='(L1) Ensure ''Configure security policy processing: Process even if the Group Policy objects have not changed'' is set to ''Enabled: TRUE'' (Automated)'
    Section='18.9.19 Group Policy'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{827D319E-6EAC-11D2-A4EA-00C04F79F83A}'
    ValueName='NoGPOListChanges'
    Expected=0
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.9.19.5'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2016 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2016 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='18.9.19.6'
    Title='(L1) Ensure ''Continue experiences on this device'' is set to ''Disabled'' (Automated)'
    Section='18.9.19 Group Policy'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Windows\System'
    ValueName='EnableCdp'
    Expected=0
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.9.19.6'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2016 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2016 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='18.9.19.7'
    Title='(L1) Ensure ''Turn off background refresh of Group Policy'' is set to ''Disabled'' (Automated)'
    Section='18.9.19 Group Policy'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
    ValueName='DisableBkGndGroupPolicy'
    Expected=0
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.9.19.7'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2016 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2016 Benchmark documentation for detailed remediation steps.'
  },

  # 18.9.20 Internet Communication Management
  @{
    Id='18.9.20.1.1'
    Title='(L1) Ensure ''Turn off downloading of print drivers over HTTP'' is set to ''Enabled'' (Automated)'
    Section='18.9.20 Internet Communication Management'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers'
    ValueName='DisableWebPnPDownload'
    Expected=1
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.9.20.1.1'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2016 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2016 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='18.9.20.1.2'
    Title='(L2) Ensure ''Turn off handwriting personalization data sharing'' is set to ''Enabled'' (Automated)'
    Section='18.9.20 Internet Communication Management'
    Profile='Level2'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Windows\TabletPC'
    ValueName='PreventHandwritingDataSharing'
    Expected=1
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.9.20.1.2'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2016 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2016 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='18.9.20.1.3'
    Title='(L2) Ensure ''Turn off handwriting recognition error reporting'' is set to ''Enabled'' (Automated)'
    Section='18.9.20 Internet Communication Management'
    Profile='Level2'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports'
    ValueName='PreventHandwritingErrorReports'
    Expected=1
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.9.20.1.3'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2016 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2016 Benchmark documentation for detailed remediation steps.'
  },
  # EXCLUDED: 18.9.20.1.4 - Internet Connection Wizard not applicable to Windows Server 2016
  @{
    Id='18.9.20.1.5'
    Title='(L1) Ensure ''Turn off Internet download for Web publishing and online ordering wizards'' is set to ''Enabled'' (Automated)'
    Section='18.9.20 Internet Communication Management'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'
    ValueName='NoWebServices'
    Expected=1
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.9.20.1.5'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2016 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2016 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='18.9.20.1.6'
    Title='(L2) Ensure ''Turn off printing over HTTP'' is set to ''Enabled'' (Automated)'
    Section='18.9.20 Internet Communication Management'
    Profile='Level2'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers'
    ValueName='DisableHTTPPrinting'
    Expected=1
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.9.20.1.6'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2016 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2016 Benchmark documentation for detailed remediation steps.'
  },
  # EXCLUDED: 18.9.20.1.7 - Registration Wizard not applicable to Windows Server 2016
  # EXCLUDED: 18.9.20.1.8 - Search Companion not applicable to Windows Server 2016
  @{
    Id='18.9.20.1.9'
    Title='(L2) Ensure ''Turn off the "Order Prints" picture task'' is set to ''Enabled'' (Automated)'
    Section='18.9.20 Internet Communication Management'
    Profile='Level2'
    Type='Registry'
    Key='HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'
    ValueName='NoOnlinePrintsWizard'
    Expected=1
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.9.20.1.9'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2016 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2016 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='18.9.20.1.10'
    Title='(L2) Ensure ''Turn off the "Publish to Web" task for files and folders'' is set to ''Enabled'' (Automated)'
    Section='18.9.20 Internet Communication Management'
    Profile='Level2'
    Type='Registry'
    Key='HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'
    ValueName='NoPublishingWizard'
    Expected=1
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.9.20.1.10'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2016 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2016 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='18.9.20.1.11'
    Title='(L2) Ensure ''Turn off the Windows Messenger Customer Experience Improvement Program'' is set to ''Enabled'' (Automated)'
    Section='18.9.20 Internet Communication Management'
    Profile='Level2'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Messenger\Client'
    ValueName='CEIP'
    Expected=2
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.9.20.1.11'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2016 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2016 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='18.9.20.1.12'
    Title='(L2) Ensure ''Turn off Windows Customer Experience Improvement Program'' is set to ''Enabled'' (Automated)'
    Section='18.9.20 Internet Communication Management'
    Profile='Level2'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\SQMClient\Windows'
    ValueName='CEIPEnable'
    Expected=0
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.9.20.1.12'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2016 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2016 Benchmark documentation for detailed remediation steps.'
  },
  # EXCLUDED: 18.9.20.1.13 - Windows Error Reporting not applicable to Windows Server 2016

  # 18.9.23 Kerberos
  @{
    Id='18.9.23.1'
    Title='(L2) Ensure ''Support device authentication using certificate'' is set to ''Enabled: Automatic'' (Automated)'
    Section='18.9.23 Kerberos'
    Profile='Level2'
    Type='Registry'
    Key='HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\kerberos\parameters'
    ValueName='DevicePKInitBehavior'
    Expected=0
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.9.23.1'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2016 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2016 Benchmark documentation for detailed remediation steps.'
  },

  # 18.9.24 Kernel DMA Protection
  # EXCLUDED: 18.9.24.1 - Kernel DMA Protection not available on Windows Server 2016

  # 18.9.25 LAPS
  # EXCLUDED: 18.9.25.1-8 - These LAPS settings not available on Windows Server 2016

  # 18.9.27 Locale Services
  @{
    Id='18.9.27.1'
    Title='(L2) Ensure ''Disallow copying of user input methods to the system account for sign-in'' is set to ''Enabled'' (Automated)'
    Section='18.9.27 Locale Services'
    Profile='Level2'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Control Panel\International'
    ValueName='BlockUserInputMethodsForSignIn'
    Expected=1
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.9.27.1'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2016 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2016 Benchmark documentation for detailed remediation steps.'
  },

  # 18.9.28 Logon
  @{
    Id='18.9.28.1'
    Title='(L1) Ensure ''Block user from showing account details on sign-in'' is set to ''Enabled'' (Automated)'
    Section='18.9.28 Logon'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Windows\System'
    ValueName='BlockUserFromShowingAccountDetailsOnSignin'
    Expected=1
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.9.28.1'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2016 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2016 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='18.9.28.2'
    Title='(L1) Ensure ''Do not display network selection UI'' is set to ''Enabled'' (Automated)'
    Section='18.9.28 Logon'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Windows\System'
    ValueName='DontDisplayNetworkSelectionUI'
    Expected=1
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.9.28.2'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2016 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2016 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='18.9.28.3'
    Title='(L1) Ensure ''Do not enumerate connected users on domain-joined computers'' is set to ''Enabled'' (Automated)'
    Section='18.9.28 Logon'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Windows\System'
    ValueName='DontEnumerateConnectedUsers'
    Expected=1
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.9.28.3'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2016 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2016 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='18.9.28.4'
    Title='(L1) Ensure ''Enumerate local users on domain-joined computers'' is set to ''Disabled'' (MS only) (Automated)'
    Section='18.9.28 Logon'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Windows\System'
    ValueName='EnumerateLocalUsers'
    Expected=0
    AppliesTo='MS'
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.9.28.4'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2016 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2016 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='18.9.28.5'
    Title='(L1) Ensure ''Turn off app notifications on the lock screen'' is set to ''Enabled'' (Automated)'
    Section='18.9.28 Logon'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Windows\System'
    ValueName='DisableLockScreenAppNotifications'
    Expected=1
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.9.28.5'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2016 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2016 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='18.9.28.6'
    Title='(L1) Ensure ''Turn off picture password sign-in'' is set to ''Enabled'' (Automated)'
    Section='18.9.28 Logon'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Windows\System'
    ValueName='BlockDomainPicturePassword'
    Expected=1
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.9.28.6'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2016 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2016 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='18.9.28.7'
    Title='(L1) Ensure ''Turn on convenience PIN sign-in'' is set to ''Disabled'' (Automated)'
    Section='18.9.28 Logon'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Windows\System'
    ValueName='AllowDomainPINLogon'
    Expected=0
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.9.28.7'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2016 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2016 Benchmark documentation for detailed remediation steps.'
  },

  # 18.9.31 OS Policies
  # EXCLUDED: 18.9.31.1 - Clipboard sync not applicable to Windows Server 2016
  # EXCLUDED: 18.9.31.2 - User Activities upload not applicable to Windows Server 2016

  # 18.9.33 Power Management
  @{
    Id='18.9.33.6.1'
    Title='(L2) Ensure ''Allow network connectivity during connected-standby (on battery)'' is set to ''Disabled'' (Automated)'
    Section='18.9.33 Power Management'
    Profile='Level2'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Power\PowerSettings\f15576e8-98b7-4186-b944-eafa664402d9'
    ValueName='DCSettingIndex'
    Expected=0
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.9.33.6.1'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2016 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2016 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='18.9.33.6.2'
    Title='(L2) Ensure ''Allow network connectivity during connected-standby (plugged in)'' is set to ''Disabled'' (Automated)'
    Section='18.9.33 Power Management'
    Profile='Level2'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Power\PowerSettings\f15576e8-98b7-4186-b944-eafa664402d9'
    ValueName='ACSettingIndex'
    Expected=0
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.9.33.6.2'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2016 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2016 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='18.9.33.6.3'
    Title='(L1) Ensure ''Require a password when a computer wakes (on battery)'' is set to ''Enabled'' (Automated)'
    Section='18.9.33 Power Management'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51'
    ValueName='DCSettingIndex'
    Expected=1
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.9.33.6.3'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2016 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2016 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='18.9.33.6.4'
    Title='(L1) Ensure ''Require a password when a computer wakes (plugged in)'' is set to ''Enabled'' (Automated)'
    Section='18.9.33 Power Management'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51'
    ValueName='ACSettingIndex'
    Expected=1
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.9.33.6.4'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2016 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2016 Benchmark documentation for detailed remediation steps.'
  },

  # 18.9.35 Remote Assistance
  @{
    Id='18.9.35.1'
    Title='(L1) Ensure ''Configure Offer Remote Assistance'' is set to ''Disabled'' (Automated)'
    Section='18.9.35 Remote Assistance'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
    ValueName='fAllowUnsolicited'
    Expected=0
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.9.35.1'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2016 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2016 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='18.9.35.2'
    Title='(L1) Ensure ''Configure Solicited Remote Assistance'' is set to ''Disabled'' (Automated)'
    Section='18.9.35 Remote Assistance'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
    ValueName='fAllowToGetHelp'
    Expected=0
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.9.35.2'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2016 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2016 Benchmark documentation for detailed remediation steps.'
  },

  # 18.9.36 Remote Procedure Call
  @{
    Id='18.9.36.1'
    Title='(L1) Ensure ''Enable RPC Endpoint Mapper Client Authentication'' is set to ''Enabled'' (MS only) (Automated)'
    Section='18.9.36 Remote Procedure Call'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Rpc'
    ValueName='EnableAuthEpResolution'
    Expected=1
    AppliesTo='MS'
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.9.36.1'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2016 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2016 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='18.9.36.2'
    Title='(L2) Ensure ''Restrict Unauthenticated RPC clients'' is set to ''Enabled: Authenticated'' (MS only) (Automated)'
    Section='18.9.36 Remote Procedure Call'
    Profile='Level2'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Rpc'
    ValueName='RestrictRemoteClients'
    Expected=1
    AppliesTo='MS'
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.9.36.2'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2016 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2016 Benchmark documentation for detailed remediation steps.'
  },

  # 18.9.47.5.1 Microsoft Support Diagnostic Tool
  @{
    Id='18.9.47.5.1'
    Title='(L2) Ensure ''Microsoft Support Diagnostic Tool: Turn on MSDT interactive communication with support provider'' is set to ''Disabled'' (Automated)'
    Section='18.9.47 Troubleshooting and Diagnostics'
    Profile='Level2'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Windows\ScriptedDiagnosticsProvider\Policy'
    ValueName='DisableQueryRemoteServer'
    Expected=0
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.9.47.5.1'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2016 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2016 Benchmark documentation for detailed remediation steps.'
  },

  # 18.9.47.11.1 Windows Performance PerfTrack
  @{
    Id='18.9.47.11.1'
    Title='(L2) Ensure ''Enable/Disable PerfTrack'' is set to ''Disabled'' (Automated)'
    Section='18.9.47 Troubleshooting and Diagnostics'
    Profile='Level2'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Windows\WDI\{9c5a40da-b965-4fc3-8781-88dd50a6299d}'
    ValueName='ScenarioExecutionEnabled'
    Expected=0
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.9.47.11.1'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2016 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2016 Benchmark documentation for detailed remediation steps.'
  },

  # 18.9.49.1 User Profiles
  @{
    Id='18.9.49.1'
    Title='(L2) Ensure ''Turn off the advertising ID'' is set to ''Enabled'' (Automated)'
    Section='18.9.49 User Profiles'
    Profile='Level2'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo'
    ValueName='DisabledByGroupPolicy'
    Expected=1
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.9.49.1'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2016 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2016 Benchmark documentation for detailed remediation steps.'
  },

  # 18.9.51.1 Windows Time Service - Time Providers
  @{
    Id='18.9.51.1.1'
    Title='(L1) Ensure ''Enable Windows NTP Client'' is set to ''Enabled'' (Automated)'
    Section='18.9.51 Windows Time Service'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\W32Time\TimeProviders\NtpClient'
    ValueName='Enabled'
    Expected=1
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.9.51.1.1'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2016 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2016 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='18.9.51.1.2'
    Title='(L1) Ensure ''Enable Windows NTP Server'' is set to ''Disabled'' (MS only) (Automated)'
    Section='18.9.51 Windows Time Service'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\W32Time\TimeProviders\NtpServer'
    ValueName='Enabled'
    Expected=0
    AppliesTo='MS'
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.9.51.1.2'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2016 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2016 Benchmark documentation for detailed remediation steps.'
  },

  # 18.10 Windows Components
  # 18.10.4.1 App Package Deployment
  @{
    Id='18.10.4.1'
    Title='(L2) Ensure ''Allow a Windows app to share application data between users'' is set to ''Disabled'' (Automated)'
    Section='18.10 Windows Components'
    Profile='Level2'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\AppModel\StateManager'
    ValueName='AllowSharedLocalAppData'
    Expected=0
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.10.4.1'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2016 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2016 Benchmark documentation for detailed remediation steps.'
  },

  # 18.10.6.1 App runtime
  @{
    Id='18.10.6.1'
    Title='(L1) Ensure ''Allow Microsoft accounts to be optional'' is set to ''Enabled'' (Automated)'
    Section='18.10 Windows Components'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
    ValueName='MSAOptional'
    Expected=1
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.10.6.1'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2016 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2016 Benchmark documentation for detailed remediation steps.'
  },

  # 18.10.8 AutoPlay Policies
  @{
    Id='18.10.8.1'
    Title='(L1) Ensure ''Disallow Autoplay for non-volume devices'' is set to ''Enabled'' (Automated)'
    Section='18.10.8 AutoPlay Policies'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer'
    ValueName='NoAutoplayfornonVolume'
    Expected=1
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.10.8.1'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2016 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2016 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='18.10.8.2'
    Title='(L1) Ensure ''Set the default behavior for AutoRun'' is set to ''Enabled: Do not execute any autorun commands'' (Automated)'
    Section='18.10.8 AutoPlay Policies'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'
    ValueName='NoAutorun'
    Expected=1
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.10.8.2'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2016 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2016 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='18.10.8.3'
    Title='(L1) Ensure ''Turn off Autoplay'' is set to ''Enabled: All drives'' (Automated)'
    Section='18.10.8 AutoPlay Policies'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'
    ValueName='NoDriveTypeAutoRun'
    Expected=255
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.10.8.3'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2016 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2016 Benchmark documentation for detailed remediation steps.'
  },

  # 18.10.9.1 Biometrics - Facial Features
  @{
    Id='18.10.9.1.1'
    Title='(L1) Ensure ''Configure enhanced anti-spoofing'' is set to ''Enabled'' (Automated)'
    Section='18.10.9 Biometrics'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Biometrics\FacialFeatures'
    ValueName='EnhancedAntiSpoofing'
    Expected=1
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.10.9.1.1'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2016 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2016 Benchmark documentation for detailed remediation steps.'
  },

  # 18.10.11 Camera
  @{
    Id='18.10.11.1'
    Title='(L2) Ensure ''Allow Use of Camera'' is set to ''Disabled'' (Automated)'
    Section='18.10.11 Camera'
    Profile='Level2'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Camera'
    ValueName='AllowCamera'
    Expected=0
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.10.11.1'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2016 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2016 Benchmark documentation for detailed remediation steps.'
  },

  # 18.10.13 Cloud Content
  # EXCLUDED: 18.10.13.1 - Setting not visible on Windows Server 2016
  @{
    Id='18.10.13.2'
    Title='(L1) Ensure ''Turn off Microsoft consumer experiences'' is set to ''Enabled'' (Automated)'
    Section='18.10.13 Cloud Content'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent'
    ValueName='DisableWindowsConsumerFeatures'
    Expected=1
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.10.13.2'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2016 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2016 Benchmark documentation for detailed remediation steps.'
  },

  # 18.10.14 Connect
  @{
    Id='18.10.14.1'
    Title='(L1) Ensure ''Require pin for pairing'' is set to ''Enabled: First Time'' OR ''Enabled: Always'' (Automated)'
    Section='18.10.14 Connect'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Windows\Connect'
    ValueName='RequirePinForPairing'
    Operator='GreaterOrEqual'
    Expected=1
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.10.14.1'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2016 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2016 Benchmark documentation for detailed remediation steps.'
  },

  # 18.10.15 Credential User Interface
  @{
    Id='18.10.15.1'
    Title='(L1) Ensure ''Do not display the password reveal button'' is set to ''Enabled'' (Automated)'
    Section='18.10.15 Credential User Interface'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Windows\CredUI'
    ValueName='DisablePasswordReveal'
    Expected=1
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.10.15.1'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2016 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2016 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='18.10.15.2'
    Title='(L1) Ensure ''Enumerate administrator accounts on elevation'' is set to ''Disabled'' (Automated)'
    Section='18.10.15 Credential User Interface'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Windows\CredUI'
    ValueName='EnumerateAdministrators'
    Expected=0
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.10.15.2'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2016 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2016 Benchmark documentation for detailed remediation steps.'
  },

  # 18.10.16 Data Collection and Preview Builds
  @{
    Id='18.10.16.1'
    Title='(L1) Ensure ''Allow Diagnostic Data'' is set to ''Enabled: Diagnostic data off (not recommended)'' or ''Enabled: Send required diagnostic data'' (Automated)'
    Section='18.10.16 Data Collection and Preview Builds'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection'
    ValueName='AllowTelemetry'
    Operator='LessOrEqual'
    Expected=1
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.10.16.1'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2016 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2016 Benchmark documentation for detailed remediation steps.'
  },
  # EXCLUDED: 18.10.16.2 - Not applicable to Windows Server 2016
  # EXCLUDED: 18.10.16.3 - OneSettings not available on Windows Server 2016
  @{
    Id='18.10.16.4'
    Title='(L1) Ensure ''Do not show feedback notifications'' is set to ''Enabled'' (Automated)'
    Section='18.10.16 Data Collection and Preview Builds'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection'
    ValueName='DoNotShowFeedbackNotifications'
    Expected=1
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.10.16.4'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2016 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2016 Benchmark documentation for detailed remediation steps.'
  },
  # EXCLUDED: 18.10.16.5 - OneSettings not available on Windows Server 2016
  # EXCLUDED: 18.10.16.6 - Not applicable to Windows Server 2016
  # EXCLUDED: 18.10.16.7 - Not applicable to Windows Server 2016

  # 18.10.18 Desktop App Installer
  # EXCLUDED: All 18.10.18.x controls (18.10.18.1-7) - Desktop App Installer/winget not available on Windows Server 2016

  # 18.10.26 Event Log Service
  # 18.10.26.1 Application
  @{
    Id='18.10.26.1.1'
    Title='(L1) Ensure ''Application: Control Event Log behavior when the log file reaches its maximum size'' is set to ''Disabled'' (Automated)'
    Section='18.10.26 Event Log Service'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application'
    ValueName='Retention'
    Expected='0'
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.10.26.1.1'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2016 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2016 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='18.10.26.1.2'
    Title='(L1) Ensure ''Application: Specify the maximum log file size (KB)'' is set to ''Enabled: 32,768 or greater'' (Automated)'
    Section='18.10.26 Event Log Service'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application'
    ValueName='MaxSize'
    Operator='GreaterOrEqual'
    Expected=32768
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.10.26.1.2'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2016 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2016 Benchmark documentation for detailed remediation steps.'
  },
  # 18.10.26.2 Security
  @{
    Id='18.10.26.2.1'
    Title='(L1) Ensure ''Security: Control Event Log behavior when the log file reaches its maximum size'' is set to ''Disabled'' (Automated)'
    Section='18.10.26 Event Log Service'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security'
    ValueName='Retention'
    Expected='0'
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.10.26.2.1'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2016 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2016 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='18.10.26.2.2'
    Title='(L1) Ensure ''Security: Specify the maximum log file size (KB)'' is set to ''Enabled: 196,608 or greater'' (Automated)'
    Section='18.10.26 Event Log Service'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security'
    ValueName='MaxSize'
    Operator='GreaterOrEqual'
    Expected=196608
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.10.26.2.2'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2016 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2016 Benchmark documentation for detailed remediation steps.'
  },
  # 18.10.26.3 Setup
  @{
    Id='18.10.26.3.1'
    Title='(L1) Ensure ''Setup: Control Event Log behavior when the log file reaches its maximum size'' is set to ''Disabled'' (Automated)'
    Section='18.10.26 Event Log Service'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\Setup'
    ValueName='Retention'
    Expected='0'
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.10.26.3.1'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2016 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2016 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='18.10.26.3.2'
    Title='(L1) Ensure ''Setup: Specify the maximum log file size (KB)'' is set to ''Enabled: 32,768 or greater'' (Automated)'
    Section='18.10.26 Event Log Service'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\Setup'
    ValueName='MaxSize'
    Operator='GreaterOrEqual'
    Expected=32768
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.10.26.3.2'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2016 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2016 Benchmark documentation for detailed remediation steps.'
  },
  # 18.10.26.4 System
  @{
    Id='18.10.26.4.1'
    Title='(L1) Ensure ''System: Control Event Log behavior when the log file reaches its maximum size'' is set to ''Disabled'' (Automated)'
    Section='18.10.26 Event Log Service'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\System'
    ValueName='Retention'
    Expected='0'
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.10.26.4.1'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2016 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2016 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='18.10.26.4.2'
    Title='(L1) Ensure ''System: Specify the maximum log file size (KB)'' is set to ''Enabled: 32,768 or greater'' (Automated)'
    Section='18.10.26 Event Log Service'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\System'
    ValueName='MaxSize'
    Operator='GreaterOrEqual'
    Expected=32768
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.10.26.4.2'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2016 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2016 Benchmark documentation for detailed remediation steps.'
  },

  # 18.10.29 File Explorer
  @{
    Id='18.10.29.2'
    Title='(L1) Ensure ''Do not apply the Mark of the Web tag to files copied from insecure sources'' is set to ''Disabled'' (Automated)'
    Section='18.10.29 File Explorer'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments'
    ValueName='SaveZoneInformation'
    Expected=2
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.10.29.2'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2016 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2016 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='18.10.29.3'
    Title='(L1) Ensure ''Turn off Data Execution Prevention for Explorer'' is set to ''Disabled'' (Automated)'
    Section='18.10.29 File Explorer'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer'
    ValueName='NoDataExecutionPrevention'
    Expected=0
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.10.29.3'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2016 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2016 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='18.10.29.4'
    Title='(L1) Ensure ''Turn off heap termination on corruption'' is set to ''Disabled'' (Automated)'
    Section='18.10.29 File Explorer'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer'
    ValueName='NoHeapTerminationOnCorruption'
    Expected=0
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.10.29.4'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2016 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2016 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='18.10.29.5'
    Title='(L1) Ensure ''Turn off shell protocol protected mode'' is set to ''Disabled'' (Automated)'
    Section='18.10.29 File Explorer'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'
    ValueName='PreXPSP2ShellProtocolBehavior'
    Expected=0
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.10.29.5'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2016 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2016 Benchmark documentation for detailed remediation steps.'
  },

  # 18.10.37 Location and Sensors
  @{
    Id='18.10.37.1'
    Title='(L2) Ensure ''Turn off location'' is set to ''Enabled'' (Automated)'
    Section='18.10.37 Location and Sensors'
    Profile='Level2'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors'
    ValueName='DisableLocation'
    Expected=1
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.10.37.1'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2016 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2016 Benchmark documentation for detailed remediation steps.'
  },

  # 18.10.41 Messaging
  # EXCLUDED: 18.10.41.1 - Messaging app not available on Windows Server 2016

  # 18.10.42 Microsoft account
  # EXCLUDED: 18.10.42.1 - Consumer Microsoft account settings not applicable to Windows Server 2016

  # 18.10.43 Microsoft Defender Antivirus
  # EXCLUDED: All 18.10.43.x controls - Microsoft Defender Antivirus not applicable to Windows Server 2016
  # (18.10.43.4.1, 18.10.43.5.1, 18.10.43.5.2, 18.10.43.6.1.1, 18.10.43.6.1.2, 18.10.43.6.3.1,
  #  18.10.43.7.1, 18.10.43.8.1, 18.10.43.10.1-5, 18.10.43.11.1.1.1-2, 18.10.43.11.1.2.1,
  #  18.10.43.12.1, 18.10.43.13.1-5, 18.10.43.16, 18.10.43.17)

  # Placeholder to maintain structure
  @{
    Id='__EXCLUDED_18.10.43__'
    Title='(L1) Ensure ''Enable EDR in block mode'' is set to ''Enabled'' (Automated)'
    Section='18.10.43 Microsoft Defender Antivirus'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Windows Advanced Threat Protection'
    ValueName='ForceDefenderPassiveMode'
    Expected=0
  }
    Title='(L1) Ensure ''Configure local setting override for reporting to Microsoft MAPS'' is set to ''Disabled'' (Automated)'
    Section='18.10.43 Microsoft Defender Antivirus'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet'
    ValueName='LocalSettingOverrideSpynetReporting'

    Title='(L2) Ensure ''Join Microsoft MAPS'' is set to ''Disabled'' (Automated)'
    Section='18.10.43 Microsoft Defender Antivirus'
    Profile='Level2'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet'
    ValueName='SpynetReporting'

    Title='(L1) Ensure ''Configure Attack Surface Reduction rules'' is set to ''Enabled'' (Automated)'
    Section='18.10.43 Microsoft Defender Antivirus'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR'
    ValueName='ExploitGuard_ASR_Rules'

    Title='(L1) Ensure ''Configure Attack Surface Reduction rules: Set the state for each ASR rule'' is configured (Automated)'
    Section='18.10.43 Microsoft Defender Antivirus'
    Profile='Level1'
    Type='Manual'
    Expected='ASR rules configured appropriately'
    Evidence='Check Group Policy for ASR rule configuration'
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.10.43.6.1.2'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2016 Benchmark documentation.'

    Title='(L1) Ensure ''Prevent users and apps from accessing dangerous websites'' is set to ''Enabled: Block'' (Automated)'
    Section='18.10.43 Microsoft Defender Antivirus'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Network Protection'
    ValueName='EnableNetworkProtection'

    Title='(L1) Ensure ''Enable file hash computation feature'' is set to ''Enabled'' (Automated)'
    Section='18.10.43 Microsoft Defender Antivirus'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\MpEngine'
    ValueName='EnableFileHashComputation'

    Title='(L2) Ensure ''Convert warn verdict to block'' is set to ''Enabled'' (Automated)'
    Section='18.10.43 Microsoft Defender Antivirus'
    Profile='Level2'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\NIS'
    ValueName='DisableProtocolRecognition'

    Title='(L1) Ensure ''Configure real-time protection and Security Intelligence Updates during OOBE'' is set to ''Enabled'' (Automated)'
    Section='18.10.43 Microsoft Defender Antivirus'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection'
    ValueName='RealtimeScanDirection'

    Title='(L1) Ensure ''Scan all downloaded files and attachments'' is set to ''Enabled'' (Automated)'
    Section='18.10.43 Microsoft Defender Antivirus'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection'
    ValueName='DisableIOAVProtection'

    Title='(L1) Ensure ''Turn off real-time protection'' is set to ''Disabled'' (Automated)'
    Section='18.10.43 Microsoft Defender Antivirus'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection'
    ValueName='DisableRealtimeMonitoring'

    Title='(L1) Ensure ''Turn on behavior monitoring'' is set to ''Enabled'' (Automated)'
    Section='18.10.43 Microsoft Defender Antivirus'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection'
    ValueName='DisableBehaviorMonitoring'

    Title='(L1) Ensure ''Turn on script scanning'' is set to ''Enabled'' (Automated)'
    Section='18.10.43 Microsoft Defender Antivirus'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection'
    ValueName='DisableScriptScanning'

    Title='(L2) Ensure ''Configure Brute-Force Protection aggressiveness'' is set to ''Enabled: Medium'' or higher (Automated)'
    Section='18.10.43 Microsoft Defender Antivirus'
    Profile='Level2'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\BruteForceProtection'
    ValueName='BruteForceProtectionAggressiveness'
    Operator='GreaterOrEqual'

    Title='(L1) Ensure ''Configure Remote Encryption Protection Mode'' is set to ''Enabled: Audit'' or higher (Automated)'
    Section='18.10.43 Microsoft Defender Antivirus'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\BruteForceProtection'
    ValueName='BruteForceProtectionMode'
    Operator='GreaterOrEqual'

    Title='(L2) Ensure ''Configure how aggressively Remote Encryption Protection blocks threats'' is set to ''Enabled: Medium'' or higher (Automated)'
    Section='18.10.43 Microsoft Defender Antivirus'
    Profile='Level2'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\RemoteEncryptionProtection'
    ValueName='AggressivenessLevel'
    Operator='GreaterOrEqual'

    Title='(L2) Ensure ''Configure Watson events'' is set to ''Disabled'' (Automated)'
    Section='18.10.43 Microsoft Defender Antivirus'
    Profile='Level2'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Reporting'
    ValueName='DisableGenericRePorts'

    Title='(L1) Ensure ''Scan excluded files and directories during quick scans'' is set to ''Enabled: 1'' (Automated)'
    Section='18.10.43 Microsoft Defender Antivirus'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Scan'
    ValueName='DisableArchiveScanning'

    Title='(L1) Ensure ''Scan packed executables'' is set to ''Enabled'' (Automated)'
    Section='18.10.43 Microsoft Defender Antivirus'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Scan'
    ValueName='DisablePackedExeScanning'

    Title='(L1) Ensure ''Scan removable drives'' is set to ''Enabled'' (Automated)'
    Section='18.10.43 Microsoft Defender Antivirus'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Scan'
    ValueName='DisableRemovableDriveScanning'

    Title='(L1) Ensure ''Trigger a quick scan after X days without any scans'' is set to ''Enabled: 7'' (Automated)'
    Section='18.10.43 Microsoft Defender Antivirus'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Scan'
    ValueName='ScanOnlyIfIdleEnabled'

    Title='(L1) Ensure ''Turn on e-mail scanning'' is set to ''Enabled'' (Automated)'
    Section='18.10.43 Microsoft Defender Antivirus'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Scan'
    ValueName='DisableEmailScanning'

  # EXCLUDED: 18.10.43.16 - Not applicable to Windows Server 2016
  # EXCLUDED: 18.10.43.17 - Not applicable to Windows Server 2016

  # 18.10.51 OneDrive
  @{
    Id='18.10.51.1'
    Title='(L1) Ensure ''Prevent the usage of OneDrive for file storage'' is set to ''Enabled'' (Automated)'
    Section='18.10.51 OneDrive'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Windows\OneDrive'
    ValueName='DisableFileSyncNGSC'
    Expected=1
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.10.51.1'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2016 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2016 Benchmark documentation for detailed remediation steps.'
  },

  # 18.10.56 Push To Install
  # EXCLUDED: 18.10.56.1 - Not applicable to Windows Server 2016

  # 18.10.57 Remote Desktop Services
  # 18.10.57.2.2 Remote Desktop Connection Client
  @{
    Id='18.10.57.2.2'
    Title='(L1) Ensure ''Do not allow passwords to be saved'' is set to ''Enabled'' (Automated)'
    Section='18.10.57 Remote Desktop Services'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
    ValueName='DisablePasswordSaving'
    Expected=1
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.10.57.2.2'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2016 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2016 Benchmark documentation for detailed remediation steps.'
  },
  # 18.10.57.3 Remote Desktop Session Host
  @{
    Id='18.10.57.3.2.1'
    Title='(L2) Ensure ''Restrict Remote Desktop Services users to a single Remote Desktop Services session'' is set to ''Enabled'' (Automated)'
    Section='18.10.57 Remote Desktop Services'
    Profile='Level2'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
    ValueName='fSingleSessionPerUser'
    Expected=1
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.10.57.3.2.1'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2016 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2016 Benchmark documentation for detailed remediation steps.'
  },
  # 18.10.57.3.3 Device and Resource Redirection
  @{
    Id='18.10.57.3.3.1'
    Title='(L2) Ensure ''Do not allow COM port redirection'' is set to ''Enabled'' (Automated)'
    Section='18.10.57 Remote Desktop Services'
    Profile='Level2'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
    ValueName='fDisableCcm'
    Expected=1
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.10.57.3.3.1'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2016 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2016 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='18.10.57.3.3.2'
    Title='(L1) Ensure ''Do not allow drive redirection'' is set to ''Enabled'' (Automated)'
    Section='18.10.57 Remote Desktop Services'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
    ValueName='fDisableCdm'
    Expected=1
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.10.57.3.3.2'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2016 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2016 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='18.10.57.3.3.3'
    Title='(L2) Ensure ''Do not allow LPT port redirection'' is set to ''Enabled'' (Automated)'
    Section='18.10.57 Remote Desktop Services'
    Profile='Level2'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
    ValueName='fDisableLPT'
    Expected=1
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.10.57.3.3.3'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2016 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2016 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='18.10.57.3.3.4'
    Title='(L2) Ensure ''Do not allow supported Plug and Play device redirection'' is set to ''Enabled'' (Automated)'
    Section='18.10.57 Remote Desktop Services'
    Profile='Level2'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
    ValueName='fDisablePNPRedir'
    Expected=1
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.10.57.3.3.4'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2016 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2016 Benchmark documentation for detailed remediation steps.'
  },
  # 18.10.57.3.9 Security
  @{
    Id='18.10.57.3.9.1'
    Title='(L1) Ensure ''Always prompt for password upon connection'' is set to ''Enabled'' (Automated)'
    Section='18.10.57 Remote Desktop Services'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
    ValueName='fPromptForPassword'
    Expected=1
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.10.57.3.9.1'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2016 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2016 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='18.10.57.3.9.2'
    Title='(L1) Ensure ''Require secure RPC communication'' is set to ''Enabled'' (Automated)'
    Section='18.10.57 Remote Desktop Services'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
    ValueName='fEncryptRPCTraffic'
    Expected=1
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.10.57.3.9.2'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2016 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2016 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='18.10.57.3.9.3'
    Title='(L1) Ensure ''Require use of specific security layer for remote (RDP) connections'' is set to ''Enabled: SSL'' (Automated)'
    Section='18.10.57 Remote Desktop Services'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
    ValueName='SecurityLayer'
    Expected=2
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.10.57.3.9.3'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2016 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2016 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='18.10.57.3.9.4'
    Title='(L1) Ensure ''Require user authentication for remote connections by using Network Level Authentication'' is set to ''Enabled'' (Automated)'
    Section='18.10.57 Remote Desktop Services'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
    ValueName='UserAuthentication'
    Expected=1
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.10.57.3.9.4'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2016 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2016 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='18.10.57.3.9.5'
    Title='(L1) Ensure ''Set client connection encryption level'' is set to ''Enabled: High Level'' (Automated)'
    Section='18.10.57 Remote Desktop Services'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
    ValueName='MinEncryptionLevel'
    Expected=3
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.10.57.3.9.5'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2016 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2016 Benchmark documentation for detailed remediation steps.'
  },
  # 18.10.57.3.10 Session Time Limits
  @{
    Id='18.10.57.3.10.1'
    Title='(L2) Ensure ''Set time limit for active but idle Remote Desktop Services sessions'' is set to ''Enabled: 15 minutes or less, but not Never (0)'' (Automated)'
    Section='18.10.57 Remote Desktop Services'
    Profile='Level2'
    Type='Composite'
    AllOf=@(
        @{ Type='Registry'; Key='HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'; ValueName='MaxIdleTime'; Operator='LessOrEqual'; Expected=900000 },
        @{ Type='Registry'; Key='HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'; ValueName='MaxIdleTime'; Operator='NotEquals'; Expected=0 }
    )
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.10.57.3.10.1'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2016 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2016 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='18.10.57.3.10.2'
    Title='(L2) Ensure ''Set time limit for disconnected sessions'' is set to ''Enabled: 1 minute'' (Automated)'
    Section='18.10.57 Remote Desktop Services'
    Profile='Level2'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
    ValueName='MaxDisconnectionTime'
    Expected=60000
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.10.57.3.10.2'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2016 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2016 Benchmark documentation for detailed remediation steps.'
  },
  # 18.10.57.3.11 Temporary folders
  @{
    Id='18.10.57.3.11.1'
    Title='(L1) Ensure ''Do not delete temp folders upon exit'' is set to ''Disabled'' (Automated)'
    Section='18.10.57 Remote Desktop Services'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
    ValueName='DeleteTempDirsOnExit'
    Expected=1
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.10.57.3.11.1'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2016 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2016 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='18.10.57.3.11.2'
    Title='(L1) Ensure ''Do not use temporary folders per session'' is set to ''Disabled'' (Automated)'
    Section='18.10.57 Remote Desktop Services'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
    ValueName='PerSessionTempDir'
    Expected=1
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.10.57.3.11.2'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2016 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2016 Benchmark documentation for detailed remediation steps.'
  },

  # 18.10.58 RSS Feeds
  @{
    Id='18.10.58.1'
    Title='(L1) Ensure ''Prevent downloading of enclosures'' is set to ''Enabled'' (Automated)'
    Section='18.10.58 RSS Feeds'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds'
    ValueName='DisableEnclosureDownload'
    Expected=1
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.10.58.1'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2016 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2016 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='18.10.58.2'
    Title='(L1) Ensure ''Turn on Basic feed authentication over HTTP'' is set to ''Disabled'' (Automated)'
    Section='18.10.58 RSS Feeds'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds'
    ValueName='AllowBasicAuthInClear'
    Expected=0
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.10.58.2'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2016 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2016 Benchmark documentation for detailed remediation steps.'
  },

  # 18.10.59 Search
  # EXCLUDED: 18.10.59.2 - Not applicable to Windows Server 2016
  @{
    Id='18.10.59.3'
    Title='(L1) Ensure ''Allow indexing of encrypted files'' is set to ''Disabled'' (Automated)'
    Section='18.10.59 Search'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search'
    ValueName='AllowIndexingEncryptedStoresOrItems'
    Expected=0
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.10.59.3'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2016 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2016 Benchmark documentation for detailed remediation steps.'
  },
  # EXCLUDED: 18.10.59.4 - Not applicable to Windows Server 2016

  # 18.10.63 Software Protection Platform
  @{
    Id='18.10.63.1'
    Title='(L2) Ensure ''Turn off KMS Client Online AVS Validation'' is set to ''Enabled'' (Automated)'
    Section='18.10.63 Software Protection Platform'
    Profile='Level2'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\Software Protection Platform'
    ValueName='NoGenTicket'
    Expected=1
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.10.63.1'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2016 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2016 Benchmark documentation for detailed remediation steps.'
  },

  # 18.10.76 Windows Defender SmartScreen
  # EXCLUDED: 18.10.76.2.1 - Not applicable to Windows Server 2016

  # 18.10.80 Windows Ink Workspace
  @{
    Id='18.10.80.1'
    Title='(L2) Ensure ''Allow suggested apps in Windows Ink Workspace'' is set to ''Disabled'' (Automated)'
    Section='18.10.80 Windows Ink Workspace'
    Profile='Level2'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\WindowsInkWorkspace'
    ValueName='AllowSuggestedAppsInWindowsInkWorkspace'
    Expected=0
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.10.80.1'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2016 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2016 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='18.10.80.2'
    Title='(L1) Ensure ''Allow Windows Ink Workspace'' is set to ''Enabled: On, but disallow access above lock'' OR ''Enabled: Disabled'' (Automated)'
    Section='18.10.80 Windows Ink Workspace'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\WindowsInkWorkspace'
    ValueName='AllowWindowsInkWorkspace'
    Operator='LessOrEqual'
    Expected=1
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.10.80.2'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2016 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2016 Benchmark documentation for detailed remediation steps.'
  },

  # 18.10.81 Windows Installer
  @{
    Id='18.10.81.1'
    Title='(L1) Ensure ''Allow user control over installs'' is set to ''Disabled'' (Automated)'
    Section='18.10.81 Windows Installer'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer'
    ValueName='EnableUserControl'
    Expected=0
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.10.81.1'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2016 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2016 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='18.10.81.2'
    Title='(L1) Ensure ''Always install with elevated privileges'' is set to ''Disabled'' (Automated)'
    Section='18.10.81 Windows Installer'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer'
    ValueName='AlwaysInstallElevated'
    Expected=0
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.10.81.2'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2016 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2016 Benchmark documentation for detailed remediation steps.'
  },
  # EXCLUDED: 18.10.81.3 - Not applicable to Windows Server 2016

  # 18.10.82 Windows Logon Options
  # EXCLUDED: 18.10.82.1 - Not applicable to Windows Server 2016

  # 18.10.87 Windows PowerShell
  @{
    Id='18.10.87.1'
    Title='(L2) Ensure ''Turn on PowerShell Script Block Logging'' is set to ''Enabled'' (Automated)'
    Section='18.10.87 Windows PowerShell'
    Profile='Level2'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
    ValueName='EnableScriptBlockLogging'
    Expected=1
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.10.87.1'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2016 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2016 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='18.10.87.2'
    Title='(L2) Ensure ''Turn on PowerShell Transcription'' is set to ''Enabled'' (Automated)'
    Section='18.10.87 Windows PowerShell'
    Profile='Level2'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription'
    ValueName='EnableTranscripting'
    Expected=1
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.10.87.2'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2016 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2016 Benchmark documentation for detailed remediation steps.'
  },

  # 18.10.89 Windows Remote Management (WinRM)
  # 18.10.89.1 WinRM Client
  @{
    Id='18.10.89.1.1'
    Title='(L1) Ensure ''Allow Basic authentication'' is set to ''Disabled'' (Automated)'
    Section='18.10.89 Windows Remote Management'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client'
    ValueName='AllowBasic'
    Expected=0
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.10.89.1.1'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2016 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2016 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='18.10.89.1.2'
    Title='(L1) Ensure ''Allow unencrypted traffic'' is set to ''Disabled'' (Automated)'
    Section='18.10.89 Windows Remote Management'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client'
    ValueName='AllowUnencryptedTraffic'
    Expected=0
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.10.89.1.2'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2016 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2016 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='18.10.89.1.3'
    Title='(L1) Ensure ''Disallow Digest authentication'' is set to ''Enabled'' (Automated)'
    Section='18.10.89 Windows Remote Management'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client'
    ValueName='AllowDigest'
    Expected=0
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.10.89.1.3'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2016 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2016 Benchmark documentation for detailed remediation steps.'
  },
  # 18.10.89.2 WinRM Service
  @{
    Id='18.10.89.2.1'
    Title='(L1) Ensure ''Allow Basic authentication'' is set to ''Disabled'' (Automated)'
    Section='18.10.89 Windows Remote Management'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service'
    ValueName='AllowBasic'
    Expected=0
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.10.89.2.1'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2016 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2016 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='18.10.89.2.2'
    Title='(L2) Ensure ''Allow remote server management through WinRM'' is set to ''Disabled'' (Automated)'
    Section='18.10.89 Windows Remote Management'
    Profile='Level2'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service'
    ValueName='AllowAutoConfig'
    Expected=0
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.10.89.2.2'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2016 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2016 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='18.10.89.2.3'
    Title='(L1) Ensure ''Allow unencrypted traffic'' is set to ''Disabled'' (Automated)'
    Section='18.10.89 Windows Remote Management'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service'
    ValueName='AllowUnencryptedTraffic'
    Expected=0
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.10.89.2.3'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2016 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2016 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='18.10.89.2.4'
    Title='(L1) Ensure ''Disallow WinRM from storing RunAs credentials'' is set to ''Enabled'' (Automated)'
    Section='18.10.89 Windows Remote Management'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service'
    ValueName='DisallowRunAsCredentials'
    Expected=1
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.10.89.2.4'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2016 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2016 Benchmark documentation for detailed remediation steps.'
  },

  # 18.10.90 Windows Remote Shell
  @{
    Id='18.10.90.1'
    Title='(L2) Ensure ''Allow Remote Shell Access'' is set to ''Disabled'' (Automated)'
    Section='18.10.90 Windows Remote Shell'
    Profile='Level2'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service\WinRS'
    ValueName='AllowRemoteShellAccess'
    Expected=0
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.10.90.1'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2016 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2016 Benchmark documentation for detailed remediation steps.'
  },

  # 18.10.92 Windows Security
  # EXCLUDED: 18.10.92.2.1 - WindowsDefenderSecurityCenter.admx not applicable to Windows Server 2016

  # 18.10.93 Windows Update
  # EXCLUDED: All Windows Update controls (18.10.93.x) - WindowsUpdate.admx not applicable to Windows Server 2016
)