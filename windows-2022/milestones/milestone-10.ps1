# 18.9.36-18.10.26 Remote Procedure Call, Windows Components, Event Log (Windows Server 2022)
$Global:Rules += @(
  # 18.9.36 Remote Procedure Call
  @{
    Id='18.9.36.1'
    Title='(L1) Ensure ''Enable RPC Endpoint Mapper Client Authentication'' is set to ''Enabled'' (MS only) (Automated)'
    Section='18.9.36 Remote Procedure Call'
    Profile='Level1'
    Type='Registry'
    Key='HKLM:\Software\Policies\Microsoft\Windows NT\Rpc'
    ValueName='EnableAuthEpResolution'
    Expected=1
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.9.36.1'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2022 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2022 Benchmark documentation for detailed remediation steps.'
  },

  # 18.9.51.1 Time Providers
  @{
    Id='18.9.51.1.1'
    Title='(L1) Ensure ''Enable Windows NTP Client'' is set to ''Enabled'' (Automated)'
    Section='18.9.51.1 Time Providers'
    Profile='Level1'
    Type='Registry'
    Key='HKLM:\Software\Policies\Microsoft\W32Time\TimeProviders\NtpClient'
    ValueName='Enabled'
    Expected=1
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.9.51.1.1'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2022 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2022 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='18.9.51.1.2'
    Title='(L1) Ensure ''Enable Windows NTP Server'' is set to ''Disabled'' (MS only) (Automated)'
    Section='18.9.51.1 Time Providers'
    Profile='Level1'
    Type='Registry'
    Key='HKLM:\Software\Policies\Microsoft\W32Time\TimeProviders\NtpServer'
    ValueName='Enabled'
    Expected=0
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.9.51.1.2'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2022 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2022 Benchmark documentation for detailed remediation steps.'
  },

  # 18.10.6 App runtime
  @{
    Id='18.10.6.1'
    Title='(L1) Ensure ''Allow Microsoft accounts to be optional'' is set to ''Enabled'' (Automated)'
    Section='18.10.6 App runtime'
    Profile='Level1'
    Type='Registry'
    Key='HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System'
    ValueName='MSAOptional'
    Expected=1
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.10.6.1'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2022 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2022 Benchmark documentation for detailed remediation steps.'
  },

  # 18.10.8 AutoPlay Policies
  @{
    Id='18.10.8.1'
    Title='(L1) Ensure ''Disallow Autoplay for non-volume devices'' is set to ''Enabled'' (Automated)'
    Section='18.10.8 AutoPlay Policies'
    Profile='Level1'
    Type='Registry'
    Key='HKLM:\Software\Policies\Microsoft\Windows\Explorer'
    ValueName='NoAutoplayfornonVolume'
    Expected=1
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.10.8.1'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2022 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2022 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='18.10.8.2'
    Title='(L1) Ensure ''Set the default behavior for AutoRun'' is set to ''Enabled: Do not execute any autorun commands'' (Automated)'
    Section='18.10.8 AutoPlay Policies'
    Profile='Level1'
    Type='Registry'
    Key='HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer'
    ValueName='NoAutorun'
    Expected=1
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.10.8.2'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2022 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2022 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='18.10.8.3'
    Title='(L1) Ensure ''Turn off Autoplay'' is set to ''Enabled: All drives'' (Automated)'
    Section='18.10.8 AutoPlay Policies'
    Profile='Level1'
    Type='Registry'
    Key='HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer'
    ValueName='NoDriveTypeAutoRun'
    Expected=255
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.10.8.3'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2022 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2022 Benchmark documentation for detailed remediation steps.'
  },

  # 18.10.9.1 Facial Features
  @{
    Id='18.10.9.1.1'
    Title='(L1) Ensure ''Configure enhanced anti-spoofing'' is set to ''Enabled'' (Automated)'
    Section='18.10.9.1 Facial Features'
    Profile='Level1'
    Type='Registry'
    Key='HKLM:\Software\Policies\Microsoft\Biometrics\FacialFeatures'
    ValueName='EnhancedAntiSpoofing'
    Expected=1
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.10.9.1.1'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2022 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2022 Benchmark documentation for detailed remediation steps.'
  },

  # 18.10.13 Cloud Content
  @{
    Id='18.10.13.1'
    Title='(L1) Ensure ''Turn off cloud consumer account state content'' is set to ''Enabled'' (Automated)'
    Section='18.10.13 Cloud Content'
    Profile='Level1'
    Type='Registry'
    Key='HKLM:\Software\Policies\Microsoft\Windows\CloudContent'
    ValueName='DisableConsumerAccountStateContent'
    Expected=1
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.10.13.1'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2022 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2022 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='18.10.13.2'
    Title='(L1) Ensure ''Turn off Microsoft consumer experiences'' is set to ''Enabled'' (Automated)'
    Section='18.10.13 Cloud Content'
    Profile='Level1'
    Type='Registry'
    Key='HKLM:\Software\Policies\Microsoft\Windows\CloudContent'
    ValueName='DisableWindowsConsumerFeatures'
    Expected=1
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.10.13.2'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2022 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2022 Benchmark documentation for detailed remediation steps.'
  },

  # 18.10.15 Credential User Interface
  @{
    Id='18.10.15.1'
    Title='(L1) Ensure ''Do not display the password reveal button'' is set to ''Enabled'' (Automated)'
    Section='18.10.15 Credential User Interface'
    Profile='Level1'
    Type='Registry'
    Key='HKLM:\Software\Policies\Microsoft\Windows\CredUI'
    ValueName='DisablePasswordReveal'
    Expected=1
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.10.15.1'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2022 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2022 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='18.10.15.2'
    Title='(L1) Ensure ''Enumerate administrator accounts on elevation'' is set to ''Disabled'' (Automated)'
    Section='18.10.15 Credential User Interface'
    Profile='Level1'
    Type='Registry'
    Key='HKLM:\Software\Policies\Microsoft\Windows\CredUI'
    ValueName='EnumerateAdministrators'
    Expected=0
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.10.15.2'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2022 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2022 Benchmark documentation for detailed remediation steps.'
  },

  # 18.10.16 Data Collection and Preview Builds
  @{
    Id='18.10.16.1'
    Title='(L1) Ensure ''Allow Diagnostic Data'' is set to ''Enabled: Diagnostic data off (not recommended)'' or ''Enabled: Send required diagnostic data'' (Automated)'
    Section='18.10.16 Data Collection and Preview Builds'
    Profile='Level1'
    Type='Registry'
    Key='HKLM:\Software\Policies\Microsoft\Windows\DataCollection'
    ValueName='AllowTelemetry'
    Expected=1
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.10.16.1'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2022 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2022 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='18.10.16.3'
    Title='(L1) Ensure ''Disable OneSettings Downloads'' is set to ''Enabled'' (Automated)'
    Section='18.10.16 Data Collection and Preview Builds'
    Profile='Level1'
    Type='Registry'
    Key='HKLM:\Software\Policies\Microsoft\Windows\DataCollection'
    ValueName='DisableOneSettingsDownloads'
    Expected=1
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.10.16.3'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2022 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2022 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='18.10.16.4'
    Title='(L1) Ensure ''Do not show feedback notifications'' is set to ''Enabled'' (Automated)'
    Section='18.10.16 Data Collection and Preview Builds'
    Profile='Level1'
    Type='Registry'
    Key='HKLM:\Software\Policies\Microsoft\Windows\DataCollection'
    ValueName='DoNotShowFeedbackNotifications'
    Expected=1
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.10.16.4'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2022 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2022 Benchmark documentation for detailed remediation steps.'
  }
)