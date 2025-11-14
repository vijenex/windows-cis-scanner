# 18.10.57-18.10.76 Remote Desktop Services, Search, Windows Defender SmartScreen (Windows Server 2019)
$Global:Rules += @(
  # 18.10.57.2.2 Remote Desktop Connection Client
  @{
    Id='18.10.57.2.2'
    Title='(L1) Ensure ''Do not allow passwords to be saved'' is set to ''Enabled'' (Automated)'
    Section='18.10.57.2 Remote Desktop Connection Client'
    Profile='Level1'
    Type='Registry'
    Key='HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services'
    ValueName='DisablePasswordSaving'
    Expected=1
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.10.57.2.2'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, please refer to the official CIS Microsoft Windows Server 2019 Benchmark document at the above URL.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },

  # 18.10.57.3.3 Device and Resource Redirection
  @{
    Id='18.10.57.3.3.2'
    Title='(L1) Ensure ''Do not allow drive redirection'' is set to ''Enabled'' (Automated)'
    Section='18.10.57.3.3 Device and Resource Redirection'
    Profile='Level1'
    Type='Registry'
    Key='HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services'
    ValueName='fDisableCdm'
    Expected=1
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.10.57.3.3.2'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, please refer to the official CIS Microsoft Windows Server 2019 Benchmark document at the above URL.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },

  # 18.10.57.3.9 Security
  @{
    Id='18.10.57.3.9.1'
    Title='(L1) Ensure ''Always prompt for password upon connection'' is set to ''Enabled'' (Automated)'
    Section='18.10.57.3.9 Security'
    Profile='Level1'
    Type='Registry'
    Key='HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services'
    ValueName='fPromptForPassword'
    Expected=1
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.10.57.3.9.1'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, please refer to the official CIS Microsoft Windows Server 2019 Benchmark document at the above URL.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='18.10.57.3.9.2'
    Title='(L1) Ensure ''Require secure RPC communication'' is set to ''Enabled'' (Automated)'
    Section='18.10.57.3.9 Security'
    Profile='Level1'
    Type='Registry'
    Key='HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services'
    ValueName='fEncryptRPCTraffic'
    Expected=1
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.10.57.3.9.2'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, please refer to the official CIS Microsoft Windows Server 2019 Benchmark document at the above URL.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='18.10.57.3.9.3'
    Title='(L1) Ensure ''Require use of specific security layer for remote (RDP) connections'' is set to ''Enabled: SSL'' (Automated)'
    Section='18.10.57.3.9 Security'
    Profile='Level1'
    Type='Registry'
    Key='HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services'
    ValueName='SecurityLayer'
    Expected=2
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.10.57.3.9.3'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, please refer to the official CIS Microsoft Windows Server 2019 Benchmark document at the above URL.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='18.10.57.3.9.4'
    Title='(L1) Ensure ''Require user authentication for remote connections by using Network Level Authentication'' is set to ''Enabled'' (Automated)'
    Section='18.10.57.3.9 Security'
    Profile='Level1'
    Type='Registry'
    Key='HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services'
    ValueName='UserAuthentication'
    Expected=1
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.10.57.3.9.4'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, please refer to the official CIS Microsoft Windows Server 2019 Benchmark document at the above URL.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='18.10.57.3.9.5'
    Title='(L1) Ensure ''Set client connection encryption level'' is set to ''Enabled: High Level'' (Automated)'
    Section='18.10.57.3.9 Security'
    Profile='Level1'
    Type='Registry'
    Key='HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services'
    ValueName='MinEncryptionLevel'
    Expected=3
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.10.57.3.9.5'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, please refer to the official CIS Microsoft Windows Server 2019 Benchmark document at the above URL.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },

  # 18.10.57.3.11 Temporary folders
  @{
    Id='18.10.57.3.11.1'
    Title='(L1) Ensure ''Do not delete temp folders upon exit'' is set to ''Disabled'' (Automated)'
    Section='18.10.57.3.11 Temporary folders'
    Profile='Level1'
    Type='Registry'
    Key='HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services'
    ValueName='DeleteTempDirsOnExit'
    Expected=1
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.10.57.3.11.1'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, please refer to the official CIS Microsoft Windows Server 2019 Benchmark document at the above URL.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='18.10.57.3.11.2'
    Title='(L1) Ensure ''Do not use temporary folders per session'' is set to ''Disabled'' (Automated)'
    Section='18.10.57.3.11 Temporary folders'
    Profile='Level1'
    Type='Registry'
    Key='HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services'
    ValueName='PerSessionTempDir'
    Expected=1
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.10.57.3.11.2'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, please refer to the official CIS Microsoft Windows Server 2019 Benchmark document at the above URL.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },

  # 18.10.58 RSS Feeds
  @{
    Id='18.10.58.1'
    Title='(L1) Ensure ''Prevent downloading of enclosures'' is set to ''Enabled'' (Automated)'
    Section='18.10.58 RSS Feeds'
    Profile='Level1'
    Type='Registry'
    Key='HKLM:\Software\Policies\Microsoft\Internet Explorer\Feeds'
    ValueName='DisableEnclosureDownload'
    Expected=1
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.10.58.1'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, please refer to the official CIS Microsoft Windows Server 2019 Benchmark document at the above URL.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },

  # 18.10.59 Search
  @{
    Id='18.10.59.3'
    Title='(L1) Ensure ''Allow indexing of encrypted files'' is set to ''Disabled'' (Automated)'
    Section='18.10.59 Search'
    Profile='Level1'
    Type='Registry'
    Key='HKLM:\Software\Policies\Microsoft\Windows\Windows Search'
    ValueName='AllowIndexingEncryptedStoresOrItems'
    Expected=0
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.10.59.3'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, please refer to the official CIS Microsoft Windows Server 2019 Benchmark document at the above URL.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },

  # 18.10.76.2 Explorer
  @{
    Id='18.10.76.2.1'
    Title='(L1) Ensure ''Configure Windows Defender SmartScreen'' is set to ''Enabled: Warn and prevent bypass'' (Automated)'
    Section='18.10.76.2 Explorer'
    Profile='Level1'
    Type='Registry'
    Key='HKLM:\Software\Policies\Microsoft\Windows\System'
    ValueName='EnableSmartScreen'
    Expected=2
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.10.76.2.1'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, please refer to the official CIS Microsoft Windows Server 2019 Benchmark document at the above URL.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },

  # 18.10.80 Windows Ink Workspace
  @{
    Id='18.10.80.2'
    Title='(L1) Ensure ''Allow Windows Ink Workspace'' is set to ''Enabled: On, but disallow access above lock'' OR ''Enabled: Disabled'' (Automated)'
    Section='18.10.80 Windows Ink Workspace'
    Profile='Level1'
    Type='Registry'
    Key='HKLM:\Software\Policies\Microsoft\WindowsInkWorkspace'
    ValueName='AllowWindowsInkWorkspace'
    Expected=1
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.10.80.2'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, please refer to the official CIS Microsoft Windows Server 2019 Benchmark document at the above URL.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },

  # 18.10.81 Windows Installer
  @{
    Id='18.10.81.1'
    Title='(L1) Ensure ''Allow user control over installs'' is set to ''Disabled'' (Automated)'
    Section='18.10.81 Windows Installer'
    Profile='Level1'
    Type='Registry'
    Key='HKLM:\Software\Policies\Microsoft\Windows\Installer'
    ValueName='EnableUserControl'
    Expected=0
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.10.81.1'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, please refer to the official CIS Microsoft Windows Server 2019 Benchmark document at the above URL.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='18.10.81.2'
    Title='(L1) Ensure ''Always install with elevated privileges'' is set to ''Disabled'' (Automated)'
    Section='18.10.81 Windows Installer'
    Profile='Level1'
    Type='Registry'
    Key='HKLM:\Software\Policies\Microsoft\Windows\Installer'
    ValueName='AlwaysInstallElevated'
    Expected=0
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.10.81.2'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, please refer to the official CIS Microsoft Windows Server 2019 Benchmark document at the above URL.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  }
)