# 19 Administrative Templates (User) - User Configuration Controls (Windows Server 2019)
$Global:Rules += @(
  # 19.5.1 Notifications
  @{
    Id='19.5.1.1'
    Title='(L1) Ensure ''Turn off toast notifications on the lock screen'' is set to ''Enabled'' (Automated)'
    Section='19.5.1 Notifications'
    Profile='Level1'
    Type='Registry'
    Key='HKCU:\Software\Policies\Microsoft\Windows\CurrentVersion\PushNotifications'
    ValueName='NoToastApplicationNotificationOnLockScreen'
    Expected=1
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='19.5.1.1'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, please refer to the official CIS Microsoft Windows Server 2019 Benchmark document at the above URL.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },

  # 19.6.6.1 Internet Communication settings
  @{
    Id='19.6.6.1.1'
    Title='(L2) Ensure ''Turn off Help Experience Improvement Program'' is set to ''Enabled'' (Automated)'
    Section='19.6.6.1 Internet Communication settings'
    Profile='Level2'
    Type='Registry'
    Key='HKCU:\Software\Policies\Microsoft\Assistance\Client\1.0'
    ValueName='NoImplicitFeedback'
    Expected=1
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='19.6.6.1.1'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, please refer to the official CIS Microsoft Windows Server 2019 Benchmark document at the above URL.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },

  # 19.7.5 Attachment Manager
  @{
    Id='19.7.5.1'
    Title='(L1) Ensure ''Do not preserve zone information in file attachments'' is set to ''Disabled'' (Automated)'
    Section='19.7.5 Attachment Manager'
    Profile='Level1'
    Type='Registry'
    Key='HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments'
    ValueName='SaveZoneInformation'
    Expected=2
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='19.7.5.1'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, please refer to the official CIS Microsoft Windows Server 2019 Benchmark document at the above URL.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='19.7.5.2'
    Title='(L1) Ensure ''Notify antivirus programs when opening attachments'' is set to ''Enabled'' (Automated)'
    Section='19.7.5 Attachment Manager'
    Profile='Level1'
    Type='Registry'
    Key='HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments'
    ValueName='ScanWithAntiVirus'
    Expected=3
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='19.7.5.2'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, please refer to the official CIS Microsoft Windows Server 2019 Benchmark document at the above URL.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },

  # 19.7.8 Cloud Content
  @{
    Id='19.7.8.1'
    Title='(L1) Ensure ''Configure Windows spotlight on lock screen'' is set to ''Disabled'' (Automated)'
    Section='19.7.8 Cloud Content'
    Profile='Level1'
    Type='Registry'
    Key='HKCU:\Software\Policies\Microsoft\Windows\CloudContent'
    ValueName='ConfigureWindowsSpotlight'
    Expected=2
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='19.7.8.1'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, please refer to the official CIS Microsoft Windows Server 2019 Benchmark document at the above URL.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='19.7.8.2'
    Title='(L1) Ensure ''Do not suggest third-party content in Windows spotlight'' is set to ''Enabled'' (Automated)'
    Section='19.7.8 Cloud Content'
    Profile='Level1'
    Type='Registry'
    Key='HKCU:\Software\Policies\Microsoft\Windows\CloudContent'
    ValueName='DisableThirdPartySuggestions'
    Expected=1
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='19.7.8.2'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, please refer to the official CIS Microsoft Windows Server 2019 Benchmark document at the above URL.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='19.7.8.5'
    Title='(L1) Ensure ''Turn off Spotlight collection on Desktop'' is set to ''Enabled'' (Automated)'
    Section='19.7.8 Cloud Content'
    Profile='Level1'
    Type='Registry'
    Key='HKCU:\Software\Policies\Microsoft\Windows\CloudContent'
    ValueName='DisableSpotlightCollectionOnDesktop'
    Expected=1
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='19.7.8.5'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, please refer to the official CIS Microsoft Windows Server 2019 Benchmark document at the above URL.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },

  # 19.7.26 Network Sharing
  @{
    Id='19.7.26.1'
    Title='(L1) Ensure ''Prevent users from sharing files within their profile.'' is set to ''Enabled'' (Automated)'
    Section='19.7.26 Network Sharing'
    Profile='Level1'
    Type='Registry'
    Key='HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer'
    ValueName='NoInPlaceSharing'
    Expected=1
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='19.7.26.1'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, please refer to the official CIS Microsoft Windows Server 2019 Benchmark document at the above URL.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },

  # 19.7.44 Windows Installer
  @{
    Id='19.7.44.1'
    Title='(L1) Ensure ''Always install with elevated privileges'' is set to ''Disabled'' (Automated)'
    Section='19.7.44 Windows Installer'
    Profile='Level1'
    Type='Registry'
    Key='HKCU:\Software\Policies\Microsoft\Windows\Installer'
    ValueName='AlwaysInstallElevated'
    Expected=0
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='19.7.44.1'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, please refer to the official CIS Microsoft Windows Server 2019 Benchmark document at the above URL.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },

  # 19.7.46.2 Playbook - Final Control
  @{
    Id='19.7.46.2.1'
    Title='(L2) Ensure ''Prevent Codec Download'' is set to ''Enabled'' (Automated)'
    Section='19.7.46.2 Playback'
    Profile='Level2'
    Type='Registry'
    Key='HKCU:\Software\Policies\Microsoft\WindowsMediaPlayer'
    ValueName='PreventCodecDownload'
    Expected=1
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='19.7.46.2.1'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, please refer to the official CIS Microsoft Windows Server 2019 Benchmark document at the above URL.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  }
)