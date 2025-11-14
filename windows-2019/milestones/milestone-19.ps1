# 19 Administrative Templates (User) (Windows Server 2019) — Audit-only
$Global:Rules += @(
  # 19.5.1 Notifications
  @{
    Id='19.5.1.1'
    Title='(L1) Ensure ''Turn off toast notifications on the lock screen'' is set to ''Enabled'' (Automated)'
    Section='19.5.1 Notifications'
    Profile='Level1'
    Type='Registry'
    Key='HKCU\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications'
    ValueName='NoToastApplicationNotificationOnLockScreen'
    Expected=1
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='19.5.1.1'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },

  # 19.6.6.1 Internet Communication settings
  @{
    Id='19.6.6.1.1'
    Title='(L2) Ensure ''Turn off Help Experience Improvement Program'' is set to ''Enabled'' (Automated)'
    Section='19.6.6 Internet Communication Management'
    Profile='Level2'
    Type='Registry'
    Key='HKCU\SOFTWARE\Policies\Microsoft\Assistance\Client\1.0'
    ValueName='NoImplicitFeedback'
    Expected=1
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='19.6.6.1.1'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },

  # 19.7 Windows Components
  # 19.7.5 Attachment Manager
  @{
    Id='19.7.5.1'
    Title='(L1) Ensure ''Do not preserve zone information in file attachments'' is set to ''Disabled'' (Automated)'
    Section='19.7.5 Attachment Manager'
    Profile='Level1'
    Type='Registry'
    Key='HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments'
    ValueName='SaveZoneInformation'
    Expected=2
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='19.7.5.1'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='19.7.5.2'
    Title='(L1) Ensure ''Notify antivirus programs when opening attachments'' is set to ''Enabled'' (Automated)'
    Section='19.7.5 Attachment Manager'
    Profile='Level1'
    Type='Registry'
    Key='HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments'
    ValueName='ScanWithAntiVirus'
    Expected=3
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='19.7.5.2'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },

  # 19.7.8 Cloud Content
  @{
    Id='19.7.8.1'
    Title='(L1) Ensure ''Configure Windows spotlight on lock screen'' is set to ''Disabled'' (Automated)'
    Section='19.7.8 Cloud Content'
    Profile='Level1'
    Type='Registry'
    Key='HKCU\SOFTWARE\Policies\Microsoft\Windows\CloudContent'
    ValueName='ConfigureWindowsSpotlight'
    Expected=2
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='19.7.8.1'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='19.7.8.2'
    Title='(L1) Ensure ''Do not suggest third-party content in Windows spotlight'' is set to ''Enabled'' (Automated)'
    Section='19.7.8 Cloud Content'
    Profile='Level1'
    Type='Registry'
    Key='HKCU\SOFTWARE\Policies\Microsoft\Windows\CloudContent'
    ValueName='DisableThirdPartySuggestions'
    Expected=1
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='19.7.8.2'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='19.7.8.3'
    Title='(L2) Ensure ''Do not use diagnostic data for tailored experiences'' is set to ''Enabled'' (Automated)'
    Section='19.7.8 Cloud Content'
    Profile='Level2'
    Type='Registry'
    Key='HKCU\SOFTWARE\Policies\Microsoft\Windows\CloudContent'
    ValueName='DisableTailoredExperiencesWithDiagnosticData'
    Expected=1
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='19.7.8.3'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='19.7.8.4'
    Title='(L2) Ensure ''Turn off all Windows spotlight features'' is set to ''Enabled'' (Automated)'
    Section='19.7.8 Cloud Content'
    Profile='Level2'
    Type='Registry'
    Key='HKCU\SOFTWARE\Policies\Microsoft\Windows\CloudContent'
    ValueName='DisableWindowsSpotlightFeatures'
    Expected=1
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='19.7.8.4'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='19.7.8.5'
    Title='(L1) Ensure ''Turn off Spotlight collection on Desktop'' is set to ''Enabled'' (Automated)'
    Section='19.7.8 Cloud Content'
    Profile='Level1'
    Type='Registry'
    Key='HKCU\SOFTWARE\Policies\Microsoft\Windows\CloudContent'
    ValueName='DisableSpotlightCollectionOnDesktop'
    Expected=1
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='19.7.8.5'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },

  # 19.7.26 Network Sharing
  @{
    Id='19.7.26.1'
    Title='(L1) Ensure ''Prevent users from sharing files within their profile.'' is set to ''Enabled'' (Automated)'
    Section='19.7.26 Network Sharing'
    Profile='Level1'
    Type='Registry'
    Key='HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'
    ValueName='NoInPlaceSharing'
    Expected=1
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='19.7.26.1'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },

  # 19.7.44 Windows Installer
  @{
    Id='19.7.44.1'
    Title='(L1) Ensure ''Always install with elevated privileges'' is set to ''Disabled'' (Automated)'
    Section='19.7.44 Windows Installer'
    Profile='Level1'
    Type='Registry'
    Key='HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer'
    ValueName='AlwaysInstallElevated'
    Expected=0
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='19.7.44.1'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },

  # 19.7.46.2 Windows Media Player - Playback
  @{
    Id='19.7.46.2.1'
    Title='(L2) Ensure ''Prevent Codec Download'' is set to ''Enabled'' (Automated)'
    Section='19.7.46 Windows Media Player'
    Profile='Level2'
    Type='Registry'
    Key='HKCU\SOFTWARE\Policies\Microsoft\WindowsMediaPlayer'
    ValueName='PreventCodecDownload'
    Expected=1
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='19.7.46.2.1'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  }
)