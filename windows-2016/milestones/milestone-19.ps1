# 19 Administrative Templates (User) (Windows Server 2016) — Audit-only
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
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2016 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2016 Benchmark documentation for detailed remediation steps.'
  },

  # 19.6.6.1 Internet Communication settings
  # EXCLUDED: 19.6.6.1.1 - Help Experience Improvement Program not applicable to Windows Server 2016

  # 19.7 Windows Components
  # 19.7.5 Attachment Manager
  # EXCLUDED: 19.7.5.1 - Attachment Manager not applicable to Windows Server 2016
  # EXCLUDED: 19.7.5.2 - Attachment Manager not applicable to Windows Server 2016

  # 19.7.8 Cloud Content
  # EXCLUDED: 19.7.8.1 - Windows Spotlight not applicable to Windows Server 2016
  # EXCLUDED: 19.7.8.2 - Windows Spotlight not applicable to Windows Server 2016
  # EXCLUDED: 19.7.8.3 - Tailored experiences not applicable to Windows Server 2016
  # EXCLUDED: 19.7.8.4 - Windows Spotlight not applicable to Windows Server 2016
  # EXCLUDED: 19.7.8.5 - Windows Spotlight not applicable to Windows Server 2016

  # 19.7.26 Network Sharing
  # EXCLUDED: 19.7.26.1 - Network Sharing not applicable to Windows Server 2016

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
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2016 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2016 Benchmark documentation for detailed remediation steps.'
  },

  # 19.7.46.2 Windows Media Player - Playback
  # EXCLUDED: 19.7.46.2.1 - Windows Media Player not applicable to Windows Server 2016
)