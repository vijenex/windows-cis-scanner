# Section 19: Administrative Templates (User) (Windows Server 2025)
$Global:Rules += @(
  # 19.5.1 Notifications
  @{ Id='19.5.1.1'; Title='(L1) Turn off toast notifications on the lock screen'; Section='19.5.1 Notifications'; Profile='Level1'; Type='Registry'; Key='HKCU:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications'; ValueName='NoToastApplicationNotificationOnLockScreen'; Expected=1; Description='Disables lock screen notifications'; Impact='Prevents information disclosure'; Remediation='Disable lock screen toast notifications' },
  
  # 19.6.6.1 Internet Communication settings
  @{ Id='19.6.6.1.1'; Title='(L2) Turn off Help Experience Improvement Program'; Section='19.6.6.1 Internet Communication settings'; Profile='Level2'; Type='Registry'; Key='HKCU:\SOFTWARE\Policies\Microsoft\Assistance\Client\1.0'; ValueName='NoImplicitFeedback'; Expected=1; Description='Disables help improvement program'; Impact='Reduces data collection'; Remediation='Disable help improvement program' },
  
  # 19.7.5 Attachment Manager
  @{ Id='19.7.5.1'; Title='(L1) Do not preserve zone information in file attachments'; Section='19.7.5 Attachment Manager'; Profile='Level1'; Type='Registry'; Key='HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments'; ValueName='SaveZoneInformation'; Expected=2; Description='Preserves zone information'; Impact='Maintains security warnings'; Remediation='Preserve zone information' },
  @{ Id='19.7.5.2'; Title='(L1) Notify antivirus programs when opening attachments'; Section='19.7.5 Attachment Manager'; Profile='Level1'; Type='Registry'; Key='HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments'; ValueName='ScanWithAntiVirus'; Expected=3; Description='Notifies antivirus programs'; Impact='Improves malware detection'; Remediation='Enable antivirus notification' },
  
  # 19.7.8 Cloud Content
  @{ Id='19.7.8.1'; Title='(L1) Configure Windows spotlight on lock screen'; Section='19.7.8 Cloud Content'; Profile='Level1'; Type='Registry'; Key='HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent'; ValueName='DisableWindowsSpotlightOnLockScreen'; Expected=1; Description='Disables Windows spotlight'; Impact='Reduces data collection'; Remediation='Disable Windows spotlight' },
  @{ Id='19.7.8.2'; Title='(L1) Do not suggest third-party content in Windows spotlight'; Section='19.7.8 Cloud Content'; Profile='Level1'; Type='Registry'; Key='HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent'; ValueName='DisableThirdPartySuggestions'; Expected=1; Description='Disables third-party suggestions'; Impact='Reduces unwanted content'; Remediation='Disable third-party suggestions' },
  @{ Id='19.7.8.3'; Title='(L2) Do not use diagnostic data for tailored experiences'; Section='19.7.8 Cloud Content'; Profile='Level2'; Type='Registry'; Key='HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent'; ValueName='DisableTailoredExperiencesWithDiagnosticData'; Expected=1; Description='Disables tailored experiences'; Impact='Reduces data collection'; Remediation='Disable tailored experiences' },
  @{ Id='19.7.8.4'; Title='(L2) Turn off all Windows spotlight features'; Section='19.7.8 Cloud Content'; Profile='Level2'; Type='Registry'; Key='HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent'; ValueName='DisableWindowsSpotlightFeatures'; Expected=1; Description='Disables all spotlight features'; Impact='Reduces data collection'; Remediation='Disable all spotlight features' },
  @{ Id='19.7.8.5'; Title='(L1) Turn off Spotlight collection on Desktop'; Section='19.7.8 Cloud Content'; Profile='Level1'; Type='Registry'; Key='HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent'; ValueName='DisableSpotlightCollectionOnDesktop'; Expected=1; Description='Disables desktop spotlight'; Impact='Reduces data collection'; Remediation='Disable desktop spotlight' },
  
  # 19.7.26 Network Sharing
  @{ Id='19.7.26.1'; Title='(L1) Prevent users from sharing files within their profile'; Section='19.7.26 Network Sharing'; Profile='Level1'; Type='Registry'; Key='HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'; ValueName='NoInPlaceSharing'; Expected=1; Description='Prevents profile sharing'; Impact='Improves security'; Remediation='Disable profile sharing' },
  
  # 19.7.44 Windows Installer
  @{ Id='19.7.44.1'; Title='(L1) Always install with elevated privileges'; Section='19.7.44 Windows Installer'; Profile='Level1'; Type='Registry'; Key='HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer'; ValueName='AlwaysInstallElevated'; Expected=0; Description='Prevents elevated installation'; Impact='Prevents privilege escalation'; Remediation='Disable elevated installation' }
)