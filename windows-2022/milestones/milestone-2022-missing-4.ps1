# Windows Server 2022 CIS Benchmark - Missing Controls Part 4
# WinRM (6) + SmartScreen (1) + Security (1) + Updates (4) = 12 controls

$Global:Rules += @(
  # 18.10.89 Windows Remote Management
  @{
    Id='18.10.89.1.1'
    Title='(L1) Ensure ''Allow Basic authentication'' is set to ''Disabled'' (Automated)'
    Section='18.10.89 Windows Remote Management'
    Profile='Level1'
    Type='Registry'
    Key='HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client'
    ValueName='AllowBasic'
    Expected=0
    Remediation='Set registry value: HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client\AllowBasic = 0'
  },
  @{
    Id='18.10.89.1.2'
    Title='(L1) Ensure ''Allow unencrypted traffic'' is set to ''Disabled'' (Automated)'
    Section='18.10.89 Windows Remote Management'
    Profile='Level1'
    Type='Registry'
    Key='HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client'
    ValueName='AllowUnencryptedTraffic'
    Expected=0
    Remediation='Set registry value: HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client\AllowUnencryptedTraffic = 0'
  },
  @{
    Id='18.10.89.1.3'
    Title='(L1) Ensure ''Disallow Digest authentication'' is set to ''Enabled'' (Automated)'
    Section='18.10.89 Windows Remote Management'
    Profile='Level1'
    Type='Registry'
    Key='HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client'
    ValueName='AllowDigest'
    Expected=0
    Remediation='Set registry value: HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client\AllowDigest = 0'
  },
  @{
    Id='18.10.89.2.1'
    Title='(L1) Ensure ''Allow Basic authentication'' is set to ''Disabled'' (Automated)'
    Section='18.10.89 Windows Remote Management'
    Profile='Level1'
    Type='Registry'
    Key='HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service'
    ValueName='AllowBasic'
    Expected=0
    Remediation='Set registry value: HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service\AllowBasic = 0'
  },
  @{
    Id='18.10.89.2.3'
    Title='(L1) Ensure ''Allow unencrypted traffic'' is set to ''Disabled'' (Automated)'
    Section='18.10.89 Windows Remote Management'
    Profile='Level1'
    Type='Registry'
    Key='HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service'
    ValueName='AllowUnencryptedTraffic'
    Expected=0
    Remediation='Set registry value: HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service\AllowUnencryptedTraffic = 0'
  },
  @{
    Id='18.10.89.2.4'
    Title='(L1) Ensure ''Disallow WinRM from storing RunAs credentials'' is set to ''Enabled'' (Automated)'
    Section='18.10.89 Windows Remote Management'
    Profile='Level1'
    Type='Registry'
    Key='HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service'
    ValueName='DisableRunAs'
    Expected=1
    Remediation='Set registry value: HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service\DisableRunAs = 1'
  },

  # 18.10.76 Windows Defender SmartScreen
  @{
    Id='18.10.76.2.1'
    Title='(L1) Ensure ''Configure Windows Defender SmartScreen'' is set to ''Enabled: Warn and prevent bypass'' (Automated)'
    Section='18.10.76 Windows Defender SmartScreen'
    Profile='Level1'
    Type='Manual'
    Remediation='Configure via Group Policy: Computer Configuration → Administrative Templates → Windows Components → Windows Defender SmartScreen → Explorer → Configure Windows Defender SmartScreen'
  },

  # 18.10.92 Windows Security
  @{
    Id='18.10.92.2.1'
    Title='(L1) Ensure ''Prevent users from modifying settings'' is set to ''Enabled'' (Automated)'
    Section='18.10.92 Windows Security'
    Profile='Level1'
    Type='Registry'
    Key='HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\App and Browser protection'
    ValueName='DisallowExploitProtectionOverride'
    Expected=1
    Remediation='Set registry value: HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\App and Browser protection\DisallowExploitProtectionOverride = 1'
  },

  # 18.10.93 Windows Update
  @{
    Id='18.10.93.1.1'
    Title='(L1) Ensure ''No auto-restart with logged on users for scheduled automatic updates installations'' is set to ''Disabled'' (Automated)'
    Section='18.10.93 Windows Update'
    Profile='Level1'
    Type='Registry'
    Key='HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU'
    ValueName='NoAutoRebootWithLoggedOnUsers'
    Expected=0
    Remediation='Set registry value: HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU\NoAutoRebootWithLoggedOnUsers = 0'
  },
  @{
    Id='18.10.93.2.1'
    Title='(L1) Ensure ''Configure Automatic Updates'' is set to ''Enabled'' (Automated)'
    Section='18.10.93 Windows Update'
    Profile='Level1'
    Type='Registry'
    Key='HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU'
    ValueName='NoAutoUpdate'
    Expected=0
    Remediation='Set registry value: HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU\NoAutoUpdate = 0'
  },
  @{
    Id='18.10.93.2.2'
    Title='(L1) Ensure ''Configure Automatic Updates: Scheduled install day'' is set to ''0 - Every day'' (Automated)'
    Section='18.10.93 Windows Update'
    Profile='Level1'
    Type='Registry'
    Key='HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU'
    ValueName='ScheduledInstallDay'
    Expected=0
    Remediation='Set registry value: HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU\ScheduledInstallDay = 0'
  },
  @{
    Id='18.10.93.4.1'
    Title='(L1) Ensure ''Manage preview builds'' is set to ''Disabled'' (Automated)'
    Section='18.10.93 Windows Update'
    Profile='Level1'
    Type='Registry'
    Key='HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'
    ValueName='ManagePreviewBuilds'
    Expected=1
    Remediation='Set registry value: HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\ManagePreviewBuilds = 1'
  },
  @{
    Id='18.10.93.4.2'
    Title='(L1) Ensure ''Select when Preview Builds and Feature Updates are received'' is set to ''Enabled: 180 or more days'' (Automated)'
    Section='18.10.93 Windows Update'
    Profile='Level1'
    Type='Manual'
    Remediation='Configure via Group Policy: Computer Configuration → Administrative Templates → Windows Components → Windows Update → Windows Update for Business → Select when Preview Builds and Feature Updates are received'
  },
  @{
    Id='18.10.93.4.3'
    Title='(L1) Ensure ''Select when Quality Updates are received'' is set to ''Enabled: 0 days'' (Automated)'
    Section='18.10.93 Windows Update'
    Profile='Level1'
    Type='Manual'
    Remediation='Configure via Group Policy: Computer Configuration → Administrative Templates → Windows Components → Windows Update → Windows Update for Business → Select when Quality Updates are received'
  }
)
