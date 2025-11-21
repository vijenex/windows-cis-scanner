# Windows Server 2022 CIS Benchmark - Missing Controls Part 1
# Event Log Service (8) + Power Management (2) + Time Service (2) + Biometrics (1) = 13 controls

$Global:Rules += @(
  # 18.10.26 Event Log Service
  @{
    Id='18.10.26.1.1'
    Title='(L1) Ensure ''Application: Control Event Log behavior when the log file reaches its maximum size'' is set to ''Disabled'' (Automated)'
    Section='18.10.26 Event Log Service'
    Profile='Level1'
    Type='Registry'
    Key='HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application'
    ValueName='Retention'
    Expected='0'
    Remediation='Set registry value: HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application\Retention = 0'
  },
  @{
    Id='18.10.26.1.2'
    Title='(L1) Ensure ''Application: Specify the maximum log file size (KB)'' is set to ''Enabled: 32,768 or greater'' (Automated)'
    Section='18.10.26 Event Log Service'
    Profile='Level1'
    Type='Registry'
    Key='HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application'
    ValueName='MaxSize'
    Expected=32768
    Operator='GreaterOrEqual'
    Remediation='Set registry value: HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application\MaxSize >= 32768'
  },
  @{
    Id='18.10.26.2.1'
    Title='(L1) Ensure ''Security: Control Event Log behavior when the log file reaches its maximum size'' is set to ''Disabled'' (Automated)'
    Section='18.10.26 Event Log Service'
    Profile='Level1'
    Type='Registry'
    Key='HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security'
    ValueName='Retention'
    Expected='0'
    Remediation='Set registry value: HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security\Retention = 0'
  },
  @{
    Id='18.10.26.2.2'
    Title='(L1) Ensure ''Security: Specify the maximum log file size (KB)'' is set to ''Enabled: 196,608 or greater'' (Automated)'
    Section='18.10.26 Event Log Service'
    Profile='Level1'
    Type='Registry'
    Key='HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security'
    ValueName='MaxSize'
    Expected=196608
    Operator='GreaterOrEqual'
    Remediation='Set registry value: HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security\MaxSize >= 196608'
  },
  @{
    Id='18.10.26.3.1'
    Title='(L1) Ensure ''Setup: Control Event Log behavior when the log file reaches its maximum size'' is set to ''Disabled'' (Automated)'
    Section='18.10.26 Event Log Service'
    Profile='Level1'
    Type='Registry'
    Key='HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Setup'
    ValueName='Retention'
    Expected='0'
    Remediation='Set registry value: HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Setup\Retention = 0'
  },
  @{
    Id='18.10.26.3.2'
    Title='(L1) Ensure ''Setup: Specify the maximum log file size (KB)'' is set to ''Enabled: 32,768 or greater'' (Automated)'
    Section='18.10.26 Event Log Service'
    Profile='Level1'
    Type='Registry'
    Key='HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Setup'
    ValueName='MaxSize'
    Expected=32768
    Operator='GreaterOrEqual'
    Remediation='Set registry value: HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Setup\MaxSize >= 32768'
  },
  @{
    Id='18.10.26.4.1'
    Title='(L1) Ensure ''System: Control Event Log behavior when the log file reaches its maximum size'' is set to ''Disabled'' (Automated)'
    Section='18.10.26 Event Log Service'
    Profile='Level1'
    Type='Registry'
    Key='HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\System'
    ValueName='Retention'
    Expected='0'
    Remediation='Set registry value: HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\System\Retention = 0'
  },
  @{
    Id='18.10.26.4.2'
    Title='(L1) Ensure ''System: Specify the maximum log file size (KB)'' is set to ''Enabled: 32,768 or greater'' (Automated)'
    Section='18.10.26 Event Log Service'
    Profile='Level1'
    Type='Registry'
    Key='HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\System'
    ValueName='MaxSize'
    Expected=32768
    Operator='GreaterOrEqual'
    Remediation='Set registry value: HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\System\MaxSize >= 32768'
  },

  # 18.9.33 Power Management
  @{
    Id='18.9.33.6.3'
    Title='(L1) Ensure ''Require a password when a computer wakes (on battery)'' is set to ''Enabled'' (Automated)'
    Section='18.9.33 Power Management'
    Profile='Level1'
    Type='Registry'
    Key='HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51'
    ValueName='DCSettingIndex'
    Expected=1
    Remediation='Set registry value: HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51\DCSettingIndex = 1'
  },
  @{
    Id='18.9.33.6.4'
    Title='(L1) Ensure ''Require a password when a computer wakes (plugged in)'' is set to ''Enabled'' (Automated)'
    Section='18.9.33 Power Management'
    Profile='Level1'
    Type='Registry'
    Key='HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51'
    ValueName='ACSettingIndex'
    Expected=1
    Remediation='Set registry value: HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51\ACSettingIndex = 1'
  },

  # 18.9.51 Windows Time Service
  @{
    Id='18.9.51.1.1'
    Title='(L1) Ensure ''Enable Windows NTP Client'' is set to ''Enabled'' (Automated)'
    Section='18.9.51 Windows Time Service'
    Profile='Level1'
    Type='Registry'
    Key='HKLM:\SOFTWARE\Policies\Microsoft\W32Time\TimeProviders\NtpClient'
    ValueName='Enabled'
    Expected=1
    Remediation='Set registry value: HKLM:\SOFTWARE\Policies\Microsoft\W32Time\TimeProviders\NtpClient\Enabled = 1'
  },
  @{
    Id='18.9.51.1.2'
    Title='(L1) Ensure ''Enable Windows NTP Server'' is set to ''Disabled'' (MS only) (Automated)'
    Section='18.9.51 Windows Time Service'
    Profile='Level1'
    Type='Registry'
    Key='HKLM:\SOFTWARE\Policies\Microsoft\W32Time\TimeProviders\NtpServer'
    ValueName='Enabled'
    Expected=0
    Remediation='Set registry value: HKLM:\SOFTWARE\Policies\Microsoft\W32Time\TimeProviders\NtpServer\Enabled = 0'
  },

  # 18.10.9 Biometrics
  @{
    Id='18.10.9.1.1'
    Title='(L1) Ensure ''Configure enhanced anti-spoofing'' is set to ''Enabled'' (Automated)'
    Section='18.10.9 Biometrics'
    Profile='Level1'
    Type='Registry'
    Key='HKLM:\SOFTWARE\Policies\Microsoft\Biometrics\FacialFeatures'
    ValueName='EnhancedAntiSpoofing'
    Expected=1
    Remediation='Set registry value: HKLM:\SOFTWARE\Policies\Microsoft\Biometrics\FacialFeatures\EnhancedAntiSpoofing = 1'
  }
)
