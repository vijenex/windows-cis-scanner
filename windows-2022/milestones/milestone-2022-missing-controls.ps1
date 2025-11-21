# Missing 55 Controls for Windows Server 2022 CIS Benchmark
$Global:Rules += @(
  # 18.9.20.1.1 - Turn off downloading of print drivers over HTTP
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
    Remediation='Refer to official CIS Microsoft Windows Server 2022 Benchmark documentation for detailed remediation steps.'
  },
  # 18.9.20.1.5 - Turn off Internet download for Web publishing
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
    Remediation='Refer to official CIS Microsoft Windows Server 2022 Benchmark documentation for detailed remediation steps.'
  },
  # 18.9.33.6.3 - Require password on battery
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
    Remediation='Refer to official CIS Microsoft Windows Server 2022 Benchmark documentation for detailed remediation steps.'
  },
  # 18.9.33.6.4 - Require password plugged in
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
    Remediation='Refer to official CIS Microsoft Windows Server 2022 Benchmark documentation for detailed remediation steps.'
  },
  # 18.9.51.1.1 - Enable Windows NTP Client
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
    Remediation='Refer to official CIS Microsoft Windows Server 2022 Benchmark documentation for detailed remediation steps.'
  },
  # 18.9.51.1.2 - Disable Windows NTP Server
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
    Remediation='Refer to official CIS Microsoft Windows Server 2022 Benchmark documentation for detailed remediation steps.'
  },
  # 18.10.9.1.1 - Configure enhanced anti-spoofing
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
    Remediation='Refer to official CIS Microsoft Windows Server 2022 Benchmark documentation for detailed remediation steps.'
  },
  # Event Log controls
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
    Remediation='Refer to official CIS Microsoft Windows Server 2022 Benchmark documentation for detailed remediation steps.'
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
    Remediation='Refer to official CIS Microsoft Windows Server 2022 Benchmark documentation for detailed remediation steps.'
  },
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
    Remediation='Refer to official CIS Microsoft Windows Server 2022 Benchmark documentation for detailed remediation steps.'
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
    Remediation='Refer to official CIS Microsoft Windows Server 2022 Benchmark documentation for detailed remediation steps.'
  },
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
    Remediation='Refer to official CIS Microsoft Windows Server 2022 Benchmark documentation for detailed remediation steps.'
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
    Remediation='Refer to official CIS Microsoft Windows Server 2022 Benchmark documentation for detailed remediation steps.'
  },
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
    Remediation='Refer to official CIS Microsoft Windows Server 2022 Benchmark documentation for detailed remediation steps.'
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
    Remediation='Refer to official CIS Microsoft Windows Server 2022 Benchmark documentation for detailed remediation steps.'
  }
)
