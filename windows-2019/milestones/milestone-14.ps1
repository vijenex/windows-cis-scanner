# 18.10.82-18.10.93 Windows Logon Options, PowerShell, WinRM, Windows Update (Windows Server 2019)
$Global:Rules += @(
  # 18.10.82 Windows Logon Options
  @{
    Id='18.10.82.1'
    Title='(L1) Ensure ''Sign-in and lock last interactive user automatically after a restart'' is set to ''Disabled'' (Automated)'
    Section='18.10.82 Windows Logon Options'
    Profile='Level1'
    Type='Registry'
    Key='HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System'
    ValueName='DisableAutomaticRestartSignOn'
    Expected=1
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.10.82.1'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },

  # 18.10.89.1 WinRM Client
  @{
    Id='18.10.89.1.1'
    Title='(L1) Ensure ''Allow Basic authentication'' is set to ''Disabled'' (Automated)'
    Section='18.10.89.1 WinRM Client'
    Profile='Level1'
    Type='Registry'
    Key='HKLM:\Software\Policies\Microsoft\Windows\WinRM\Client'
    ValueName='AllowBasic'
    Expected=0
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.10.89.1.1'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='18.10.89.1.2'
    Title='(L1) Ensure ''Allow unencrypted traffic'' is set to ''Disabled'' (Automated)'
    Section='18.10.89.1 WinRM Client'
    Profile='Level1'
    Type='Registry'
    Key='HKLM:\Software\Policies\Microsoft\Windows\WinRM\Client'
    ValueName='AllowUnencryptedTraffic'
    Expected=0
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.10.89.1.2'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='18.10.89.1.3'
    Title='(L1) Ensure ''Disallow Digest authentication'' is set to ''Enabled'' (Automated)'
    Section='18.10.89.1 WinRM Client'
    Profile='Level1'
    Type='Registry'
    Key='HKLM:\Software\Policies\Microsoft\Windows\WinRM\Client'
    ValueName='AllowDigest'
    Expected=0
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.10.89.1.3'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },

  # 18.10.89.2 WinRM Service
  @{
    Id='18.10.89.2.1'
    Title='(L1) Ensure ''Allow Basic authentication'' is set to ''Disabled'' (Automated)'
    Section='18.10.89.2 WinRM Service'
    Profile='Level1'
    Type='Registry'
    Key='HKLM:\Software\Policies\Microsoft\Windows\WinRM\Service'
    ValueName='AllowBasic'
    Expected=0
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.10.89.2.1'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='18.10.89.2.3'
    Title='(L1) Ensure ''Allow unencrypted traffic'' is set to ''Disabled'' (Automated)'
    Section='18.10.89.2 WinRM Service'
    Profile='Level1'
    Type='Registry'
    Key='HKLM:\Software\Policies\Microsoft\Windows\WinRM\Service'
    ValueName='AllowUnencryptedTraffic'
    Expected=0
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.10.89.2.3'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='18.10.89.2.4'
    Title='(L1) Ensure ''Disallow WinRM from storing RunAs credentials'' is set to ''Enabled'' (Automated)'
    Section='18.10.89.2 WinRM Service'
    Profile='Level1'
    Type='Registry'
    Key='HKLM:\Software\Policies\Microsoft\Windows\WinRM\Service'
    ValueName='DisableRunAs'
    Expected=1
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.10.89.2.4'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },

  # 18.10.92.2 App and browser protection
  @{
    Id='18.10.92.2.1'
    Title='(L1) Ensure ''Prevent users from modifying settings'' is set to ''Enabled'' (Automated)'
    Section='18.10.92.2 App and browser protection'
    Profile='Level1'
    Type='Registry'
    Key='HKLM:\Software\Policies\Microsoft\Windows Defender Security Center\App and Browser protection'
    ValueName='DisallowExploitProtectionOverride'
    Expected=1
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.10.92.2.1'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },

  # 18.10.93.1 Legacy Policies
  @{
    Id='18.10.93.1.1'
    Title='(L1) Ensure ''No auto-restart with logged on users for scheduled automatic updates installations'' is set to ''Disabled'' (Automated)'
    Section='18.10.93.1 Legacy Policies'
    Profile='Level1'
    Type='Registry'
    Key='HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU'
    ValueName='NoAutoRebootWithLoggedOnUsers'
    Expected=0
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.10.93.1.1'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },

  # 18.10.93.2 Manage end user experience
  @{
    Id='18.10.93.2.1'
    Title='(L1) Ensure ''Configure Automatic Updates'' is set to ''Enabled'' (Automated)'
    Section='18.10.93.2 Manage end user experience'
    Profile='Level1'
    Type='Registry'
    Key='HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU'
    ValueName='NoAutoUpdate'
    Expected=0
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.10.93.2.1'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='18.10.93.2.2'
    Title='(L1) Ensure ''Configure Automatic Updates: Scheduled install day'' is set to ''0 - Every day'' (Automated)'
    Section='18.10.93.2 Manage end user experience'
    Profile='Level1'
    Type='Registry'
    Key='HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU'
    ValueName='ScheduledInstallDay'
    Expected=0
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.10.93.2.2'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },

  # 18.10.93.4 Manage updates offered from Windows Update
  @{
    Id='18.10.93.4.1'
    Title='(L1) Ensure ''Manage preview builds'' is set to ''Disabled'' (Automated)'
    Section='18.10.93.4 Manage updates offered from Windows Update'
    Profile='Level1'
    Type='Registry'
    Key='HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate'
    ValueName='ManagePreviewBuilds'
    Expected=1
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.10.93.4.1'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='18.10.93.4.2'
    Title='(L1) Ensure ''Select when Preview Builds and Feature Updates are received'' is set to ''Enabled: 180 or more days'' (Automated)'
    Section='18.10.93.4 Manage updates offered from Windows Update'
    Profile='Level1'
    Type='Registry'
    Key='HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate'
    ValueName='DeferFeatureUpdatesPeriodInDays'
    Expected=180
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.10.93.4.2'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='18.10.93.4.3'
    Title='(L1) Ensure ''Select when Quality Updates are received'' is set to ''Enabled: 0 days'' (Automated)'
    Section='18.10.93.4 Manage updates offered from Windows Update'
    Profile='Level1'
    Type='Registry'
    Key='HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate'
    ValueName='DeferQualityUpdatesPeriodInDays'
    Expected=0
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.10.93.4.3'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  }
)