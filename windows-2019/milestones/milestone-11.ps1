# 18.10.26-18.10.43 Event Log Service, Microsoft Defender Antivirus (Windows Server 2019)
$Global:Rules += @(
  # 18.10.26.1 Application
  @{
    Id='18.10.26.1.1'
    Title='(L1) Ensure ''Application: Control Event Log behavior when the log file reaches its maximum size'' is set to ''Disabled'' (Automated)'
    Section='18.10.26.1 Application'
    Profile='Level1'
    Type='Registry'
    Key='HKLM:\Software\Policies\Microsoft\Windows\EventLog\Application'
    ValueName='Retention'
    Expected='0'
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.10.26.1.1'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, please refer to the official CIS Microsoft Windows Server 2019 Benchmark document at the above URL.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='18.10.26.1.2'
    Title='(L1) Ensure ''Application: Specify the maximum log file size (KB)'' is set to ''Enabled: 32,768 or greater'' (Automated)'
    Section='18.10.26.1 Application'
    Profile='Level1'
    Type='Registry'
    Key='HKLM:\Software\Policies\Microsoft\Windows\EventLog\Application'
    ValueName='MaxSize'
    Expected=32768
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.10.26.1.2'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, please refer to the official CIS Microsoft Windows Server 2019 Benchmark document at the above URL.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },

  # 18.10.26.2 Security
  @{
    Id='18.10.26.2.1'
    Title='(L1) Ensure ''Security: Control Event Log behavior when the log file reaches its maximum size'' is set to ''Disabled'' (Automated)'
    Section='18.10.26.2 Security'
    Profile='Level1'
    Type='Registry'
    Key='HKLM:\Software\Policies\Microsoft\Windows\EventLog\Security'
    ValueName='Retention'
    Expected='0'
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.10.26.2.1'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, please refer to the official CIS Microsoft Windows Server 2019 Benchmark document at the above URL.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='18.10.26.2.2'
    Title='(L1) Ensure ''Security: Specify the maximum log file size (KB)'' is set to ''Enabled: 196,608 or greater'' (Automated)'
    Section='18.10.26.2 Security'
    Profile='Level1'
    Type='Registry'
    Key='HKLM:\Software\Policies\Microsoft\Windows\EventLog\Security'
    ValueName='MaxSize'
    Expected=196608
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.10.26.2.2'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, please refer to the official CIS Microsoft Windows Server 2019 Benchmark document at the above URL.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },

  # 18.10.26.3 Setup
  @{
    Id='18.10.26.3.1'
    Title='(L1) Ensure ''Setup: Control Event Log behavior when the log file reaches its maximum size'' is set to ''Disabled'' (Automated)'
    Section='18.10.26.3 Setup'
    Profile='Level1'
    Type='Registry'
    Key='HKLM:\Software\Policies\Microsoft\Windows\EventLog\Setup'
    ValueName='Retention'
    Expected='0'
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.10.26.3.1'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, please refer to the official CIS Microsoft Windows Server 2019 Benchmark document at the above URL.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='18.10.26.3.2'
    Title='(L1) Ensure ''Setup: Specify the maximum log file size (KB)'' is set to ''Enabled: 32,768 or greater'' (Automated)'
    Section='18.10.26.3 Setup'
    Profile='Level1'
    Type='Registry'
    Key='HKLM:\Software\Policies\Microsoft\Windows\EventLog\Setup'
    ValueName='MaxSize'
    Expected=32768
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.10.26.3.2'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, please refer to the official CIS Microsoft Windows Server 2019 Benchmark document at the above URL.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },

  # 18.10.26.4 System
  @{
    Id='18.10.26.4.1'
    Title='(L1) Ensure ''System: Control Event Log behavior when the log file reaches its maximum size'' is set to ''Disabled'' (Automated)'
    Section='18.10.26.4 System'
    Profile='Level1'
    Type='Registry'
    Key='HKLM:\Software\Policies\Microsoft\Windows\EventLog\System'
    ValueName='Retention'
    Expected='0'
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.10.26.4.1'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, please refer to the official CIS Microsoft Windows Server 2019 Benchmark document at the above URL.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='18.10.26.4.2'
    Title='(L1) Ensure ''System: Specify the maximum log file size (KB)'' is set to ''Enabled: 32,768 or greater'' (Automated)'
    Section='18.10.26.4 System'
    Profile='Level1'
    Type='Registry'
    Key='HKLM:\Software\Policies\Microsoft\Windows\EventLog\System'
    ValueName='MaxSize'
    Expected=32768
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.10.26.4.2'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, please refer to the official CIS Microsoft Windows Server 2019 Benchmark document at the above URL.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },

  # 18.10.29 File Explorer
  @{
    Id='18.10.29.2'
    Title='(L1) Ensure ''Do not apply the Mark of the Web tag to files copied from insecure sources'' is set to ''Disabled'' (Automated)'
    Section='18.10.29 File Explorer'
    Profile='Level1'
    Type='Registry'
    Key='HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
    ValueName='270C'
    Expected=0
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.10.29.2'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, please refer to the official CIS Microsoft Windows Server 2019 Benchmark document at the above URL.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='18.10.29.3'
    Title='(L1) Ensure ''Turn off Data Execution Prevention for Explorer'' is set to ''Disabled'' (Automated)'
    Section='18.10.29 File Explorer'
    Profile='Level1'
    Type='Registry'
    Key='HKLM:\Software\Policies\Microsoft\Windows\Explorer'
    ValueName='NoDataExecutionPrevention'
    Expected=0
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.10.29.3'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, please refer to the official CIS Microsoft Windows Server 2019 Benchmark document at the above URL.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='18.10.29.4'
    Title='(L1) Ensure ''Turn off heap termination on corruption'' is set to ''Disabled'' (Automated)'
    Section='18.10.29 File Explorer'
    Profile='Level1'
    Type='Registry'
    Key='HKLM:\Software\Policies\Microsoft\Windows\Explorer'
    ValueName='NoHeapTerminationOnCorruption'
    Expected=0
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.10.29.4'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, please refer to the official CIS Microsoft Windows Server 2019 Benchmark document at the above URL.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='18.10.29.5'
    Title='(L1) Ensure ''Turn off shell protocol protected mode'' is set to ''Disabled'' (Automated)'
    Section='18.10.29 File Explorer'
    Profile='Level1'
    Type='Registry'
    Key='HKLM:\Software\Policies\Microsoft\Windows\Explorer'
    ValueName='PreXPSP2ShellProtocolBehavior'
    Expected=0
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.10.29.5'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, please refer to the official CIS Microsoft Windows Server 2019 Benchmark document at the above URL.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },

  # 18.10.42 Microsoft account
  @{
    Id='18.10.42.1'
    Title='(L1) Ensure ''Block all consumer Microsoft account user authentication'' is set to ''Enabled'' (Automated)'
    Section='18.10.42 Microsoft account'
    Profile='Level1'
    Type='Registry'
    Key='HKLM:\Software\Policies\Microsoft\MicrosoftAccount'
    ValueName='DisableUserAuth'
    Expected=1
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.10.42.1'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, please refer to the official CIS Microsoft Windows Server 2019 Benchmark document at the above URL.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  }
)