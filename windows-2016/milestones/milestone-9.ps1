# 9 Windows Defender Firewall with Advanced Security (Windows Server 2016) — Audit-only
$Global:Rules += @(
  # 9.1 Domain Profile
  @{
    Id='9.1.1'
    Title='(L1) Ensure ''Windows Firewall: Domain: Firewall state'' is set to ''On (recommended)'' (Automated)'
    Section='9.1 Domain Profile'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile'
    ValueName='EnableFirewall'
    Expected=1
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='9.1.1'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2016 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2016 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='9.1.2'
    Title='(L1) Ensure ''Windows Firewall: Domain: Inbound connections'' is set to ''Block (default)'' (Automated)'
    Section='9.1 Domain Profile'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile'
    ValueName='DefaultInboundAction'
    Expected=1
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='9.1.2'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2016 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2016 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='9.1.3'
    Title='(L1) Ensure ''Windows Firewall: Domain: Settings: Display a notification'' is set to ''No'' (Automated)'
    Section='9.1 Domain Profile'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile'
    ValueName='DisableNotifications'
    Expected=1
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='9.1.3'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2016 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2016 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='9.1.4'
    Title='(L1) Ensure ''Windows Firewall: Domain: Logging: Name'' is set to ''%SystemRoot%\System32\logfiles\firewall\domainfw.log'' (Automated)'
    Section='9.1 Domain Profile'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging'
    ValueName='LogFilePath'
    Expected='%SystemRoot%\System32\logfiles\firewall\domainfw.log'
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='9.1.4'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2016 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2016 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='9.1.5'
    Title='(L1) Ensure ''Windows Firewall: Domain: Logging: Size limit (KB)'' is set to ''16,384 KB or greater'' (Automated)'
    Section='9.1 Domain Profile'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging'
    ValueName='LogFileSize'
    Operator='GreaterOrEqual'
    Expected=16384
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='9.1.5'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2016 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2016 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='9.1.6'
    Title='(L1) Ensure ''Windows Firewall: Domain: Logging: Log dropped packets'' is set to ''Yes'' (Automated)'
    Section='9.1 Domain Profile'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging'
    ValueName='LogDroppedPackets'
    Expected=1
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='9.1.6'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2016 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2016 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='9.1.7'
    Title='(L1) Ensure ''Windows Firewall: Domain: Logging: Log successful connections'' is set to ''Yes'' (Automated)'
    Section='9.1 Domain Profile'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging'
    ValueName='LogSuccessfulConnections'
    Expected=1
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='9.1.7'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2016 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2016 Benchmark documentation for detailed remediation steps.'
  },

  # 9.2 Private Profile
  @{
    Id='9.2.1'
    Title='(L1) Ensure ''Windows Firewall: Private: Firewall state'' is set to ''On (recommended)'' (Automated)'
    Section='9.2 Private Profile'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile'
    ValueName='EnableFirewall'
    Expected=1
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='9.2.1'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2016 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2016 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='9.2.2'
    Title='(L1) Ensure ''Windows Firewall: Private: Inbound connections'' is set to ''Block (default)'' (Automated)'
    Section='9.2 Private Profile'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile'
    ValueName='DefaultInboundAction'
    Expected=1
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='9.2.2'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2016 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2016 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='9.2.3'
    Title='(L1) Ensure ''Windows Firewall: Private: Settings: Display a notification'' is set to ''No'' (Automated)'
    Section='9.2 Private Profile'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile'
    ValueName='DisableNotifications'
    Expected=1
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='9.2.3'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2016 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2016 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='9.2.4'
    Title='(L1) Ensure ''Windows Firewall: Private: Logging: Name'' is set to ''%SystemRoot%\System32\logfiles\firewall\privatefw.log'' (Automated)'
    Section='9.2 Private Profile'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging'
    ValueName='LogFilePath'
    Expected='%SystemRoot%\System32\logfiles\firewall\privatefw.log'
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='9.2.4'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2016 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2016 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='9.2.5'
    Title='(L1) Ensure ''Windows Firewall: Private: Logging: Size limit (KB)'' is set to ''16,384 KB or greater'' (Automated)'
    Section='9.2 Private Profile'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging'
    ValueName='LogFileSize'
    Operator='GreaterOrEqual'
    Expected=16384
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='9.2.5'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2016 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2016 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='9.2.6'
    Title='(L1) Ensure ''Windows Firewall: Private: Logging: Log dropped packets'' is set to ''Yes'' (Automated)'
    Section='9.2 Private Profile'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging'
    ValueName='LogDroppedPackets'
    Expected=1
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='9.2.6'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2016 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2016 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='9.2.7'
    Title='(L1) Ensure ''Windows Firewall: Private: Logging: Log successful connections'' is set to ''Yes'' (Automated)'
    Section='9.2 Private Profile'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging'
    ValueName='LogSuccessfulConnections'
    Expected=1
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='9.2.7'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2016 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2016 Benchmark documentation for detailed remediation steps.'
  },

  # 9.3 Public Profile
  @{
    Id='9.3.1'
    Title='(L1) Ensure ''Windows Firewall: Public: Firewall state'' is set to ''On (recommended)'' (Automated)'
    Section='9.3 Public Profile'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile'
    ValueName='EnableFirewall'
    Expected=1
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='9.3.1'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2016 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2016 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='9.3.2'
    Title='(L1) Ensure ''Windows Firewall: Public: Inbound connections'' is set to ''Block (default)'' (Automated)'
    Section='9.3 Public Profile'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile'
    ValueName='DefaultInboundAction'
    Expected=1
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='9.3.2'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2016 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2016 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='9.3.3'
    Title='(L1) Ensure ''Windows Firewall: Public: Settings: Display a notification'' is set to ''No'' (Automated)'
    Section='9.3 Public Profile'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile'
    ValueName='DisableNotifications'
    Expected=1
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='9.3.3'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2016 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2016 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='9.3.4'
    Title='(L1) Ensure ''Windows Firewall: Public: Settings: Apply local firewall rules'' is set to ''No'' (Automated)'
    Section='9.3 Public Profile'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile'
    ValueName='AllowLocalPolicyMerge'
    Expected=0
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='9.3.4'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2016 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2016 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='9.3.5'
    Title='(L1) Ensure ''Windows Firewall: Public: Settings: Apply local connection security rules'' is set to ''No'' (Automated)'
    Section='9.3 Public Profile'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile'
    ValueName='AllowLocalIPsecPolicyMerge'
    Expected=0
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='9.3.5'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2016 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2016 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='9.3.6'
    Title='(L1) Ensure ''Windows Firewall: Public: Logging: Name'' is set to ''%SystemRoot%\System32\logfiles\firewall\publicfw.log'' (Automated)'
    Section='9.3 Public Profile'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging'
    ValueName='LogFilePath'
    Expected='%SystemRoot%\System32\logfiles\firewall\publicfw.log'
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='9.3.6'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2016 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2016 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='9.3.7'
    Title='(L1) Ensure ''Windows Firewall: Public: Logging: Size limit (KB)'' is set to ''16,384 KB or greater'' (Automated)'
    Section='9.3 Public Profile'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging'
    ValueName='LogFileSize'
    Operator='GreaterOrEqual'
    Expected=16384
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='9.3.7'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2016 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2016 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='9.3.8'
    Title='(L1) Ensure ''Windows Firewall: Public: Logging: Log dropped packets'' is set to ''Yes'' (Automated)'
    Section='9.3 Public Profile'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging'
    ValueName='LogDroppedPackets'
    Expected=1
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='9.3.8'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2016 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2016 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='9.3.9'
    Title='(L1) Ensure ''Windows Firewall: Public: Logging: Log successful connections'' is set to ''Yes'' (Automated)'
    Section='9.3 Public Profile'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging'
    ValueName='LogSuccessfulConnections'
    Expected=1
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='9.3.9'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2016 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2016 Benchmark documentation for detailed remediation steps.'
  }
)