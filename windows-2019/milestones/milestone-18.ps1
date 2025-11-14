# 18 Administrative Templates (Computer) (Windows Server 2019) — Audit-only
$Global:Rules += @(
  # 18.1 Control Panel
  # 18.1.1 Personalization
  @{
    Id='18.1.1.1'
    Title='(L1) Ensure ''Prevent enabling lock screen camera'' is set to ''Enabled'' (Automated)'
    Section='18.1.1 Personalization'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Windows\Personalization'
    ValueName='NoLockScreenCamera'
    Expected=1
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.1.1.1'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='18.1.1.2'
    Title='(L1) Ensure ''Prevent enabling lock screen slide show'' is set to ''Enabled'' (Automated)'
    Section='18.1.1 Personalization'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Windows\Personalization'
    ValueName='NoLockScreenSlideshow'
    Expected=1
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.1.1.2'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },

  # 18.1.2 Regional and Language Options
  @{
    Id='18.1.2.2'
    Title='(L1) Ensure ''Allow users to enable online speech recognition services'' is set to ''Disabled'' (Automated)'
    Section='18.1.2 Regional and Language Options'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\InputPersonalization'
    ValueName='AllowInputPersonalization'
    Expected=0
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.1.2.2'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='18.1.3'
    Title='(L2) Ensure ''Allow Online Tips'' is set to ''Disabled'' (Automated)'
    Section='18.1 Control Panel'
    Profile='Level2'
    Type='Registry'
    Key='HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'
    ValueName='AllowOnlineTips'
    Expected=0
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.1.3'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },

  # 18.4 MS Security Guide
  @{
    Id='18.4.1'
    Title='(L1) Ensure ''Apply UAC restrictions to local accounts on network logons'' is set to ''Enabled'' (MS only) (Automated)'
    Section='18.4 MS Security Guide'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
    ValueName='LocalAccountTokenFilterPolicy'
    Expected=0
    AppliesTo='MS'
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.4.1'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='18.4.2'
    Title='(L1) Ensure ''Configure SMB v1 client driver'' is set to ''Enabled: Disable driver (recommended)'' (Automated)'
    Section='18.4 MS Security Guide'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SYSTEM\CurrentControlSet\Services\mrxsmb10'
    ValueName='Start'
    Expected=4
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.4.2'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='18.4.3'
    Title='(L1) Ensure ''Configure SMB v1 server'' is set to ''Disabled'' (Automated)'
    Section='18.4 MS Security Guide'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'
    ValueName='SMB1'
    Expected=0
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.4.3'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='18.4.4'
    Title='(L1) Ensure ''Enable Certificate Padding'' is set to ''Enabled'' (Automated)'
    Section='18.4 MS Security Guide'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SOFTWARE\Microsoft\Cryptography\Wintrust\Config'
    ValueName='EnableCertPaddingCheck'
    Expected=1
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.4.4'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='18.4.5'
    Title='(L1) Ensure ''Enable Structured Exception Handling Overwrite Protection (SEHOP)'' is set to ''Enabled'' (Automated)'
    Section='18.4 MS Security Guide'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel'
    ValueName='DisableExceptionChainValidation'
    Expected=0
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.4.5'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='18.4.6'
    Title='(L1) Ensure ''LSA Protection'' is set to ''Enabled'' (Automated)'
    Section='18.4 MS Security Guide'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SYSTEM\CurrentControlSet\Control\Lsa'
    ValueName='RunAsPPL'
    Expected=1
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.4.6'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='18.4.7'
    Title='(L1) Ensure ''NetBT NodeType configuration'' is set to ''Enabled: P-node (recommended)'' (Automated)'
    Section='18.4 MS Security Guide'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SYSTEM\CurrentControlSet\Services\NetBT\Parameters'
    ValueName='NodeType'
    Expected=2
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.4.7'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='18.4.8'
    Title='(L1) Ensure ''WDigest Authentication'' is set to ''Disabled'' (Automated)'
    Section='18.4 MS Security Guide'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest'
    ValueName='UseLogonCredential'
    Expected=0
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.4.8'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },

  # 18.5 MSS (Legacy)
  @{
    Id='18.5.1'
    Title='(L1) Ensure ''MSS: (AutoAdminLogon) Enable Automatic Logon'' is set to ''Disabled'' (Automated)'
    Section='18.5 MSS (Legacy)'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
    ValueName='AutoAdminLogon'
    Expected='0'
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.5.1'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='18.5.2'
    Title='(L1) Ensure ''MSS: (DisableIPSourceRouting IPv6) IP source routing protection level'' is set to ''Enabled: Highest protection, source routing is completely disabled'' (Automated)'
    Section='18.5 MSS (Legacy)'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters'
    ValueName='DisableIPSourceRouting'
    Expected=2
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.5.2'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='18.5.3'
    Title='(L1) Ensure ''MSS: (DisableIPSourceRouting) IP source routing protection level'' is set to ''Enabled: Highest protection, source routing is completely disabled'' (Automated)'
    Section='18.5 MSS (Legacy)'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters'
    ValueName='DisableIPSourceRouting'
    Expected=2
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.5.3'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='18.5.4'
    Title='(L1) Ensure ''MSS: (EnableICMPRedirect) Allow ICMP redirects to override OSPF generated routes'' is set to ''Disabled'' (Automated)'
    Section='18.5 MSS (Legacy)'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters'
    ValueName='EnableICMPRedirect'
    Expected=0
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.5.4'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='18.5.5'
    Title='(L2) Ensure ''MSS: (KeepAliveTime) How often keep-alive packets are sent in milliseconds'' is set to ''Enabled: 300,000 or 5 minutes'' (Automated)'
    Section='18.5 MSS (Legacy)'
    Profile='Level2'
    Type='Registry'
    Key='HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters'
    ValueName='KeepAliveTime'
    Expected=300000
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.5.5'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='18.5.6'
    Title='(L1) Ensure ''MSS: (NoNameReleaseOnDemand) Allow the computer to ignore NetBIOS name release requests except from WINS servers'' is set to ''Enabled'' (Automated)'
    Section='18.5 MSS (Legacy)'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SYSTEM\CurrentControlSet\Services\NetBT\Parameters'
    ValueName='NoNameReleaseOnDemand'
    Expected=1
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.5.6'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='18.5.7'
    Title='(L2) Ensure ''MSS: (PerformRouterDiscovery) Allow IRDP to detect and configure Default Gateway addresses'' is set to ''Disabled'' (Automated)'
    Section='18.5 MSS (Legacy)'
    Profile='Level2'
    Type='Registry'
    Key='HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters'
    ValueName='PerformRouterDiscovery'
    Expected=0
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.5.7'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='18.5.8'
    Title='(L1) Ensure ''MSS: (SafeDllSearchMode) Enable Safe DLL search mode'' is set to ''Enabled'' (Automated)'
    Section='18.5 MSS (Legacy)'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SYSTEM\CurrentControlSet\Control\Session Manager'
    ValueName='SafeDllSearchMode'
    Expected=1
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.5.8'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='18.5.9'
    Title='(L1) Ensure ''MSS: (ScreenSaverGracePeriod) The time in seconds before the screen saver grace period expires'' is set to ''Enabled: 5 or fewer seconds'' (Automated)'
    Section='18.5 MSS (Legacy)'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
    ValueName='ScreenSaverGracePeriod'
    Operator='LessOrEqual'
    Expected=5
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.5.9'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='18.5.10'
    Title='(L2) Ensure ''MSS: (TcpMaxDataRetransmissions IPv6) How many times unacknowledged data is retransmitted'' is set to ''Enabled: 3'' (Automated)'
    Section='18.5 MSS (Legacy)'
    Profile='Level2'
    Type='Registry'
    Key='HKLM\SYSTEM\CurrentControlSet\Services\TCPIP6\Parameters'
    ValueName='TcpMaxDataRetransmissions'
    Expected=3
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.5.10'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='18.5.11'
    Title='(L2) Ensure ''MSS: (TcpMaxDataRetransmissions) How many times unacknowledged data is retransmitted'' is set to ''Enabled: 3'' (Automated)'
    Section='18.5 MSS (Legacy)'
    Profile='Level2'
    Type='Registry'
    Key='HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters'
    ValueName='TcpMaxDataRetransmissions'
    Expected=3
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.5.11'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='18.5.12'
    Title='(L1) Ensure ''MSS: (WarningLevel) Percentage threshold for the security event log at which the system will generate a warning'' is set to ''Enabled: 90% or less'' (Automated)'
    Section='18.5 MSS (Legacy)'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SYSTEM\CurrentControlSet\Services\Eventlog\Security'
    ValueName='WarningLevel'
    Operator='LessOrEqual'
    Expected=90
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.5.12'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },

  # 18.6 Network
  # 18.6.4 DNS Client
  @{
    Id='18.6.4.1'
    Title='(L1) Ensure ''Configure multicast DNS (mDNS) protocol'' is set to ''Disabled'' (Automated)'
    Section='18.6.4 DNS Client'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient'
    ValueName='EnableMulticast'
    Expected=0
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.6.4.1'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='18.6.4.2'
    Title='(L1) Ensure ''Configure NetBIOS settings'' is set to ''Enabled: Disable NetBIOS name resolution on public networks'' (Automated)'
    Section='18.6.4 DNS Client'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient'
    ValueName='EnableNetbios'
    Expected=2
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.6.4.2'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='18.6.4.3'
    Title='(L2) Ensure ''Turn off default IPv6 DNS Servers'' is set to ''Enabled'' (Automated)'
    Section='18.6.4 DNS Client'
    Profile='Level2'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient'
    ValueName='DisableSmartNameResolution'
    Expected=1
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.6.4.3'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='18.6.4.4'
    Title='(L1) Ensure ''Turn off multicast name resolution'' is set to ''Enabled'' (Automated)'
    Section='18.6.4 DNS Client'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient'
    ValueName='EnableMulticast'
    Expected=0
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.6.4.4'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },

  # 18.6.5 Fonts
  @{
    Id='18.6.5.1'
    Title='(L2) Ensure ''Enable Font Providers'' is set to ''Disabled'' (Automated)'
    Section='18.6.5 Fonts'
    Profile='Level2'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Windows\System'
    ValueName='EnableFontProviders'
    Expected=0
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.6.5.1'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },

  # 18.6.8 Lanman Workstation
  @{
    Id='18.6.8.1'
    Title='(L1) Ensure ''Enable insecure guest logons'' is set to ''Disabled'' (Automated)'
    Section='18.6.8 Lanman Workstation'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation'
    ValueName='AllowInsecureGuestAuth'
    Expected=0
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.6.8.1'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },

  # 18.6.9 Link-Layer Topology Discovery
  @{
    Id='18.6.9.1'
    Title='(L2) Ensure ''Turn on Mapper I/O (LLTDIO) driver'' is set to ''Disabled'' (Automated)'
    Section='18.6.9 Link-Layer Topology Discovery'
    Profile='Level2'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Windows\LLTD'
    ValueName='AllowLLTDIOOnDomain'
    Expected=0
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.6.9.1'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='18.6.9.2'
    Title='(L2) Ensure ''Turn on Responder (RSPNDR) driver'' is set to ''Disabled'' (Automated)'
    Section='18.6.9 Link-Layer Topology Discovery'
    Profile='Level2'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Windows\LLTD'
    ValueName='AllowRspndrOnDomain'
    Expected=0
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.6.9.2'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },

  # 18.6.10 Microsoft Peer-to-Peer Networking Services
  @{
    Id='18.6.10.2'
    Title='(L2) Ensure ''Turn off Microsoft Peer-to-Peer Networking Services'' is set to ''Enabled'' (Automated)'
    Section='18.6.10 Microsoft Peer-to-Peer Networking Services'
    Profile='Level2'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Peernet'
    ValueName='Disabled'
    Expected=1
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.6.10.2'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },

  # 18.6.11 Network Connections
  @{
    Id='18.6.11.2'
    Title='(L1) Ensure ''Prohibit installation and configuration of Network Bridge on your DNS domain network'' is set to ''Enabled'' (Automated)'
    Section='18.6.11 Network Connections'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Windows\Network Connections'
    ValueName='NC_AllowNetBridge_NLA'
    Expected=0
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.6.11.2'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='18.6.11.3'
    Title='(L1) Ensure ''Prohibit use of Internet Connection Sharing on your DNS domain network'' is set to ''Enabled'' (Automated)'
    Section='18.6.11 Network Connections'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Windows\Network Connections'
    ValueName='NC_ShowSharedAccessUI'
    Expected=0
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.6.11.3'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='18.6.11.4'
    Title='(L1) Ensure ''Require domain users to elevate when setting a network''s location'' is set to ''Enabled'' (Automated)'
    Section='18.6.11 Network Connections'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Windows\Network Connections'
    ValueName='NC_StdDomainUserSetLocation'
    Expected=1
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.6.11.4'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },

  # 18.6.14 Network Provider
  @{
    Id='18.6.14.1'
    Title='(L1) Ensure ''Hardened UNC Paths'' is set to ''Enabled, with "Require Mutual Authentication", "Require Integrity", and "Require Privacy" set for all NETLOGON and SYSVOL shares'' (Automated)'
    Section='18.6.14 Network Provider'
    Profile='Level1'
    Type='Manual'
    Expected='Configured with RequireMutualAuthentication=1, RequireIntegrity=1, RequirePrivacy=1'
    Evidence='Check Group Policy for Hardened UNC Paths configuration'
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.6.14.1'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },

  # 18.6.19 TCPIP Settings
  @{
    Id='18.6.19.2.1'
    Title='(L2) Disable IPv6 (Ensure TCPIP6 Parameter ''DisabledComponents'' is set to ''0xff (255)'') (Automated)'
    Section='18.6.19 TCPIP Settings'
    Profile='Level2'
    Type='Registry'
    Key='HKLM\SYSTEM\CurrentControlSet\Services\TCPIP6\Parameters'
    ValueName='DisabledComponents'
    Expected=255
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.6.19.2.1'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },

  # 18.6.20 Windows Connect Now
  @{
    Id='18.6.20.1'
    Title='(L2) Ensure ''Configuration of wireless settings using Windows Connect Now'' is set to ''Disabled'' (Automated)'
    Section='18.6.20 Windows Connect Now'
    Profile='Level2'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars'
    ValueName='EnableRegistrars'
    Expected=0
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.6.20.1'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='18.6.20.2'
    Title='(L2) Ensure ''Prohibit access of the Windows Connect Now wizards'' is set to ''Enabled'' (Automated)'
    Section='18.6.20 Windows Connect Now'
    Profile='Level2'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Windows\WCN\UI'
    ValueName='DisableWcnUi'
    Expected=1
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.6.20.2'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },

  # 18.6.21 Windows Connection Manager
  @{
    Id='18.6.21.1'
    Title='(L1) Ensure ''Minimize the number of simultaneous connections to the Internet or a Windows Domain'' is set to ''Enabled: 3 = Prevent Wi-Fi when on Ethernet'' (Automated)'
    Section='18.6.21 Windows Connection Manager'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy'
    ValueName='fMinimizeConnections'
    Expected=3
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.6.21.1'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='18.6.21.2'
    Title='(L2) Ensure ''Prohibit connection to non-domain networks when connected to domain authenticated network'' is set to ''Enabled'' (MS only) (Automated)'
    Section='18.6.21 Windows Connection Manager'
    Profile='Level2'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy'
    ValueName='fBlockNonDomain'
    Expected=1
    AppliesTo='MS'
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.6.21.2'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },

  # 18.7 Printers
  @{
    Id='18.7.1'
    Title='(L1) Ensure ''Allow Print Spooler to accept client connections'' is set to ''Disabled'' (Automated)'
    Section='18.7 Printers'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers'
    ValueName='RegisterSpoolerRemoteRpcEndPoint'
    Expected=2
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.7.1'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='18.7.2'
    Title='(L1) Ensure ''Configure Redirection Guard'' is set to ''Enabled: Redirection Guard Enabled'' (Automated)'
    Section='18.7 Printers'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers'
    ValueName='RedirectionguardPolicy'
    Expected=1
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.7.2'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='18.7.3'
    Title='(L1) Ensure ''Configure RPC connection settings: Protocol to use for outgoing RPC connections'' is set to ''Enabled: RPC over TCP'' (Automated)'
    Section='18.7 Printers'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers\RPC'
    ValueName='RpcProtocols'
    Expected=5
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.7.3'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='18.7.4'
    Title='(L1) Ensure ''Configure RPC connection settings: Use authentication for outgoing RPC connections'' is set to ''Enabled: Default'' (Automated)'
    Section='18.7 Printers'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers\RPC'
    ValueName='RpcAuthentication'
    Expected=0
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.7.4'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='18.7.5'
    Title='(L1) Ensure ''Configure RPC listener settings: Protocols to allow for incoming RPC connections'' is set to ''Enabled: RPC over TCP'' (Automated)'
    Section='18.7 Printers'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers\RPC'
    ValueName='RpcProtocols'
    Expected=5
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.7.5'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='18.7.6'
    Title='(L1) Ensure ''Configure RPC listener settings: Authentication protocol to use for incoming RPC connections:'' is set to ''Enabled: Negotiate'' or higher (Automated)'
    Section='18.7 Printers'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers\RPC'
    ValueName='RpcAuthentication'
    Operator='GreaterOrEqual'
    Expected=9
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.7.6'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='18.7.7'
    Title='(L1) Ensure ''Configure RPC over TCP port'' is set to ''Enabled: 0'' (Automated)'
    Section='18.7 Printers'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers\RPC'
    ValueName='RpcTcpPort'
    Expected=0
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.7.7'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='18.7.8'
    Title='(L1) Ensure ''Configure RPC packet level privacy setting for incoming connections'' is set to ''Enabled'' (Automated)'
    Section='18.7 Printers'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers\RPC'
    ValueName='RpcAuthnLevelPrivacyEnabled'
    Expected=1
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.7.8'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='18.7.9'
    Title='(L1) Ensure ''Limits print driver installation to Administrators'' is set to ''Enabled'' (Automated)'
    Section='18.7 Printers'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint'
    ValueName='RestrictDriverInstallationToAdministrators'
    Expected=1
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.7.9'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='18.7.10'
    Title='(L1) Ensure ''Manage processing of Queue-specific files'' is set to ''Enabled: Limit Queue-specific files to Color profiles'' (Automated)'
    Section='18.7 Printers'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers'
    ValueName='CopyFilesPolicy'
    Expected=1
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.7.10'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='18.7.11'
    Title='(L1) Ensure ''Point and Print Restrictions: When installing drivers for a new connection'' is set to ''Enabled: Show warning and elevation prompt'' (Automated)'
    Section='18.7 Printers'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint'
    ValueName='NoWarningNoElevationOnInstall'
    Expected=0
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.7.11'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='18.7.12'
    Title='(L1) Ensure ''Point and Print Restrictions: When updating drivers for an existing connection'' is set to ''Enabled: Show warning and elevation prompt'' (Automated)'
    Section='18.7 Printers'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint'
    ValueName='NoWarningNoElevationOnUpdate'
    Expected=0
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.7.12'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },

  # 18.8 Start Menu and Taskbar
  # 18.8.1 Notifications
  @{
    Id='18.8.1.1'
    Title='(L2) Ensure ''Turn off notifications network usage'' is set to ''Enabled'' (Automated)'
    Section='18.8.1 Notifications'
    Profile='Level2'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications'
    ValueName='NoCloudApplicationNotification'
    Expected=1
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.8.1.1'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },

  # 18.9 System
  # 18.9.3 Audit Process Creation
  @{
    Id='18.9.3.1'
    Title='(L1) Ensure ''Include command line in process creation events'' is set to ''Enabled'' (Automated)'
    Section='18.9.3 Audit Process Creation'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit'
    ValueName='ProcessCreationIncludeCmdLine_Enabled'
    Expected=1
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.9.3.1'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },

  # 18.9.4 Credentials Delegation
  @{
    Id='18.9.4.1'
    Title='(L1) Ensure ''Encryption Oracle Remediation'' is set to ''Enabled: Force Updated Clients'' (Automated)'
    Section='18.9.4 Credentials Delegation'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\CredSSP\Parameters'
    ValueName='AllowEncryptionOracle'
    Expected=0
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.9.4.1'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='18.9.4.2'
    Title='(L1) Ensure ''Remote host allows delegation of non-exportable credentials'' is set to ''Enabled'' (Automated)'
    Section='18.9.4 Credentials Delegation'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation'
    ValueName='AllowProtectedCreds'
    Expected=1
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.9.4.2'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },

  # 18.9.5 Device Guard
  @{
    Id='18.9.5.1'
    Title='(NG) Ensure ''Turn On Virtualization Based Security'' is set to ''Enabled'' (Automated)'
    Section='18.9.5 Device Guard'
    Profile='NextGeneration'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard'
    ValueName='EnableVirtualizationBasedSecurity'
    Expected=1
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.9.5.1'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='18.9.5.2'
    Title='(NG) Ensure ''Turn On Virtualization Based Security: Select Platform Security Level'' is set to ''Secure Boot'' or higher (Automated)'
    Section='18.9.5 Device Guard'
    Profile='NextGeneration'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard'
    ValueName='RequirePlatformSecurityFeatures'
    Operator='GreaterOrEqual'
    Expected=1
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.9.5.2'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='18.9.5.3'
    Title='(NG) Ensure ''Turn On Virtualization Based Security: Virtualization Based Protection of Code Integrity'' is set to ''Enabled with UEFI lock'' (Automated)'
    Section='18.9.5 Device Guard'
    Profile='NextGeneration'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard'
    ValueName='HypervisorEnforcedCodeIntegrity'
    Expected=1
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.9.5.3'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='18.9.5.4'
    Title='(NG) Ensure ''Turn On Virtualization Based Security: Require UEFI Memory Attributes Table'' is set to ''True (checked)'' (Automated)'
    Section='18.9.5 Device Guard'
    Profile='NextGeneration'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard'
    ValueName='HVCIMATRequired'
    Expected=1
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.9.5.4'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='18.9.5.5'
    Title='(NG) Ensure ''Turn On Virtualization Based Security: Credential Guard Configuration'' is set to ''Enabled with UEFI lock'' (MS Only) (Automated)'
    Section='18.9.5 Device Guard'
    Profile='NextGeneration'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard'
    ValueName='LsaCfgFlags'
    Expected=1
    AppliesTo='MS'
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.9.5.5'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='18.9.5.6'
    Title='(NG) Ensure ''Turn On Virtualization Based Security: Credential Guard Configuration'' is set to ''Disabled'' (DC Only) (Automated)'
    Section='18.9.5 Device Guard'
    Profile='NextGeneration'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard'
    ValueName='LsaCfgFlags'
    Expected=0
    AppliesTo='DC'
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.9.5.6'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='18.9.5.7'
    Title='(NG) Ensure ''Turn On Virtualization Based Security: Secure Launch Configuration'' is set to ''Enabled'' (Automated)'
    Section='18.9.5 Device Guard'
    Profile='NextGeneration'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard'
    ValueName='ConfigureSystemGuardLaunch'
    Expected=1
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.9.5.7'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },

  # 18.9.7 Device Installation
  @{
    Id='18.9.7.2'
    Title='(L1) Ensure ''Prevent device metadata retrieval from the Internet'' is set to ''Enabled'' (Automated)'
    Section='18.9.7 Device Installation'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Windows\Device Metadata'
    ValueName='PreventDeviceMetadataFromNetwork'
    Expected=1
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.9.7.2'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },

  # 18.9.13 Early Launch Antimalware
  @{
    Id='18.9.13.1'
    Title='(L1) Ensure ''Boot-Start Driver Initialization Policy'' is set to ''Enabled: Good, unknown and bad but critical'' (Automated)'
    Section='18.9.13 Early Launch Antimalware'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SYSTEM\CurrentControlSet\Policies\EarlyLaunch'
    ValueName='DriverLoadPolicy'
    Expected=3
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.9.13.1'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },

  # 18.9.19 Group Policy
  @{
    Id='18.9.19.2'
    Title='(L1) Ensure ''Configure registry policy processing: Do not apply during periodic background processing'' is set to ''Enabled: FALSE'' (Automated)'
    Section='18.9.19 Group Policy'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}'
    ValueName='NoBackgroundPolicy'
    Expected=0
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.9.19.2'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='18.9.19.3'
    Title='(L1) Ensure ''Configure registry policy processing: Process even if the Group Policy objects have not changed'' is set to ''Enabled: TRUE'' (Automated)'
    Section='18.9.19 Group Policy'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}'
    ValueName='NoGPOListChanges'
    Expected=0
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.9.19.3'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='18.9.19.4'
    Title='(L1) Ensure ''Configure security policy processing: Do not apply during periodic background processing'' is set to ''Enabled: FALSE'' (Automated)'
    Section='18.9.19 Group Policy'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{827D319E-6EAC-11D2-A4EA-00C04F79F83A}'
    ValueName='NoBackgroundPolicy'
    Expected=0
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.9.19.4'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='18.9.19.5'
    Title='(L1) Ensure ''Configure security policy processing: Process even if the Group Policy objects have not changed'' is set to ''Enabled: TRUE'' (Automated)'
    Section='18.9.19 Group Policy'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{827D319E-6EAC-11D2-A4EA-00C04F79F83A}'
    ValueName='NoGPOListChanges'
    Expected=0
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.9.19.5'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='18.9.19.6'
    Title='(L1) Ensure ''Continue experiences on this device'' is set to ''Disabled'' (Automated)'
    Section='18.9.19 Group Policy'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Windows\System'
    ValueName='EnableCdp'
    Expected=0
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.9.19.6'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='18.9.19.7'
    Title='(L1) Ensure ''Turn off background refresh of Group Policy'' is set to ''Disabled'' (Automated)'
    Section='18.9.19 Group Policy'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
    ValueName='DisableBkGndGroupPolicy'
    Expected=0
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.9.19.7'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },

  # 18.9.20 Internet Communication Management
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
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='18.9.20.1.2'
    Title='(L2) Ensure ''Turn off handwriting personalization data sharing'' is set to ''Enabled'' (Automated)'
    Section='18.9.20 Internet Communication Management'
    Profile='Level2'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Windows\TabletPC'
    ValueName='PreventHandwritingDataSharing'
    Expected=1
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.9.20.1.2'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='18.9.20.1.3'
    Title='(L2) Ensure ''Turn off handwriting recognition error reporting'' is set to ''Enabled'' (Automated)'
    Section='18.9.20 Internet Communication Management'
    Profile='Level2'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports'
    ValueName='PreventHandwritingErrorReports'
    Expected=1
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.9.20.1.3'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='18.9.20.1.4'
    Title='(L2) Ensure ''Turn off Internet Connection Wizard if URL connection is referring to Microsoft.com'' is set to ''Enabled'' (Automated)'
    Section='18.9.20 Internet Communication Management'
    Profile='Level2'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Windows\Internet Connection Wizard'
    ValueName='ExitOnMSICW'
    Expected=1
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.9.20.1.4'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
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
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='18.9.20.1.6'
    Title='(L2) Ensure ''Turn off printing over HTTP'' is set to ''Enabled'' (Automated)'
    Section='18.9.20 Internet Communication Management'
    Profile='Level2'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers'
    ValueName='DisableHTTPPrinting'
    Expected=1
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.9.20.1.6'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='18.9.20.1.7'
    Title='(L2) Ensure ''Turn off Registration if URL connection is referring to Microsoft.com'' is set to ''Enabled'' (Automated)'
    Section='18.9.20 Internet Communication Management'
    Profile='Level2'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Windows\Registration Wizard Control'
    ValueName='NoRegistration'
    Expected=1
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.9.20.1.7'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='18.9.20.1.8'
    Title='(L2) Ensure ''Turn off Search Companion content file updates'' is set to ''Enabled'' (Automated)'
    Section='18.9.20 Internet Communication Management'
    Profile='Level2'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\SearchCompanion'
    ValueName='DisableContentFileUpdates'
    Expected=1
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.9.20.1.8'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='18.9.20.1.9'
    Title='(L2) Ensure ''Turn off the "Order Prints" picture task'' is set to ''Enabled'' (Automated)'
    Section='18.9.20 Internet Communication Management'
    Profile='Level2'
    Type='Registry'
    Key='HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'
    ValueName='NoOnlinePrintsWizard'
    Expected=1
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.9.20.1.9'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='18.9.20.1.10'
    Title='(L2) Ensure ''Turn off the "Publish to Web" task for files and folders'' is set to ''Enabled'' (Automated)'
    Section='18.9.20 Internet Communication Management'
    Profile='Level2'
    Type='Registry'
    Key='HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'
    ValueName='NoPublishingWizard'
    Expected=1
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.9.20.1.10'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='18.9.20.1.11'
    Title='(L2) Ensure ''Turn off the Windows Messenger Customer Experience Improvement Program'' is set to ''Enabled'' (Automated)'
    Section='18.9.20 Internet Communication Management'
    Profile='Level2'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Messenger\Client'
    ValueName='CEIP'
    Expected=2
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.9.20.1.11'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='18.9.20.1.12'
    Title='(L2) Ensure ''Turn off Windows Customer Experience Improvement Program'' is set to ''Enabled'' (Automated)'
    Section='18.9.20 Internet Communication Management'
    Profile='Level2'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\SQMClient\Windows'
    ValueName='CEIPEnable'
    Expected=0
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.9.20.1.12'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='18.9.20.1.13'
    Title='(L2) Ensure ''Turn off Windows Error Reporting'' is set to ''Enabled'' (Automated)'
    Section='18.9.20 Internet Communication Management'
    Profile='Level2'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting'
    ValueName='Disabled'
    Expected=1
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.9.20.1.13'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },

  # 18.9.23 Kerberos
  @{
    Id='18.9.23.1'
    Title='(L2) Ensure ''Support device authentication using certificate'' is set to ''Enabled: Automatic'' (Automated)'
    Section='18.9.23 Kerberos'
    Profile='Level2'
    Type='Registry'
    Key='HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\kerberos\parameters'
    ValueName='DevicePKInitBehavior'
    Expected=0
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.9.23.1'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },

  # 18.9.24 Kernel DMA Protection
  @{
    Id='18.9.24.1'
    Title='(L1) Ensure ''Enumeration policy for external devices incompatible with Kernel DMA Protection'' is set to ''Enabled: Block All'' (Automated)'
    Section='18.9.24 Kernel DMA Protection'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Windows\Kernel DMA Protection'
    ValueName='DeviceEnumerationPolicy'
    Expected=0
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.9.24.1'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },

  # 18.9.25 LAPS
  @{
    Id='18.9.25.1'
    Title='(L1) Ensure ''Configure password backup directory'' is set to ''Enabled: Active Directory'' or ''Enabled: Azure Active Directory'' (Automated)'
    Section='18.9.25 LAPS'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft Services\AdmPwd'
    ValueName='BackupDirectory'
    Expected=1
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.9.25.1'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='18.9.25.2'
    Title='(L1) Ensure ''Do not allow password expiration time longer than required by policy'' is set to ''Enabled'' (Automated)'
    Section='18.9.25 LAPS'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft Services\AdmPwd'
    ValueName='PwdExpirationProtectionEnabled'
    Expected=1
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.9.25.2'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='18.9.25.3'
    Title='(L1) Ensure ''Enable password encryption'' is set to ''Enabled'' (Automated)'
    Section='18.9.25 LAPS'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft Services\AdmPwd'
    ValueName='PasswordEncryptionEnabled'
    Expected=1
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.9.25.3'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='18.9.25.4'
    Title='(L1) Ensure ''Password Settings: Password Complexity'' is set to ''Enabled: Large letters + small letters + numbers + special characters'' (Automated)'
    Section='18.9.25 LAPS'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft Services\AdmPwd'
    ValueName='PasswordComplexity'
    Expected=4
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.9.25.4'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='18.9.25.5'
    Title='(L1) Ensure ''Password Settings: Password Length'' is set to ''Enabled: 15 or more'' (Automated)'
    Section='18.9.25 LAPS'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft Services\AdmPwd'
    ValueName='PasswordLength'
    Operator='GreaterOrEqual'
    Expected=15
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.9.25.5'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='18.9.25.6'
    Title='(L1) Ensure ''Password Settings: Password Age (Days)'' is set to ''Enabled: 30 or fewer'' (Automated)'
    Section='18.9.25 LAPS'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft Services\AdmPwd'
    ValueName='PasswordAgeDays'
    Operator='LessOrEqual'
    Expected=30
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.9.25.6'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='18.9.25.7'
    Title='(L1) Ensure ''Post-authentication actions: Grace period (hours)'' is set to ''Enabled: 8 or fewer hours, but not 0'' (Automated)'
    Section='18.9.25 LAPS'
    Profile='Level1'
    Type='Composite'
    AllOf=@(
        @{ Type='Registry'; Key='HKLM\SOFTWARE\Policies\Microsoft Services\AdmPwd'; ValueName='PostAuthenticationResetDelay'; Operator='LessOrEqual'; Expected=8 },
        @{ Type='Registry'; Key='HKLM\SOFTWARE\Policies\Microsoft Services\AdmPwd'; ValueName='PostAuthenticationResetDelay'; Operator='NotEquals'; Expected=0 }
    )
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.9.25.7'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='18.9.25.8'
    Title='(L1) Ensure ''Post-authentication actions: Actions'' is set to ''Enabled: Reset the password and logoff the managed account'' or higher (Automated)'
    Section='18.9.25 LAPS'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft Services\AdmPwd'
    ValueName='PostAuthenticationActions'
    Operator='GreaterOrEqual'
    Expected=3
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.9.25.8'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },

  # 18.9.27 Locale Services
  @{
    Id='18.9.27.1'
    Title='(L2) Ensure ''Disallow copying of user input methods to the system account for sign-in'' is set to ''Enabled'' (Automated)'
    Section='18.9.27 Locale Services'
    Profile='Level2'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Control Panel\International'
    ValueName='BlockUserInputMethodsForSignIn'
    Expected=1
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.9.27.1'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },

  # 18.9.28 Logon
  @{
    Id='18.9.28.1'
    Title='(L1) Ensure ''Block user from showing account details on sign-in'' is set to ''Enabled'' (Automated)'
    Section='18.9.28 Logon'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Windows\System'
    ValueName='BlockUserFromShowingAccountDetailsOnSignin'
    Expected=1
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.9.28.1'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='18.9.28.2'
    Title='(L1) Ensure ''Do not display network selection UI'' is set to ''Enabled'' (Automated)'
    Section='18.9.28 Logon'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Windows\System'
    ValueName='DontDisplayNetworkSelectionUI'
    Expected=1
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.9.28.2'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='18.9.28.3'
    Title='(L1) Ensure ''Do not enumerate connected users on domain-joined computers'' is set to ''Enabled'' (Automated)'
    Section='18.9.28 Logon'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Windows\System'
    ValueName='DontEnumerateConnectedUsers'
    Expected=1
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.9.28.3'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='18.9.28.4'
    Title='(L1) Ensure ''Enumerate local users on domain-joined computers'' is set to ''Disabled'' (MS only) (Automated)'
    Section='18.9.28 Logon'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Windows\System'
    ValueName='EnumerateLocalUsers'
    Expected=0
    AppliesTo='MS'
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.9.28.4'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='18.9.28.5'
    Title='(L1) Ensure ''Turn off app notifications on the lock screen'' is set to ''Enabled'' (Automated)'
    Section='18.9.28 Logon'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Windows\System'
    ValueName='DisableLockScreenAppNotifications'
    Expected=1
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.9.28.5'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='18.9.28.6'
    Title='(L1) Ensure ''Turn off picture password sign-in'' is set to ''Enabled'' (Automated)'
    Section='18.9.28 Logon'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Windows\System'
    ValueName='BlockDomainPicturePassword'
    Expected=1
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.9.28.6'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='18.9.28.7'
    Title='(L1) Ensure ''Turn on convenience PIN sign-in'' is set to ''Disabled'' (Automated)'
    Section='18.9.28 Logon'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Windows\System'
    ValueName='AllowDomainPINLogon'
    Expected=0
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.9.28.7'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },

  # 18.9.31 OS Policies
  @{
    Id='18.9.31.1'
    Title='(L2) Ensure ''Allow Clipboard synchronization across devices'' is set to ''Disabled'' (Automated)'
    Section='18.9.31 OS Policies'
    Profile='Level2'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Windows\System'
    ValueName='AllowCrossDeviceClipboard'
    Expected=0
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.9.31.1'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='18.9.31.2'
    Title='(L2) Ensure ''Allow upload of User Activities'' is set to ''Disabled'' (Automated)'
    Section='18.9.31 OS Policies'
    Profile='Level2'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Windows\System'
    ValueName='UploadUserActivities'
    Expected=0
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.9.31.2'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },

  # 18.9.33 Power Management
  @{
    Id='18.9.33.6.1'
    Title='(L2) Ensure ''Allow network connectivity during connected-standby (on battery)'' is set to ''Disabled'' (Automated)'
    Section='18.9.33 Power Management'
    Profile='Level2'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Power\PowerSettings\f15576e8-98b7-4186-b944-eafa664402d9'
    ValueName='DCSettingIndex'
    Expected=0
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.9.33.6.1'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='18.9.33.6.2'
    Title='(L2) Ensure ''Allow network connectivity during connected-standby (plugged in)'' is set to ''Disabled'' (Automated)'
    Section='18.9.33 Power Management'
    Profile='Level2'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Power\PowerSettings\f15576e8-98b7-4186-b944-eafa664402d9'
    ValueName='ACSettingIndex'
    Expected=0
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.9.33.6.2'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
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
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
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
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },

  # 18.9.35 Remote Assistance
  @{
    Id='18.9.35.1'
    Title='(L1) Ensure ''Configure Offer Remote Assistance'' is set to ''Disabled'' (Automated)'
    Section='18.9.35 Remote Assistance'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
    ValueName='fAllowUnsolicited'
    Expected=0
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.9.35.1'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='18.9.35.2'
    Title='(L1) Ensure ''Configure Solicited Remote Assistance'' is set to ''Disabled'' (Automated)'
    Section='18.9.35 Remote Assistance'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
    ValueName='fAllowToGetHelp'
    Expected=0
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.9.35.2'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },

  # 18.9.36 Remote Procedure Call
  @{
    Id='18.9.36.1'
    Title='(L1) Ensure ''Enable RPC Endpoint Mapper Client Authentication'' is set to ''Enabled'' (MS only) (Automated)'
    Section='18.9.36 Remote Procedure Call'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Rpc'
    ValueName='EnableAuthEpResolution'
    Expected=1
    AppliesTo='MS'
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.9.36.1'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='18.9.36.2'
    Title='(L2) Ensure ''Restrict Unauthenticated RPC clients'' is set to ''Enabled: Authenticated'' (MS only) (Automated)'
    Section='18.9.36 Remote Procedure Call'
    Profile='Level2'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Rpc'
    ValueName='RestrictRemoteClients'
    Expected=1
    AppliesTo='MS'
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.9.36.2'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },

  # 18.9.47.5.1 Microsoft Support Diagnostic Tool
  @{
    Id='18.9.47.5.1'
    Title='(L2) Ensure ''Microsoft Support Diagnostic Tool: Turn on MSDT interactive communication with support provider'' is set to ''Disabled'' (Automated)'
    Section='18.9.47 Troubleshooting and Diagnostics'
    Profile='Level2'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Windows\ScriptedDiagnosticsProvider\Policy'
    ValueName='DisableQueryRemoteServer'
    Expected=0
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.9.47.5.1'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },

  # 18.9.47.11.1 Windows Performance PerfTrack
  @{
    Id='18.9.47.11.1'
    Title='(L2) Ensure ''Enable/Disable PerfTrack'' is set to ''Disabled'' (Automated)'
    Section='18.9.47 Troubleshooting and Diagnostics'
    Profile='Level2'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Windows\WDI\{9c5a40da-b965-4fc3-8781-88dd50a6299d}'
    ValueName='ScenarioExecutionEnabled'
    Expected=0
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.9.47.11.1'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },

  # 18.9.49.1 User Profiles
  @{
    Id='18.9.49.1'
    Title='(L2) Ensure ''Turn off the advertising ID'' is set to ''Enabled'' (Automated)'
    Section='18.9.49 User Profiles'
    Profile='Level2'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo'
    ValueName='DisabledByGroupPolicy'
    Expected=1
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.9.49.1'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },

  # 18.9.51.1 Windows Time Service - Time Providers
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
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
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
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },

  # 18.10 Windows Components
  # 18.10.4.1 App Package Deployment
  @{
    Id='18.10.4.1'
    Title='(L2) Ensure ''Allow a Windows app to share application data between users'' is set to ''Disabled'' (Automated)'
    Section='18.10 Windows Components'
    Profile='Level2'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\AppModel\StateManager'
    ValueName='AllowSharedLocalAppData'
    Expected=0
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.10.4.1'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },

  # 18.10.6.1 App runtime
  @{
    Id='18.10.6.1'
    Title='(L1) Ensure ''Allow Microsoft accounts to be optional'' is set to ''Enabled'' (Automated)'
    Section='18.10 Windows Components'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
    ValueName='MSAOptional'
    Expected=1
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.10.6.1'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },

  # 18.10.8 AutoPlay Policies
  @{
    Id='18.10.8.1'
    Title='(L1) Ensure ''Disallow Autoplay for non-volume devices'' is set to ''Enabled'' (Automated)'
    Section='18.10.8 AutoPlay Policies'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer'
    ValueName='NoAutoplayfornonVolume'
    Expected=1
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.10.8.1'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='18.10.8.2'
    Title='(L1) Ensure ''Set the default behavior for AutoRun'' is set to ''Enabled: Do not execute any autorun commands'' (Automated)'
    Section='18.10.8 AutoPlay Policies'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'
    ValueName='NoAutorun'
    Expected=1
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.10.8.2'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='18.10.8.3'
    Title='(L1) Ensure ''Turn off Autoplay'' is set to ''Enabled: All drives'' (Automated)'
    Section='18.10.8 AutoPlay Policies'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'
    ValueName='NoDriveTypeAutoRun'
    Expected=255
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.10.8.3'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },

  # 18.10.9.1 Biometrics - Facial Features
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
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },

  # 18.10.11 Camera
  @{
    Id='18.10.11.1'
    Title='(L2) Ensure ''Allow Use of Camera'' is set to ''Disabled'' (Automated)'
    Section='18.10.11 Camera'
    Profile='Level2'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Camera'
    ValueName='AllowCamera'
    Expected=0
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.10.11.1'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },

  # 18.10.13 Cloud Content
  @{
    Id='18.10.13.1'
    Title='(L1) Ensure ''Turn off cloud consumer account state content'' is set to ''Enabled'' (Automated)'
    Section='18.10.13 Cloud Content'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent'
    ValueName='DisableConsumerAccountStateContent'
    Expected=1
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.10.13.1'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='18.10.13.2'
    Title='(L1) Ensure ''Turn off Microsoft consumer experiences'' is set to ''Enabled'' (Automated)'
    Section='18.10.13 Cloud Content'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent'
    ValueName='DisableWindowsConsumerFeatures'
    Expected=1
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.10.13.2'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },

  # 18.10.14 Connect
  @{
    Id='18.10.14.1'
    Title='(L1) Ensure ''Require pin for pairing'' is set to ''Enabled: First Time'' OR ''Enabled: Always'' (Automated)'
    Section='18.10.14 Connect'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Windows\Connect'
    ValueName='RequirePinForPairing'
    Operator='GreaterOrEqual'
    Expected=1
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.10.14.1'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },

  # 18.10.15 Credential User Interface
  @{
    Id='18.10.15.1'
    Title='(L1) Ensure ''Do not display the password reveal button'' is set to ''Enabled'' (Automated)'
    Section='18.10.15 Credential User Interface'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Windows\CredUI'
    ValueName='DisablePasswordReveal'
    Expected=1
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.10.15.1'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='18.10.15.2'
    Title='(L1) Ensure ''Enumerate administrator accounts on elevation'' is set to ''Disabled'' (Automated)'
    Section='18.10.15 Credential User Interface'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Windows\CredUI'
    ValueName='EnumerateAdministrators'
    Expected=0
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.10.15.2'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },

  # 18.10.16 Data Collection and Preview Builds
  @{
    Id='18.10.16.1'
    Title='(L1) Ensure ''Allow Diagnostic Data'' is set to ''Enabled: Diagnostic data off (not recommended)'' or ''Enabled: Send required diagnostic data'' (Automated)'
    Section='18.10.16 Data Collection and Preview Builds'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection'
    ValueName='AllowTelemetry'
    Operator='LessOrEqual'
    Expected=1
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.10.16.1'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='18.10.16.2'
    Title='(L2) Ensure ''Configure Authenticated Proxy usage for the Connected User Experience and Telemetry service'' is set to ''Enabled: Disable Authenticated Proxy usage'' (Automated)'
    Section='18.10.16 Data Collection and Preview Builds'
    Profile='Level2'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection'
    ValueName='DisableEnterpriseAuthProxy'
    Expected=1
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.10.16.2'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='18.10.16.3'
    Title='(L1) Ensure ''Disable OneSettings Downloads'' is set to ''Enabled'' (Automated)'
    Section='18.10.16 Data Collection and Preview Builds'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection'
    ValueName='DisableOneSettingsDownloads'
    Expected=1
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.10.16.3'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='18.10.16.4'
    Title='(L1) Ensure ''Do not show feedback notifications'' is set to ''Enabled'' (Automated)'
    Section='18.10.16 Data Collection and Preview Builds'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection'
    ValueName='DoNotShowFeedbackNotifications'
    Expected=1
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.10.16.4'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='18.10.16.5'
    Title='(L1) Ensure ''Enable OneSettings Auditing'' is set to ''Enabled'' (Automated)'
    Section='18.10.16 Data Collection and Preview Builds'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection'
    ValueName='EnableOneSettingsAuditing'
    Expected=1
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.10.16.5'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='18.10.16.6'
    Title='(L1) Ensure ''Limit Diagnostic Log Collection'' is set to ''Enabled'' (Automated)'
    Section='18.10.16 Data Collection and Preview Builds'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection'
    ValueName='LimitDiagnosticLogCollection'
    Expected=1
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.10.16.6'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='18.10.16.7'
    Title='(L1) Ensure ''Limit Dump Collection'' is set to ''Enabled'' (Automated)'
    Section='18.10.16 Data Collection and Preview Builds'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection'
    ValueName='LimitDumpCollection'
    Expected=1
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.10.16.7'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },

  # 18.10.18 Desktop App Installer
  @{
    Id='18.10.18.1'
    Title='(L2) Ensure ''Enable App Installer'' is set to ''Disabled'' (Automated)'
    Section='18.10.18 Desktop App Installer'
    Profile='Level2'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Windows\AppInstaller'
    ValueName='EnableAppInstaller'
    Expected=0
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.10.18.1'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='18.10.18.2'
    Title='(L1) Ensure ''Enable App Installer Experimental Features'' is set to ''Disabled'' (Automated)'
    Section='18.10.18 Desktop App Installer'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Windows\AppInstaller'
    ValueName='EnableExperimentalFeatures'
    Expected=0
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.10.18.2'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='18.10.18.3'
    Title='(L1) Ensure ''Enable App Installer Hash Override'' is set to ''Disabled'' (Automated)'
    Section='18.10.18 Desktop App Installer'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Windows\AppInstaller'
    ValueName='EnableHashOverride'
    Expected=0
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.10.18.3'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='18.10.18.4'
    Title='(L1) Ensure ''Enable App Installer Local Archive Malware Scan Override'' is set to ''Disabled'' (Automated)'
    Section='18.10.18 Desktop App Installer'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Windows\AppInstaller'
    ValueName='EnableLocalArchiveMalwareScanOverride'
    Expected=0
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.10.18.4'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='18.10.18.5'
    Title='(L1) Ensure ''Enable App Installer ms-appinstaller protocol'' is set to ''Disabled'' (Automated)'
    Section='18.10.18 Desktop App Installer'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Windows\AppInstaller'
    ValueName='EnableMSAppInstallerProtocol'
    Expected=0
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.10.18.5'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='18.10.18.6'
    Title='(L1) Ensure ''Enable App Installer Microsoft Store Source Certificate Validation Bypass'' is set to ''Disabled'' (Automated)'
    Section='18.10.18 Desktop App Installer'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Windows\AppInstaller'
    ValueName='EnableMicrosoftStoreSourceCertificateValidationBypass'
    Expected=0
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.10.18.6'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='18.10.18.7'
    Title='(L2) Ensure ''Enable Windows Package Manager command line interfaces'' is set to ''Disabled'' (Automated)'
    Section='18.10.18 Desktop App Installer'
    Profile='Level2'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Windows\AppInstaller'
    ValueName='EnableWindowsPackageManagerCommandLineInterfaces'
    Expected=0
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.10.18.7'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },

  # 18.10.26 Event Log Service
  # 18.10.26.1 Application
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
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
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
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  # 18.10.26.2 Security
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
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
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
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  # 18.10.26.3 Setup
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
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
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
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  # 18.10.26.4 System
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
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
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
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },

  # 18.10.29 File Explorer
  @{
    Id='18.10.29.2'
    Title='(L1) Ensure ''Do not apply the Mark of the Web tag to files copied from insecure sources'' is set to ''Disabled'' (Automated)'
    Section='18.10.29 File Explorer'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments'
    ValueName='SaveZoneInformation'
    Expected=2
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.10.29.2'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='18.10.29.3'
    Title='(L1) Ensure ''Turn off Data Execution Prevention for Explorer'' is set to ''Disabled'' (Automated)'
    Section='18.10.29 File Explorer'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer'
    ValueName='NoDataExecutionPrevention'
    Expected=0
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.10.29.3'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='18.10.29.4'
    Title='(L1) Ensure ''Turn off heap termination on corruption'' is set to ''Disabled'' (Automated)'
    Section='18.10.29 File Explorer'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer'
    ValueName='NoHeapTerminationOnCorruption'
    Expected=0
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.10.29.4'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='18.10.29.5'
    Title='(L1) Ensure ''Turn off shell protocol protected mode'' is set to ''Disabled'' (Automated)'
    Section='18.10.29 File Explorer'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'
    ValueName='PreXPSP2ShellProtocolBehavior'
    Expected=0
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.10.29.5'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },

  # 18.10.37 Location and Sensors
  @{
    Id='18.10.37.1'
    Title='(L2) Ensure ''Turn off location'' is set to ''Enabled'' (Automated)'
    Section='18.10.37 Location and Sensors'
    Profile='Level2'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors'
    ValueName='DisableLocation'
    Expected=1
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.10.37.1'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },

  # 18.10.41 Messaging
  @{
    Id='18.10.41.1'
    Title='(L2) Ensure ''Allow Message Service Cloud Sync'' is set to ''Disabled'' (Automated)'
    Section='18.10.41 Messaging'
    Profile='Level2'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Windows\Messaging'
    ValueName='AllowMessageSync'
    Expected=0
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.10.41.1'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },

  # 18.10.42 Microsoft account
  @{
    Id='18.10.42.1'
    Title='(L1) Ensure ''Block all consumer Microsoft account user authentication'' is set to ''Enabled'' (Automated)'
    Section='18.10.42 Microsoft account'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\MicrosoftAccount'
    ValueName='DisableUserAuth'
    Expected=1
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.10.42.1'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },

  # 18.10.43 Microsoft Defender Antivirus
  # 18.10.43.4.1 Features
  @{
    Id='18.10.43.4.1'
    Title='(L1) Ensure ''Enable EDR in block mode'' is set to ''Enabled'' (Automated)'
    Section='18.10.43 Microsoft Defender Antivirus'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Windows Advanced Threat Protection'
    ValueName='ForceDefenderPassiveMode'
    Expected=0
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.10.43.4.1'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  # 18.10.43.5 MAPS
  @{
    Id='18.10.43.5.1'
    Title='(L1) Ensure ''Configure local setting override for reporting to Microsoft MAPS'' is set to ''Disabled'' (Automated)'
    Section='18.10.43 Microsoft Defender Antivirus'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet'
    ValueName='LocalSettingOverrideSpynetReporting'
    Expected=0
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.10.43.5.1'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='18.10.43.5.2'
    Title='(L2) Ensure ''Join Microsoft MAPS'' is set to ''Disabled'' (Automated)'
    Section='18.10.43 Microsoft Defender Antivirus'
    Profile='Level2'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet'
    ValueName='SpynetReporting'
    Expected=0
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.10.43.5.2'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  # 18.10.43.6.1 Attack Surface Reduction
  @{
    Id='18.10.43.6.1.1'
    Title='(L1) Ensure ''Configure Attack Surface Reduction rules'' is set to ''Enabled'' (Automated)'
    Section='18.10.43 Microsoft Defender Antivirus'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR'
    ValueName='ExploitGuard_ASR_Rules'
    Expected=1
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.10.43.6.1.1'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='18.10.43.6.1.2'
    Title='(L1) Ensure ''Configure Attack Surface Reduction rules: Set the state for each ASR rule'' is configured (Automated)'
    Section='18.10.43 Microsoft Defender Antivirus'
    Profile='Level1'
    Type='Manual'
    Expected='ASR rules configured appropriately'
    Evidence='Check Group Policy for ASR rule configuration'
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.10.43.6.1.2'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  # 18.10.43.6.3 Network Protection
  @{
    Id='18.10.43.6.3.1'
    Title='(L1) Ensure ''Prevent users and apps from accessing dangerous websites'' is set to ''Enabled: Block'' (Automated)'
    Section='18.10.43 Microsoft Defender Antivirus'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Network Protection'
    ValueName='EnableNetworkProtection'
    Expected=1
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.10.43.6.3.1'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  # 18.10.43.7 MpEngine
  @{
    Id='18.10.43.7.1'
    Title='(L1) Ensure ''Enable file hash computation feature'' is set to ''Enabled'' (Automated)'
    Section='18.10.43 Microsoft Defender Antivirus'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\MpEngine'
    ValueName='EnableFileHashComputation'
    Expected=1
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.10.43.7.1'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  # 18.10.43.8 Network Inspection System
  @{
    Id='18.10.43.8.1'
    Title='(L2) Ensure ''Convert warn verdict to block'' is set to ''Enabled'' (Automated)'
    Section='18.10.43 Microsoft Defender Antivirus'
    Profile='Level2'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\NIS'
    ValueName='DisableProtocolRecognition'
    Expected=0
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.10.43.8.1'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  # 18.10.43.10 Real-time Protection
  @{
    Id='18.10.43.10.1'
    Title='(L1) Ensure ''Configure real-time protection and Security Intelligence Updates during OOBE'' is set to ''Enabled'' (Automated)'
    Section='18.10.43 Microsoft Defender Antivirus'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection'
    ValueName='RealtimeScanDirection'
    Expected=0
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.10.43.10.1'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='18.10.43.10.2'
    Title='(L1) Ensure ''Scan all downloaded files and attachments'' is set to ''Enabled'' (Automated)'
    Section='18.10.43 Microsoft Defender Antivirus'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection'
    ValueName='DisableIOAVProtection'
    Expected=0
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.10.43.10.2'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='18.10.43.10.3'
    Title='(L1) Ensure ''Turn off real-time protection'' is set to ''Disabled'' (Automated)'
    Section='18.10.43 Microsoft Defender Antivirus'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection'
    ValueName='DisableRealtimeMonitoring'
    Expected=0
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.10.43.10.3'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='18.10.43.10.4'
    Title='(L1) Ensure ''Turn on behavior monitoring'' is set to ''Enabled'' (Automated)'
    Section='18.10.43 Microsoft Defender Antivirus'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection'
    ValueName='DisableBehaviorMonitoring'
    Expected=0
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.10.43.10.4'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='18.10.43.10.5'
    Title='(L1) Ensure ''Turn on script scanning'' is set to ''Enabled'' (Automated)'
    Section='18.10.43 Microsoft Defender Antivirus'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection'
    ValueName='DisableScriptScanning'
    Expected=0
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.10.43.10.5'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  # 18.10.43.11.1.1 Brute-Force Protection
  @{
    Id='18.10.43.11.1.1.1'
    Title='(L2) Ensure ''Configure Brute-Force Protection aggressiveness'' is set to ''Enabled: Medium'' or higher (Automated)'
    Section='18.10.43 Microsoft Defender Antivirus'
    Profile='Level2'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\BruteForceProtection'
    ValueName='BruteForceProtectionAggressiveness'
    Operator='GreaterOrEqual'
    Expected=1
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.10.43.11.1.1.1'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='18.10.43.11.1.1.2'
    Title='(L1) Ensure ''Configure Remote Encryption Protection Mode'' is set to ''Enabled: Audit'' or higher (Automated)'
    Section='18.10.43 Microsoft Defender Antivirus'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\BruteForceProtection'
    ValueName='BruteForceProtectionMode'
    Operator='GreaterOrEqual'
    Expected=1
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.10.43.11.1.1.2'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  # 18.10.43.11.1.2 Remote Encryption Protection
  @{
    Id='18.10.43.11.1.2.1'
    Title='(L2) Ensure ''Configure how aggressively Remote Encryption Protection blocks threats'' is set to ''Enabled: Medium'' or higher (Automated)'
    Section='18.10.43 Microsoft Defender Antivirus'
    Profile='Level2'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\RemoteEncryptionProtection'
    ValueName='AggressivenessLevel'
    Operator='GreaterOrEqual'
    Expected=1
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.10.43.11.1.2.1'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  # 18.10.43.12 Reporting
  @{
    Id='18.10.43.12.1'
    Title='(L2) Ensure ''Configure Watson events'' is set to ''Disabled'' (Automated)'
    Section='18.10.43 Microsoft Defender Antivirus'
    Profile='Level2'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Reporting'
    ValueName='DisableGenericRePorts'
    Expected=1
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.10.43.12.1'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  # 18.10.43.13 Scan
  @{
    Id='18.10.43.13.1'
    Title='(L1) Ensure ''Scan excluded files and directories during quick scans'' is set to ''Enabled: 1'' (Automated)'
    Section='18.10.43 Microsoft Defender Antivirus'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Scan'
    ValueName='DisableArchiveScanning'
    Expected=0
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.10.43.13.1'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='18.10.43.13.2'
    Title='(L1) Ensure ''Scan packed executables'' is set to ''Enabled'' (Automated)'
    Section='18.10.43 Microsoft Defender Antivirus'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Scan'
    ValueName='DisablePackedExeScanning'
    Expected=0
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.10.43.13.2'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='18.10.43.13.3'
    Title='(L1) Ensure ''Scan removable drives'' is set to ''Enabled'' (Automated)'
    Section='18.10.43 Microsoft Defender Antivirus'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Scan'
    ValueName='DisableRemovableDriveScanning'
    Expected=0
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.10.43.13.3'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='18.10.43.13.4'
    Title='(L1) Ensure ''Trigger a quick scan after X days without any scans'' is set to ''Enabled: 7'' (Automated)'
    Section='18.10.43 Microsoft Defender Antivirus'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Scan'
    ValueName='ScanOnlyIfIdleEnabled'
    Expected=1
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.10.43.13.4'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='18.10.43.13.5'
    Title='(L1) Ensure ''Turn on e-mail scanning'' is set to ''Enabled'' (Automated)'
    Section='18.10.43 Microsoft Defender Antivirus'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Scan'
    ValueName='DisableEmailScanning'
    Expected=0
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.10.43.13.5'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='18.10.43.16'
    Title='(L1) Ensure ''Configure detection for potentially unwanted applications'' is set to ''Enabled: Block'' (Automated)'
    Section='18.10.43 Microsoft Defender Antivirus'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Windows Defender'
    ValueName='PUAProtection'
    Expected=1
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.10.43.16'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='18.10.43.17'
    Title='(L1) Ensure ''Control whether exclusions are visible to local users'' is set to ''Enabled'' (Automated)'
    Section='18.10.43 Microsoft Defender Antivirus'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\UX Configuration'
    ValueName='Notification_Suppress'
    Expected=0
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.10.43.17'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },

  # 18.10.51 OneDrive
  @{
    Id='18.10.51.1'
    Title='(L1) Ensure ''Prevent the usage of OneDrive for file storage'' is set to ''Enabled'' (Automated)'
    Section='18.10.51 OneDrive'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Windows\OneDrive'
    ValueName='DisableFileSyncNGSC'
    Expected=1
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.10.51.1'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },

  # 18.10.56 Push To Install
  @{
    Id='18.10.56.1'
    Title='(L2) Ensure ''Turn off Push To Install service'' is set to ''Enabled'' (Automated)'
    Section='18.10.56 Push To Install'
    Profile='Level2'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\PushToInstall'
    ValueName='DisablePushToInstall'
    Expected=1
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.10.56.1'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },

  # 18.10.57 Remote Desktop Services
  # 18.10.57.2.2 Remote Desktop Connection Client
  @{
    Id='18.10.57.2.2'
    Title='(L1) Ensure ''Do not allow passwords to be saved'' is set to ''Enabled'' (Automated)'
    Section='18.10.57 Remote Desktop Services'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
    ValueName='DisablePasswordSaving'
    Expected=1
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.10.57.2.2'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  # 18.10.57.3 Remote Desktop Session Host
  @{
    Id='18.10.57.3.2.1'
    Title='(L2) Ensure ''Restrict Remote Desktop Services users to a single Remote Desktop Services session'' is set to ''Enabled'' (Automated)'
    Section='18.10.57 Remote Desktop Services'
    Profile='Level2'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
    ValueName='fSingleSessionPerUser'
    Expected=1
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.10.57.3.2.1'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  # 18.10.57.3.3 Device and Resource Redirection
  @{
    Id='18.10.57.3.3.1'
    Title='(L2) Ensure ''Do not allow COM port redirection'' is set to ''Enabled'' (Automated)'
    Section='18.10.57 Remote Desktop Services'
    Profile='Level2'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
    ValueName='fDisableCcm'
    Expected=1
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.10.57.3.3.1'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='18.10.57.3.3.2'
    Title='(L1) Ensure ''Do not allow drive redirection'' is set to ''Enabled'' (Automated)'
    Section='18.10.57 Remote Desktop Services'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
    ValueName='fDisableCdm'
    Expected=1
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.10.57.3.3.2'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='18.10.57.3.3.3'
    Title='(L2) Ensure ''Do not allow LPT port redirection'' is set to ''Enabled'' (Automated)'
    Section='18.10.57 Remote Desktop Services'
    Profile='Level2'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
    ValueName='fDisableLPT'
    Expected=1
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.10.57.3.3.3'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='18.10.57.3.3.4'
    Title='(L2) Ensure ''Do not allow supported Plug and Play device redirection'' is set to ''Enabled'' (Automated)'
    Section='18.10.57 Remote Desktop Services'
    Profile='Level2'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
    ValueName='fDisablePNPRedir'
    Expected=1
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.10.57.3.3.4'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  # 18.10.57.3.9 Security
  @{
    Id='18.10.57.3.9.1'
    Title='(L1) Ensure ''Always prompt for password upon connection'' is set to ''Enabled'' (Automated)'
    Section='18.10.57 Remote Desktop Services'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
    ValueName='fPromptForPassword'
    Expected=1
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.10.57.3.9.1'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='18.10.57.3.9.2'
    Title='(L1) Ensure ''Require secure RPC communication'' is set to ''Enabled'' (Automated)'
    Section='18.10.57 Remote Desktop Services'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
    ValueName='fEncryptRPCTraffic'
    Expected=1
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.10.57.3.9.2'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='18.10.57.3.9.3'
    Title='(L1) Ensure ''Require use of specific security layer for remote (RDP) connections'' is set to ''Enabled: SSL'' (Automated)'
    Section='18.10.57 Remote Desktop Services'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
    ValueName='SecurityLayer'
    Expected=2
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.10.57.3.9.3'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='18.10.57.3.9.4'
    Title='(L1) Ensure ''Require user authentication for remote connections by using Network Level Authentication'' is set to ''Enabled'' (Automated)'
    Section='18.10.57 Remote Desktop Services'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
    ValueName='UserAuthentication'
    Expected=1
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.10.57.3.9.4'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='18.10.57.3.9.5'
    Title='(L1) Ensure ''Set client connection encryption level'' is set to ''Enabled: High Level'' (Automated)'
    Section='18.10.57 Remote Desktop Services'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
    ValueName='MinEncryptionLevel'
    Expected=3
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.10.57.3.9.5'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  # 18.10.57.3.10 Session Time Limits
  @{
    Id='18.10.57.3.10.1'
    Title='(L2) Ensure ''Set time limit for active but idle Remote Desktop Services sessions'' is set to ''Enabled: 15 minutes or less, but not Never (0)'' (Automated)'
    Section='18.10.57 Remote Desktop Services'
    Profile='Level2'
    Type='Composite'
    AllOf=@(
        @{ Type='Registry'; Key='HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'; ValueName='MaxIdleTime'; Operator='LessOrEqual'; Expected=900000 },
        @{ Type='Registry'; Key='HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'; ValueName='MaxIdleTime'; Operator='NotEquals'; Expected=0 }
    )
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.10.57.3.10.1'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='18.10.57.3.10.2'
    Title='(L2) Ensure ''Set time limit for disconnected sessions'' is set to ''Enabled: 1 minute'' (Automated)'
    Section='18.10.57 Remote Desktop Services'
    Profile='Level2'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
    ValueName='MaxDisconnectionTime'
    Expected=60000
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.10.57.3.10.2'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  # 18.10.57.3.11 Temporary folders
  @{
    Id='18.10.57.3.11.1'
    Title='(L1) Ensure ''Do not delete temp folders upon exit'' is set to ''Disabled'' (Automated)'
    Section='18.10.57 Remote Desktop Services'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
    ValueName='DeleteTempDirsOnExit'
    Expected=1
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.10.57.3.11.1'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='18.10.57.3.11.2'
    Title='(L1) Ensure ''Do not use temporary folders per session'' is set to ''Disabled'' (Automated)'
    Section='18.10.57 Remote Desktop Services'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
    ValueName='PerSessionTempDir'
    Expected=1
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.10.57.3.11.2'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },

  # 18.10.58 RSS Feeds
  @{
    Id='18.10.58.1'
    Title='(L1) Ensure ''Prevent downloading of enclosures'' is set to ''Enabled'' (Automated)'
    Section='18.10.58 RSS Feeds'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds'
    ValueName='DisableEnclosureDownload'
    Expected=1
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.10.58.1'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='18.10.58.2'
    Title='(L1) Ensure ''Turn on Basic feed authentication over HTTP'' is set to ''Disabled'' (Automated)'
    Section='18.10.58 RSS Feeds'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds'
    ValueName='AllowBasicAuthInClear'
    Expected=0
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.10.58.2'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },

  # 18.10.59 Search
  @{
    Id='18.10.59.2'
    Title='(L2) Ensure ''Allow Cloud Search'' is set to ''Enabled: Disable Cloud Search'' (Automated)'
    Section='18.10.59 Search'
    Profile='Level2'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search'
    ValueName='AllowCloudSearch'
    Expected=0
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.10.59.2'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='18.10.59.3'
    Title='(L1) Ensure ''Allow indexing of encrypted files'' is set to ''Disabled'' (Automated)'
    Section='18.10.59 Search'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search'
    ValueName='AllowIndexingEncryptedStoresOrItems'
    Expected=0
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.10.59.3'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='18.10.59.4'
    Title='(L2) Ensure ''Allow search highlights'' is set to ''Disabled'' (Automated)'
    Section='18.10.59 Search'
    Profile='Level2'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search'
    ValueName='EnableDynamicContentInWSB'
    Expected=0
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.10.59.4'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },

  # 18.10.63 Software Protection Platform
  @{
    Id='18.10.63.1'
    Title='(L2) Ensure ''Turn off KMS Client Online AVS Validation'' is set to ''Enabled'' (Automated)'
    Section='18.10.63 Software Protection Platform'
    Profile='Level2'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\Software Protection Platform'
    ValueName='NoGenTicket'
    Expected=1
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.10.63.1'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },

  # 18.10.76 Windows Defender SmartScreen
  @{
    Id='18.10.76.2.1'
    Title='(L1) Ensure ''Configure Windows Defender SmartScreen'' is set to ''Enabled: Warn and prevent bypass'' (Automated)'
    Section='18.10.76 Windows Defender SmartScreen'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Windows\System'
    ValueName='EnableSmartScreen'
    Expected=2
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.10.76.2.1'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },

  # 18.10.80 Windows Ink Workspace
  @{
    Id='18.10.80.1'
    Title='(L2) Ensure ''Allow suggested apps in Windows Ink Workspace'' is set to ''Disabled'' (Automated)'
    Section='18.10.80 Windows Ink Workspace'
    Profile='Level2'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\WindowsInkWorkspace'
    ValueName='AllowSuggestedAppsInWindowsInkWorkspace'
    Expected=0
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.10.80.1'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='18.10.80.2'
    Title='(L1) Ensure ''Allow Windows Ink Workspace'' is set to ''Enabled: On, but disallow access above lock'' OR ''Enabled: Disabled'' (Automated)'
    Section='18.10.80 Windows Ink Workspace'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\WindowsInkWorkspace'
    ValueName='AllowWindowsInkWorkspace'
    Operator='LessOrEqual'
    Expected=1
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.10.80.2'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },

  # 18.10.81 Windows Installer
  @{
    Id='18.10.81.1'
    Title='(L1) Ensure ''Allow user control over installs'' is set to ''Disabled'' (Automated)'
    Section='18.10.81 Windows Installer'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer'
    ValueName='EnableUserControl'
    Expected=0
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.10.81.1'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='18.10.81.2'
    Title='(L1) Ensure ''Always install with elevated privileges'' is set to ''Disabled'' (Automated)'
    Section='18.10.81 Windows Installer'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer'
    ValueName='AlwaysInstallElevated'
    Expected=0
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.10.81.2'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='18.10.81.3'
    Title='(L2) Ensure ''Prevent Internet Explorer security prompt for Windows Installer scripts'' is set to ''Disabled'' (Automated)'
    Section='18.10.81 Windows Installer'
    Profile='Level2'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer'
    ValueName='SafeForScripting'
    Expected=0
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.10.81.3'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },

  # 18.10.82 Windows Logon Options
  @{
    Id='18.10.82.1'
    Title='(L1) Ensure ''Sign-in and lock last interactive user automatically after a restart'' is set to ''Disabled'' (Automated)'
    Section='18.10.82 Windows Logon Options'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
    ValueName='DisableAutomaticRestartSignOn'
    Expected=1
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.10.82.1'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },

  # 18.10.87 Windows PowerShell
  @{
    Id='18.10.87.1'
    Title='(L2) Ensure ''Turn on PowerShell Script Block Logging'' is set to ''Enabled'' (Automated)'
    Section='18.10.87 Windows PowerShell'
    Profile='Level2'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
    ValueName='EnableScriptBlockLogging'
    Expected=1
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.10.87.1'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='18.10.87.2'
    Title='(L2) Ensure ''Turn on PowerShell Transcription'' is set to ''Enabled'' (Automated)'
    Section='18.10.87 Windows PowerShell'
    Profile='Level2'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription'
    ValueName='EnableTranscripting'
    Expected=1
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.10.87.2'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },

  # 18.10.89 Windows Remote Management (WinRM)
  # 18.10.89.1 WinRM Client
  @{
    Id='18.10.89.1.1'
    Title='(L1) Ensure ''Allow Basic authentication'' is set to ''Disabled'' (Automated)'
    Section='18.10.89 Windows Remote Management'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client'
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
    Section='18.10.89 Windows Remote Management'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client'
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
    Section='18.10.89 Windows Remote Management'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client'
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
    Section='18.10.89 Windows Remote Management'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service'
    ValueName='AllowBasic'
    Expected=0
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.10.89.2.1'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='18.10.89.2.2'
    Title='(L2) Ensure ''Allow remote server management through WinRM'' is set to ''Disabled'' (Automated)'
    Section='18.10.89 Windows Remote Management'
    Profile='Level2'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service'
    ValueName='AllowAutoConfig'
    Expected=0
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.10.89.2.2'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='18.10.89.2.3'
    Title='(L1) Ensure ''Allow unencrypted traffic'' is set to ''Disabled'' (Automated)'
    Section='18.10.89 Windows Remote Management'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service'
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
    Section='18.10.89 Windows Remote Management'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service'
    ValueName='DisallowRunAsCredentials'
    Expected=1
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.10.89.2.4'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },

  # 18.10.90 Windows Remote Shell
  @{
    Id='18.10.90.1'
    Title='(L2) Ensure ''Allow Remote Shell Access'' is set to ''Disabled'' (Automated)'
    Section='18.10.90 Windows Remote Shell'
    Profile='Level2'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service\WinRS'
    ValueName='AllowRemoteShellAccess'
    Expected=0
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.10.90.1'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },

  # 18.10.92 Windows Security
  @{
    Id='18.10.92.2.1'
    Title='(L1) Ensure ''Prevent users from modifying settings'' is set to ''Enabled'' (Automated)'
    Section='18.10.92 Windows Security'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\App and Browser protection'
    ValueName='DisallowExploitProtectionOverride'
    Expected=1
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.10.92.2.1'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },

  # 18.10.93 Windows Update
  @{
    Id='18.10.93.1.1'
    Title='(L1) Ensure ''No auto-restart with logged on users for scheduled automatic updates installations'' is set to ''Disabled'' (Automated)'
    Section='18.10.93 Windows Update'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU'
    ValueName='NoAutoRebootWithLoggedOnUsers'
    Expected=0
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.10.93.1.1'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='18.10.93.2.1'
    Title='(L1) Ensure ''Configure Automatic Updates'' is set to ''Enabled'' (Automated)'
    Section='18.10.93 Windows Update'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU'
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
    Section='18.10.93 Windows Update'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU'
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
    Section='18.10.93 Windows Update'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'
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
    Section='18.10.93 Windows Update'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'
    ValueName='DeferFeatureUpdatesPeriodInDays'
    Operator='GreaterOrEqual'
    Expected=180
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.10.93.4.2'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='18.10.93.4.3'
    Title='(L1) Ensure ''Select when Quality Updates are received'' is set to ''Enabled: 0 days'' (Automated)'
    Section='18.10.93 Windows Update'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'
    ValueName='DeferQualityUpdatesPeriodInDays'
    Expected=0
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.10.93.4.3'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  }
)