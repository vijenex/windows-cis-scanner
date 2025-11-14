# 18.5-18.6 MSS Legacy & Network Controls (Windows Server 2019)
$Global:Rules += @(
  # 18.5 MSS (Legacy)
  @{
    Id='18.5.1'
    Title='(L1) Ensure ''MSS: (AutoAdminLogon) Enable Automatic Logon'' is set to ''Disabled'' (Automated)'
    Section='18.5 MSS (Legacy)'
    Profile='Level1'
    Type='Registry'
    Key='HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon'
    ValueName='AutoAdminLogon'
    Expected='0'
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.5.1'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, please refer to the official CIS Microsoft Windows Server 2019 Benchmark document at the above URL.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='18.5.2'
    Title='(L1) Ensure ''MSS: (DisableIPSourceRouting IPv6) IP source routing protection level'' is set to ''Enabled: Highest protection, source routing is completely disabled'' (Automated)'
    Section='18.5 MSS (Legacy)'
    Profile='Level1'
    Type='Registry'
    Key='HKLM:\System\CurrentControlSet\Services\Tcpip6\Parameters'
    ValueName='DisableIPSourceRouting'
    Expected=2
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.5.2'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, please refer to the official CIS Microsoft Windows Server 2019 Benchmark document at the above URL.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='18.5.3'
    Title='(L1) Ensure ''MSS: (DisableIPSourceRouting) IP source routing protection level'' is set to ''Enabled: Highest protection, source routing is completely disabled'' (Automated)'
    Section='18.5 MSS (Legacy)'
    Profile='Level1'
    Type='Registry'
    Key='HKLM:\System\CurrentControlSet\Services\Tcpip\Parameters'
    ValueName='DisableIPSourceRouting'
    Expected=2
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.5.3'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, please refer to the official CIS Microsoft Windows Server 2019 Benchmark document at the above URL.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='18.5.4'
    Title='(L1) Ensure ''MSS: (EnableICMPRedirect) Allow ICMP redirects to override OSPF generated routes'' is set to ''Disabled'' (Automated)'
    Section='18.5 MSS (Legacy)'
    Profile='Level1'
    Type='Registry'
    Key='HKLM:\System\CurrentControlSet\Services\Tcpip\Parameters'
    ValueName='EnableICMPRedirect'
    Expected=0
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.5.4'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, please refer to the official CIS Microsoft Windows Server 2019 Benchmark document at the above URL.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='18.5.6'
    Title='(L1) Ensure ''MSS: (NoNameReleaseOnDemand) Allow the computer to ignore NetBIOS name release requests except from WINS servers'' is set to ''Enabled'' (Automated)'
    Section='18.5 MSS (Legacy)'
    Profile='Level1'
    Type='Registry'
    Key='HKLM:\System\CurrentControlSet\Services\NetBT\Parameters'
    ValueName='NoNameReleaseOnDemand'
    Expected=1
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.5.6'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, please refer to the official CIS Microsoft Windows Server 2019 Benchmark document at the above URL.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='18.5.8'
    Title='(L1) Ensure ''MSS: (SafeDllSearchMode) Enable Safe DLL search mode'' is set to ''Enabled'' (Automated)'
    Section='18.5 MSS (Legacy)'
    Profile='Level1'
    Type='Registry'
    Key='HKLM:\System\CurrentControlSet\Control\Session Manager'
    ValueName='SafeDllSearchMode'
    Expected=1
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.5.8'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, please refer to the official CIS Microsoft Windows Server 2019 Benchmark document at the above URL.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='18.5.9'
    Title='(L1) Ensure ''MSS: (ScreenSaverGracePeriod) The time in seconds before the screen saver grace period expires'' is set to ''Enabled: 5 or fewer seconds'' (Automated)'
    Section='18.5 MSS (Legacy)'
    Profile='Level1'
    Type='Registry'
    Key='HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon'
    ValueName='ScreenSaverGracePeriod'
    Expected=5
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.5.9'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, please refer to the official CIS Microsoft Windows Server 2019 Benchmark document at the above URL.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },

  # 18.6.4 DNS Client
  @{
    Id='18.6.4.1'
    Title='(L1) Ensure ''Configure multicast DNS (mDNS) protocol'' is set to ''Disabled'' (Automated)'
    Section='18.6.4 DNS Client'
    Profile='Level1'
    Type='Registry'
    Key='HKLM:\Software\Policies\Microsoft\Windows NT\DNSClient'
    ValueName='EnableMulticast'
    Expected=0
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.6.4.1'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, please refer to the official CIS Microsoft Windows Server 2019 Benchmark document at the above URL.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='18.6.4.4'
    Title='(L1) Ensure ''Turn off multicast name resolution'' is set to ''Enabled'' (Automated)'
    Section='18.6.4 DNS Client'
    Profile='Level1'
    Type='Registry'
    Key='HKLM:\Software\Policies\Microsoft\Windows NT\DNSClient'
    ValueName='EnableMulticast'
    Expected=0
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.6.4.4'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, please refer to the official CIS Microsoft Windows Server 2019 Benchmark document at the above URL.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },

  # 18.6.8 Lanman Workstation
  @{
    Id='18.6.8.1'
    Title='(L1) Ensure ''Enable insecure guest logons'' is set to ''Disabled'' (Automated)'
    Section='18.6.8 Lanman Workstation'
    Profile='Level1'
    Type='Registry'
    Key='HKLM:\Software\Policies\Microsoft\Windows\LanmanWorkstation'
    ValueName='AllowInsecureGuestAuth'
    Expected=0
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.6.8.1'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, please refer to the official CIS Microsoft Windows Server 2019 Benchmark document at the above URL.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },

  # 18.6.11 Network Connections
  @{
    Id='18.6.11.2'
    Title='(L1) Ensure ''Prohibit installation and configuration of Network Bridge on your DNS domain network'' is set to ''Enabled'' (Automated)'
    Section='18.6.11 Network Connections'
    Profile='Level1'
    Type='Registry'
    Key='HKLM:\Software\Policies\Microsoft\Windows\Network Connections'
    ValueName='NC_AllowNetBridge_NLA'
    Expected=0
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.6.11.2'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, please refer to the official CIS Microsoft Windows Server 2019 Benchmark document at the above URL.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='18.6.11.3'
    Title='(L1) Ensure ''Prohibit use of Internet Connection Sharing on your DNS domain network'' is set to ''Enabled'' (Automated)'
    Section='18.6.11 Network Connections'
    Profile='Level1'
    Type='Registry'
    Key='HKLM:\Software\Policies\Microsoft\Windows\Network Connections'
    ValueName='NC_ShowSharedAccessUI'
    Expected=0
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.6.11.3'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, please refer to the official CIS Microsoft Windows Server 2019 Benchmark document at the above URL.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='18.6.11.4'
    Title='(L1) Ensure ''Require domain users to elevate when setting a network''s location'' is set to ''Enabled'' (Automated)'
    Section='18.6.11 Network Connections'
    Profile='Level1'
    Type='Registry'
    Key='HKLM:\Software\Policies\Microsoft\Windows\Network Connections'
    ValueName='NC_StdDomainUserSetLocation'
    Expected=1
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.6.11.4'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, please refer to the official CIS Microsoft Windows Server 2019 Benchmark document at the above URL.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },

  # 18.6.21 Windows Connection Manager
  @{
    Id='18.6.21.1'
    Title='(L1) Ensure ''Minimize the number of simultaneous connections to the Internet or a Windows Domain'' is set to ''Enabled: 3 = Prevent Wi-Fi when on Ethernet'' (Automated)'
    Section='18.6.21 Windows Connection Manager'
    Profile='Level1'
    Type='Registry'
    Key='HKLM:\Software\Policies\Microsoft\Windows\WcmSvc\GroupPolicy'
    ValueName='fMinimizeConnections'
    Expected=3
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.6.21.1'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, please refer to the official CIS Microsoft Windows Server 2019 Benchmark document at the above URL.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  }
)