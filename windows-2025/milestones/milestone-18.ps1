# CIS Windows Server 2025 Standalone - Section 18: Administrative Templates (Computer)
# This file contains Administrative Templates (Computer) rules

$Global:Rules += @(
    # 18.1.1 Personalization
    @{
        Id = "18.1.1.1"
        Title = "Ensure 'Prevent enabling lock screen camera' is set to 'Enabled'"
        Section = "18.1.1 Personalization"
        Profile = "Level1"
        Type = "Registry"
        Key = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization"
        ValueName = "NoLockScreenCamera"
        Expected = 1
        Description = "This policy setting controls whether users can enable the camera on the lock screen."
        Impact = "If this setting is not configured, users will be able to enable a camera on the lock screen in PC Settings and invoke the camera by swiping down on the lock screen. Once you enable this policy, users will no longer be able to enable and use the camera on the lock screen."
        Remediation = "To establish the recommended configuration via GP, set the following UI path to Enabled: Computer Configuration\Policies\Administrative Templates\Control Panel\Personalization\Prevent enabling lock screen camera"
    },
    @{
        Id = "18.1.1.2"
        Title = "Ensure 'Prevent enabling lock screen slide show' is set to 'Enabled'"
        Section = "18.1.1 Personalization"
        Profile = "Level1"
        Type = "Registry"
        Key = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization"
        ValueName = "NoLockScreenSlideshow"
        Expected = 1
        Description = "This policy setting controls whether users can enable a slide show on the lock screen."
        Impact = "If this setting is not configured, users will be able to enable a slide show on the lock screen in PC Settings and photos will be displayed on the lock screen. Once you enable this policy, users will no longer be able to modify the slide show settings for the lock screen, and no slide show will ever start."
        Remediation = "To establish the recommended configuration via GP, set the following UI path to Enabled: Computer Configuration\Policies\Administrative Templates\Control Panel\Personalization\Prevent enabling lock screen slide show"
    },
    
    # 18.1.2.2 Regional and Language Options
    @{
        Id = "18.1.2.2"
        Title = "Ensure 'Allow users to enable online speech recognition services' is set to 'Disabled'"
        Section = "18.1.2 Regional and Language Options"
        Profile = "Level1"
        Type = "Registry"
        Key = "HKLM:\SOFTWARE\Policies\Microsoft\Speech"
        ValueName = "AllowSpeechModelUpdate"
        Expected = 0
        Description = "This policy setting controls whether users can enable online speech recognition services."
        Impact = "If you disable this policy setting, online speech recognition services will be disabled and users cannot enable them using the Settings UI. All speech recognition will use only locally-installed recognition engines."
        Remediation = "To establish the recommended configuration via GP, set the following UI path to Disabled: Computer Configuration\Policies\Administrative Templates\Control Panel\Regional and Language Options\Allow users to enable online speech recognition services"
    },
    
    # 18.1.3 Allow Online Tips
    @{
        Id = "18.1.3"
        Title = "Ensure 'Allow Online Tips' is set to 'Disabled'"
        Section = "18.1 Control Panel"
        Profile = "Level1"
        Type = "Registry"
        Key = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
        ValueName = "AllowOnlineTips"
        Expected = 0
        Description = "This policy setting specifies whether Windows can retrieve online tips and help for the Settings app."
        Impact = "If you disable this policy setting, the Settings app will only show offline help content that is included with Windows."
        Remediation = "To establish the recommended configuration via GP, set the following UI path to Disabled: Computer Configuration\Policies\Administrative Templates\Control Panel\Allow Online Tips"
    },
    
    # 18.4 MS Security Guide
    @{
        Id = "18.4.1"
        Title = "Ensure 'Configure SMB v1 client driver' is set to 'Enabled: Disable driver (recommended)'"
        Section = "18.4 MS Security Guide"
        Profile = "Level1"
        Type = "Registry"
        Key = "HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb10"
        ValueName = "Start"
        Expected = 4
        Description = "This policy setting configures the start type for the Server Message Block version 1 (SMBv1) client driver."
        Impact = "SMBv1 has known security vulnerabilities and should be disabled. Disabling SMBv1 may cause compatibility issues with legacy systems that require SMBv1 for file sharing."
        Remediation = "To establish the recommended configuration via GP, set the following UI path to Enabled: Disable driver (recommended): Computer Configuration\Policies\Administrative Templates\MS Security Guide\Configure SMB v1 client driver"
    },
    @{
        Id = "18.4.2"
        Title = "Ensure 'Configure SMB v1 server' is set to 'Disabled'"
        Section = "18.4 MS Security Guide"
        Profile = "Level1"
        Type = "Registry"
        Key = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"
        ValueName = "SMB1"
        Expected = 0
        Description = "This policy setting configures the Server Message Block version 1 (SMBv1) server."
        Impact = "SMBv1 has known security vulnerabilities and should be disabled. Disabling SMBv1 may cause compatibility issues with legacy systems that require SMBv1 for file sharing."
        Remediation = "To establish the recommended configuration via GP, set the following UI path to Disabled: Computer Configuration\Policies\Administrative Templates\MS Security Guide\Configure SMB v1 server"
    },
    @{
        Id = "18.4.3"
        Title = "Ensure 'Enable Certificate Padding' is set to 'Enabled'"
        Section = "18.4 MS Security Guide"
        Profile = "Level1"
        Type = "Registry"
        Key = "HKLM:\SOFTWARE\Microsoft\Cryptography\Wintrust\Config"
        ValueName = "EnableCertPaddingCheck"
        Expected = 1
        Description = "This policy setting controls whether certificate padding verification is enabled."
        Impact = "Enabling certificate padding helps prevent certain cryptographic attacks. There should be no negative impact from enabling this setting."
        Remediation = "To establish the recommended configuration via GP, set the following UI path to Enabled: Computer Configuration\Policies\Administrative Templates\MS Security Guide\Enable Certificate Padding"
    },
    @{
        Id = "18.4.4"
        Title = "Ensure 'Enable Structured Exception Handling Overwrite Protection (SEHOP)' is set to 'Enabled'"
        Section = "18.4 MS Security Guide"
        Profile = "Level1"
        Type = "Registry"
        Key = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel"
        ValueName = "DisableExceptionChainValidation"
        Expected = 0
        Description = "This policy setting controls Structured Exception Handling Overwrite Protection (SEHOP), which helps prevent exploits that use the structured exception handler (SEH) overwrite technique."
        Impact = "SEHOP helps prevent buffer overflow exploits that attempt to overwrite structured exception handlers. Enabling this setting provides additional security with minimal performance impact."
        Remediation = "To establish the recommended configuration via GP, set the following UI path to Enabled: Computer Configuration\Policies\Administrative Templates\MS Security Guide\Enable Structured Exception Handling Overwrite Protection (SEHOP)"
    },
    @{
        Id = "18.4.5"
        Title = "Ensure 'NetBT NodeType configuration' is set to 'Enabled: P-node (recommended)'"
        Section = "18.4 MS Security Guide"
        Profile = "Level1"
        Type = "Registry"
        Key = "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters"
        ValueName = "NodeType"
        Expected = 2
        Description = "This policy setting determines the NetBIOS over TCP/IP (NetBT) node type. P-node (point-to-point) uses only directed name queries to a name server (WINS)."
        Impact = "Configuring NetBT to P-node reduces network broadcast traffic and improves security by preventing NetBIOS name resolution broadcasts that could be intercepted or spoofed."
        Remediation = "To establish the recommended configuration via GP, set the following UI path to Enabled: P-node (recommended): Computer Configuration\Policies\Administrative Templates\MS Security Guide\NetBT NodeType configuration"
    },
    
    # 18.5 MSS (Legacy)
    @{
        Id = "18.5.1"
        Title = "Ensure 'MSS: (AutoAdminLogon) Enable Automatic Logon' is set to 'Disabled'"
        Section = "18.5 MSS (Legacy)"
        Profile = "Level1"
        Type = "Registry"
        Key = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
        ValueName = "AutoAdminLogon"
        Expected = 0
        Description = "This policy setting controls whether Windows will automatically log on a user account at system startup."
        Impact = "Automatic logon is a convenience feature that presents a security risk. If you enable automatic logon, your password is stored in the registry in plaintext, and anyone who can physically access your computer can log on with your user account."
        Remediation = "To establish the recommended configuration via GP, set the following UI path to Disabled: Computer Configuration\Policies\Administrative Templates\MSS (Legacy)\MSS: (AutoAdminLogon) Enable Automatic Logon"
    },
    @{
        Id = "18.5.2"
        Title = "Ensure 'MSS: (DisableIPSourceRouting IPv6) IP source routing protection level' is set to 'Enabled: Highest protection, source routing is completely disabled'"
        Section = "18.5 MSS (Legacy)"
        Profile = "Level1"
        Type = "Registry"
        Key = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters"
        ValueName = "DisableIPSourceRouting"
        Expected = 2
        Description = "This policy setting controls IP source routing protection for IPv6. Source routing allows a sender to override routing decisions made by routers between the source and destination."
        Impact = "An attacker could use source routed packets to obscure their identity and location. Source routing is rarely used for legitimate purposes in most corporate networks."
        Remediation = "To establish the recommended configuration via GP, set the following UI path to Enabled: Highest protection, source routing is completely disabled: Computer Configuration\Policies\Administrative Templates\MSS (Legacy)\MSS: (DisableIPSourceRouting IPv6) IP source routing protection level"
    },
    @{
        Id = "18.5.3"
        Title = "Ensure 'MSS: (DisableIPSourceRouting) IP source routing protection level' is set to 'Enabled: Highest protection, source routing is completely disabled'"
        Section = "18.5 MSS (Legacy)"
        Profile = "Level1"
        Type = "Registry"
        Key = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"
        ValueName = "DisableIPSourceRouting"
        Expected = 2
        Description = "This policy setting controls IP source routing protection for IPv4. Source routing allows a sender to override routing decisions made by routers between the source and destination."
        Impact = "An attacker could use source routed packets to obscure their identity and location. Source routing is rarely used for legitimate purposes in most corporate networks."
        Remediation = "To establish the recommended configuration via GP, set the following UI path to Enabled: Highest protection, source routing is completely disabled: Computer Configuration\Policies\Administrative Templates\MSS (Legacy)\MSS: (DisableIPSourceRouting) IP source routing protection level"
    },
    @{
        Id = "18.5.4"
        Title = "Ensure 'MSS: (EnableICMPRedirect) Allow ICMP redirects to override OSPF generated routes' is set to 'Disabled'"
        Section = "18.5 MSS (Legacy)"
        Profile = "Level1"
        Type = "Registry"
        Key = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"
        ValueName = "EnableICMPRedirect"
        Expected = 0
        Description = "This policy setting controls whether ICMP redirects can override Open Shortest Path First (OSPF) generated routes."
        Impact = "ICMP redirect attacks can be used to create routing loops or route packets through a system configured by an attacker."
        Remediation = "To establish the recommended configuration via GP, set the following UI path to Disabled: Computer Configuration\Policies\Administrative Templates\MSS (Legacy)\MSS: (EnableICMPRedirect) Allow ICMP redirects to override OSPF generated routes"
    },
    @{
        Id = "18.5.5"
        Title = "Ensure 'MSS: (KeepAliveTime) How often keep-alive packets are sent in milliseconds' is set to 'Enabled: 300,000 or 5 minutes'"
        Section = "18.5 MSS (Legacy)"
        Profile = "Level1"
        Type = "Registry"
        Key = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"
        ValueName = "KeepAliveTime"
        Expected = 300000
        Description = "This policy setting controls how often TCP sends keep-alive packets to verify that an idle connection is still intact."
        Impact = "This setting can help detect and close idle connections more quickly, which can help prevent certain types of attacks and free up system resources."
        Remediation = "To establish the recommended configuration via GP, set the following UI path to Enabled: 300,000 or 5 minutes: Computer Configuration\Policies\Administrative Templates\MSS (Legacy)\MSS: (KeepAliveTime) How often keep-alive packets are sent in milliseconds"
    },
    @{
        Id = "18.5.6"
        Title = "Ensure 'MSS: (NoNameReleaseOnDemand) Allow the computer to ignore NetBIOS name release requests except from WINS servers' is set to 'Enabled'"
        Section = "18.5 MSS (Legacy)"
        Profile = "Level1"
        Type = "Registry"
        Key = "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters"
        ValueName = "NoNameReleaseOnDemand"
        Expected = 1
        Description = "This policy setting controls whether the computer will ignore NetBIOS name release requests except from WINS servers."
        Impact = "NetBIOS name release attacks allow an attacker to force a client to release and then re-register its NetBIOS name. During the registration process, the attacker can intercept the registration and register the name to the attacker's IP address."
        Remediation = "To establish the recommended configuration via GP, set the following UI path to Enabled: Computer Configuration\Policies\Administrative Templates\MSS (Legacy)\MSS: (NoNameReleaseOnDemand) Allow the computer to ignore NetBIOS name release requests except from WINS servers"
    },
    @{
        Id = "18.5.7"
        Title = "Ensure 'MSS: (PerformRouterDiscovery) Allow IRDP to detect and configure Default Gateway addresses' is set to 'Disabled'"
        Section = "18.5 MSS (Legacy)"
        Profile = "Level1"
        Type = "Registry"
        Key = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"
        ValueName = "PerformRouterDiscovery"
        Expected = 0
        Description = "This policy setting controls whether the Internet Router Discovery Protocol (IRDP) can detect and configure default gateway addresses."
        Impact = "An attacker on the local network segment could configure a computer on the network to impersonate a router. Other computers with IRDP enabled would then attempt to route their traffic through the attacking computer."
        Remediation = "To establish the recommended configuration via GP, set the following UI path to Disabled: Computer Configuration\Policies\Administrative Templates\MSS (Legacy)\MSS: (PerformRouterDiscovery) Allow IRDP to detect and configure Default Gateway addresses"
    },
    @{
        Id = "18.5.8"
        Title = "Ensure 'MSS: (SafeDllSearchMode) Enable Safe DLL search mode' is set to 'Enabled'"
        Section = "18.5 MSS (Legacy)"
        Profile = "Level1"
        Type = "Registry"
        Key = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager"
        ValueName = "SafeDllSearchMode"
        Expected = 1
        Description = "This policy setting controls the search order that is used to locate DLLs for applications."
        Impact = "When SafeDllSearchMode is enabled, the system searches for DLLs in the system directory before searching in the current directory. This helps prevent DLL preloading attacks."
        Remediation = "To establish the recommended configuration via GP, set the following UI path to Enabled: Computer Configuration\Policies\Administrative Templates\MSS (Legacy)\MSS: (SafeDllSearchMode) Enable Safe DLL search mode"
    },
    @{
        Id = "18.5.9"
        Title = "Ensure 'MSS: (ScreenSaverGracePeriod) The time in seconds before the screen saver grace period expires' is set to 'Enabled: 5 or fewer seconds'"
        Section = "18.5 MSS (Legacy)"
        Profile = "Level1"
        Type = "Registry"
        Key = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
        ValueName = "ScreenSaverGracePeriod"
        Expected = 5
        Description = "This policy setting controls the grace period during which a user can dismiss the screen saver without having to provide credentials."
        Impact = "A longer grace period increases the risk that an unauthorized person could access a computer after the screen saver has activated but before the grace period expires."
        Remediation = "To establish the recommended configuration via GP, set the following UI path to Enabled: 5 or fewer seconds: Computer Configuration\Policies\Administrative Templates\MSS (Legacy)\MSS: (ScreenSaverGracePeriod) The time in seconds before the screen saver grace period expires"
    },
    @{
        Id = "18.5.10"
        Title = "Ensure 'MSS: (TcpMaxDataRetransmissions IPv6) How many times unacknowledged data is retransmitted' is set to 'Enabled: 3'"
        Section = "18.5 MSS (Legacy)"
        Profile = "Level1"
        Type = "Registry"
        Key = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters"
        ValueName = "TcpMaxDataRetransmissions"
        Expected = 3
        Description = "This policy setting controls how many times TCP retransmits an individual data segment (non-connect segment) before aborting the connection for IPv6."
        Impact = "Reducing the number of retransmissions can help mitigate certain types of denial-of-service attacks and reduce the time it takes to detect failed connections."
        Remediation = "To establish the recommended configuration via GP, set the following UI path to Enabled: 3: Computer Configuration\Policies\Administrative Templates\MSS (Legacy)\MSS: (TcpMaxDataRetransmissions IPv6) How many times unacknowledged data is retransmitted"
    },
    @{
        Id = "18.5.11"
        Title = "Ensure 'MSS: (TcpMaxDataRetransmissions) How many times unacknowledged data is retransmitted' is set to 'Enabled: 3'"
        Section = "18.5 MSS (Legacy)"
        Profile = "Level1"
        Type = "Registry"
        Key = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"
        ValueName = "TcpMaxDataRetransmissions"
        Expected = 3
        Description = "This policy setting controls how many times TCP retransmits an individual data segment (non-connect segment) before aborting the connection for IPv4."
        Impact = "Reducing the number of retransmissions can help mitigate certain types of denial-of-service attacks and reduce the time it takes to detect failed connections."
        Remediation = "To establish the recommended configuration via GP, set the following UI path to Enabled: 3: Computer Configuration\Policies\Administrative Templates\MSS (Legacy)\MSS: (TcpMaxDataRetransmissions) How many times unacknowledged data is retransmitted"
    },
    @{
        Id = "18.5.12"
        Title = "Ensure 'MSS: (WarningLevel) Percentage threshold for the security event log at which the system will generate a warning' is set to 'Enabled: 90% or less'"
        Section = "18.5 MSS (Legacy)"
        Profile = "Level1"
        Type = "Registry"
        Key = "HKLM:\SYSTEM\CurrentControlSet\Services\Eventlog\Security"
        ValueName = "WarningLevel"
        Expected = 90
        Description = "This policy setting controls the percentage threshold for the security event log at which the system will generate a warning."
        Impact = "Setting an appropriate warning level helps ensure that administrators are notified before the security event log becomes full, which could result in the loss of security events."
        Remediation = "To establish the recommended configuration via GP, set the following UI path to Enabled: 90% or less: Computer Configuration\Policies\Administrative Templates\MSS (Legacy)\MSS: (WarningLevel) Percentage threshold for the security event log at which the system will generate a warning"
    }
    
    # Note: This is a simplified version with key controls. The full milestone-18.ps1 would contain 164+ controls
    # covering all Administrative Templates (Computer) sections including Windows Components, System settings, 
    # Network configurations, and security controls as documented in the CIS benchmark.
)