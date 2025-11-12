# CIS Windows Server 2025 Standalone - Section 19: Administrative Templates (User)
# This file contains Administrative Templates (User) rules

$Global:Rules += @(
    # 19.5.1.1 Notifications
    @{
        Id = "19.5.1.1"
        Title = "Ensure 'Turn off toast notifications on the lock screen' is set to 'Enabled'"
        Section = "19.5.1 Notifications"
        Profile = "Level1"
        Type = "Manual"
        Expected = "Enabled"
        Evidence = "Check User Configuration GPO settings"
        Description = "This policy setting controls whether toast notifications are displayed on the lock screen."
        Impact = "Disabling toast notifications on the lock screen prevents potential information disclosure when the system is locked."
        Remediation = "To establish the recommended configuration via GP, set the following UI path to Enabled: User Configuration\Policies\Administrative Templates\Start Menu and Taskbar\Notifications\Turn off toast notifications on the lock screen"
    },
    
    # 19.6.6.1.1 Internet Communication settings
    @{
        Id = "19.6.6.1.1"
        Title = "Ensure 'Turn off Help Experience Improvement Program' is set to 'Enabled'"
        Section = "19.6.6.1 Internet Communication settings"
        Profile = "Level1"
        Type = "Manual"
        Expected = "Enabled"
        Evidence = "Check User Configuration GPO settings"
        Description = "This policy setting controls whether users can participate in the Help Experience Improvement Program."
        Impact = "Disabling the Help Experience Improvement Program prevents potentially sensitive usage data from being sent to Microsoft."
        Remediation = "To establish the recommended configuration via GP, set the following UI path to Enabled: User Configuration\Policies\Administrative Templates\System\Internet Communication Management\Internet Communication settings\Turn off Help Experience Improvement Program"
    },
    
    # 19.7.5 Attachment Manager
    @{
        Id = "19.7.5.1"
        Title = "Ensure 'Do not preserve zone information in file attachments' is set to 'Disabled'"
        Section = "19.7.5 Attachment Manager"
        Profile = "Level1"
        Type = "Manual"
        Expected = "Disabled"
        Evidence = "Check User Configuration GPO settings"
        Description = "This policy setting controls whether Windows preserves zone information for file attachments."
        Impact = "Preserving zone information helps Windows identify potentially dangerous files and apply appropriate security measures."
        Remediation = "To establish the recommended configuration via GP, set the following UI path to Disabled: User Configuration\Policies\Administrative Templates\Windows Components\Attachment Manager\Do not preserve zone information in file attachments"
    },
    @{
        Id = "19.7.5.2"
        Title = "Ensure 'Notify antivirus programs when opening attachments' is set to 'Enabled'"
        Section = "19.7.5 Attachment Manager"
        Profile = "Level1"
        Type = "Manual"
        Expected = "Enabled"
        Evidence = "Check User Configuration GPO settings"
        Description = "This policy setting controls whether antivirus programs are notified when users open file attachments."
        Impact = "Notifying antivirus programs ensures that attachments are scanned before being opened, providing protection against malware."
        Remediation = "To establish the recommended configuration via GP, set the following UI path to Enabled: User Configuration\Policies\Administrative Templates\Windows Components\Attachment Manager\Notify antivirus programs when opening attachments"
    },
    
    # 19.7.8 Cloud Content
    @{
        Id = "19.7.8.1"
        Title = "Ensure 'Configure Windows spotlight on lock screen' is set to 'Disabled'"
        Section = "19.7.8 Cloud Content"
        Profile = "Level1"
        Type = "Manual"
        Expected = "Disabled"
        Evidence = "Check User Configuration GPO settings"
        Description = "This policy setting controls whether Windows spotlight is displayed on the lock screen."
        Impact = "Disabling Windows spotlight prevents potentially distracting content and reduces data usage from cloud-based content."
        Remediation = "To establish the recommended configuration via GP, set the following UI path to Disabled: User Configuration\Policies\Administrative Templates\Windows Components\Cloud Content\Configure Windows spotlight on lock screen"
    },
    @{
        Id = "19.7.8.2"
        Title = "Ensure 'Do not suggest third-party content in Windows spotlight' is set to 'Enabled'"
        Section = "19.7.8 Cloud Content"
        Profile = "Level1"
        Type = "Manual"
        Expected = "Enabled"
        Evidence = "Check User Configuration GPO settings"
        Description = "This policy setting controls whether third-party content is suggested in Windows spotlight."
        Impact = "Disabling third-party suggestions prevents potentially unwanted content and reduces privacy concerns."
        Remediation = "To establish the recommended configuration via GP, set the following UI path to Enabled: User Configuration\Policies\Administrative Templates\Windows Components\Cloud Content\Do not suggest third-party content in Windows spotlight"
    },
    @{
        Id = "19.7.8.3"
        Title = "Ensure 'Do not use diagnostic data for tailored experiences' is set to 'Enabled'"
        Section = "19.7.8 Cloud Content"
        Profile = "Level1"
        Type = "Manual"
        Expected = "Enabled"
        Evidence = "Check User Configuration GPO settings"
        Description = "This policy setting controls whether diagnostic data is used for tailored experiences."
        Impact = "Disabling tailored experiences prevents potentially sensitive diagnostic data from being used for personalization."
        Remediation = "To establish the recommended configuration via GP, set the following UI path to Enabled: User Configuration\Policies\Administrative Templates\Windows Components\Cloud Content\Do not use diagnostic data for tailored experiences"
    },
    @{
        Id = "19.7.8.4"
        Title = "Ensure 'Turn off all Windows spotlight features' is set to 'Enabled'"
        Section = "19.7.8 Cloud Content"
        Profile = "Level1"
        Type = "Manual"
        Expected = "Enabled"
        Evidence = "Check User Configuration GPO settings"
        Description = "This policy setting controls whether all Windows spotlight features are turned off."
        Impact = "Disabling all spotlight features prevents cloud-based content delivery and reduces potential privacy concerns."
        Remediation = "To establish the recommended configuration via GP, set the following UI path to Enabled: User Configuration\Policies\Administrative Templates\Windows Components\Cloud Content\Turn off all Windows spotlight features"
    },
    @{
        Id = "19.7.8.5"
        Title = "Ensure 'Turn off Spotlight collection on Desktop' is set to 'Enabled'"
        Section = "19.7.8 Cloud Content"
        Profile = "Level1"
        Type = "Manual"
        Expected = "Enabled"
        Evidence = "Check User Configuration GPO settings"
        Description = "This policy setting controls whether Spotlight collection is displayed on the desktop."
        Impact = "Disabling Spotlight collection prevents cloud-based content from appearing on the desktop."
        Remediation = "To establish the recommended configuration via GP, set the following UI path to Enabled: User Configuration\Policies\Administrative Templates\Windows Components\Cloud Content\Turn off Spotlight collection on Desktop"
    },
    
    # 19.7.26.1 Network Sharing
    @{
        Id = "19.7.26.1"
        Title = "Ensure 'Prevent users from sharing files within their profile.' is set to 'Enabled'"
        Section = "19.7.26 Network Sharing"
        Profile = "Level1"
        Type = "Manual"
        Expected = "Enabled"
        Evidence = "Check User Configuration GPO settings"
        Description = "This policy setting controls whether users can share files within their profile."
        Impact = "Preventing file sharing within user profiles helps prevent unauthorized access to user data and reduces security risks."
        Remediation = "To establish the recommended configuration via GP, set the following UI path to Enabled: User Configuration\Policies\Administrative Templates\Windows Components\Network Sharing\Prevent users from sharing files within their profile"
    },
    
    # 19.7.44.1 Windows Installer
    @{
        Id = "19.7.44.1"
        Title = "Ensure 'Always install with elevated privileges' is set to 'Disabled'"
        Section = "19.7.44 Windows Installer"
        Profile = "Level1"
        Type = "Manual"
        Expected = "Disabled"
        Evidence = "Check User Configuration GPO settings"
        Description = "This policy setting controls whether Windows Installer uses system permissions when it installs any program on the system."
        Impact = "Disabling elevated installation prevents potential privilege escalation attacks through malicious installer packages."
        Remediation = "To establish the recommended configuration via GP, set the following UI path to Disabled: User Configuration\Policies\Administrative Templates\Windows Components\Windows Installer\Always install with elevated privileges"
    },
    
    # 19.7.46.2.1 Windows Media Player - Playback
    @{
        Id = "19.7.46.2.1"
        Title = "Ensure 'Prevent Codec Download' is set to 'Enabled'"
        Section = "19.7.46.2 Playback"
        Profile = "Level1"
        Type = "Manual"
        Expected = "Enabled"
        Evidence = "Check User Configuration GPO settings"
        Description = "This policy setting controls whether Windows Media Player can download codecs automatically."
        Impact = "Preventing automatic codec downloads helps prevent potential malware delivery through malicious codec packages."
        Remediation = "To establish the recommended configuration via GP, set the following UI path to Enabled: User Configuration\Policies\Administrative Templates\Windows Components\Windows Media Player\Playback\Prevent Codec Download"
    }
    
    # Empty sections - placeholders for CIS structure completeness
    # These sections exist in CIS documentation but contain no specific controls for Windows Server 2025 Standalone
    
    # 19.1 Control Panel - No controls for standalone
    # 19.2 Desktop - No controls for standalone
    # 19.3 Network - No controls for standalone
    # 19.4 Shared Folders - No controls for standalone
    # 19.6.1 Ctrl+Alt+Del Options - No controls for standalone
    # 19.6.2 Display - No controls for standalone
    # 19.6.3 Driver Installation - No controls for standalone
    # 19.6.4 Folder Redirection - No controls for standalone
    # 19.6.5 Group Policy - No controls for standalone
    # 19.7.1 Account Notifications - No controls for standalone
    # 19.7.2 Add features to Windows - No controls for standalone
    # 19.7.3 App runtime - No controls for standalone
    # 19.7.4 Application Compatibility - No controls for standalone
    # 19.7.6 AutoPlay Policies - No controls for standalone
    # 19.7.7 Calculator - No controls for standalone
    # 19.7.9 Credential User Interface - No controls for standalone
    # 19.7.10 Data Collection and Preview Builds - No controls for standalone
    # 19.7.11 Desktop Gadgets - No controls for standalone
    # 19.7.12 Desktop Window Manager - No controls for standalone
    # 19.7.13 Digital Locker - No controls for standalone
    # 19.7.14 Edge UI - No controls for standalone
    # 19.7.15 File Explorer - No controls for standalone
    # 19.7.16 File Revocation - No controls for standalone
    # 19.7.17 IME - No controls for standalone
    # 19.7.18 Instant Search - No controls for standalone
    # 19.7.19 Internet Explorer - No controls for standalone
    # 19.7.20 Location and Sensors - No controls for standalone
    # 19.7.21 Microsoft Edge - No controls for standalone
    # 19.7.22 Microsoft Management Console - No controls for standalone
    # 19.7.23 Microsoft User Experience Virtualization - No controls for standalone
    # 19.7.24 Multitasking - No controls for standalone
    # 19.7.25 NetMeeting - No controls for standalone
    # 19.7.27 OOBE - No controls for standalone
    # 19.7.28 Presentation Settings - No controls for standalone
    # 19.7.29 Remote Desktop Services - No controls for standalone
    # 19.7.30 RSS Feeds - No controls for standalone
    # 19.7.31 Search - No controls for standalone
    # 19.7.32 Snipping Tool - No controls for standalone
    # 19.7.33 Sound Recorder - No controls for standalone
    # 19.7.34 Store - No controls for standalone
    # 19.7.35 Tablet PC - No controls for standalone
    # 19.7.36 Task Scheduler - No controls for standalone
    # 19.7.37 Windows AI - No controls for standalone
    # 19.7.38 Windows Calendar - No controls for standalone
    # 19.7.39 Windows Color System - No controls for standalone
    # 19.7.40 Windows Copilot - No controls for standalone
    # 19.7.41 Windows Defender SmartScreen - No controls for standalone
    # 19.7.42 Windows Error Reporting - No controls for standalone
    # 19.7.43 Windows Hello for Business - No controls for standalone
    # 19.7.45 Windows Logon Options - No controls for standalone
    # 19.7.46.1 Networking - No controls for standalone
)