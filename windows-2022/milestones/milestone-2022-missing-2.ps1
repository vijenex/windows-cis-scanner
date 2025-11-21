# Windows Server 2022 CIS Benchmark - Missing Controls Part 2
# Microsoft Defender Antivirus (20) + Internet Communication (2) = 22 controls

$Global:Rules += @(
  # 18.10.43 Microsoft Defender Antivirus
  @{
    Id='18.10.43.4.1'
    Title='(L1) Ensure ''Enable EDR in block mode'' is set to ''Enabled'' (Automated)'
    Section='18.10.43 Microsoft Defender Antivirus'
    Profile='Level1'
    Type='Registry'
    Key='HKLM:\SOFTWARE\Policies\Microsoft\Windows Advanced Threat Protection'
    ValueName='ForceDefenderPassiveMode'
    Expected=0
    Remediation='Set registry value: HKLM:\SOFTWARE\Policies\Microsoft\Windows Advanced Threat Protection\ForceDefenderPassiveMode = 0'
  },
  @{
    Id='18.10.43.5.1'
    Title='(L1) Ensure ''Configure local setting override for reporting to Microsoft MAPS'' is set to ''Disabled'' (Automated)'
    Section='18.10.43 Microsoft Defender Antivirus'
    Profile='Level1'
    Type='Registry'
    Key='HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet'
    ValueName='LocalSettingOverrideSpynetReporting'
    Expected=0
    Remediation='Set registry value: HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet\LocalSettingOverrideSpynetReporting = 0'
  },
  @{
    Id='18.10.43.6.1.1'
    Title='(L1) Ensure ''Configure Attack Surface Reduction rules'' is set to ''Enabled'' (Automated)'
    Section='18.10.43 Microsoft Defender Antivirus'
    Profile='Level1'
    Type='Registry'
    Key='HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR'
    ValueName='ExploitGuard_ASR_Rules'
    Expected=1
    Remediation='Set registry value: HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\ExploitGuard_ASR_Rules = 1'
  },
  @{
    Id='18.10.43.6.1.2'
    Title='(L1) Ensure ''Configure Attack Surface Reduction rules: Set the state for each ASR rule'' is configured (Automated)'
    Section='18.10.43 Microsoft Defender Antivirus'
    Profile='Level1'
    Type='Manual'
    Remediation='Configure ASR rules via Group Policy or registry. Refer to CIS Benchmark for specific rule GUIDs.'
  },
  @{
    Id='18.10.43.6.3.1'
    Title='(L1) Ensure ''Prevent users and apps from accessing dangerous websites'' is set to ''Enabled: Block'' (Automated)'
    Section='18.10.43 Microsoft Defender Antivirus'
    Profile='Level1'
    Type='Registry'
    Key='HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Network Protection'
    ValueName='EnableNetworkProtection'
    Expected=1
    Remediation='Set registry value: HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Network Protection\EnableNetworkProtection = 1'
  },
  @{
    Id='18.10.43.7.1'
    Title='(L1) Ensure ''Enable file hash computation feature'' is set to ''Enabled'' (Automated)'
    Section='18.10.43 Microsoft Defender Antivirus'
    Profile='Level1'
    Type='Registry'
    Key='HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\MpEngine'
    ValueName='EnableFileHashComputation'
    Expected=1
    Remediation='Set registry value: HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\MpEngine\EnableFileHashComputation = 1'
  },
  @{
    Id='18.10.43.10.1'
    Title='(L1) Ensure ''Configure real-time protection and Security Intelligence Updates during OOBE'' is set to ''Enabled'' (Automated)'
    Section='18.10.43 Microsoft Defender Antivirus'
    Profile='Level1'
    Type='Registry'
    Key='HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender'
    ValueName='OobeEnableRtpAndSigUpdate'
    Expected=1
    Remediation='Set registry value: HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\OobeEnableRtpAndSigUpdate = 1'
  },
  @{
    Id='18.10.43.10.2'
    Title='(L1) Ensure ''Scan all downloaded files and attachments'' is set to ''Enabled'' (Automated)'
    Section='18.10.43 Microsoft Defender Antivirus'
    Profile='Level1'
    Type='Registry'
    Key='HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection'
    ValueName='DisableIOAVProtection'
    Expected=0
    Remediation='Set registry value: HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection\DisableIOAVProtection = 0'
  },
  @{
    Id='18.10.43.10.3'
    Title='(L1) Ensure ''Turn off real-time protection'' is set to ''Disabled'' (Automated)'
    Section='18.10.43 Microsoft Defender Antivirus'
    Profile='Level1'
    Type='Registry'
    Key='HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection'
    ValueName='DisableRealtimeMonitoring'
    Expected=0
    Remediation='Set registry value: HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection\DisableRealtimeMonitoring = 0'
  },
  @{
    Id='18.10.43.10.4'
    Title='(L1) Ensure ''Turn on behavior monitoring'' is set to ''Enabled'' (Automated)'
    Section='18.10.43 Microsoft Defender Antivirus'
    Profile='Level1'
    Type='Registry'
    Key='HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection'
    ValueName='DisableBehaviorMonitoring'
    Expected=0
    Remediation='Set registry value: HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection\DisableBehaviorMonitoring = 0'
  },
  @{
    Id='18.10.43.10.5'
    Title='(L1) Ensure ''Turn on script scanning'' is set to ''Enabled'' (Automated)'
    Section='18.10.43 Microsoft Defender Antivirus'
    Profile='Level1'
    Type='Registry'
    Key='HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection'
    ValueName='DisableScriptScanning'
    Expected=0
    Remediation='Set registry value: HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection\DisableScriptScanning = 0'
  },
  @{
    Id='18.10.43.11.1.1.2'
    Title='(L1) Ensure ''Configure Remote Encryption Protection Mode'' is set to ''Enabled: Audit'' or higher (Automated)'
    Section='18.10.43 Microsoft Defender Antivirus'
    Profile='Level1'
    Type='Registry'
    Key='HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Policy Manager'
    ValueName='RemoteEncryptionProtectionConfiguredState'
    Expected=1
    Operator='GreaterOrEqual'
    Remediation='Set registry value: HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Policy Manager\RemoteEncryptionProtectionConfiguredState >= 1'
  },
  @{
    Id='18.10.43.13.1'
    Title='(L1) Ensure ''Scan excluded files and directories during quick scans'' is set to ''Enabled: 1'' (Automated)'
    Section='18.10.43 Microsoft Defender Antivirus'
    Profile='Level1'
    Type='Registry'
    Key='HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Scan'
    ValueName='DisableArchiveScanning'
    Expected=0
    Remediation='Set registry value: HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Scan\DisableArchiveScanning = 0'
  },
  @{
    Id='18.10.43.13.2'
    Title='(L1) Ensure ''Scan packed executables'' is set to ''Enabled'' (Automated)'
    Section='18.10.43 Microsoft Defender Antivirus'
    Profile='Level1'
    Type='Registry'
    Key='HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Scan'
    ValueName='DisablePackedExeScanning'
    Expected=0
    Remediation='Set registry value: HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Scan\DisablePackedExeScanning = 0'
  },
  @{
    Id='18.10.43.13.3'
    Title='(L1) Ensure ''Scan removable drives'' is set to ''Enabled'' (Automated)'
    Section='18.10.43 Microsoft Defender Antivirus'
    Profile='Level1'
    Type='Registry'
    Key='HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Scan'
    ValueName='DisableRemovableDriveScanning'
    Expected=0
    Remediation='Set registry value: HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Scan\DisableRemovableDriveScanning = 0'
  },
  @{
    Id='18.10.43.13.4'
    Title='(L1) Ensure ''Trigger a quick scan after X days without any scans'' is set to ''Enabled: 7'' (Automated)'
    Section='18.10.43 Microsoft Defender Antivirus'
    Profile='Level1'
    Type='Registry'
    Key='HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Scan'
    ValueName='DaysUntilAGSSNotificationIsShown'
    Expected=7
    Remediation='Set registry value: HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Scan\DaysUntilAGSSNotificationIsShown = 7'
  },
  @{
    Id='18.10.43.13.5'
    Title='(L1) Ensure ''Turn on e-mail scanning'' is set to ''Enabled'' (Automated)'
    Section='18.10.43 Microsoft Defender Antivirus'
    Profile='Level1'
    Type='Registry'
    Key='HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Scan'
    ValueName='DisableEmailScanning'
    Expected=0
    Remediation='Set registry value: HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Scan\DisableEmailScanning = 0'
  },

  # 18.9.20 Internet Communication Management
  @{
    Id='18.9.20.1.1'
    Title='(L1) Ensure ''Turn off downloading of print drivers over HTTP'' is set to ''Enabled'' (Automated)'
    Section='18.9.20 Internet Communication Management'
    Profile='Level1'
    Type='Registry'
    Key='HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers'
    ValueName='DisableWebPnPDownload'
    Expected=1
    Remediation='Set registry value: HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\DisableWebPnPDownload = 1'
  },
  @{
    Id='18.9.20.1.5'
    Title='(L1) Ensure ''Turn off Internet download for Web publishing and online ordering wizards'' is set to ''Enabled'' (Automated)'
    Section='18.9.20 Internet Communication Management'
    Profile='Level1'
    Type='Registry'
    Key='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'
    ValueName='NoWebServices'
    Expected=1
    Remediation='Set registry value: HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoWebServices = 1'
  }
)
