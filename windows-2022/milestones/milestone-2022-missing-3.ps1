# Windows Server 2022 CIS Benchmark - Missing Controls Part 3
# Remote Desktop Services (10 controls)

$Global:Rules += @(
  @{
    Id='18.10.57.2.2'
    Title='(L1) Ensure ''Do not allow passwords to be saved'' is set to ''Enabled'' (Automated)'
    Section='18.10.57 Remote Desktop Services'
    Profile='Level1'
    Type='Registry'
    Key='HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
    ValueName='DisablePasswordSaving'
    Expected=1
    Remediation='Set registry value: HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\DisablePasswordSaving = 1'
  },
  @{
    Id='18.10.57.3.3.2'
    Title='(L1) Ensure ''Do not allow drive redirection'' is set to ''Enabled'' (Automated)'
    Section='18.10.57 Remote Desktop Services'
    Profile='Level1'
    Type='Registry'
    Key='HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
    ValueName='fDisableCdm'
    Expected=1
    Remediation='Set registry value: HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\fDisableCdm = 1'
  },
  @{
    Id='18.10.57.3.9.1'
    Title='(L1) Ensure ''Always prompt for password upon connection'' is set to ''Enabled'' (Automated)'
    Section='18.10.57 Remote Desktop Services'
    Profile='Level1'
    Type='Registry'
    Key='HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
    ValueName='fPromptForPassword'
    Expected=1
    Remediation='Set registry value: HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\fPromptForPassword = 1'
  },
  @{
    Id='18.10.57.3.9.2'
    Title='(L1) Ensure ''Require secure RPC communication'' is set to ''Enabled'' (Automated)'
    Section='18.10.57 Remote Desktop Services'
    Profile='Level1'
    Type='Registry'
    Key='HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
    ValueName='fEncryptRPCTraffic'
    Expected=1
    Remediation='Set registry value: HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\fEncryptRPCTraffic = 1'
  },
  @{
    Id='18.10.57.3.9.3'
    Title='(L1) Ensure ''Require use of specific security layer for remote (RDP) connections'' is set to ''Enabled: SSL'' (Automated)'
    Section='18.10.57 Remote Desktop Services'
    Profile='Level1'
    Type='Registry'
    Key='HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
    ValueName='SecurityLayer'
    Expected=2
    Remediation='Set registry value: HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\SecurityLayer = 2'
  },
  @{
    Id='18.10.57.3.9.4'
    Title='(L1) Ensure ''Require user authentication for remote connections by using Network Level Authentication'' is set to ''Enabled'' (Automated)'
    Section='18.10.57 Remote Desktop Services'
    Profile='Level1'
    Type='Registry'
    Key='HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
    ValueName='UserAuthentication'
    Expected=1
    Remediation='Set registry value: HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\UserAuthentication = 1'
  },
  @{
    Id='18.10.57.3.9.5'
    Title='(L1) Ensure ''Set client connection encryption level'' is set to ''Enabled: High Level'' (Automated)'
    Section='18.10.57 Remote Desktop Services'
    Profile='Level1'
    Type='Registry'
    Key='HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
    ValueName='MinEncryptionLevel'
    Expected=3
    Remediation='Set registry value: HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\MinEncryptionLevel = 3'
  },
  @{
    Id='18.10.57.3.11.1'
    Title='(L1) Ensure ''Do not delete temp folders upon exit'' is set to ''Disabled'' (Automated)'
    Section='18.10.57 Remote Desktop Services'
    Profile='Level1'
    Type='Registry'
    Key='HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
    ValueName='DeleteTempDirsOnExit'
    Expected=1
    Remediation='Set registry value: HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\DeleteTempDirsOnExit = 1'
  },
  @{
    Id='18.10.57.3.11.2'
    Title='(L1) Ensure ''Do not use temporary folders per session'' is set to ''Disabled'' (Automated)'
    Section='18.10.57 Remote Desktop Services'
    Profile='Level1'
    Type='Registry'
    Key='HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
    ValueName='PerSessionTempDir'
    Expected=1
    Remediation='Set registry value: HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\PerSessionTempDir = 1'
  }
)
