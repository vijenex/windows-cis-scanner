# 18.10.43-18.10.57 Microsoft Defender Antivirus, Remote Desktop Services (Windows Server 2022)
$Global:Rules += @(
  # 18.10.43.4 Features
  @{
    Id='18.10.43.4.1'
    Title='(L1) Ensure ''Enable EDR in block mode'' is set to ''Enabled'' (Automated)'
    Section='18.10.43.4 Features'
    Profile='Level1'
    Type='Registry'
    Key='HKLM:\Software\Policies\Microsoft\Windows Advanced Threat Protection'
    ValueName='ForceDefenderPassiveMode'
    Expected=0
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.10.43.4.1'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2022 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2022 Benchmark documentation for detailed remediation steps.'
  },

  # 18.10.43.5 MAPS
  @{
    Id='18.10.43.5.1'
    Title='(L1) Ensure ''Configure local setting override for reporting to Microsoft MAPS'' is set to ''Disabled'' (Automated)'
    Section='18.10.43.5 MAPS'
    Profile='Level1'
    Type='Registry'
    Key='HKLM:\Software\Policies\Microsoft\Windows Defender\Spynet'
    ValueName='LocalSettingOverrideSpynetReporting'
    Expected=0
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.10.43.5.1'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2022 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2022 Benchmark documentation for detailed remediation steps.'
  },

  # 18.10.43.6.1 Attack Surface Reduction
  @{
    Id='18.10.43.6.1.1'
    Title='(L1) Ensure ''Configure Attack Surface Reduction rules'' is set to ''Enabled'' (Automated)'
    Section='18.10.43.6.1 Attack Surface Reduction'
    Profile='Level1'
    Type='Registry'
    Key='HKLM:\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR'
    ValueName='ExploitGuard_ASR_Rules'
    Expected=1
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.10.43.6.1.1'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2022 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2022 Benchmark documentation for detailed remediation steps.'
  },

  # 18.10.43.6.3 Network Protection
  @{
    Id='18.10.43.6.3.1'
    Title='(L1) Ensure ''Prevent users and apps from accessing dangerous websites'' is set to ''Enabled: Block'' (Automated)'
    Section='18.10.43.6.3 Network Protection'
    Profile='Level1'
    Type='Registry'
    Key='HKLM:\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Network Protection'
    ValueName='EnableNetworkProtection'
    Expected=1
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.10.43.6.3.1'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2022 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2022 Benchmark documentation for detailed remediation steps.'
  },

  # 18.10.43.7 MpEngine
  @{
    Id='18.10.43.7.1'
    Title='(L1) Ensure ''Enable file hash computation feature'' is set to ''Enabled'' (Automated)'
    Section='18.10.43.7 MpEngine'
    Profile='Level1'
    Type='Registry'
    Key='HKLM:\Software\Policies\Microsoft\Windows Defender\MpEngine'
    ValueName='EnableFileHashComputation'
    Expected=1
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.10.43.7.1'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2022 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2022 Benchmark documentation for detailed remediation steps.'
  },

  # 18.10.43.10 Real-time Protection
  @{
    Id='18.10.43.10.1'
    Title='(L1) Ensure ''Configure real-time protection and Security Intelligence Updates during OOBE'' is set to ''Enabled'' (Automated)'
    Section='18.10.43.10 Real-time Protection'
    Profile='Level1'
    Type='Registry'
    Key='HKLM:\Software\Policies\Microsoft\Windows Defender\Real-Time Protection'
    ValueName='RealtimeScanDirection'
    Expected=0
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.10.43.10.1'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2022 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2022 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='18.10.43.10.2'
    Title='(L1) Ensure ''Scan all downloaded files and attachments'' is set to ''Enabled'' (Automated)'
    Section='18.10.43.10 Real-time Protection'
    Profile='Level1'
    Type='Registry'
    Key='HKLM:\Software\Policies\Microsoft\Windows Defender\Real-Time Protection'
    ValueName='DisableIOAVProtection'
    Expected=0
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.10.43.10.2'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2022 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2022 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='18.10.43.10.3'
    Title='(L1) Ensure ''Turn off real-time protection'' is set to ''Disabled'' (Automated)'
    Section='18.10.43.10 Real-time Protection'
    Profile='Level1'
    Type='Registry'
    Key='HKLM:\Software\Policies\Microsoft\Windows Defender\Real-Time Protection'
    ValueName='DisableRealtimeMonitoring'
    Expected=0
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.10.43.10.3'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2022 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2022 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='18.10.43.10.4'
    Title='(L1) Ensure ''Turn on behavior monitoring'' is set to ''Enabled'' (Automated)'
    Section='18.10.43.10 Real-time Protection'
    Profile='Level1'
    Type='Registry'
    Key='HKLM:\Software\Policies\Microsoft\Windows Defender\Real-Time Protection'
    ValueName='DisableBehaviorMonitoring'
    Expected=0
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.10.43.10.4'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2022 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2022 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='18.10.43.10.5'
    Title='(L1) Ensure ''Turn on script scanning'' is set to ''Enabled'' (Automated)'
    Section='18.10.43.10 Real-time Protection'
    Profile='Level1'
    Type='Registry'
    Key='HKLM:\Software\Policies\Microsoft\Windows Defender\Real-Time Protection'
    ValueName='DisableScriptScanning'
    Expected=0
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.10.43.10.5'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2022 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2022 Benchmark documentation for detailed remediation steps.'
  },

  # 18.10.43.13 Scan
  @{
    Id='18.10.43.13.2'
    Title='(L1) Ensure ''Scan packed executables'' is set to ''Enabled'' (Automated)'
    Section='18.10.43.13 Scan'
    Profile='Level1'
    Type='Registry'
    Key='HKLM:\Software\Policies\Microsoft\Windows Defender\Scan'
    ValueName='DisablePackedExeScanning'
    Expected=0
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.10.43.13.2'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2022 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2022 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='18.10.43.13.3'
    Title='(L1) Ensure ''Scan removable drives'' is set to ''Enabled'' (Automated)'
    Section='18.10.43.13 Scan'
    Profile='Level1'
    Type='Registry'
    Key='HKLM:\Software\Policies\Microsoft\Windows Defender\Scan'
    ValueName='DisableRemovableDriveScanning'
    Expected=0
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.10.43.13.3'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2022 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2022 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='18.10.43.13.5'
    Title='(L1) Ensure ''Turn on e-mail scanning'' is set to ''Enabled'' (Automated)'
    Section='18.10.43.13 Scan'
    Profile='Level1'
    Type='Registry'
    Key='HKLM:\Software\Policies\Microsoft\Windows Defender\Scan'
    ValueName='DisableEmailScanning'
    Expected=0
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.10.43.13.5'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2022 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2022 Benchmark documentation for detailed remediation steps.'
  },

  # 18.10.43.16-17
  @{
    Id='18.10.43.16'
    Title='(L1) Ensure ''Configure detection for potentially unwanted applications'' is set to ''Enabled: Block'' (Automated)'
    Section='18.10.43 Microsoft Defender Antivirus'
    Profile='Level1'
    Type='Registry'
    Key='HKLM:\Software\Policies\Microsoft\Windows Defender'
    ValueName='PUAProtection'
    Expected=1
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.10.43.16'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2022 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2022 Benchmark documentation for detailed remediation steps.'
  },

  # 18.10.51 OneDrive
  @{
    Id='18.10.51.1'
    Title='(L1) Ensure ''Prevent the usage of OneDrive for file storage'' is set to ''Enabled'' (Automated)'
    Section='18.10.51 OneDrive'
    Profile='Level1'
    Type='Registry'
    Key='HKLM:\Software\Policies\Microsoft\Windows\OneDrive'
    ValueName='DisableFileSyncNGSC'
    Expected=1
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.10.51.1'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2022 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2022 Benchmark documentation for detailed remediation steps.'
  }
)