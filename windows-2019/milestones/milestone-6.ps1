# 18.1-18.4 Administrative Templates - Control Panel & MS Security Guide (Windows Server 2019)
$Global:Rules += @(
  # 18.1.1 Personalization
  @{
    Id='18.1.1.1'
    Title='(L1) Ensure ''Prevent enabling lock screen camera'' is set to ''Enabled'' (Automated)'
    Section='18.1.1 Personalization'
    Profile='Level1'
    Type='Registry'
    Key='HKLM:\Software\Policies\Microsoft\Windows\Personalization'
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
    Key='HKLM:\Software\Policies\Microsoft\Windows\Personalization'
    ValueName='NoLockScreenSlideshow'
    Expected=1
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.1.1.2'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },

  # 18.1.2.2 Regional and Language Options
  @{
    Id='18.1.2.2'
    Title='(L1) Ensure ''Allow users to enable online speech recognition services'' is set to ''Disabled'' (Automated)'
    Section='18.1.2 Regional and Language Options'
    Profile='Level1'
    Type='Registry'
    Key='HKLM:\Software\Policies\Microsoft\Speech'
    ValueName='AllowSpeechModelUpdate'
    Expected=0
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.1.2.2'
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
    Key='HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System'
    ValueName='LocalAccountTokenFilterPolicy'
    Expected=0
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
    Key='HKLM:\System\CurrentControlSet\Services\mrxsmb10'
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
    Key='HKLM:\System\CurrentControlSet\Services\LanmanServer\Parameters'
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
    Key='HKLM:\Software\Microsoft\Cryptography\Wintrust\Config'
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
    Key='HKLM:\System\CurrentControlSet\Control\Session Manager\kernel'
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
    Key='HKLM:\System\CurrentControlSet\Control\Lsa'
    ValueName='RunAsPPL'
    Expected=1
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.4.6'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='18.4.8'
    Title='(L1) Ensure ''WDigest Authentication'' is set to ''Disabled'' (Automated)'
    Section='18.4 MS Security Guide'
    Profile='Level1'
    Type='Registry'
    Key='HKLM:\System\CurrentControlSet\Control\SecurityProviders\WDigest'
    ValueName='UseLogonCredential'
    Expected=0
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='18.4.8'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  }
)