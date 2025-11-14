# 5 System Services (Windows Server 2019) — Audit-only
$Global:Rules += @(
  @{
    Id='5.1'
    Title='(L1) Ensure ''Print Spooler (Spooler)'' is set to ''Disabled'' (DC only) (Automated)'
    Section='5 System Services'
    Profile='Level1'
    Type='Service'
    ServiceName='Spooler'
    Expected='Disabled'
    AppliesTo='DC'
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='5.1'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, please refer to the official CIS Microsoft Windows Server 2019 Benchmark document at the above URL.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='5.2'
    Title='(L2) Ensure ''Print Spooler (Spooler)'' is set to ''Disabled'' (MS only) (Automated)'
    Section='5 System Services'
    Profile='Level2'
    Type='Service'
    ServiceName='Spooler'
    Expected='Disabled'
    AppliesTo='MS'
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='5.2'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, please refer to the official CIS Microsoft Windows Server 2019 Benchmark document at the above URL.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  }
)