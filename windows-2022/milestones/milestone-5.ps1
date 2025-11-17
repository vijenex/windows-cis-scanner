# 5 System Services (Windows Server 2022) — Audit-only
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
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2022 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2022 Benchmark documentation for detailed remediation steps.'
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
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2022 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2022 Benchmark documentation for detailed remediation steps.'
  }
)