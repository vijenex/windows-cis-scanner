# 5 System Services (Windows Server 2016) — Audit-only
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
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2016 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2016 Benchmark documentation for detailed remediation steps.'
  },
  # EXCLUDED: 5.2 - Print Spooler needed for production servers
)