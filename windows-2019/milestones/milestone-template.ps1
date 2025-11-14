# Template for Windows Server 2019 CIS Controls
# Copy this template and modify for each milestone section
# DO NOT add actual rules to this template file

<#
Example control structure:

$Global:Rules += @(
  @{ 
    Id='X.X.X'
    Title='(L1) Example Control Title'
    Section='X.X Example Section'
    Profile='Level1'
    Type='SecEdit'  # or 'AuditPolicy', 'Registry', 'PrivRight', 'Composite', 'Manual'
    SectionName='System Access'  # For SecEdit type
    Key='ExampleKey'
    Operator='Equals'  # or 'GreaterOrEqual', 'LessOrEqual', 'NotEquals'
    Expected=1
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='X.X.X'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, please refer to the official CIS Microsoft Windows Server 2019 Benchmark document at the above URL.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  }
)
#>