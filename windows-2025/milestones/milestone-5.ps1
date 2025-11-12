# milestone-5.ps1 — System Services (5.1)
$Global:Rules += @(
  # 5.1 Print Spooler (Spooler) = Disabled
  @{
    Id='5.1'
    Title='(L2) Ensure ''Print Spooler (Spooler)'' is set to ''Disabled'' (Automated)'
    Section='5 System Services'
    Profile='Level1'
    Type='Manual'
    Expected='Disabled'
    Evidence='Check Services.msc or Get-Service'
    Description='The Print Spooler service manages all local and network print queues and controls all printing jobs. If this service is stopped, printing will not be available on the computer.'
    Impact='Disabling the Print Spooler service prevents the computer from printing to local or network printers. However, this also eliminates the attack surface presented by the service, including vulnerabilities like PrintNightmare.'
    Remediation='To establish the recommended configuration via GP, set the following UI path to Disabled: Computer Configuration\Policies\Windows Settings\Security Settings\System Services\Print Spooler'
  }

  # Note: This is the only System Services rule in the CIS documentation
)