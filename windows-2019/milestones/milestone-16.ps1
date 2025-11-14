# Additional User Rights Assignment Controls (Windows Server 2019) - Part 2
$Global:Rules += @(
  # 2.2 User Rights Assignment (Continued - Controls 16-30)
  @{
    Id='2.2.16'
    Title='(L1) Ensure ''Deny access to this computer from the network'' to include ''Guests'' (Automated)'
    Section='2.2 User Rights Assignment'
    Profile='Level1'
    Type='PrivRight'
    Key='SeDenyNetworkLogonRight'
    ExpectedPrincipals=@('BUILTIN\GUESTS')
    SetMode='Superset'
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='2.2.16'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, please refer to the official CIS Microsoft Windows Server 2019 Benchmark document at the above URL.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='2.2.17'
    Title='(L1) Ensure ''Deny log on as a batch job'' to include ''Guests'' (Automated)'
    Section='2.2 User Rights Assignment'
    Profile='Level1'
    Type='PrivRight'
    Key='SeDenyBatchLogonRight'
    ExpectedPrincipals=@('BUILTIN\GUESTS')
    SetMode='Superset'
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='2.2.17'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, please refer to the official CIS Microsoft Windows Server 2019 Benchmark document at the above URL.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='2.2.18'
    Title='(L1) Ensure ''Deny log on as a service'' to include ''Guests'' (Automated)'
    Section='2.2 User Rights Assignment'
    Profile='Level1'
    Type='PrivRight'
    Key='SeDenyServiceLogonRight'
    ExpectedPrincipals=@('BUILTIN\GUESTS')
    SetMode='Superset'
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='2.2.18'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, please refer to the official CIS Microsoft Windows Server 2019 Benchmark document at the above URL.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='2.2.19'
    Title='(L1) Ensure ''Deny log on locally'' to include ''Guests'' (Automated)'
    Section='2.2 User Rights Assignment'
    Profile='Level1'
    Type='PrivRight'
    Key='SeDenyInteractiveLogonRight'
    ExpectedPrincipals=@('BUILTIN\GUESTS')
    SetMode='Superset'
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='2.2.19'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, please refer to the official CIS Microsoft Windows Server 2019 Benchmark document at the above URL.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='2.2.20'
    Title='(L1) Ensure ''Deny log on through Remote Desktop Services'' is set to ''Guests, Local account'' (MS only) (Automated)'
    Section='2.2 User Rights Assignment'
    Profile='Level1'
    Type='PrivRight'
    Key='SeDenyRemoteInteractiveLogonRight'
    ExpectedPrincipals=@('BUILTIN\GUESTS','NT AUTHORITY\Local account')
    SetMode='Superset'
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='2.2.20'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, please refer to the official CIS Microsoft Windows Server 2019 Benchmark document at the above URL.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='2.2.21'
    Title='(L1) Ensure ''Enable computer and user accounts to be trusted for delegation'' is set to ''No One'' (MS only) (Automated)'
    Section='2.2 User Rights Assignment'
    Profile='Level1'
    Type='PrivRight'
    Key='SeEnableDelegationPrivilege'
    ExpectedPrincipals=@()
    SetMode='Exact'
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='2.2.21'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, please refer to the official CIS Microsoft Windows Server 2019 Benchmark document at the above URL.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='2.2.22'
    Title='(L1) Ensure ''Force shutdown from a remote system'' is set to ''Administrators'' (Automated)'
    Section='2.2 User Rights Assignment'
    Profile='Level1'
    Type='PrivRight'
    Key='SeRemoteShutdownPrivilege'
    ExpectedPrincipals=@('BUILTIN\ADMINISTRATORS')
    SetMode='Exact'
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='2.2.22'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, please refer to the official CIS Microsoft Windows Server 2019 Benchmark document at the above URL.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='2.2.23'
    Title='(L1) Ensure ''Generate security audits'' is set to ''LOCAL SERVICE, NETWORK SERVICE'' (Automated)'
    Section='2.2 User Rights Assignment'
    Profile='Level1'
    Type='PrivRight'
    Key='SeAuditPrivilege'
    ExpectedPrincipals=@('NT AUTHORITY\LOCAL SERVICE','NT AUTHORITY\NETWORK SERVICE')
    SetMode='Exact'
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='2.2.23'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, please refer to the official CIS Microsoft Windows Server 2019 Benchmark document at the above URL.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='2.2.24'
    Title='(L1) Ensure ''Impersonate a client after authentication'' is set to ''Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE'' and (when the Web Server (IIS) Role with Web Services Role Service is installed) ''IIS_IUSRS'' (MS only) (Automated)'
    Section='2.2 User Rights Assignment'
    Profile='Level1'
    Type='PrivRight'
    Key='SeImpersonatePrivilege'
    ExpectedPrincipals=@('BUILTIN\ADMINISTRATORS','NT AUTHORITY\LOCAL SERVICE','NT AUTHORITY\NETWORK SERVICE','NT AUTHORITY\SERVICE','BUILTIN\IIS_IUSRS')
    SetMode='Exact'
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='2.2.24'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, please refer to the official CIS Microsoft Windows Server 2019 Benchmark document at the above URL.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='2.2.25'
    Title='(L1) Ensure ''Increase scheduling priority'' is set to ''Administrators, Window Manager\Window Manager Group'' (Automated)'
    Section='2.2 User Rights Assignment'
    Profile='Level1'
    Type='PrivRight'
    Key='SeIncreaseBasePriorityPrivilege'
    ExpectedPrincipals=@('BUILTIN\ADMINISTRATORS','Window Manager\Window Manager Group')
    SetMode='Exact'
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='2.2.25'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, please refer to the official CIS Microsoft Windows Server 2019 Benchmark document at the above URL.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='2.2.26'
    Title='(L1) Ensure ''Load and unload device drivers'' is set to ''Administrators'' (Automated)'
    Section='2.2 User Rights Assignment'
    Profile='Level1'
    Type='PrivRight'
    Key='SeLoadDriverPrivilege'
    ExpectedPrincipals=@('BUILTIN\ADMINISTRATORS')
    SetMode='Exact'
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='2.2.26'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, please refer to the official CIS Microsoft Windows Server 2019 Benchmark document at the above URL.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='2.2.27'
    Title='(L1) Ensure ''Lock pages in memory'' is set to ''No One'' (Automated)'
    Section='2.2 User Rights Assignment'
    Profile='Level1'
    Type='PrivRight'
    Key='SeLockMemoryPrivilege'
    ExpectedPrincipals=@()
    SetMode='Exact'
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='2.2.27'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, please refer to the official CIS Microsoft Windows Server 2019 Benchmark document at the above URL.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='2.2.28'
    Title='(L1) Ensure ''Manage auditing and security log'' is set to ''Administrators'' (MS only) (Automated)'
    Section='2.2 User Rights Assignment'
    Profile='Level1'
    Type='PrivRight'
    Key='SeSecurityPrivilege'
    ExpectedPrincipals=@('BUILTIN\ADMINISTRATORS')
    SetMode='Exact'
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='2.2.28'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, please refer to the official CIS Microsoft Windows Server 2019 Benchmark document at the above URL.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='2.2.29'
    Title='(L1) Ensure ''Modify an object label'' is set to ''No One'' (Automated)'
    Section='2.2 User Rights Assignment'
    Profile='Level1'
    Type='PrivRight'
    Key='SeRelabelPrivilege'
    ExpectedPrincipals=@()
    SetMode='Exact'
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='2.2.29'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, please refer to the official CIS Microsoft Windows Server 2019 Benchmark document at the above URL.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='2.2.30'
    Title='(L1) Ensure ''Modify firmware environment values'' is set to ''Administrators'' (Automated)'
    Section='2.2 User Rights Assignment'
    Profile='Level1'
    Type='PrivRight'
    Key='SeSystemEnvironmentPrivilege'
    ExpectedPrincipals=@('BUILTIN\ADMINISTRATORS')
    SetMode='Exact'
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='2.2.30'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, please refer to the official CIS Microsoft Windows Server 2019 Benchmark document at the above URL.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  }
)