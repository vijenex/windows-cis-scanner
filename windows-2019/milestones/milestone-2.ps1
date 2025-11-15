# 2 Local Policies (Windows Server 2019) — Audit-only
$Global:Rules += @(
  # 2.2 User Rights Assignment
  @{
    Id='2.2.1'
    Title='(L1) Ensure ''Access Credential Manager as a trusted caller'' is set to ''No One'' (Automated)'
    Section='2.2 User Rights Assignment'
    Profile='Level1'
    Type='PrivRight'
    Key='SeTrustedCredManAccessPrivilege'
    ExpectedPrincipals=@()
    SetMode='Exact'
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='2.2.1'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='2.2.2'
    Title='(L1) Ensure ''Access this computer from the network'' is set to ''Administrators, Authenticated Users, ENTERPRISE DOMAIN CONTROLLERS'' (DC only) (Automated)'
    Section='2.2 User Rights Assignment'
    Profile='Level1'
    Type='PrivRight'
    Key='SeNetworkLogonRight'
    ExpectedPrincipals=@('BUILTIN\Administrators','NT AUTHORITY\Authenticated Users','NT AUTHORITY\ENTERPRISE DOMAIN CONTROLLERS')
    SetMode='Exact'
    AppliesTo='DC'
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='2.2.2'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='2.2.3'
    Title='(L1) Ensure ''Access this computer from the network'' is set to ''Administrators, Authenticated Users'' (MS only) (Automated)'
    Section='2.2 User Rights Assignment'
    Profile='Level1'
    Type='PrivRight'
    Key='SeNetworkLogonRight'
    ExpectedPrincipals=@('BUILTIN\Administrators','NT AUTHORITY\Authenticated Users')
    SetMode='Exact'
    AppliesTo='MS'
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='2.2.3'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='2.2.4'
    Title='(L1) Ensure ''Act as part of the operating system'' is set to ''No One'' (Automated)'
    Section='2.2 User Rights Assignment'
    Profile='Level1'
    Type='PrivRight'
    Key='SeTcbPrivilege'
    ExpectedPrincipals=@()
    SetMode='Exact'
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='2.2.4'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='2.2.5'
    Title='(L1) Ensure ''Add workstations to domain'' is set to ''Administrators'' (DC only) (Automated)'
    Section='2.2 User Rights Assignment'
    Profile='Level1'
    Type='PrivRight'
    Key='SeMachineAccountPrivilege'
    ExpectedPrincipals=@('BUILTIN\Administrators')
    SetMode='Exact'
    AppliesTo='DC'
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='2.2.5'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='2.2.6'
    Title='(L1) Ensure ''Adjust memory quotas for a process'' is set to ''Administrators, LOCAL SERVICE, NETWORK SERVICE'' (Automated)'
    Section='2.2 User Rights Assignment'
    Profile='Level1'
    Type='PrivRight'
    Key='SeIncreaseQuotaPrivilege'
    ExpectedPrincipals=@('BUILTIN\Administrators','NT AUTHORITY\LOCAL SERVICE','NT AUTHORITY\NETWORK SERVICE')
    SetMode='Exact'
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='2.2.6'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='2.2.7'
    Title='(L1) Ensure ''Allow log on locally'' is set to ''Administrators, ENTERPRISE DOMAIN CONTROLLERS'' (DC only) (Automated)'
    Section='2.2 User Rights Assignment'
    Profile='Level1'
    Type='PrivRight'
    Key='SeInteractiveLogonRight'
    ExpectedPrincipals=@('BUILTIN\Administrators','NT AUTHORITY\ENTERPRISE DOMAIN CONTROLLERS')
    SetMode='Exact'
    AppliesTo='DC'
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='2.2.7'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='2.2.8'
    Title='(L1) Ensure ''Allow log on locally'' is set to ''Administrators'' (MS only) (Automated)'
    Section='2.2 User Rights Assignment'
    Profile='Level1'
    Type='PrivRight'
    Key='SeInteractiveLogonRight'
    ExpectedPrincipals=@('BUILTIN\Administrators')
    SetMode='Exact'
    AppliesTo='MS'
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='2.2.8'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='2.2.9'
    Title='(L1) Ensure ''Allow log on through Remote Desktop Services'' is set to ''Administrators'' (DC only) (Automated)'
    Section='2.2 User Rights Assignment'
    Profile='Level1'
    Type='PrivRight'
    Key='SeRemoteInteractiveLogonRight'
    ExpectedPrincipals=@('BUILTIN\Administrators')
    SetMode='Exact'
    AppliesTo='DC'
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='2.2.9'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='2.2.10'
    Title='(L1) Ensure ''Allow log on through Remote Desktop Services'' is set to ''Administrators, Remote Desktop Users'' (MS only) (Automated)'
    Section='2.2 User Rights Assignment'
    Profile='Level1'
    Type='PrivRight'
    Key='SeRemoteInteractiveLogonRight'
    ExpectedPrincipals=@('BUILTIN\Administrators','BUILTIN\Remote Desktop Users')
    SetMode='Exact'
    AppliesTo='MS'
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='2.2.10'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='2.2.11'
    Title='(L1) Ensure ''Back up files and directories'' is set to ''Administrators'' (Automated)'
    Section='2.2 User Rights Assignment'
    Profile='Level1'
    Type='PrivRight'
    Key='SeBackupPrivilege'
    ExpectedPrincipals=@('BUILTIN\Administrators')
    SetMode='Exact'
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='2.2.11'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='2.2.12'
    Title='(L1) Ensure ''Change the system time'' is set to ''Administrators, LOCAL SERVICE'' (Automated)'
    Section='2.2 User Rights Assignment'
    Profile='Level1'
    Type='PrivRight'
    Key='SeSystemtimePrivilege'
    ExpectedPrincipals=@('BUILTIN\Administrators','NT AUTHORITY\LOCAL SERVICE')
    SetMode='Exact'
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='2.2.12'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='2.2.13'
    Title='(L1) Ensure ''Change the time zone'' is set to ''Administrators, LOCAL SERVICE'' (Automated)'
    Section='2.2 User Rights Assignment'
    Profile='Level1'
    Type='PrivRight'
    Key='SeTimeZonePrivilege'
    ExpectedPrincipals=@('BUILTIN\Administrators','NT AUTHORITY\LOCAL SERVICE')
    SetMode='Exact'
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='2.2.13'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='2.2.14'
    Title='(L1) Ensure ''Create a pagefile'' is set to ''Administrators'' (Automated)'
    Section='2.2 User Rights Assignment'
    Profile='Level1'
    Type='PrivRight'
    Key='SeCreatePagefilePrivilege'
    ExpectedPrincipals=@('BUILTIN\Administrators')
    SetMode='Exact'
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='2.2.14'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='2.2.15'
    Title='(L1) Ensure ''Create a token object'' is set to ''No One'' (Automated)'
    Section='2.2 User Rights Assignment'
    Profile='Level1'
    Type='PrivRight'
    Key='SeCreateTokenPrivilege'
    ExpectedPrincipals=@()
    SetMode='Exact'
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='2.2.15'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='2.2.16'
    Title='(L1) Ensure ''Create global objects'' is set to ''Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE'' (Automated)'
    Section='2.2 User Rights Assignment'
    Profile='Level1'
    Type='PrivRight'
    Key='SeCreateGlobalPrivilege'
    ExpectedPrincipals=@('BUILTIN\Administrators','NT AUTHORITY\LOCAL SERVICE','NT AUTHORITY\NETWORK SERVICE','NT AUTHORITY\SERVICE')
    SetMode='Exact'
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='2.2.16'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='2.2.17'
    Title='(L1) Ensure ''Create permanent shared objects'' is set to ''No One'' (Automated)'
    Section='2.2 User Rights Assignment'
    Profile='Level1'
    Type='PrivRight'
    Key='SeCreatePermanentPrivilege'
    ExpectedPrincipals=@()
    SetMode='Exact'
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='2.2.17'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='2.2.18'
    Title='(L1) Ensure ''Create symbolic links'' is set to ''Administrators'' (DC only) (Automated)'
    Section='2.2 User Rights Assignment'
    Profile='Level1'
    Type='PrivRight'
    Key='SeCreateSymbolicLinkPrivilege'
    ExpectedPrincipals=@('BUILTIN\Administrators')
    SetMode='Exact'
    AppliesTo='DC'
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='2.2.18'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='2.2.19'
    Title='(L1) Ensure ''Create symbolic links'' is set to ''Administrators, NT VIRTUAL MACHINE\Virtual Machines'' (MS only) (Automated)'
    Section='2.2 User Rights Assignment'
    Profile='Level1'
    Type='PrivRight'
    Key='SeCreateSymbolicLinkPrivilege'
    ExpectedPrincipals=@('BUILTIN\Administrators','NT VIRTUAL MACHINE\Virtual Machines')
    SetMode='Exact'
    AppliesTo='MS'
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='2.2.19'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='2.2.20'
    Title='(L1) Ensure ''Debug programs'' is set to ''Administrators'' (Automated)'
    Section='2.2 User Rights Assignment'
    Profile='Level1'
    Type='PrivRight'
    Key='SeDebugPrivilege'
    ExpectedPrincipals=@('BUILTIN\Administrators')
    SetMode='Exact'
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='2.2.20'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='2.2.21'
    Title='(L1) Ensure ''Deny access to this computer from the network'' to include ''Guests'' (DC only) (Automated)'
    Section='2.2 User Rights Assignment'
    Profile='Level1'
    Type='PrivRight'
    Key='SeDenyNetworkLogonRight'
    ExpectedPrincipals=@('BUILTIN\Guests')
    SetMode='Superset'
    AppliesTo='DC'
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='2.2.21'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='2.2.22'
    Title='(L1) Ensure ''Deny access to this computer from the network'' to include ''Guests, Local account and member of Administrators group'' (MS only) (Automated)'
    Section='2.2 User Rights Assignment'
    Profile='Level1'
    Type='PrivRight'
    Key='SeDenyNetworkLogonRight'
    ExpectedPrincipals=@('BUILTIN\Guests','NT AUTHORITY\Local account and member of Administrators group')
    SetMode='Superset'
    DefaultValue=@()
    AppliesTo='MS'
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='2.2.22'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='2.2.23'
    Title='(L1) Ensure ''Deny log on as a batch job'' to include ''Guests'' (Automated)'
    Section='2.2 User Rights Assignment'
    Profile='Level1'
    Type='PrivRight'
    Key='SeDenyBatchLogonRight'
    ExpectedPrincipals=@('BUILTIN\Guests')
    SetMode='Superset'
    DefaultValue=@()
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='2.2.23'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='2.2.24'
    Title='(L1) Ensure ''Deny log on as a service'' to include ''Guests'' (Automated)'
    Section='2.2 User Rights Assignment'
    Profile='Level1'
    Type='PrivRight'
    Key='SeDenyServiceLogonRight'
    ExpectedPrincipals=@('BUILTIN\Guests')
    SetMode='Superset'
    DefaultValue=@()
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='2.2.24'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='2.2.25'
    Title='(L1) Ensure ''Deny log on locally'' to include ''Guests'' (Automated)'
    Section='2.2 User Rights Assignment'
    Profile='Level1'
    Type='PrivRight'
    Key='SeDenyInteractiveLogonRight'
    ExpectedPrincipals=@('BUILTIN\Guests')
    SetMode='Superset'
    DefaultValue=@()
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='2.2.25'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='2.2.26'
    Title='(L1) Ensure ''Deny log on through Remote Desktop Services'' to include ''Guests'' (DC only) (Automated)'
    Section='2.2 User Rights Assignment'
    Profile='Level1'
    Type='PrivRight'
    Key='SeDenyRemoteInteractiveLogonRight'
    ExpectedPrincipals=@('BUILTIN\Guests')
    SetMode='Superset'
    AppliesTo='DC'
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='2.2.26'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='2.2.27'
    Title='(L1) Ensure ''Deny log on through Remote Desktop Services'' is set to ''Guests, Local account'' (MS only) (Automated)'
    Section='2.2 User Rights Assignment'
    Profile='Level1'
    Type='PrivRight'
    Key='SeDenyRemoteInteractiveLogonRight'
    ExpectedPrincipals=@('BUILTIN\Guests','NT AUTHORITY\Local account')
    SetMode='Superset'
    DefaultValue=@()
    AppliesTo='MS'
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='2.2.27'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='2.2.28'
    Title='(L1) Ensure ''Enable computer and user accounts to be trusted for delegation'' is set to ''Administrators'' (DC only) (Automated)'
    Section='2.2 User Rights Assignment'
    Profile='Level1'
    Type='PrivRight'
    Key='SeEnableDelegationPrivilege'
    ExpectedPrincipals=@('BUILTIN\Administrators')
    SetMode='Exact'
    AppliesTo='DC'
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='2.2.28'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='2.2.29'
    Title='(L1) Ensure ''Enable computer and user accounts to be trusted for delegation'' is set to ''No One'' (MS only) (Automated)'
    Section='2.2 User Rights Assignment'
    Profile='Level1'
    Type='PrivRight'
    Key='SeEnableDelegationPrivilege'
    ExpectedPrincipals=@()
    SetMode='Exact'
    AppliesTo='MS'
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='2.2.29'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='2.2.30'
    Title='(L1) Ensure ''Force shutdown from a remote system'' is set to ''Administrators'' (Automated)'
    Section='2.2 User Rights Assignment'
    Profile='Level1'
    Type='PrivRight'
    Key='SeRemoteShutdownPrivilege'
    ExpectedPrincipals=@('BUILTIN\Administrators')
    SetMode='Exact'
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='2.2.30'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='2.2.31'
    Title='(L1) Ensure ''Generate security audits'' is set to ''LOCAL SERVICE, NETWORK SERVICE'' (Automated)'
    Section='2.2 User Rights Assignment'
    Profile='Level1'
    Type='PrivRight'
    Key='SeAuditPrivilege'
    ExpectedPrincipals=@('NT AUTHORITY\LOCAL SERVICE','NT AUTHORITY\NETWORK SERVICE')
    SetMode='Exact'
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='2.2.31'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='2.2.32'
    Title='(L1) Ensure ''Impersonate a client after authentication'' is set to ''Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE'' (DC only) (Automated)'
    Section='2.2 User Rights Assignment'
    Profile='Level1'
    Type='PrivRight'
    Key='SeImpersonatePrivilege'
    ExpectedPrincipals=@('BUILTIN\Administrators','NT AUTHORITY\LOCAL SERVICE','NT AUTHORITY\NETWORK SERVICE','NT AUTHORITY\SERVICE')
    SetMode='Exact'
    AppliesTo='DC'
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='2.2.32'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='2.2.33'
    Title='(L1) Ensure ''Impersonate a client after authentication'' is set to ''Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE'' and (when the Web Server (IIS) Role with Web Services Role Service is installed) ''IIS_IUSRS'' (MS only) (Automated)'
    Section='2.2 User Rights Assignment'
    Profile='Level1'
    Type='PrivRight'
    Key='SeImpersonatePrivilege'
    ExpectedPrincipals=@('BUILTIN\Administrators','NT AUTHORITY\LOCAL SERVICE','NT AUTHORITY\NETWORK SERVICE','NT AUTHORITY\SERVICE','BUILTIN\IIS_IUSRS')
    SetMode='Exact'
    AppliesTo='MS'
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='2.2.33'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='2.2.34'
    Title='(L1) Ensure ''Increase scheduling priority'' is set to ''Administrators, Window Manager\Window Manager Group'' (Automated)'
    Section='2.2 User Rights Assignment'
    Profile='Level1'
    Type='PrivRight'
    Key='SeIncreaseBasePriorityPrivilege'
    ExpectedPrincipals=@('BUILTIN\Administrators','Window Manager\Window Manager Group')
    SetMode='Exact'
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='2.2.34'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='2.2.35'
    Title='(L1) Ensure ''Load and unload device drivers'' is set to ''Administrators'' (Automated)'
    Section='2.2 User Rights Assignment'
    Profile='Level1'
    Type='PrivRight'
    Key='SeLoadDriverPrivilege'
    ExpectedPrincipals=@('BUILTIN\Administrators')
    SetMode='Exact'
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='2.2.35'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='2.2.36'
    Title='(L1) Ensure ''Lock pages in memory'' is set to ''No One'' (Automated)'
    Section='2.2 User Rights Assignment'
    Profile='Level1'
    Type='PrivRight'
    Key='SeLockMemoryPrivilege'
    ExpectedPrincipals=@()
    SetMode='Exact'
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='2.2.36'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='2.2.37'
    Title='(L2) Ensure ''Log on as a batch job'' is set to ''Administrators'' (DC Only) (Automated)'
    Section='2.2 User Rights Assignment'
    Profile='Level2'
    Type='PrivRight'
    Key='SeBatchLogonRight'
    ExpectedPrincipals=@('BUILTIN\Administrators')
    SetMode='Exact'
    AppliesTo='DC'
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='2.2.37'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='2.2.38'
    Title='(L1) Ensure ''Manage auditing and security log'' is set to ''Administrators'' (DC only) (Automated)'
    Section='2.2 User Rights Assignment'
    Profile='Level1'
    Type='PrivRight'
    Key='SeSecurityPrivilege'
    ExpectedPrincipals=@('BUILTIN\Administrators')
    SetMode='Exact'
    AppliesTo='DC'
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='2.2.38'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='2.2.39'
    Title='(L1) Ensure ''Manage auditing and security log'' is set to ''Administrators'' (MS only) (Automated)'
    Section='2.2 User Rights Assignment'
    Profile='Level1'
    Type='PrivRight'
    Key='SeSecurityPrivilege'
    ExpectedPrincipals=@('BUILTIN\Administrators')
    SetMode='Exact'
    AppliesTo='MS'
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='2.2.39'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='2.2.40'
    Title='(L1) Ensure ''Modify an object label'' is set to ''No One'' (Automated)'
    Section='2.2 User Rights Assignment'
    Profile='Level1'
    Type='PrivRight'
    Key='SeRelabelPrivilege'
    ExpectedPrincipals=@()
    SetMode='Exact'
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='2.2.40'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='2.2.41'
    Title='(L1) Ensure ''Modify firmware environment values'' is set to ''Administrators'' (Automated)'
    Section='2.2 User Rights Assignment'
    Profile='Level1'
    Type='PrivRight'
    Key='SeSystemEnvironmentPrivilege'
    ExpectedPrincipals=@('BUILTIN\Administrators')
    SetMode='Exact'
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='2.2.41'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='2.2.42'
    Title='(L1) Ensure ''Perform volume maintenance tasks'' is set to ''Administrators'' (Automated)'
    Section='2.2 User Rights Assignment'
    Profile='Level1'
    Type='PrivRight'
    Key='SeManageVolumePrivilege'
    ExpectedPrincipals=@('BUILTIN\Administrators')
    SetMode='Exact'
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='2.2.42'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='2.2.43'
    Title='(L1) Ensure ''Profile single process'' is set to ''Administrators'' (Automated)'
    Section='2.2 User Rights Assignment'
    Profile='Level1'
    Type='PrivRight'
    Key='SeProfileSingleProcessPrivilege'
    ExpectedPrincipals=@('BUILTIN\Administrators')
    SetMode='Exact'
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='2.2.43'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='2.2.44'
    Title='(L1) Ensure ''Profile system performance'' is set to ''Administrators, NT SERVICE\WdiServiceHost'' (Automated)'
    Section='2.2 User Rights Assignment'
    Profile='Level1'
    Type='PrivRight'
    Key='SeSystemProfilePrivilege'
    ExpectedPrincipals=@('BUILTIN\Administrators','NT SERVICE\WdiServiceHost')
    SetMode='Exact'
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='2.2.44'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='2.2.45'
    Title='(L1) Ensure ''Replace a process level token'' is set to ''LOCAL SERVICE, NETWORK SERVICE'' (Automated)'
    Section='2.2 User Rights Assignment'
    Profile='Level1'
    Type='PrivRight'
    Key='SeAssignPrimaryTokenPrivilege'
    ExpectedPrincipals=@('NT AUTHORITY\LOCAL SERVICE','NT AUTHORITY\NETWORK SERVICE')
    SetMode='Exact'
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='2.2.45'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='2.2.46'
    Title='(L1) Ensure ''Restore files and directories'' is set to ''Administrators'' (Automated)'
    Section='2.2 User Rights Assignment'
    Profile='Level1'
    Type='PrivRight'
    Key='SeRestorePrivilege'
    ExpectedPrincipals=@('BUILTIN\Administrators')
    SetMode='Exact'
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='2.2.46'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='2.2.47'
    Title='(L1) Ensure ''Shut down the system'' is set to ''Administrators'' (Automated)'
    Section='2.2 User Rights Assignment'
    Profile='Level1'
    Type='PrivRight'
    Key='SeShutdownPrivilege'
    ExpectedPrincipals=@('BUILTIN\Administrators')
    SetMode='Exact'
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='2.2.47'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='2.2.48'
    Title='(L1) Ensure ''Synchronize directory service data'' is set to ''No One'' (DC only) (Automated)'
    Section='2.2 User Rights Assignment'
    Profile='Level1'
    Type='PrivRight'
    Key='SeSyncAgentPrivilege'
    ExpectedPrincipals=@()
    SetMode='Exact'
    AppliesTo='DC'
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='2.2.48'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='2.2.49'
    Title='(L1) Ensure ''Take ownership of files or other objects'' is set to ''Administrators'' (Automated)'
    Section='2.2 User Rights Assignment'
    Profile='Level1'
    Type='PrivRight'
    Key='SeTakeOwnershipPrivilege'
    ExpectedPrincipals=@('BUILTIN\Administrators')
    SetMode='Exact'
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='2.2.49'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },

  # 2.3 Security Options
  # 2.3.1 Accounts
  @{
    Id='2.3.1.1'
    Title='(L1) Ensure ''Accounts: Guest account status'' is set to ''Disabled'' (MS only) (Automated)'
    Section='2.3.1 Accounts'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
    ValueName='EnableGuestAccount'
    Expected=0
    AppliesTo='MS'
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='2.3.1.1'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='2.3.1.2'
    Title='(L1) Ensure ''Accounts: Limit local account use of blank passwords to console logon only'' is set to ''Enabled'' (Automated)'
    Section='2.3.1 Accounts'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SYSTEM\CurrentControlSet\Control\Lsa'
    ValueName='LimitBlankPasswordUse'
    Expected=1
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='2.3.1.2'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='2.3.1.3'
    Title='(L1) Configure ''Accounts: Rename administrator account'' (Automated)'
    Section='2.3.1 Accounts'
    Profile='Level1'
    Type='Manual'
    Expected='Renamed from Administrator'
    Evidence='Check Local Security Policy'
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='2.3.1.3'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='2.3.1.4'
    Title='(L1) Configure ''Accounts: Rename guest account'' (Automated)'
    Section='2.3.1 Accounts'
    Profile='Level1'
    Type='Manual'
    Expected='Renamed from Guest'
    Evidence='Check Local Security Policy'
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='2.3.1.4'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },

  # 2.3.2 Audit
  @{
    Id='2.3.2.1'
    Title='(L1) Ensure ''Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit policy category settings'' is set to ''Enabled'' (Automated)'
    Section='2.3.2 Audit'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SYSTEM\CurrentControlSet\Control\Lsa'
    ValueName='SCENoApplyLegacyAuditPolicy'
    Expected=1
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='2.3.2.1'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='2.3.2.2'
    Title='(L1) Ensure ''Audit: Shut down system immediately if unable to log security audits'' is set to ''Disabled'' (Automated)'
    Section='2.3.2 Audit'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SYSTEM\CurrentControlSet\Control\Lsa'
    ValueName='CrashOnAuditFail'
    Expected=0
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='2.3.2.2'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },

  # 2.3.4 Devices
  @{
    Id='2.3.4.1'
    Title='(L1) Ensure ''Devices: Prevent users from installing printer drivers'' is set to ''Enabled'' (Automated)'
    Section='2.3.4 Devices'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SYSTEM\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers'
    ValueName='AddPrinterDrivers'
    Expected=1
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='2.3.4.1'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },

  # 2.3.5 Domain controller
  @{
    Id='2.3.5.1'
    Title='(L1) Ensure ''Domain controller: Allow server operators to schedule tasks'' is set to ''Disabled'' (DC only) (Automated)'
    Section='2.3.5 Domain controller'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SYSTEM\CurrentControlSet\Control\Lsa'
    ValueName='SubmitControl'
    Expected=0
    AppliesTo='DC'
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='2.3.5.1'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='2.3.5.2'
    Title='(L1) Ensure ''Domain controller: Allow vulnerable Netlogon secure channel connections'' is set to ''Not Configured'' (DC Only) (Automated)'
    Section='2.3.5 Domain controller'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters'
    ValueName='VulnerableChannelAllowList'
    Expected='NotConfigured'
    AppliesTo='DC'
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='2.3.5.2'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='2.3.5.3'
    Title='(L1) Ensure ''Domain controller: LDAP server channel binding token requirements'' is set to ''Always'' (DC Only) (Automated)'
    Section='2.3.5 Domain controller'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Parameters'
    ValueName='LdapEnforceChannelBinding'
    Expected=2
    AppliesTo='DC'
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='2.3.5.3'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='2.3.5.4'
    Title='(L1) Ensure ''Domain controller: LDAP server signing requirements'' is set to ''Require signing'' (DC only) (Automated)'
    Section='2.3.5 Domain controller'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Parameters'
    ValueName='LDAPServerIntegrity'
    Expected=2
    AppliesTo='DC'
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='2.3.5.4'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='2.3.5.5'
    Title='(L1) Ensure ''Domain controller: Refuse machine account password changes'' is set to ''Disabled'' (DC only) (Automated)'
    Section='2.3.5 Domain controller'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters'
    ValueName='RefusePasswordChange'
    Expected=0
    AppliesTo='DC'
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='2.3.5.5'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },

  # 2.3.6 Domain member
  @{
    Id='2.3.6.1'
    Title='(L1) Ensure ''Domain member: Digitally encrypt or sign secure channel data (always)'' is set to ''Enabled'' (Automated)'
    Section='2.3.6 Domain member'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters'
    ValueName='RequireSignOrSeal'
    Expected=1
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='2.3.6.1'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='2.3.6.2'
    Title='(L1) Ensure ''Domain member: Digitally encrypt secure channel data (when possible)'' is set to ''Enabled'' (Automated)'
    Section='2.3.6 Domain member'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters'
    ValueName='SealSecureChannel'
    Expected=1
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='2.3.6.2'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='2.3.6.3'
    Title='(L1) Ensure ''Domain member: Digitally sign secure channel data (when possible)'' is set to ''Enabled'' (Automated)'
    Section='2.3.6 Domain member'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters'
    ValueName='SignSecureChannel'
    Expected=1
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='2.3.6.3'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='2.3.6.4'
    Title='(L1) Ensure ''Domain member: Disable machine account password changes'' is set to ''Disabled'' (Automated)'
    Section='2.3.6 Domain member'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters'
    ValueName='DisablePasswordChange'
    Expected=0
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='2.3.6.4'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='2.3.6.5'
    Title='(L1) Ensure ''Domain member: Maximum machine account password age'' is set to ''30 or fewer days, but not 0'' (Automated)'
    Section='2.3.6 Domain member'
    Profile='Level1'
    Type='Composite'
    AllOf=@(
        @{ Type='Registry'; Key='HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters'; ValueName='MaximumPasswordAge'; Operator='LessOrEqual'; Expected=30 },
        @{ Type='Registry'; Key='HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters'; ValueName='MaximumPasswordAge'; Operator='NotEquals'; Expected=0 }
    )
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='2.3.6.5'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='2.3.6.6'
    Title='(L1) Ensure ''Domain member: Require strong (Windows 2000 or later) session key'' is set to ''Enabled'' (Automated)'
    Section='2.3.6 Domain member'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters'
    ValueName='RequireStrongKey'
    Expected=1
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='2.3.6.6'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },

  # 2.3.7 Interactive logon
  @{
    Id='2.3.7.1'
    Title='(L1) Ensure ''Interactive logon: Do not require CTRL+ALT+DEL'' is set to ''Disabled'' (Automated)'
    Section='2.3.7 Interactive logon'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
    ValueName='DisableCAD'
    Expected=0
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='2.3.7.1'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='2.3.7.2'
    Title='(L1) Ensure ''Interactive logon: Don''t display last signed-in'' is set to ''Enabled'' (Automated)'
    Section='2.3.7 Interactive logon'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
    ValueName='DontDisplayLastUserName'
    Expected=1
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='2.3.7.2'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='2.3.7.3'
    Title='(L1) Ensure ''Interactive logon: Machine inactivity limit'' is set to ''900 or fewer second(s), but not 0'' (Automated)'
    Section='2.3.7 Interactive logon'
    Profile='Level1'
    Type='Composite'
    AllOf=@(
        @{ Type='Registry'; Key='HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'; ValueName='InactivityTimeoutSecs'; Operator='LessOrEqual'; Expected=900 },
        @{ Type='Registry'; Key='HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'; ValueName='InactivityTimeoutSecs'; Operator='NotEquals'; Expected=0 }
    )
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='2.3.7.3'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='2.3.7.4'
    Title='(L1) Configure ''Interactive logon: Message text for users attempting to log on'' (Automated)'
    Section='2.3.7 Interactive logon'
    Profile='Level1'
    Type='Manual'
    Expected='Configured with appropriate message'
    Evidence='Check Local Security Policy'
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='2.3.7.4'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='2.3.7.5'
    Title='(L1) Configure ''Interactive logon: Message title for users attempting to log on'' (Automated)'
    Section='2.3.7 Interactive logon'
    Profile='Level1'
    Type='Manual'
    Expected='Configured with appropriate title'
    Evidence='Check Local Security Policy'
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='2.3.7.5'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='2.3.7.6'
    Title='(L2) Ensure ''Interactive logon: Number of previous logons to cache (in case domain controller is not available)'' is set to ''4 or fewer logon(s)'' (MS only) (Automated)'
    Section='2.3.7 Interactive logon'
    Profile='Level2'
    Type='Registry'
    Key='HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
    ValueName='CachedLogonsCount'
    Operator='LessOrEqual'
    Expected=4
    AppliesTo='MS'
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='2.3.7.6'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='2.3.7.7'
    Title='(L1) Ensure ''Interactive logon: Prompt user to change password before expiration'' is set to ''between 5 and 14 days'' (Automated)'
    Section='2.3.7 Interactive logon'
    Profile='Level1'
    Type='Composite'
    AllOf=@(
        @{ Type='Registry'; Key='HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'; ValueName='PasswordExpiryWarning'; Operator='GreaterOrEqual'; Expected=5 },
        @{ Type='Registry'; Key='HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'; ValueName='PasswordExpiryWarning'; Operator='LessOrEqual'; Expected=14 }
    )
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='2.3.7.7'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='2.3.7.8'
    Title='(L1) Ensure ''Interactive logon: Require Domain Controller Authentication to unlock workstation'' is set to ''Enabled'' (MS only) (Automated)'
    Section='2.3.7 Interactive logon'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
    ValueName='ForceUnlockLogon'
    Expected=1
    AppliesTo='MS'
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='2.3.7.8'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='2.3.7.9'
    Title='(L1) Ensure ''Interactive logon: Smart card removal behavior'' is set to ''Lock Workstation'' or higher (Automated)'
    Section='2.3.7 Interactive logon'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
    ValueName='ScRemoveOption'
    Operator='GreaterOrEqual'
    Expected=1
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='2.3.7.9'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },

  # 2.3.8 Microsoft network client
  @{
    Id='2.3.8.1'
    Title='(L1) Ensure ''Microsoft network client: Digitally sign communications (always)'' is set to ''Enabled'' (Automated)'
    Section='2.3.8 Microsoft network client'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters'
    ValueName='RequireSecuritySignature'
    Expected=1
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='2.3.8.1'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='2.3.8.2'
    Title='(L1) Ensure ''Microsoft network client: Digitally sign communications (if server agrees)'' is set to ''Enabled'' (Automated)'
    Section='2.3.8 Microsoft network client'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters'
    ValueName='EnableSecuritySignature'
    Expected=1
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='2.3.8.2'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='2.3.8.3'
    Title='(L1) Ensure ''Microsoft network client: Send unencrypted password to third-party SMB servers'' is set to ''Disabled'' (Automated)'
    Section='2.3.8 Microsoft network client'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters'
    ValueName='EnablePlainTextPassword'
    Expected=0
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='2.3.8.3'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },

  # 2.3.9 Microsoft network server
  @{
    Id='2.3.9.1'
    Title='(L1) Ensure ''Microsoft network server: Amount of idle time required before suspending session'' is set to ''15 or fewer minute(s)'' (Automated)'
    Section='2.3.9 Microsoft network server'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters'
    ValueName='AutoDisconnect'
    Operator='LessOrEqual'
    Expected=15
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='2.3.9.1'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='2.3.9.2'
    Title='(L1) Ensure ''Microsoft network server: Digitally sign communications (always)'' is set to ''Enabled'' (Automated)'
    Section='2.3.9 Microsoft network server'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters'
    ValueName='RequireSecuritySignature'
    Expected=1
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='2.3.9.2'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='2.3.9.3'
    Title='(L1) Ensure ''Microsoft network server: Digitally sign communications (if client agrees)'' is set to ''Enabled'' (Automated)'
    Section='2.3.9 Microsoft network server'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters'
    ValueName='EnableSecuritySignature'
    Expected=1
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='2.3.9.3'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='2.3.9.4'
    Title='(L1) Ensure ''Microsoft network server: Disconnect clients when logon hours expire'' is set to ''Enabled'' (Automated)'
    Section='2.3.9 Microsoft network server'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters'
    ValueName='EnableForcedLogOff'
    Expected=1
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='2.3.9.4'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='2.3.9.5'
    Title='(L1) Ensure ''Microsoft network server: Server SPN target name validation level'' is set to ''Accept if provided by client'' or higher (MS only) (Automated)'
    Section='2.3.9 Microsoft network server'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters'
    ValueName='SmbServerNameHardeningLevel'
    Operator='GreaterOrEqual'
    Expected=1
    AppliesTo='MS'
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='2.3.9.5'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },

  # 2.3.10 Network access
  @{
    Id='2.3.10.1'
    Title='(L1) Ensure ''Network access: Allow anonymous SID/Name translation'' is set to ''Disabled'' (Automated)'
    Section='2.3.10 Network access'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SYSTEM\CurrentControlSet\Control\Lsa'
    ValueName='TurnOffAnonymousBlock'
    Expected=1
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='2.3.10.1'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='2.3.10.2'
    Title='(L1) Ensure ''Network access: Do not allow anonymous enumeration of SAM accounts'' is set to ''Enabled'' (MS only) (Automated)'
    Section='2.3.10 Network access'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SYSTEM\CurrentControlSet\Control\Lsa'
    ValueName='RestrictAnonymousSAM'
    Expected=1
    AppliesTo='MS'
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='2.3.10.2'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='2.3.10.3'
    Title='(L1) Ensure ''Network access: Do not allow anonymous enumeration of SAM accounts and shares'' is set to ''Enabled'' (MS only) (Automated)'
    Section='2.3.10 Network access'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SYSTEM\CurrentControlSet\Control\Lsa'
    ValueName='RestrictAnonymous'
    Expected=1
    AppliesTo='MS'
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='2.3.10.3'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='2.3.10.4'
    Title='(L2) Ensure ''Network access: Do not allow storage of passwords and credentials for network authentication'' is set to ''Enabled'' (Automated)'
    Section='2.3.10 Network access'
    Profile='Level2'
    Type='Registry'
    Key='HKLM\SYSTEM\CurrentControlSet\Control\Lsa'
    ValueName='DisableDomainCreds'
    Expected=1
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='2.3.10.4'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='2.3.10.5'
    Title='(L1) Ensure ''Network access: Let Everyone permissions apply to anonymous users'' is set to ''Disabled'' (Automated)'
    Section='2.3.10 Network access'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SYSTEM\CurrentControlSet\Control\Lsa'
    ValueName='EveryoneIncludesAnonymous'
    Expected=0
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='2.3.10.5'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='2.3.10.6'
    Title='(L1) Ensure ''Network access: Named Pipes that can be accessed anonymously'' is configured (DC only) (Automated)'
    Section='2.3.10 Network access'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters'
    ValueName='NullSessionPipes'
    Expected='COMNAP,COMNODE,SQL\QUERY,SPOOLSS,LLSRPC,EPMAPPER,LOCATOR,TrkWks,TrkSvr'
    AppliesTo='DC'
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='2.3.10.6'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='2.3.10.7'
    Title='(L1) Ensure ''Network access: Named Pipes that can be accessed anonymously'' is configured (MS only) (Automated)'
    Section='2.3.10 Network access'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters'
    ValueName='NullSessionPipes'
    Expected=''
    AppliesTo='MS'
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='2.3.10.7'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='2.3.10.8'
    Title='(L1) Ensure ''Network access: Remotely accessible registry paths'' is configured (Automated)'
    Section='2.3.10 Network access'
    Profile='Level1'
    Type='Manual'
    Expected='Configured with minimal required paths'
    Evidence='Check Local Security Policy'
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='2.3.10.8'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='2.3.10.9'
    Title='(L1) Ensure ''Network access: Remotely accessible registry paths and sub-paths'' is configured (Automated)'
    Section='2.3.10 Network access'
    Profile='Level1'
    Type='Manual'
    Expected='Configured with minimal required paths'
    Evidence='Check Local Security Policy'
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='2.3.10.9'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='2.3.10.10'
    Title='(L1) Ensure ''Network access: Restrict anonymous access to Named Pipes and Shares'' is set to ''Enabled'' (Automated)'
    Section='2.3.10 Network access'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters'
    ValueName='RestrictNullSessAccess'
    Expected=1
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='2.3.10.10'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='2.3.10.11'
    Title='(L1) Ensure ''Network access: Restrict clients allowed to make remote calls to SAM'' is set to ''Administrators: Remote Access: Allow'' (MS only) (Automated)'
    Section='2.3.10 Network access'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SYSTEM\CurrentControlSet\Control\Lsa'
    ValueName='RestrictRemoteSAM'
    Expected='O:BAG:BAD:(A;;RC;;;BA)'
    AppliesTo='MS'
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='2.3.10.11'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='2.3.10.12'
    Title='(L1) Ensure ''Network access: Shares that can be accessed anonymously'' is set to ''None'' (Automated)'
    Section='2.3.10 Network access'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters'
    ValueName='NullSessionShares'
    Expected=''
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='2.3.10.12'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='2.3.10.13'
    Title='(L1) Ensure ''Network access: Sharing and security model for local accounts'' is set to ''Classic - local users authenticate as themselves'' (Automated)'
    Section='2.3.10 Network access'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SYSTEM\CurrentControlSet\Control\Lsa'
    ValueName='ForceGuest'
    Expected=0
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='2.3.10.13'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },

  # 2.3.11 Network security
  @{
    Id='2.3.11.1'
    Title='(L1) Ensure ''Network security: Allow Local System to use computer identity for NTLM'' is set to ''Enabled'' (Automated)'
    Section='2.3.11 Network security'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SYSTEM\CurrentControlSet\Control\Lsa'
    ValueName='UseMachineId'
    Expected=1
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='2.3.11.1'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='2.3.11.2'
    Title='(L1) Ensure ''Network security: Allow LocalSystem NULL session fallback'' is set to ''Disabled'' (Automated)'
    Section='2.3.11 Network security'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0'
    ValueName='AllowNullSessionFallback'
    Expected=0
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='2.3.11.2'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='2.3.11.3'
    Title='(L1) Ensure ''Network Security: Allow PKU2U authentication requests to this computer to use online identities'' is set to ''Disabled'' (Automated)'
    Section='2.3.11 Network security'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SYSTEM\CurrentControlSet\Control\Lsa\pku2u'
    ValueName='AllowOnlineID'
    Expected=0
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='2.3.11.3'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='2.3.11.4'
    Title='(L1) Ensure ''Network security: Configure encryption types allowed for Kerberos'' is set to ''AES128_HMAC_SHA1, AES256_HMAC_SHA1, Future encryption types'' (Automated)'
    Section='2.3.11 Network security'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters'
    ValueName='SupportedEncryptionTypes'
    Expected=2147483640
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='2.3.11.4'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='2.3.11.5'
    Title='(L1) Ensure ''Network security: Do not store LAN Manager hash value on next password change'' is set to ''Enabled'' (Automated)'
    Section='2.3.11 Network security'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SYSTEM\CurrentControlSet\Control\Lsa'
    ValueName='NoLMHash'
    Expected=1
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='2.3.11.5'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='2.3.11.6'
    Title='(L1) Ensure ''Network security: Force logoff when logon hours expire'' is set to ''Enabled'' (Manual)'
    Section='2.3.11 Network security'
    Profile='Level1'
    Type='Manual'
    Expected='Enabled'
    Evidence='Check Local Security Policy'
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='2.3.11.6'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='2.3.11.7'
    Title='(L1) Ensure ''Network security: LAN Manager authentication level'' is set to ''Send NTLMv2 response only. Refuse LM & NTLM'' (Automated)'
    Section='2.3.11 Network security'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SYSTEM\CurrentControlSet\Control\Lsa'
    ValueName='LmCompatibilityLevel'
    Expected=5
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='2.3.11.7'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='2.3.11.8'
    Title='(L1) Ensure ''Network security: LDAP client signing requirements'' is set to ''Negotiate signing'' or higher (Automated)'
    Section='2.3.11 Network security'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SYSTEM\CurrentControlSet\Services\LDAP'
    ValueName='LDAPClientIntegrity'
    Operator='GreaterOrEqual'
    Expected=1
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='2.3.11.8'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='2.3.11.9'
    Title='(L1) Ensure ''Network security: Minimum session security for NTLM SSP based (including secure RPC) clients'' is set to ''Require NTLMv2 session security, Require 128-bit encryption'' (Automated)'
    Section='2.3.11 Network security'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0'
    ValueName='NTLMMinClientSec'
    Expected=537395200
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='2.3.11.9'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='2.3.11.10'
    Title='(L1) Ensure ''Network security: Minimum session security for NTLM SSP based (including secure RPC) servers'' is set to ''Require NTLMv2 session security, Require 128-bit encryption'' (Automated)'
    Section='2.3.11 Network security'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0'
    ValueName='NTLMMinServerSec'
    Expected=537395200
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='2.3.11.10'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='2.3.11.11'
    Title='(L1) Ensure ''Network security: Restrict NTLM: Audit Incoming NTLM Traffic'' is set to ''Enable auditing for all accounts'' (Automated)'
    Section='2.3.11 Network security'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0'
    ValueName='AuditReceivingNTLMTraffic'
    Expected=2
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='2.3.11.11'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='2.3.11.12'
    Title='(L1) Ensure ''Network security: Restrict NTLM: Audit NTLM authentication in this domain'' is set to ''Enable all'' (DC only) (Automated)'
    Section='2.3.11 Network security'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters'
    ValueName='AuditNTLMInDomain'
    Expected=7
    AppliesTo='DC'
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='2.3.11.12'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='2.3.11.13'
    Title='(L1) Ensure ''Network security: Restrict NTLM: Outgoing NTLM traffic to remote servers'' is set to ''Audit all'' or higher (Automated)'
    Section='2.3.11 Network security'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0'
    ValueName='RestrictSendingNTLMTraffic'
    Operator='GreaterOrEqual'
    Expected=1
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='2.3.11.13'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },

  # 2.3.13 Shutdown
  @{
    Id='2.3.13.1'
    Title='(L1) Ensure ''Shutdown: Allow system to be shut down without having to log on'' is set to ''Disabled'' (Automated)'
    Section='2.3.13 Shutdown'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
    ValueName='ShutdownWithoutLogon'
    Expected=0
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='2.3.13.1'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },

  # 2.3.15 System objects
  @{
    Id='2.3.15.1'
    Title='(L1) Ensure ''System objects: Require case insensitivity for non-Windows subsystems'' is set to ''Enabled'' (Automated)'
    Section='2.3.15 System objects'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Kernel'
    ValueName='ObCaseInsensitive'
    Expected=1
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='2.3.15.1'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='2.3.15.2'
    Title='(L1) Ensure ''System objects: Strengthen default permissions of internal system objects (e.g. Symbolic Links)'' is set to ''Enabled'' (Automated)'
    Section='2.3.15 System objects'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SYSTEM\CurrentControlSet\Control\Session Manager'
    ValueName='ProtectionMode'
    Expected=1
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='2.3.15.2'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },

  # 2.3.17 User Account Control
  @{
    Id='2.3.17.1'
    Title='(L1) Ensure ''User Account Control: Admin Approval Mode for the Built-in Administrator account'' is set to ''Enabled'' (Automated)'
    Section='2.3.17 User Account Control'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
    ValueName='FilterAdministratorToken'
    Expected=1
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='2.3.17.1'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='2.3.17.2'
    Title='(L1) Ensure ''User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode'' is set to ''Prompt for consent on the secure desktop'' or higher (Automated)'
    Section='2.3.17 User Account Control'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
    ValueName='ConsentPromptBehaviorAdmin'
    Operator='GreaterOrEqual'
    Expected=2
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='2.3.17.2'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='2.3.17.3'
    Title='(L1) Ensure ''User Account Control: Behavior of the elevation prompt for standard users'' is set to ''Automatically deny elevation requests'' (Automated)'
    Section='2.3.17 User Account Control'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
    ValueName='ConsentPromptBehaviorUser'
    Expected=0
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='2.3.17.3'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='2.3.17.4'
    Title='(L1) Ensure ''User Account Control: Detect application installations and prompt for elevation'' is set to ''Enabled'' (Automated)'
    Section='2.3.17 User Account Control'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
    ValueName='EnableInstallerDetection'
    Expected=1
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='2.3.17.4'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='2.3.17.5'
    Title='(L1) Ensure ''User Account Control: Only elevate UIAccess applications that are installed in secure locations'' is set to ''Enabled'' (Automated)'
    Section='2.3.17 User Account Control'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
    ValueName='EnableSecureUIAPaths'
    Expected=1
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='2.3.17.5'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='2.3.17.6'
    Title='(L1) Ensure ''User Account Control: Run all administrators in Admin Approval Mode'' is set to ''Enabled'' (Automated)'
    Section='2.3.17 User Account Control'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
    ValueName='EnableLUA'
    Expected=1
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='2.3.17.6'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='2.3.17.7'
    Title='(L1) Ensure ''User Account Control: Switch to the secure desktop when prompting for elevation'' is set to ''Enabled'' (Automated)'
    Section='2.3.17 User Account Control'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
    ValueName='PromptOnSecureDesktop'
    Expected=1
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='2.3.17.7'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='2.3.17.8'
    Title='(L1) Ensure ''User Account Control: Virtualize file and registry write failures to per-user locations'' is set to ''Enabled'' (Automated)'
    Section='2.3.17 User Account Control'
    Profile='Level1'
    Type='Registry'
    Key='HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
    ValueName='EnableVirtualization'
    Expected=1
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='2.3.17.8'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, refer to the CIS Reference link and official CIS Microsoft Windows Server 2019 Benchmark documentation.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  }
)