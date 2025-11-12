# 2 Local Policies (Windows Server 2025) — Audit-only
$Global:Rules += @(
  # 2.1 Audit Policy - Header only, no rules

  # 2.2 User Rights Assignment (Standalone/Workgroup - 2.2.1–2.2.37)
  @{
    Id='2.2.1'
    Title='(L1) Ensure ''Access Credential Manager as a trusted caller'' is set to ''No One'' (Automated)'
    Section='2.2 User Rights Assignment'
    Profile='Level1'
    Type='PrivRight'
    Key='SeTrustedCredManAccessPrivilege'
    ExpectedPrincipals=@()
    SetMode='Exact'
    Description='This policy setting allows a user to access Credential Manager as a trusted caller. Credential Manager is a secure store for credential information.'
    Impact='If this privilege is assigned to other users, those users may be able to read the saved credentials of other users.'
    Remediation='To establish the recommended configuration via GP, set the following UI path to No One: Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment\Access Credential Manager as a trusted caller'
  },
  @{
    Id='2.2.2'
    Title='(L1) Ensure ''Access this computer from the network'' is set to ''Administrators, Authenticated Users'' (Automated)'
    Section='2.2 User Rights Assignment'
    Profile='Level1'
    Type='PrivRight'
    Key='SeNetworkLogonRight'
    ExpectedPrincipals=@('BUILTIN\ADMINISTRATORS','NT AUTHORITY\AUTHENTICATED USERS')
    SetMode='Exact'
    Description='This policy setting allows a user to connect to the computer from the network. This capability is essential for users who connect to the computer via the network and for users who attempt to connect via Terminal Services or IIS.'
    Impact='Any account with the Access this computer from the network user right can log on to the server from the network. Accounts that do not have this user right will not be able to access the server over the network.'
    Remediation='To establish the recommended configuration via GP, set the following UI path to Administrators, Authenticated Users: Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment\Access this computer from the network'
  },
  @{
    Id='2.2.3'
    Title='(L1) Ensure ''Act as part of the operating system'' is set to ''No One'' (Automated)'
    Section='2.2 User Rights Assignment'
    Profile='Level1'
    Type='PrivRight'
    Key='SeTcbPrivilege'
    ExpectedPrincipals=@()
    SetMode='Exact'
    Description='This policy setting allows a process to authenticate like a user and thus gain access to the same resources as a user. Only low-level authentication services should require this privilege.'
    Impact='The Act as part of the operating system user right is extremely powerful. Anyone with this user right can take complete control of the computer and erase evidence of their activities.'
    Remediation='To establish the recommended configuration via GP, set the following UI path to No One: Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment\Act as part of the operating system'
  },
  @{
    Id='2.2.4'
    Title='(L1) Ensure ''Adjust memory quotas for a process'' is set to ''Administrators, LOCAL SERVICE, NETWORK SERVICE'' (Automated)'
    Section='2.2 User Rights Assignment'
    Profile='Level1'
    Type='PrivRight'
    Key='SeIncreaseQuotaPrivilege'
    ExpectedPrincipals=@('BUILTIN\ADMINISTRATORS','NT AUTHORITY\LOCAL SERVICE','NT AUTHORITY\NETWORK SERVICE')
    SetMode='Exact'
    Description='This policy setting allows a user to modify the maximum memory that can be consumed by a process. This capability is useful for system tuning, but it can be abused.'
    Impact='A user with the Adjust memory quotas for a process privilege can reduce the amount of memory that is available to any process, which could cause business-critical network applications to become slow or to fail.'
    Remediation='To establish the recommended configuration via GP, set the following UI path to Administrators, LOCAL SERVICE, NETWORK SERVICE: Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment\Adjust memory quotas for a process'
  },
  @{
    Id='2.2.5'
    Title='(L1) Ensure ''Allow log on locally'' is set to ''Administrators'' (Automated)'
    Section='2.2 User Rights Assignment'
    Profile='Level1'
    Type='PrivRight'
    Key='SeInteractiveLogonRight'
    ExpectedPrincipals=@('BUILTIN\ADMINISTRATORS')
    SetMode='Exact'
    Description='This policy setting determines which users can interactively log on to computers in your environment. Logons that are initiated by pressing the CTRL+ALT+DEL key sequence on the client computer keyboard require this user right.'
    Impact='Any account with the Allow log on locally user right can log on at the console of the computer. If you do not restrict this user right to legitimate users who need to be able to log on to the console of the computer, unauthorized users might download and run malicious software to elevate their privileges.'
    Remediation='To establish the recommended configuration via GP, set the following UI path to Administrators: Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment\Allow log on locally'
  },
  @{
    Id='2.2.6'
    Title='(L1) Ensure ''Allow log on through Remote Desktop Services'' is set to ''Administrators, Remote Desktop Users'' (Automated)'
    Section='2.2 User Rights Assignment'
    Profile='Level1'
    Type='PrivRight'
    Key='SeRemoteInteractiveLogonRight'
    ExpectedPrincipals=@('BUILTIN\ADMINISTRATORS','BUILTIN\REMOTE DESKTOP USERS')
    SetMode='Exact'
    Description='This policy setting determines which users or groups can access the logon screen of a remote computer through a Remote Desktop Services connection.'
    Impact='Any account with the Allow log on through Remote Desktop Services user right can log on to the remote console of the computer. If you do not restrict this user right to legitimate users who need to log on to the console of the computer, unauthorized users might be able to download and run malicious software or elevate their privileges.'
    Remediation='To establish the recommended configuration via GP, set the following UI path to Administrators, Remote Desktop Users: Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment\Allow log on through Remote Desktop Services'
  },
  @{
    Id='2.2.7'
    Title='(L1) Ensure ''Back up files and directories'' is set to ''Administrators'' (Automated)'
    Section='2.2 User Rights Assignment'
    Profile='Level1'
    Type='PrivRight'
    Key='SeBackupPrivilege'
    ExpectedPrincipals=@('BUILTIN\ADMINISTRATORS')
    SetMode='Exact'
    Description='This policy setting determines which users can bypass file and directory, registry, and other persistent object permissions for the purposes of backing up the system.'
    Impact='Any account with the Back up files and directories user right can read any file on the system, regardless of the permissions that protect those files. Backup programs require this user right and should be assigned to as few accounts as possible.'
    Remediation='To establish the recommended configuration via GP, set the following UI path to Administrators: Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment\Back up files and directories'
  },
  @{
    Id='2.2.8'
    Title='(L1) Ensure ''Change the system time'' is set to ''Administrators, LOCAL SERVICE'' (Automated)'
    Section='2.2 User Rights Assignment'
    Profile='Level1'
    Type='PrivRight'
    Key='SeSystemtimePrivilege'
    ExpectedPrincipals=@('BUILTIN\ADMINISTRATORS','NT AUTHORITY\LOCAL SERVICE')
    SetMode='Exact'
    Description='This policy setting determines which users and groups can change the time and date on the internal clock of the computers in your environment.'
    Impact='Users who can change the time on a computer could cause several problems. For example, time stamps on event log entries could be made inaccurate, time stamps on files and folders that are created or modified could be incorrect, and computers that belong to a domain may not be able to authenticate themselves or users who try to log on to the domain from them.'
    Remediation='To establish the recommended configuration via GP, set the following UI path to Administrators, LOCAL SERVICE: Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment\Change the system time'
  },
  @{
    Id='2.2.9'
    Title='(L1) Ensure ''Change the time zone'' is set to ''Administrators, LOCAL SERVICE'' (Automated)'
    Section='2.2 User Rights Assignment'
    Profile='Level1'
    Type='PrivRight'
    Key='SeTimeZonePrivilege'
    ExpectedPrincipals=@('BUILTIN\ADMINISTRATORS','NT AUTHORITY\LOCAL SERVICE')
    SetMode='Exact'
    Description='This policy setting determines which users can change the time zone of the computer.'
    Impact='Unauthorized users could use this capability to help mask evidence of malicious activity. The ability to change the time zone is a minor issue that could be used as part of a larger attack.'
    Remediation='To establish the recommended configuration via GP, set the following UI path to Administrators, LOCAL SERVICE: Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment\Change the time zone'
  },
  @{
    Id='2.2.10'
    Title='(L1) Ensure ''Create a pagefile'' is set to ''Administrators'' (Automated)'
    Section='2.2 User Rights Assignment'
    Profile='Level1'
    Type='PrivRight'
    Key='SeCreatePagefilePrivilege'
    ExpectedPrincipals=@('BUILTIN\ADMINISTRATORS')
    SetMode='Exact'
    Description='This policy setting determines which users and groups can call an internal application programming interface (API) to create and change the size of a page file.'
    Impact='Users who can change the page file size could make it extremely large and force the system to restart, which could cause a denial of service condition. Or, they could make the page file extremely small or move it to a highly fragmented storage volume, which could cause reduced system performance.'
    Remediation='To establish the recommended configuration via GP, set the following UI path to Administrators: Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment\Create a pagefile'
  },
  @{
    Id='2.2.11'
    Title='(L1) Ensure ''Create a token object'' is set to ''No One'' (Automated)'
    Section='2.2 User Rights Assignment'
    Profile='Level1'
    Type='PrivRight'
    Key='SeCreateTokenPrivilege'
    ExpectedPrincipals=@()
    SetMode='Exact'
    Description='This policy setting determines which accounts can be used by processes to create a token that can then be used to get access to any local resources when the process uses an internal API to create an access token.'
    Impact='A user account that is given this privilege has complete control over the system and can lead to the system being compromised. It is highly recommended that no accounts be assigned this privilege.'
    Remediation='To establish the recommended configuration via GP, set the following UI path to No One: Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment\Create a token object'
  },
  @{
    Id='2.2.12'; Title='(L1) Ensure ''Create global objects'' is set to ''Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE'' (Automated)';
    Section='2.2 User Rights Assignment'; Profile='Level1'; Type='PrivRight';
    Key='SeCreateGlobalPrivilege';
    ExpectedPrincipals=@('BUILTIN\ADMINISTRATORS','NT AUTHORITY\LOCAL SERVICE','NT AUTHORITY\NETWORK SERVICE','NT AUTHORITY\SERVICE');
    SetMode='Exact';
    Description='This policy setting determines which accounts can create global objects in a session.';
    Impact='Users with this privilege can create global objects that could be accessed by processes in other sessions, which could lead to a variety of problems.';
    Remediation='Only specified service accounts should create global objects.';
  },
  @{
    Id='2.2.13'; Title='(L1) Ensure ''Create permanent shared objects'' is set to ''No One'' (Automated)';
    Section='2.2 User Rights Assignment'; Profile='Level1'; Type='PrivRight';
    Key='SeCreatePermanentPrivilege';
    ExpectedPrincipals=@();
    SetMode='Exact';
    Description='This policy setting determines which accounts can create permanent shared objects.';
    Impact='Users with this privilege could create permanent shared objects that consume system resources.';
    Remediation='No one should create permanent shared objects.';
  },
  @{
    Id='2.2.14'; Title='(L1) Ensure ''Create symbolic links'' is set to ''Administrators, NT VIRTUAL MACHINE\Virtual Machines'' (Automated)';
    Section='2.2 User Rights Assignment'; Profile='Level1'; Type='PrivRight';
    Key='SeCreateSymbolicLinkPrivilege';
    ExpectedPrincipals=@('BUILTIN\ADMINISTRATORS','NT VIRTUAL MACHINE\VIRTUAL MACHINES');
    SetMode='Exact';
    Description='This policy setting determines which users can create symbolic links.';
    Impact='Users with this privilege can create symbolic links that could be used to access files or folders that they would not normally have access to.';
    Remediation='Only Administrators and Virtual Machines should create symbolic links.';
  },
  @{
    Id='2.2.15'
    Title='(L1) Ensure ''Debug programs'' is set to ''Administrators'' (Automated)'
    Section='2.2 User Rights Assignment'
    Profile='Level1'
    Type='PrivRight'
    Key='SeDebugPrivilege'
    ExpectedPrincipals=@('BUILTIN\ADMINISTRATORS')
    SetMode='Exact'
    Description='This policy setting determines which users can attach a debugger to any process or to the kernel, which provides complete access to sensitive and critical operating system components.'
    Impact='The Debug programs user right can be exploited to capture sensitive computer information from system memory, or to access and modify kernel or application structures. Some attack tools exploit this user right to extract hashed passwords and other private security information, or to insert rootkit code.'
    Remediation='To establish the recommended configuration via GP, set the following UI path to Administrators: Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment\Debug programs'
  },
  @{
    Id='2.2.16'; Title='(L1) Ensure ''Deny access to this computer from the network'' to include ''Guests'' (Automated)';
    Section='2.2 User Rights Assignment'; Profile='Level1'; Type='PrivRight';
    Key='SeDenyNetworkLogonRight';
    ExpectedPrincipals=@('BUILTIN\GUESTS');
    SetMode='Superset';
    Description='This policy setting determines which users are prevented from accessing a computer over the network.';
    Impact='Any account with this user right is prevented from logging on to the computer from the network.';
    Remediation='Deny network access to Guests.';
  },
  @{
    Id='2.2.17'; Title='(L1) Ensure ''Deny log on as a batch job'' to include ''Guests'' (Automated)';
    Section='2.2 User Rights Assignment'; Profile='Level1'; Type='PrivRight';
    Key='SeDenyBatchLogonRight';
    ExpectedPrincipals=@('BUILTIN\GUESTS');
    SetMode='Superset';
    Description='This policy setting determines which accounts are prevented from logging on as a batch job.';
    Impact='Accounts with this user right are prevented from logging on as a batch job.';
    Remediation='Deny batch logon to Guests.';
  },
  @{
    Id='2.2.18'; Title='(L1) Ensure ''Deny log on as a service'' to include ''Guests'' (Automated)';
    Section='2.2 User Rights Assignment'; Profile='Level1'; Type='PrivRight';
    Key='SeDenyServiceLogonRight';
    ExpectedPrincipals=@('BUILTIN\GUESTS');
    SetMode='Superset';
    Description='This policy setting determines which service accounts are prevented from registering a process as a service.';
    Impact='Accounts with this user right are prevented from registering a process as a service.';
    Remediation='Deny service logon to Guests.';
  },
  @{
    Id='2.2.19'; Title='(L1) Ensure ''Deny log on locally'' to include ''Guests'' (Automated)';
    Section='2.2 User Rights Assignment'; Profile='Level1'; Type='PrivRight';
    Key='SeDenyInteractiveLogonRight';
    ExpectedPrincipals=@('BUILTIN\GUESTS');
    SetMode='Superset';
    Description='This policy setting determines which users cannot log on at the computer.';
    Impact='Any account with this user right cannot log on at the computer.';
    Remediation='Deny local logon to Guests.';
  },
  @{
    Id='2.2.20'; Title='(L1) Ensure ''Deny log on through Remote Desktop Services'' is set to ''Guests, Local account'' (Automated)';
    Section='2.2 User Rights Assignment'; Profile='Level1'; Type='PrivRight';
    Key='SeDenyRemoteInteractiveLogonRight';
    ExpectedPrincipals=@('BUILTIN\GUESTS','NT AUTHORITY\Local account');
    SetMode='Superset';
    Description='This policy setting determines which users and groups are prohibited from logging on as a Remote Desktop Services client.';
    Impact='Any account with this user right cannot log on as a Remote Desktop Services client.';
    Remediation='Deny RDS logon to Guests and local accounts.';
  },
  @{
    Id='2.2.21'; Title='(L1) Ensure ''Enable computer and user accounts to be trusted for delegation'' is set to ''No One'' (Automated)';
    Section='2.2 User Rights Assignment'; Profile='Level1'; Type='PrivRight';
    Key='SeEnableDelegationPrivilege';
    ExpectedPrincipals=@();
    SetMode='Exact';
    Description='This policy setting determines which users can set the Trusted for Delegation setting on a user or computer object.';
    Impact='Misuse of this user right, or of the Trusted for Delegation setting, could allow unauthorized users to impersonate other users on the network.';
    Remediation='No accounts should be trusted for delegation.';
  },
  @{
    Id='2.2.22'; Title='(L1) Ensure ''Force shutdown from a remote system'' is set to ''Administrators'' (Automated)';
    Section='2.2 User Rights Assignment'; Profile='Level1'; Type='PrivRight';
    Key='SeRemoteShutdownPrivilege';
    ExpectedPrincipals=@('BUILTIN\ADMINISTRATORS');
    SetMode='Exact';
    Description='This policy setting determines which users are allowed to shut down a computer from a remote location on the network.';
    Impact='Any account with this user right can shut down the computer from a remote location on the network.';
    Remediation='Only Administrators should force remote shutdown.';
  },
  @{
    Id='2.2.23'; Title='(L1) Ensure ''Generate security audits'' is set to ''LOCAL SERVICE, NETWORK SERVICE'' (Automated)';
    Section='2.2 User Rights Assignment'; Profile='Level1'; Type='PrivRight';
    Key='SeAuditPrivilege';
    ExpectedPrincipals=@('NT AUTHORITY\LOCAL SERVICE','NT AUTHORITY\NETWORK SERVICE');
    SetMode='Exact';
    Description='This policy setting determines which accounts can be used by a process to add entries to the security log.';
    Impact='Accounts with this user right can be used by a process to add entries to the security log.';
    Remediation='Only service accounts should generate security audits.';
  },
  @{
    Id='2.2.24'; Title='(L1) Ensure ''Impersonate a client after authentication'' is set to ''Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE'' and (when the Web Server (IIS) Role with Web Services Role Service is installed) ''IIS_IUSRS'' (Automated)';
    Section='2.2 User Rights Assignment'; Profile='Level1'; Type='PrivRight';
    Key='SeImpersonatePrivilege';
    ExpectedPrincipals=@('BUILTIN\ADMINISTRATORS','NT AUTHORITY\LOCAL SERVICE','NT AUTHORITY\NETWORK SERVICE','NT AUTHORITY\SERVICE','BUILTIN\IIS_IUSRS');
    SetMode='Exact';
    Description='Assigning this user right to a user allows programs running on behalf of that user to impersonate a client.';
    Impact='An attacker with this user right could create a service, trick a client into making a connection to the service, and then impersonate that client to elevate the attacker''s level of access to that of the client.';
    Remediation='Restrict impersonation to specified service accounts.';
  },
  @{
    Id='2.2.25'; Title='(L1) Ensure ''Increase scheduling priority'' is set to ''Administrators, Window Manager\Window Manager Group'' (Automated)';
    Section='2.2 User Rights Assignment'; Profile='Level1'; Type='PrivRight';
    Key='SeIncreaseBasePriorityPrivilege';
    ExpectedPrincipals=@('BUILTIN\ADMINISTRATORS','Window Manager\Window Manager Group');
    SetMode='Exact';
    Description='This policy setting determines which accounts can use a process with Write Property access to another process to increase the execution priority assigned to the other process.';
    Impact='A user with this privilege could increase the scheduling priority of a process to Real-Time, which would leave little processing time for all other processes and could lead to a DoS condition.';
    Remediation='Only Administrators and Window Manager should increase scheduling priority.';
  },
  @{
    Id='2.2.26'; Title='(L1) Ensure ''Load and unload device drivers'' is set to ''Administrators'' (Automated)';
    Section='2.2 User Rights Assignment'; Profile='Level1'; Type='PrivRight';
    Key='SeLoadDriverPrivilege';
    ExpectedPrincipals=@('BUILTIN\ADMINISTRATORS');
    SetMode='Exact';
    Description='This policy setting determines which users can dynamically load and unload device drivers or other code in to kernel mode.';
    Impact='Users with this privilege could unintentionally install malicious code that masquerades as a device driver.';
    Remediation='Only Administrators should load/unload device drivers.';
  },
  @{
    Id='2.2.27'; Title='(L1) Ensure ''Lock pages in memory'' is set to ''No One'' (Automated)';
    Section='2.2 User Rights Assignment'; Profile='Level1'; Type='PrivRight';
    Key='SeLockMemoryPrivilege';
    ExpectedPrincipals=@();
    SetMode='Exact';
    Description='This policy setting determines which accounts can use a process to keep data in physical memory, which prevents the system from paging the data to virtual memory on disk.';
    Impact='Users with this privilege could assign physical memory to several processes, which could leave little or no RAM for other processes and result in a DoS condition.';
    Remediation='No one should lock pages in memory.';
  },
  @{
    Id='2.2.28'
    Title='(L1) Ensure ''Manage auditing and security log'' is set to ''Administrators'' (Automated)'
    Section='2.2 User Rights Assignment'
    Profile='Level1'
    Type='PrivRight'
    Key='SeSecurityPrivilege'
    ExpectedPrincipals=@('BUILTIN\ADMINISTRATORS')
    SetMode='Exact'
    Description='This policy setting determines which users can specify object access audit options for individual resources such as files, Active Directory objects, and registry keys.'
    Impact='The ability to manage the Security event log is a powerful user right and it should be closely guarded. Anyone with this user right can clear the Security log to erase important evidence of unauthorized activity.'
    Remediation='To establish the recommended configuration via GP, set the following UI path to Administrators: Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment\Manage auditing and security log'
  },
  @{
    Id='2.2.29'; Title='(L1) Ensure ''Modify an object label'' is set to ''No One'' (Automated)';
    Section='2.2 User Rights Assignment'; Profile='Level1'; Type='PrivRight';
    Key='SeRelabelPrivilege';
    ExpectedPrincipals=@();
    SetMode='Exact';
    Description='This policy setting determines which user accounts can modify the integrity label of objects, such as files, registry keys, or processes owned by other users.';
    Impact='By modifying the integrity label of an object owned by another user a user can cause data to be deleted or the system to stop responding.';
    Remediation='No one should modify object labels.';
  },
  @{
    Id='2.2.30'; Title='(L1) Ensure ''Modify firmware environment values'' is set to ''Administrators'' (Automated)';
    Section='2.2 User Rights Assignment'; Profile='Level1'; Type='PrivRight';
    Key='SeSystemEnvironmentPrivilege';
    ExpectedPrincipals=@('BUILTIN\ADMINISTRATORS');
    SetMode='Exact';
    Description='This policy setting determines who can modify the nonvolatile RAM (NVRAM) environment variables using a system application.';
    Impact='Anyone with this user right can configure the settings of a hardware component to cause it to fail, which could lead to data corruption or a DoS condition.';
    Remediation='Only Administrators should modify firmware environment values.';
  },
  @{
    Id='2.2.31'; Title='(L1) Ensure ''Perform volume maintenance tasks'' is set to ''Administrators'' (Automated)';
    Section='2.2 User Rights Assignment'; Profile='Level1'; Type='PrivRight';
    Key='SeManageVolumePrivilege';
    ExpectedPrincipals=@('BUILTIN\ADMINISTRATORS');
    SetMode='Exact';
    Description='This policy setting determines which users and groups can run maintenance tasks on a volume, such as remote defragmentation.';
    Impact='A user with this privilege could delete a volume, which could result in the loss of data or a DoS condition.';
    Remediation='Only Administrators should perform volume maintenance tasks.';
  },
  @{
    Id='2.2.32'; Title='(L1) Ensure ''Profile single process'' is set to ''Administrators'' (Automated)';
    Section='2.2 User Rights Assignment'; Profile='Level1'; Type='PrivRight';
    Key='SeProfileSingleProcessPrivilege';
    ExpectedPrincipals=@('BUILTIN\ADMINISTRATORS');
    SetMode='Exact';
    Description='This policy setting determines which users can use performance monitoring tools to monitor the performance of non-system processes.';
    Impact='The Profile single process user right presents a moderate vulnerability. An attacker with this user right could monitor a computer''s performance to help identify critical processes and could also determine what processes run on the system so that they could identify countermeasures that they may need to avoid, such as antivirus software, an intrusion-detection system, or which other users are logged on to a computer.';
    Remediation='Only Administrators should profile single process.';
  },
  @{
    Id='2.2.33'; Title='(L1) Ensure ''Profile system performance'' is set to ''Administrators, NT SERVICE\WdiServiceHost'' (Automated)';
    Section='2.2 User Rights Assignment'; Profile='Level1'; Type='PrivRight';
    Key='SeSystemProfilePrivilege';
    ExpectedPrincipals=@('BUILTIN\ADMINISTRATORS','NT SERVICE\WdiServiceHost');
    SetMode='Exact';
    Description='This policy setting determines which users can use performance monitoring tools to monitor the performance of system processes.';
    Impact='The Profile system performance user right poses a moderate vulnerability. Attackers with this user right could monitor a computer''s performance to help identify critical processes and could also determine what processes run on the system so that they could identify countermeasures that they may need to avoid, such as antivirus software or an intrusion detection system.';
    Remediation='Only Administrators and WdiServiceHost should profile system performance.';
  },
  @{
    Id='2.2.34'; Title='(L1) Ensure ''Replace a process level token'' is set to ''LOCAL SERVICE, NETWORK SERVICE'' (Automated)';
    Section='2.2 User Rights Assignment'; Profile='Level1'; Type='PrivRight';
    Key='SeAssignPrimaryTokenPrivilege';
    ExpectedPrincipals=@('NT AUTHORITY\LOCAL SERVICE','NT AUTHORITY\NETWORK SERVICE');
    SetMode='Exact';
    Description='This policy setting determines which user accounts can call the CreateProcessAsUser API so that one service can start another.';
    Impact='A user with this privilege could create new processes as another user, which could be used to hide malicious activities.';
    Remediation='Only service accounts should replace process level tokens.';
  },
  @{
    Id='2.2.35'; Title='(L1) Ensure ''Restore files and directories'' is set to ''Administrators'' (Automated)';
    Section='2.2 User Rights Assignment'; Profile='Level1'; Type='PrivRight';
    Key='SeRestorePrivilege';
    ExpectedPrincipals=@('BUILTIN\ADMINISTRATORS');
    SetMode='Exact';
    Description='This policy setting determines which users can bypass file, directory, registry, and other persistent objects permissions when restoring backed up files and directories, and determines which users can set any valid security principal as the owner of an object.';
    Impact='An attacker with this user right could restore sensitive data to a computer and overwrite data that is more recent, which could lead to loss of important data, data corruption, or a denial of service. Attackers could overwrite executable files that are used by legitimate administrators or system services with versions that include malicious code to grant themselves elevated privileges, compromise data, or install backdoors for continued access to the computer.';
    Remediation='Only Administrators should restore files and directories.';
  },
  @{
    Id='2.2.36'; Title='(L1) Ensure ''Shut down the system'' is set to ''Administrators'' (Automated)';
    Section='2.2 User Rights Assignment'; Profile='Level1'; Type='PrivRight';
    Key='SeShutdownPrivilege';
    ExpectedPrincipals=@('BUILTIN\ADMINISTRATORS');
    SetMode='Exact';
    Description='This policy setting determines which users who are logged on locally to the computers in your environment can shut down the operating system with the Shut Down command.';
    Impact='The ability to shut down domain controllers and member servers should be limited to a very small number of trusted administrators. Although the Shut down the system user right requires the ability to log on to the server, you should be very careful about which accounts and groups you allow to shut down a domain controller or member server.';
    Remediation='Only Administrators should shut down the system.';
  },
  @{
    Id='2.2.37'; Title='(L1) Ensure ''Take ownership of files or other objects'' is set to ''Administrators'' (Automated)';
    Section='2.2 User Rights Assignment'; Profile='Level1'; Type='PrivRight';
    Key='SeTakeOwnershipPrivilege';
    ExpectedPrincipals=@('BUILTIN\ADMINISTRATORS');
    SetMode='Exact';
    Description='This policy setting determines which users can take ownership of any securable object in the system, including Active Directory objects, files and folders, printers, registry keys, processes, and threads.';
    Impact='Any users with the Take ownership of files or other objects user right can take control of any object, regardless of the permissions on that object, and then make any changes they wish to that object. Such changes could result in exposure of data, corruption of data, or a DoS condition.';
    Remediation='Only Administrators should take ownership of files or objects.';
  },

  # 2.3 Security Options (2.3.1–2.3.6)
  @{
    Id='2.3.1.1'
    Title='(L1) Ensure ''Accounts: Guest account status'' is set to ''Disabled'' (Automated)'
    Section='2.3.1 Accounts'
    Profile='Level1'
    Type='SecEdit'
    SectionName='System Access'
    Key='EnableGuestAccount'
    Operator='Equals'
    Expected=0
    Description='This policy setting determines whether the Guest account is enabled or disabled. The Guest account allows unauthenticated network users to gain access to the system.'
    Impact='If the Guest account is enabled, unauthorized users could gain access to any resources that are accessible to the Guest account over the network. This capability means that any network shares with permissions that allow access to the Guest account, the Guests group, or the Everyone group will be accessible over the network, which could lead to the exposure or corruption of data.'
    Remediation='To establish the recommended configuration via GP, set the following UI path to Disabled: Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\Accounts: Guest account status'
  },
  @{
    Id='2.3.1.2'
    Title='(L1) Ensure ''Accounts: Limit local account use of blank passwords to console logon only'' is set to ''Enabled'' (Automated)'
    Section='2.3.1 Accounts'
    Profile='Level1'
    Type='SecEdit'
    SectionName='System Access'
    Key='LimitBlankPasswordUse'
    Operator='Equals'
    Expected=1
    Description='This policy setting determines whether local accounts that are not password protected can be used to log on from locations other than the physical computer console. If you enable this policy setting, local accounts that have blank passwords will not be able to log on to the network from remote client computers.'
    Impact='Blank passwords are a serious threat to computer security and should be forbidden through both organizational policy and suitable technical measures. All accounts should have strong passwords or passphrases. With the Accounts: Limit local account use of blank passwords to console logon only policy setting enabled, a user must have physical access to the computer console to log on with an account that has a blank password.'
    Remediation='To establish the recommended configuration via GP, set the following UI path to Enabled: Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\Accounts: Limit local account use of blank passwords to console logon only'
  },
  @{
    Id='2.3.1.3'
    Title='(L1) Configure ''Accounts: Rename administrator account'' (Automated)'
    Section='2.3.1 Accounts'
    Profile='Level1'
    Type='Manual'
    Expected='Renamed from Administrator'
    Evidence='Check Local Security Policy'
    Description='The built-in Administrator account is a well-known account name that attackers will target. It is recommended to choose another name for this account, and to avoid names that denote administrative or elevated access accounts.'
    Impact='The Administrator account exists on all computers that run Windows. If you rename this account, it is slightly more difficult for unauthorized persons to guess this privileged account name and password combination.'
    Remediation='To establish the recommended configuration via GP, set the following UI path to a name other than Administrator: Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\Accounts: Rename administrator account'
  },
  @{
    Id='2.3.1.4'
    Title='(L1) Configure ''Accounts: Rename guest account'' (Automated)'
    Section='2.3.1 Accounts'
    Profile='Level1'
    Type='Manual'
    Expected='Renamed from Guest'
    Evidence='Check Local Security Policy'
    Description='The built-in Guest account is a well-known account name that attackers will target. It is recommended to choose another name for this account.'
    Impact='The Guest account is disabled by default. Even if you enable the Guest account, renaming it makes it slightly more difficult for unauthorized persons to guess this account name and gain access to the server.'
    Remediation='To establish the recommended configuration via GP, set the following UI path to a name other than Guest: Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\Accounts: Rename guest account'
  },
  @{
    Id='2.3.2.1'; Title='(L1) Ensure ''Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit policy category settings'' is set to ''Enabled'' (Automated)';
    Section='2.3.2 Audit'; Profile='Level1'; Type='SecEdit';
    SectionName='System Access'; Key='SCENoApplyLegacyAuditPolicy'; Operator='Equals'; Expected=1;
    Description='This policy setting allows you to force audit policy subcategory settings to override audit policy category settings.';
    Impact='This setting ensures that subcategory audit policy settings take precedence over category settings, providing more granular control over auditing.';
    Remediation='Set ''Audit: Force audit policy subcategory settings'' to Enabled in Security Options.';
  },
  @{
    Id='2.3.2.2'; Title='(L1) Ensure ''Audit: Shut down system immediately if unable to log security audits'' is set to ''Disabled'' (Automated)';
    Section='2.3.2 Audit'; Profile='Level1'; Type='SecEdit';
    SectionName='System Access'; Key='CrashOnAuditFail'; Operator='Equals'; Expected=0;
    Description='This policy setting determines whether the system shuts down if it is unable to log Security events.';
    Impact='If this policy is enabled, it creates a denial of service vulnerability, as an attacker could generate a large volume of security events to fill the Security log and shut down the system.';
    Remediation='Set ''Audit: Shut down system immediately if unable to log security audits'' to Disabled in Security Options.';
  },
  @{
    Id='2.3.4.1'; Title='(L1) Ensure ''Devices: Prevent users from installing printer drivers'' is set to ''Enabled'' (Automated)';
    Section='2.3.4 Devices'; Profile='Level1'; Type='SecEdit';
    SectionName='System Access'; Key='AddPrinterDrivers'; Operator='Equals'; Expected=1;
    Description='For a computer to print to a shared printer, the driver for that shared printer must be installed on the local computer. This policy setting determines who is allowed to install a printer driver as part of connecting to a shared printer.';
    Impact='It may be appropriate in some organizations to allow users to install printer drivers on their own workstations. However, you should allow only Administrators, not users, to do so on servers, because printer driver installation on a server may unintentionally cause the computer to become less stable.';
    Remediation='Set ''Devices: Prevent users from installing printer drivers'' to Enabled in Security Options.';
  },
  @{
    Id='2.3.7.1'; Title='(L1) Ensure ''Interactive logon: Do not require CTRL+ALT+DEL'' is set to ''Disabled'' (Automated)';
    Section='2.3.7 Interactive logon'; Profile='Level1'; Type='SecEdit';
    SectionName='System Access'; Key='DisableCAD'; Operator='Equals'; Expected=0;
    Description='This policy setting determines whether users must press CTRL+ALT+DEL before they log on.';
    Impact='Microsoft developed this feature to make it more difficult for malware to capture a user''s password. Requiring CTRL+ALT+DEL before users log on ensures that users are communicating by means of a trusted path when entering their passwords.';
    Remediation='Set ''Interactive logon: Do not require CTRL+ALT+DEL'' to Disabled in Security Options.';
  },
  @{
    Id='2.3.7.2'; Title='(L1) Ensure ''Interactive logon: Don''t display last signed-in'' is set to ''Enabled'' (Automated)';
    Section='2.3.7 Interactive logon'; Profile='Level1'; Type='SecEdit';
    SectionName='System Access'; Key='DontDisplayLastUserName'; Operator='Equals'; Expected=1;
    Description='This policy setting determines whether the account name of the last user to log on to the client computers in your organization will be displayed in each computer''s respective Windows logon screen.';
    Impact='An attacker with access to the console (for example, someone with physical access or someone who is able to connect to the server through Remote Desktop Services) could view the name of the last user who logged on to the server. The attacker could then try to guess the password, use a dictionary, or use a brute-force attack to try and log on.';
    Remediation='Set ''Interactive logon: Don''t display last signed-in'' to Enabled in Security Options.';
  },
  @{
    Id='2.3.7.3'; Title='(L1) Ensure ''Interactive logon: Machine inactivity limit'' is set to ''900 or fewer second(s), but not 0'' (Automated)';
    Section='2.3.7 Interactive logon'; Profile='Level1'; Type='Composite';
    AllOf=@(
        @{ SectionName='System Access'; Key='InactivityTimeoutSecs'; Operator='LessOrEqual'; Expected=900 },
        @{ SectionName='System Access'; Key='InactivityTimeoutSecs'; Operator='NotEquals'; Expected=0 }
    );
    Description='Windows notices inactivity of a logon session, and if the amount of inactive time exceeds the inactivity limit, then the screen saver will run, locking the session.';
    Impact='If a user forgets to lock their computer when they walk away from it, the computer will eventually lock itself. However, the user''s programs will continue to run.';
    Remediation='Set ''Interactive logon: Machine inactivity limit'' to 900 or fewer seconds, but not 0 in Security Options.';
  }

  # Note: Additional Security Options rules would continue here...
  # This is a condensed version showing the structure. Full implementation would include all 61 Security Options controls.
)