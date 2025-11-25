# Manual verification script for all 2.2.x and 2.3.x controls

Write-Host "`n=== SECTION 2.2.x - USER RIGHTS ASSIGNMENT ===" -ForegroundColor Cyan

# Export secedit for user rights
$tempFile = "$env:TEMP\secpol-verify.inf"
secedit /export /cfg $tempFile /quiet

Write-Host "`n2.2.1 - Access this computer from the network" -ForegroundColor Yellow
(Get-Content $tempFile | Select-String "SeNetworkLogonRight").Line

Write-Host "`n2.2.2 - Act as part of the operating system" -ForegroundColor Yellow
(Get-Content $tempFile | Select-String "SeTcbPrivilege").Line

Write-Host "`n2.2.3 - Adjust memory quotas for a process" -ForegroundColor Yellow
(Get-Content $tempFile | Select-String "SeIncreaseQuotaPrivilege").Line

Write-Host "`n2.2.4 - Allow log on locally" -ForegroundColor Yellow
(Get-Content $tempFile | Select-String "SeInteractiveLogonRight").Line

Write-Host "`n2.2.5 - Allow log on through Remote Desktop Services" -ForegroundColor Yellow
(Get-Content $tempFile | Select-String "SeRemoteInteractiveLogonRight").Line

Write-Host "`n2.2.6 - Back up files and directories" -ForegroundColor Yellow
(Get-Content $tempFile | Select-String "SeBackupPrivilege").Line

Write-Host "`n2.2.7 - Change the system time" -ForegroundColor Yellow
(Get-Content $tempFile | Select-String "SeSystemtimePrivilege").Line

Write-Host "`n2.2.8 - Change the time zone" -ForegroundColor Yellow
(Get-Content $tempFile | Select-String "SeTimeZonePrivilege").Line

Write-Host "`n2.2.9 - Create a pagefile" -ForegroundColor Yellow
(Get-Content $tempFile | Select-String "SeCreatePagefilePrivilege").Line

Write-Host "`n2.2.10 - Create a token object" -ForegroundColor Yellow
(Get-Content $tempFile | Select-String "SeCreateTokenPrivilege").Line

Write-Host "`n2.2.11 - Create global objects" -ForegroundColor Yellow
(Get-Content $tempFile | Select-String "SeCreateGlobalPrivilege").Line

Write-Host "`n2.2.12 - Create permanent shared objects" -ForegroundColor Yellow
(Get-Content $tempFile | Select-String "SeCreatePermanentPrivilege").Line

Write-Host "`n2.2.13 - Create symbolic links" -ForegroundColor Yellow
(Get-Content $tempFile | Select-String "SeCreateSymbolicLinkPrivilege").Line

Write-Host "`n2.2.14 - Debug programs" -ForegroundColor Yellow
(Get-Content $tempFile | Select-String "SeDebugPrivilege").Line

Write-Host "`n2.2.15 - Deny access to this computer from the network" -ForegroundColor Yellow
(Get-Content $tempFile | Select-String "SeDenyNetworkLogonRight").Line

Write-Host "`n2.2.16 - Deny log on as a batch job" -ForegroundColor Yellow
(Get-Content $tempFile | Select-String "SeDenyBatchLogonRight").Line

Write-Host "`n2.2.17 - Deny log on as a service" -ForegroundColor Yellow
(Get-Content $tempFile | Select-String "SeDenyServiceLogonRight").Line

Write-Host "`n2.2.18 - Deny log on locally" -ForegroundColor Yellow
(Get-Content $tempFile | Select-String "SeDenyInteractiveLogonRight").Line

Write-Host "`n2.2.19 - Deny log on through Remote Desktop Services" -ForegroundColor Yellow
(Get-Content $tempFile | Select-String "SeDenyRemoteInteractiveLogonRight").Line

Write-Host "`n2.2.20 - Enable computer and user accounts to be trusted for delegation" -ForegroundColor Yellow
(Get-Content $tempFile | Select-String "SeEnableDelegationPrivilege").Line

Write-Host "`n2.2.21 - Force shutdown from a remote system" -ForegroundColor Yellow
(Get-Content $tempFile | Select-String "SeRemoteShutdownPrivilege").Line

Write-Host "`n2.2.22 - Generate security audits" -ForegroundColor Yellow
(Get-Content $tempFile | Select-String "SeAuditPrivilege").Line

Write-Host "`n2.2.23 - Impersonate a client after authentication" -ForegroundColor Yellow
(Get-Content $tempFile | Select-String "SeImpersonatePrivilege").Line

Write-Host "`n2.2.24 - Increase scheduling priority" -ForegroundColor Yellow
(Get-Content $tempFile | Select-String "SeIncreaseBasePriorityPrivilege").Line

Write-Host "`n2.2.25 - Load and unload device drivers" -ForegroundColor Yellow
(Get-Content $tempFile | Select-String "SeLoadDriverPrivilege").Line

Write-Host "`n2.2.26 - Lock pages in memory" -ForegroundColor Yellow
(Get-Content $tempFile | Select-String "SeLockMemoryPrivilege").Line

Write-Host "`n2.2.27 - Manage auditing and security log" -ForegroundColor Yellow
(Get-Content $tempFile | Select-String "SeSecurityPrivilege").Line

Write-Host "`n2.2.28 - Modify an object label" -ForegroundColor Yellow
(Get-Content $tempFile | Select-String "SeRelabelPrivilege").Line

Write-Host "`n2.2.29 - Modify firmware environment values" -ForegroundColor Yellow
(Get-Content $tempFile | Select-String "SeSystemEnvironmentPrivilege").Line

Write-Host "`n2.2.30 - Perform volume maintenance tasks" -ForegroundColor Yellow
(Get-Content $tempFile | Select-String "SeManageVolumePrivilege").Line

Write-Host "`n2.2.31 - Profile single process" -ForegroundColor Yellow
(Get-Content $tempFile | Select-String "SeProfileSingleProcessPrivilege").Line

Write-Host "`n2.2.32 - Profile system performance" -ForegroundColor Yellow
(Get-Content $tempFile | Select-String "SeSystemProfilePrivilege").Line

Write-Host "`n2.2.33 - Replace a process level token" -ForegroundColor Yellow
(Get-Content $tempFile | Select-String "SeAssignPrimaryTokenPrivilege").Line

Write-Host "`n2.2.34 - Restore files and directories" -ForegroundColor Yellow
(Get-Content $tempFile | Select-String "SeRestorePrivilege").Line

Write-Host "`n2.2.35 - Shut down the system" -ForegroundColor Yellow
(Get-Content $tempFile | Select-String "SeShutdownPrivilege").Line

Write-Host "`n2.2.36 - Take ownership of files or other objects" -ForegroundColor Yellow
(Get-Content $tempFile | Select-String "SeTakeOwnershipPrivilege").Line

Write-Host "`n`n=== SECTION 2.3.x - REGISTRY SETTINGS ===" -ForegroundColor Cyan

Write-Host "`n2.3.1.x - Accounts settings" -ForegroundColor Yellow
Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -ErrorAction SilentlyContinue | Select-Object LimitBlankPasswordUse, NoLMHash

Write-Host "`n2.3.2.x - Audit settings" -ForegroundColor Yellow
Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -ErrorAction SilentlyContinue | Select-Object CrashOnAuditFail

Write-Host "`n2.3.4.x - Devices settings" -ForegroundColor Yellow
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -ErrorAction SilentlyContinue | Select-Object AllocateDASD

Write-Host "`n2.3.6.x - Interactive logon settings" -ForegroundColor Yellow
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -ErrorAction SilentlyContinue | Select-Object DisableCAD, DontDisplayLastUserName, InactivityTimeoutSecs
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -ErrorAction SilentlyContinue | Select-Object ScRemoveOption

Write-Host "`n2.3.7.x - Microsoft network client settings" -ForegroundColor Yellow
Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" -ErrorAction SilentlyContinue | Select-Object RequireSecuritySignature, EnableSecuritySignature, EnablePlainTextPassword

Write-Host "`n2.3.8.x - Microsoft network server settings" -ForegroundColor Yellow
Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" -ErrorAction SilentlyContinue | Select-Object AutoDisconnect, RequireSecuritySignature, EnableSecuritySignature, EnableForcedLogOff, SmbServerNameHardeningLevel

Write-Host "`n2.3.9.x - Network access settings" -ForegroundColor Yellow
Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -ErrorAction SilentlyContinue | Select-Object RestrictAnonymous, RestrictAnonymousSAM, DisableDomainCreds, EveryoneIncludesAnonymous, RestrictRemoteSAM

Write-Host "`n2.3.10.x - Network security settings" -ForegroundColor Yellow
Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -ErrorAction SilentlyContinue | Select-Object NoLMHash, LmCompatibilityLevel, NTLMMinClientSec, NTLMMinServerSec
Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" -ErrorAction SilentlyContinue | Select-Object NTLMMinClientSec, NTLMMinServerSec

Write-Host "`n2.3.11.x - System objects settings" -ForegroundColor Yellow
Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" -ErrorAction SilentlyContinue | Select-Object ProtectionMode

Write-Host "`n2.3.15.x - System settings" -ForegroundColor Yellow
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -ErrorAction SilentlyContinue | Select-Object ShutdownWithoutLogon, EnableInstallerDetection, EnableSecureUIAPaths, EnableLUA, PromptOnSecureDesktop, EnableVirtualization, FilterAdministratorToken, ConsentPromptBehaviorAdmin, ConsentPromptBehaviorUser, ValidateAdminCodeSignatures

Write-Host "`n2.3.17.x - User Account Control settings" -ForegroundColor Yellow
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -ErrorAction SilentlyContinue | Select-Object EnableLUA, EnableVirtualization, FilterAdministratorToken, ConsentPromptBehaviorAdmin, ConsentPromptBehaviorUser, EnableInstallerDetection, ValidateAdminCodeSignatures, EnableSecureUIAPaths, PromptOnSecureDesktop

# Cleanup
Remove-Item $tempFile -Force -ErrorAction SilentlyContinue

Write-Host "`n`nDone! Compare these values with your scanner output." -ForegroundColor Green
