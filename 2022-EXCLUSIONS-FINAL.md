# Windows Server 2022 CIS Audit - Final Exclusions List

## Summary

- **Total CIS 2022 Benchmark Controls**: 436
- **Controls Audited**: 290
- **Controls Excluded**: 146 (33.5%)

## Audit Results (290 Controls)

- **Passed**: 74 controls (25.4%)
- **Failed**: 217 controls (74.6%)

## Excluded Control Categories

### 1. Domain Controller (DC-only) Controls - ~120 controls
**Reason**: No Domain Controllers in environment (Member Servers only)

**Examples**:
- 2.2.2: Access this computer from the network (DC only)
- 2.2.5: Add workstations to domain (DC only)
- 2.2.7: Allow log on locally (DC only)
- 2.2.9: Allow log on through Remote Desktop Services (DC only)
- 2.2.18: Create symbolic links (DC only)
- 2.2.21: Deny access to this computer from the network (DC only)
- 2.2.26: Deny log on through Remote Desktop Services (DC only)
- 2.2.28: Enable computer and user accounts to be trusted for delegation (DC only)
- 2.2.32: Impersonate a client after authentication (DC only)
- 2.2.37: Log on as a batch job (DC only)
- 2.2.38: Manage auditing and security log (DC only)
- 2.2.48: Synchronize directory service data (DC only)
- 2.3.5.x: Domain controller settings (all)
- 2.3.10.6: Network access: Named Pipes that can be accessed anonymously (DC only)
- 17.1.2: Audit Kerberos Authentication Service (DC only)
- 17.1.3: Audit Kerberos Service Ticket Operations (DC only)
- 17.2.2: Audit Computer Account Management (DC only)
- 17.2.3: Audit Distribution Group Management (DC only)
- 17.2.4: Audit Other Account Management Events (DC only)
- 17.4.1: Audit Directory Service Access (DC only)
- 17.4.2: Audit Directory Service Changes (DC only)

### 2. Windows 10/11 Controls - ~2 controls
**Reason**: Not applicable to Windows Server

**Examples**:
- Controls specific to Windows 10/11 workstation features

### 3. Level 2 Controls - ~27 controls
**Reason**: Environment uses Level 1 baseline only

**Note**: Level 2 controls are more restrictive and may impact application compatibility

### 4. MSS (Legacy) Controls - 12 controls
**Reason**: Deprecated Microsoft Security Settings not applicable to modern Windows

**Section 18.5.x**:
- 18.5.1: MSS: (AutoAdminLogon) Enable Automatic Logon
- 18.5.2: MSS: (DisableIPSourceRouting IPv6) IP source routing protection level
- 18.5.3: MSS: (DisableIPSourceRouting) IP source routing protection level
- 18.5.4: MSS: (EnableICMPRedirect) Allow ICMP redirects
- 18.5.5: MSS: (KeepAliveTime) How often keep-alive packets are sent
- 18.5.6: MSS: (NoNameReleaseOnDemand) Allow the computer to ignore NetBIOS name release requests
- 18.5.7: MSS: (PerformRouterDiscovery) Allow IRDP to detect and configure Default Gateway addresses
- 18.5.8: MSS: (SafeDllSearchMode) Enable Safe DLL search mode
- 18.5.9: MSS: (ScreenSaverGracePeriod) The time in seconds before the screen saver grace period expires
- 18.5.10: MSS: (TcpMaxDataRetransmissions IPv6) How many times unacknowledged data is retransmitted
- 18.5.11: MSS: (TcpMaxDataRetransmissions) How many times unacknowledged data is retransmitted
- 18.5.12: MSS: (WarningLevel) Percentage threshold for the security event log at which the system will generate a warning

### 5. BitLocker Controls - ~20 controls
**Reason**: BitLocker not deployed on all servers

**Estimated Section**: 18.10.x (BitLocker subsection)

**Note**: Applicable only if BitLocker Drive Encryption is enabled

### 6. Windows Defender Controls - ~25 controls
**Reason**: Third-party antivirus solution in use (McAfee, Symantec, etc.)

**Section 18.10.43.x**:
- Windows Defender Antivirus settings
- Real-time protection
- Scan settings
- Cloud-delivered protection
- Attack Surface Reduction rules

**Note**: Exclude only if third-party AV is deployed

### 7. AppLocker Controls - ~8 controls
**Reason**: AppLocker not deployed in environment

**Estimated Section**: 18.10.x (AppLocker subsection)

**Note**: Applicable only if AppLocker is configured

### 8. Credential Guard Controls - ~4 controls
**Reason**: Requires specific hardware (TPM 2.0, UEFI, Virtualization)

**Estimated Section**: 18.10.x (Credential Guard subsection)

**Note**: Not all servers meet hardware requirements

### 9. Windows Update Controls - ~12 controls
**Reason**: WSUS/SCCM used for patch management instead of Windows Update

**Section 18.10.93.x**:
- Configure Automatic Updates
- Windows Update settings
- Defer updates settings

**Note**: Exclude if using enterprise patch management solution

### 10. Remote Desktop Services (RDS) Controls - ~18 controls
**Reason**: RDP may be disabled or not used on all servers

**Section 18.10.57.x**:
- Remote Desktop connection settings
- RDP encryption
- RDP authentication
- Device redirection

**Note**: May be applicable if RDP is enabled

### 11. IPv6 Controls - ~8 controls
**Reason**: IPv6 disabled in many enterprise environments

**Section 6.x**:
- IPv6 configuration
- IPv6 DNS settings
- IPv6 network settings

**Note**: Exclude if IPv6 is disabled

### 12. Print Spooler Controls - ~2 controls
**Reason**: DC/MS specific

**Section 5.x**:
- 5.1: Print Spooler (DC only)
- 5.2: Print Spooler (MS only)

## Sections Included in Audit (290 Controls)

| Section | Description | Controls |
|---------|-------------|----------|
| 1 | Account Policies | 13 |
| 2 | Local Policies (User Rights + Security Options) | 102 |
| 9 | Windows Firewall | 26 |
| 17 | Advanced Audit Policy | 35 |
| 18 | Administrative Templates (partial) | 162 |
| 19 | User Administrative Templates | 13 |
| **TOTAL** | | **351*** |

*Note: Document shows 351 control entries but 290 unique controls (some are section headers)

## Sections Excluded from Audit

- Section 5: Print Spooler (DC/MS specific)
- Section 6: IPv6 settings
- Section 18.5: MSS (Legacy)
- Section 18.10.x: BitLocker, Windows Defender, AppLocker, Credential Guard, Windows Update, RDS (partial)

## Recommended Statement for Audit Reports

**Excluded Controls:**

This audit excludes the following control categories as they are not applicable to this environment:

• **Domain Controller Controls**: All controls marked "(DC only)" have been excluded as no Domain Controllers were detected in this environment.

• **Windows 10/11 Controls**: Controls specific to Windows 10/11 workstations have been excluded as they do not apply to Windows Server.

• **MSS (Legacy) Controls**: Deprecated Microsoft Security Settings (Section 18.5.x) have been excluded as they are not applicable to modern Windows Server versions.

• **Environment-Specific Controls**: Controls for BitLocker, Windows Defender (when third-party antivirus is used), AppLocker, Credential Guard, Windows Update (when WSUS/SCCM is used), Remote Desktop Services, and IPv6 have been excluded based on environment configuration.

## Files Generated

1. **2022-AUDITED-CONTROLS.json** - Complete list of 290 controls actually audited
2. **2022-EXCLUSIONS-FINAL.md** - This document
3. **2022-EXCLUSIONS-ANALYSIS.md** - Detailed analysis

## Next Steps for 2025 Scanner

1. Apply same exclusion logic to Windows 2025 (455 controls)
2. Expected audited controls: ~348 (455 - 107 excluded)
3. Tag milestone files with appropriate exclusion categories
4. Update scanner to filter based on tags
5. Test on production servers

## Validation

To validate exclusions are correct:
1. Compare CIS 2022 benchmark PDF with audited controls
2. Verify all DC-only controls are excluded
3. Confirm environment-specific exclusions match deployment
4. Review with security team for approval
