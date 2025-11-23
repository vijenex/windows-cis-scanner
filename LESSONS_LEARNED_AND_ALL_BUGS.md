# Lessons Learned & All Bugs - Complete List

## QUICK REFERENCE: Windows Server 2025 Known Issues Summary

### CRITICAL: Controls to EXCLUDE from Windows Server 2025 Scans
**Total: ~50+ controls not applicable to Windows Server 2025**

1. **Section 2.3.2.2**: Audit shutdown control - not in 2025
2. **Section 18.4.x (ALL)**: MS Security Guide - not applicable (8 controls)
3. **Section 18.5.x (ALL)**: MSS Legacy - deprecated (8+ controls)
4. **Section 18.6.4.1, 18.6.4.2, 18.6.4.4**: DNS/NetBIOS controls - not in 2025
5. **Section 18.6.7.1**: Audit encryption - not in 2025
6. **Section 18.6.8.1**: Audit guest logon - not in 2025
7. **Section 18.6.11.2, 18.6.11.3, 18.6.11.4**: Network bridge/ICS controls - not in 2025
8. **Section 18.7.8**: RPC packet privacy - not in 2025
9. **Section 18.10.18.6**: App Installer - not in 2025
10. **Section 18.10.43.4.1, 18.10.43.5.1**: Windows Defender EDR/MAPS - not in 2025
11. **Section 19.5.1.1**: Toast notifications - client only
12. **Section 19.7.5.1, 19.7.5.2**: Attachment Manager - client only
13. **Section 19.7.8.x (ALL)**: Windows Spotlight - client only
14. **Section 19.7.26.1**: Network Sharing - client only
15. **Section 2.3.11.5**: LAN Manager hash - deprecated

### CRITICAL: False Positive Controls (Enabled by Default, No Registry Key)
**Total: ~25+ controls marked FAIL but actually PASS**

**Section 2.3.x controls** - These are enabled by default in Windows Server 2025:
- 2.3.1.1, 2.3.1.2: Accounts settings
- 2.3.2.1: Audit policy override
- 2.3.4.1: Printer drivers
- 2.3.6.1-6: Domain member settings (6 controls)
- 2.3.7.1: CTRL+ALT+DEL
- 2.3.8.2, 2.3.8.3: Network client settings
- 2.3.9.1, 2.3.9.4: Network server settings
- 2.3.10.1, 2.3.10.2, 2.3.10.5, 2.3.10.8, 2.3.10.9, 2.3.10.10, 2.3.10.13: Network access (7 controls)
- 2.3.15.1, 2.3.15.2: System objects

**Root Cause**: Scanner checks for registry key existence but doesn't know that missing key = enabled by default

### CRITICAL: Duplicate Control IDs (Same Control Appears Twice)
**Impact: Shows both PASS and FAIL for same control**

- 2.2.16-2.2.20: Wrong titles, duplicate entries
- 2.3.17.4-8: UAC controls appear twice (once FAIL, once PASS)

### Scanner Bugs Requiring Code Fixes

1. **Manual Controls Bug**: Type='Manual' marked as FAIL instead of MANUAL
2. **Shorthand IDs**: Controls 18.10.57.x and 18.10.43.x use shorthand (57.x, 43.x)
3. **Truncated Titles**: Many control titles incomplete in CSV
4. **DC Detection**: No logic to skip DC-only controls on Member Servers
5. **Duplicate Entries**: Same control ID appears multiple times with different results

### Action Required Before Next Scan

1. **Update Scanner**: Add exclusion list for non-applicable controls
2. **Fix False Positives**: Add logic for default-enabled controls
3. **Remove Duplicates**: Ensure each control ID appears only once
4. **Add DC Detection**: Skip DC-only controls on Member Servers
5. **Fix Manual Controls**: Mark as MANUAL not FAIL

---

## Critical Lessons Learned

### 1. NEVER Claim "Production Ready" Without Full Validation
**What happened:** Claimed all 332 controls implemented, actually only 127 (38.3%)
**Impact:** Scanned 20 servers 3 times (60 scans) with incomplete scanner
**Lesson:** Always verify control count in code matches CIS benchmark before deployment

### 2. Always Count Controls Before Scanning
**What to do:**
```bash
# Count controls in CIS list
grep -c "^[0-9]" CIS_CONTROLS_LIST.txt

# Count controls in milestones
grep -oE '\b[0-9]+\.[0-9]+\.[0-9]+\b' milestone-*.ps1 | sort -u | wc -l

# Compare: Must match!
```

### 3. Test on ONE Server First
**What to do:**
- Scan 1 test server
- Verify CSV has all expected control IDs
- Check for PASS/FAIL/N/A distribution
- Only then scan production

### 4. DC Detection is Critical
**What happened:** Scanner checked DC-only controls on Member Servers
**Impact:** 22 false FAIL results per server
**Lesson:** Always detect server role first, skip DC-only controls on Member Servers

### 5. Duplicate Control IDs Break Everything
**What happened:** Controls 2.2.16-2.2.20 appeared twice with different titles
**Impact:** Confusion in audit reports, wrong control mappings
**Lesson:** Validate unique control IDs in CSV output

## All Bugs Fixed So Far

### Bug 1: DC Detection Failure (CRITICAL)
**Status:** Documented, not fixed
**Issue:** Scanner doesn't detect Domain Controller vs Member Server
**Impact:** 22 DC-only controls marked FAIL on Member Servers (should be N/A)
**Fix Required:**
```powershell
$domainRole = (Get-WmiObject -Class Win32_ComputerSystem).DomainRole
# 0,1,2,3 = Member Server
# 4,5 = Domain Controller
if ($domainRole -ge 4) {
    # Skip MS-only controls
} else {
    # Skip DC-only controls
}
```

### Bug 2: Duplicate Control IDs (CRITICAL)
**Status:** Documented, not fixed
**Issue:** Multiple controls appear twice in CSV with different titles and conflicting PASS/FAIL status
**Examples:**
- 2.2.16: "Create global objects" AND "Deny access to this computer from the network"
- 2.2.19: "Create symbolic links" AND "Deny log on locally"
- 2.2.20: "Debug programs" AND "Deny log on through Remote Desktop Services"
- 2.3.17.4: Appears twice - once as FAIL ("Not configured") and once as PASS ("1 (Enabled)")
- 2.3.17.5: Appears twice - once as FAIL and once as PASS
- 2.3.17.6: Appears twice - once as FAIL and once as PASS
- 2.3.17.7: Appears twice - once as FAIL and once as PASS
- 2.3.17.8: Appears twice - once as FAIL and once as PASS
**Impact:** 
- Wrong control titles in reports
- False positive failures (settings are actually enabled but show as FAIL)
- Inflated failure counts
- Confusion in audit reports
**Fix Required:** 
1. Remove duplicate control entries from scanner
2. Ensure each control ID appears only once
3. Verify registry path format (HKLM vs HKLM:) consistency

### Bug 3: Empty Secedit Values
**Status:** FIXED in v1.10.4
**Issue:** Scanner crashed when secedit returned empty values
**Fix:** Handle empty values gracefully

### Bug 4: "No One" User Rights
**Status:** FIXED in v1.10.3
**Issue:** Empty user rights should PASS for "No One" requirement
**Fix:** Treat empty as "No One"

### Bug 5: Operator Error
**Status:** FIXED in v1.10.2
**Issue:** Default operator caused evaluation errors
**Fix:** Default to "Equals" operator

### Bug 6: HashSet Count Error
**Status:** FIXED in v1.10.1
**Issue:** PrivRight evaluation crashed on HashSet.Count
**Fix:** Proper HashSet handling

### Bug 7: 121 Scanner Bugs
**Status:** FIXED in v1.10.0
**Issue:** Multiple bugs across scanner
**Fix:** Comprehensive bug fix release

### Bug 8: Incomplete Control Coverage (CRITICAL - NEW)
**Status:** DISCOVERED TODAY
**Issue:** Only 127/332 controls implemented (38.3% coverage)
**Missing:**
- Section 2.3: 65 controls (Security Options)
- Section 18.10: 84 controls (System Admin Templates)
- Section 18.9: 36 controls (System Admin Templates)
- Section 18.6: 9 controls (Network)
- Section 18.1: 3 controls (Control Panel)
- Section 19.x: 8 controls (User Templates)
**Fix Required:** Implement all 205 missing controls

## Scanner Development Checklist (Use This Going Forward)

### Phase 1: Planning
- [ ] Get official CIS benchmark PDF
- [ ] Extract all control IDs and titles to text file
- [ ] Count total controls (exclude DC-only for MS scanner)
- [ ] Verify control count: Should be ~332 for Member Server

### Phase 2: Implementation
- [ ] Implement controls in milestone files
- [ ] Add DC detection logic at start
- [ ] Ensure unique control IDs (no duplicates)
- [ ] Add proper error handling
- [ ] Include evidence collection

### Phase 3: Validation (CRITICAL)
- [ ] Count controls in milestone files
- [ ] Verify count matches CIS benchmark
- [ ] Test on ONE server first
- [ ] Check CSV output has all control IDs
- [ ] Verify no duplicate control IDs
- [ ] Check DC-only controls are N/A on Member Servers
- [ ] Review PASS/FAIL distribution

### Phase 4: Deployment
- [ ] Scan test environment first
- [ ] Review results with team
- [ ] Get approval before production
- [ ] Scan production servers
- [ ] Generate audit reports

## What to Check Before Claiming "Production Ready"

### Mandatory Checks:
1. ✓ Control count in code = Control count in CIS benchmark
2. ✓ DC detection implemented and tested
3. ✓ No duplicate control IDs in CSV output
4. ✓ Test scan on 1 server successful
5. ✓ CSV has all expected control IDs
6. ✓ Error handling works
7. ✓ Evidence collection works
8. ✓ Audit report generation works

### Never Say "Production Ready" Until ALL Checks Pass!

## Quick Reference: Scanner Versions

- v1.10.4: Fix empty secedit values
- v1.10.3: Fix "No One" user rights
- v1.10.2: Fix operator error
- v1.10.1: Fix HashSet count error
- v1.10.0: Fix 121 scanner bugs
- v1.9.8: Fix Windows 2025 scanner title
- v1.9.7: Fix Windows 2019 scanner title
- v1.9.6: Improve evidence collection

## For Today's Work (2025, 2022, 2016)

### Must Do:
1. Create complete control list from CIS PDFs (you're doing this)
2. Count controls in each list
3. Verify milestone files have ALL controls
4. Add DC detection logic
5. Fix duplicate control IDs
6. Test on 1 server per OS
7. Verify CSV completeness
8. Only then scan all servers

### Don't Repeat Mistakes:
- ❌ Don't claim complete without counting
- ❌ Don't skip test scans
- ❌ Don't scan all servers without validation
- ❌ Don't ignore DC detection
- ❌ Don't allow duplicate control IDs

## Success Criteria

### For Each OS (2025, 2022, 2016):
- [ ] Complete control list created
- [ ] All controls implemented in milestones
- [ ] DC detection working
- [ ] No duplicate control IDs
- [ ] Test scan successful
- [ ] CSV has all controls
- [ ] Audit report generated
- [ ] Screenshots attached

### Only Then: Deliver to Client


## Windows Server 2025 - Control ID Shorthand Issue

**Date:** 2024
**Severity:** Medium
**Status:** Known Issue - Workaround Applied

**Issue:**
Milestone-57.ps1 and milestone-43.ps1 use shorthand control IDs instead of full CIS IDs:
- Scanner uses: `57.3.3.1`, `57.3.9.1`, `43.6.1.1`
- Should be: `18.10.57.3.3.1`, `18.10.57.3.9.1`, `18.10.43.6.1.1`

**Impact:**
- CSV output contains shorthand IDs
- Report generation cannot match with RTF benchmark descriptions
- Missing descriptions/remediation for affected controls

**Root Cause:**
Auto-generated milestone files used section numbers instead of full CIS control IDs

**Workaround:**
Report generation script maps shorthand IDs to full IDs for RTF lookup

**Permanent Fix Required:**
1. Update milestone-57.ps1 and milestone-43.ps1 with correct full IDs
2. Re-scan all systems
3. Regenerate reports

**Files Affected:**
- windows-2025/milestones/milestone-57.ps1
- windows-2025/milestones/milestone-43.ps1


## Windows Server 2025 - Manual Controls Marked as FAIL (False Positive)

**Date:** 2024
**Severity:** High
**Status:** Bug - Needs Fix

**Issue:**
Manual controls (Type = 'Manual') are being marked as FAIL instead of MANUAL/NOT_TESTED

**Examples:**
- Control 1.2.3: "Allow Administrator account lockout" - Type='Manual' but Status='FAIL'
- Other manual controls showing same behavior

**Impact:**
- False positive failures in reports
- Inflated failure counts
- Misleading compliance metrics

**Root Cause:**
Scanner doesn't handle Type='Manual' controls properly - defaults to FAIL status

**Fix Required:**
Update scanner logic to:
1. Check if Type = 'Manual'
2. Set Status = 'MANUAL' or 'NOT_TESTED' instead of 'FAIL'
3. Add note: "This control requires manual verification"

**Files Affected:**
- windows-2025/Scripts/vijenex-scanner.ps1


## Windows Server 2025 - False Positive FAIL for Enabled-by-Default Controls

**Date:** 2024
**Severity:** High
**Status:** Scanner Bug - False Positives

**Issue:**
Controls that are enabled by default in Windows Server 2025 are marked as FAIL because registry keys don't exist (default behavior = enabled)

**Examples:**
- 2.3.1.1: "Accounts: Guest account status"
- 2.3.1.2: "Accounts: Limit local account use of blank passwords to console logon only"
- 2.3.2.1: "Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit policy category settings"
- 2.3.4.1: "Devices: Prevent users from installing printer drivers"
- 2.3.6.1: "Domain member: Digitally encrypt or sign secure channel data (always)"
- 2.3.6.2: "Domain member: Digitally encrypt secure channel data (when possible)"
- 2.3.6.3: "Domain member: Digitally sign secure channel data (when possible)"
- 2.3.6.4: "Domain member: Disable machine account password changes"
- 2.3.6.5: "Domain member: Maximum machine account password age"
- 2.3.6.6: "Domain member: Require strong (Windows 2000 or later) session key"
- 2.3.7.1: "Interactive logon: Do not require CTRL+ALT+DEL"
- 2.3.8.2: "Microsoft network client: Digitally sign communications (if server agrees)"
- 2.3.8.3: "Microsoft network client: Send unencrypted password to third-party SMB servers"
- 2.3.9.1: "Microsoft network server: Amount of idle time required before suspending session"
- 2.3.9.4: "Microsoft network server: Disconnect clients when logon hours expire"
- 2.3.10.1: "Network access: Allow anonymous SID/Name translation"
- 2.3.10.2: "Network access: Do not allow anonymous enumeration of SAM accounts"
- 2.3.10.5: "Network access: Let Everyone permissions apply to anonymous users"
- 2.3.10.8: "Network access: Remotely accessible registry paths"
- 2.3.10.9: "Network access: Remotely accessible registry paths and sub-paths"
- 2.3.10.10: "Network access: Restrict anonymous access to Named Pipes and Shares"
- 2.3.10.13: "Network access: Sharing and security model for local accounts"
- 2.3.15.1: "System objects: Require case insensitivity for non-Windows subsystems"
- 2.3.15.2: "System objects: Strengthen default permissions of internal system objects"

**Impact:**
- False positive failures for properly configured systems
- Inflated failure counts
- Unnecessary remediation attempts

**Root Cause:**
Scanner checks for registry key existence but doesn't account for Windows default behavior when key is absent

**Fix Required:**
1. Identify controls where absence of registry key = enabled by default
2. Update scanner to mark these as PASS when key doesn't exist
3. Add logic: If key missing AND default=enabled, then PASS

**Files Affected:**
- windows-2025/Scripts/vijenex-scanner.ps1
- windows-2025/milestones/milestone-2.ps1


## Windows Server 2025 - Deprecated LAN Manager Control

**Date:** 2024
**Severity:** Low
**Status:** Control Not Applicable

**Issue:**
Control 2.3.11.5 "Do not store LAN Manager hash value on next password change" is not applicable to Windows Server 2025

**Impact:**
- Control marked as FAIL but setting doesn't exist in modern Windows
- LAN Manager authentication is deprecated and disabled by default

**Root Cause:**
CIS Benchmark includes legacy control that's no longer relevant for Windows Server 2025

**Fix Required:**
Add to exclusion list for Windows Server 2025 scans

**Files Affected:**
- windows-2025/Scripts/vijenex-scanner.ps1 (add to exclusion list)


## Windows Server 2025 - Truncated Control Titles in Scanner

**Date:** 2024
**Severity:** Medium
**Status:** Known Issue - Workaround Applied

**Issue:**
Multiple control titles are truncated in milestone files, missing complete text

**Examples:**
- 57.3.11.2: "Ensure 'Do not use temporary folders per" (should be "...per session' is set to 'Disabled'")
- 57.3.10.1: "Ensure 'Set time limit for active but idle" (missing rest)
- 18.10.8.2: "Set the default behavior for AutoRun" (missing "is set to 'Enabled: Do not execute...'")

**Impact:**
- Incomplete control names in CSV output
- Reports show partial titles
- Difficult to understand control requirements

**Root Cause:**
Auto-generated milestone files have character limit or parsing issue that truncates titles

**Workaround:**
Report generator includes TITLE_FIXES dictionary with complete titles from RTF

**Permanent Fix Required:**
1. Review all milestone files for truncated titles
2. Update with complete titles from CIS Benchmark RTF
3. Ensure title extraction preserves full text

**Files Affected:**
- windows-2025/milestones/milestone-57.ps1
- windows-2025/milestones/milestone-43.ps1
- Multiple other milestone files


## Windows Server 2025 - Section 18 Controls Missing Proper Section Names

**Date:** 2024
**Severity:** Low
**Status:** Known Issue

**Issue:**
Some controls in section 18 have malformed section names in CSV output

**Examples:**
- Control 18.5.2: Section shows as " source routing is completely disabled' (Automated)" instead of "18.5 MSS (Legacy)"
- Control 18.5.3: Same issue - section name is part of title text

**Impact:**
- Confusing section names in reports
- Difficult to group controls by section
- CSV parsing issues

**Root Cause:**
Scanner milestone files have incorrect Section field or CSV export has formatting issue

**Workaround:**
Report generator can add section name mapping if needed

**Permanent Fix Required:**
1. Review milestone files for section 18 controls
2. Ensure Section field is properly set
3. Verify CSV export doesn't corrupt section names

**Files Affected:**
- windows-2025/milestones/milestone-18.ps1 (and related)
- windows-2025/Scripts/vijenex-scanner.ps1 (CSV export logic)


## Windows Server 2025 - Windows 10/11 Client-Only Controls Included in Benchmark

**Date:** 2024
**Severity:** Medium
**Status:** CIS Benchmark Issue - Exclusion Needed

**Issue:**
CIS Windows Server 2025 Benchmark includes controls designed for Windows 10/11 client OS that are not applicable to Windows Server installations

**Examples:**
- 19.7.8.1: "Do not suggest third-party content in Windows spotlight"
- 19.7.8.2: Windows Spotlight related settings
- 19.7.8.3: Windows Spotlight configuration
- 19.7.26.1: "Prevent users from sharing files within their profile" (Network Sharing)

**Impact:**
- Group Policy settings not visible in Windows Server 2025 GP Editor
- Required ADMX templates (CloudContent.admx, Sharing.admx) missing or not applicable
- Controls marked as FAIL but cannot be configured via UI
- False compliance failures for server environments

**Root Cause:**
CIS Benchmark includes comprehensive controls for all Windows environments but doesn't clearly separate client-only vs server-applicable controls

**Fix Required:**
1. Identify all Windows 10/11 client-only controls in Section 19
2. Add exclusion list to scanner for Windows Server environments
3. Mark these controls as N/A or NOT_APPLICABLE in server scans
4. Document which controls are client-only

**Affected Controls (Partial List):**
- Section 2.3.2.2: "Audit: Shut down system immediately if unable to log security audits"
- Section 18.4.x: ALL MS Security Guide controls - not applicable to Windows Server 2025
  - 18.4.1: Apply UAC restrictions to local accounts on network logons
  - 18.4.2: Configure SMB v1 client driver
  - 18.4.3: Configure SMB v1 server
  - 18.4.4: Enable Certificate Padding
  - 18.4.5: Enable Structured Exception Handling Overwrite Protection (SEHOP)
  - 18.4.6: LSA Protection
  - 18.4.7: NetBT NodeType configuration
  - 18.4.8: WDigest Authentication
- Section 18.5.x: ALL MSS (Legacy) controls - deprecated settings not applicable to modern Windows Server
  - 18.5.1: MSS: (AutoAdminLogon)
  - 18.5.2: MSS: (DisableIPSourceRouting IPv6)
  - 18.5.3: MSS: (DisableIPSourceRouting)
  - 18.5.4: MSS: (EnableICMPRedirect)
  - 18.5.6: MSS: (NoNameReleaseOnDemand)
  - 18.5.8: MSS: (SafeDllSearchMode)
  - 18.5.9: MSS: (ScreenSaverGracePeriod)
  - 18.5.12: MSS: (WarningLevel)
- Section 18.6.4.1: "Configure multicast DNS (mDNS) protocol"
- Section 18.6.4.2: "Configure NetBIOS settings"
- Section 18.6.4.4: "Turn off multicast name resolution"
- Section 18.6.7.1: "Audit client does not support encryption"
- Section 18.6.8.1: "Audit insecure guest logon"
- Section 18.6.11.2: "Prohibit installation and configuration of Network Bridge on your DNS domain network"
- Section 18.6.11.3: "Prohibit use of Internet Connection Sharing on your DNS domain network"
- Section 18.6.11.4: "Require domain users to elevate when setting a network's location"
- Section 18.7.8: "Configure RPC packet level privacy setting for incoming connections" (RPC)
- Section 18.10.18.6: "Enable App Installer Microsoft Store Source Certificate Validation Bypass" (AppInstaller)
- Section 18.10.43.4.1: "Enable EDR in block mode" (Windows Defender)
- Section 18.10.43.5.1: "Configure local setting override for reporting to Microsoft MAPS" (Windows Defender)
- Section 19.5.1.1: "Turn off toast notifications on the lock screen" (WPN.admx)
- Section 19.7.5.1: "Do not preserve zone information in file attachments" (AttachmentManager.admx)
- Section 19.7.5.2: "Notify antivirus programs when opening attachments" (AttachmentManager.admx)
- Section 19.7.8.x: Windows Spotlight controls (CloudContent.admx)
- Section 19.7.26.1: Network Sharing controls (Sharing.admx)
- Other Section 19 controls requiring client-specific ADMX templates

**Files Affected:**
- windows-2025/milestones/milestone-19.ps1
- windows-2025/Scripts/vijenex-scanner.ps1 (needs client-only exclusion logic)


## Windows Server 2025 - Missing RTF Descriptions for Specific Controls

**Date:** 2024
**Severity:** Low
**Status:** RTF Parsing Issue

**Issue:**
Some controls exist in CSV scan results but missing Description, Impact, and Remediation in generated report

**Affected Controls:**
- 18.9.4.2: "Remote host allows delegation of non-exportable credentials"

**Impact:**
- Report shows control ID and title but missing detailed information
- Users cannot understand control purpose or remediation steps from report

**Root Cause:**
Control may be missing from RTF file or RTF parsing logic cannot extract the content properly

**Fix Required:**
1. Verify control exists in CIS_Microsoft_Windows_Server_2025_Benchmark_v1.0.0.txt.rtf
2. If missing, manually add description/impact/remediation to report generator
3. If present, improve RTF parsing logic to extract content

**Files Affected:**
- /Users/satish.korra/win-reports/Prod-2025/create_2025_report.py (RTF parsing logic)
- /Users/satish.korra/win-reports/CIS_Microsoft_Windows_Server_2025_Benchmark_v1.0.0.txt.rtf
