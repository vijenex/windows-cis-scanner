# Windows Server 2016 - False Positives & Exclusions

## Based on Lessons Learned from Windows Server 2025

---

## Section 2.3.x - Default-Enabled Controls (DO NOT MARK AS FAIL)

These controls are **enabled by default** in Windows Server 2016. If registry key is missing, it means the default secure setting is in effect = **PASS**.

### Accounts (2.3.1.x)
- 2.3.1.1: Guest account status - Disabled by default
- 2.3.1.2: Limit local account use of blank passwords - Enabled by default

### Audit (2.3.2.x)
- 2.3.2.1: Force audit policy subcategory settings - Enabled by default

### Devices (2.3.4.x)
- 2.3.4.1: Prevent users from installing printer drivers - Enabled by default

### Domain Member (2.3.6.x)
- 2.3.6.1: Digitally encrypt or sign secure channel data (always) - Enabled by default
- 2.3.6.2: Digitally encrypt secure channel data (when possible) - Enabled by default
- 2.3.6.3: Digitally sign secure channel data (when possible) - Enabled by default
- 2.3.6.4: Disable machine account password changes - Disabled by default (correct)
- 2.3.6.5: Maximum machine account password age - 30 days by default
- 2.3.6.6: Require strong session key - Enabled by default

### Interactive Logon (2.3.7.x)
- 2.3.7.1: Do not require CTRL+ALT+DEL - Disabled by default (requires CTRL+ALT+DEL)

### Microsoft Network Client (2.3.8.x)
- 2.3.8.2: Digitally sign communications (if server agrees) - Enabled by default
- 2.3.8.3: Send unencrypted password to third-party SMB servers - Disabled by default

### Microsoft Network Server (2.3.9.x)
- 2.3.9.1: Amount of idle time before suspending session - 15 minutes by default
- 2.3.9.4: Disconnect clients when logon hours expire - Enabled by default

### Network Access (2.3.10.x)
- 2.3.10.1: Allow anonymous SID/Name translation - Disabled by default
- 2.3.10.2: Do not allow anonymous enumeration of SAM accounts - Enabled by default
- 2.3.10.5: Let Everyone permissions apply to anonymous users - Disabled by default
- 2.3.10.8: Remotely accessible registry paths - Configured by default
- 2.3.10.9: Remotely accessible registry paths and sub-paths - Configured by default
- 2.3.10.10: Restrict anonymous access to Named Pipes and Shares - Enabled by default
- 2.3.10.13: Sharing and security model for local accounts - Classic by default

### System Objects (2.3.15.x)
- 2.3.15.1: Require case insensitivity for non-Windows subsystems - Enabled by default
- 2.3.15.2: Strengthen default permissions of internal system objects - Enabled by default

---

## Scanner Logic for Default-Enabled Controls

```powershell
$defaultEnabledControls = @{
    "2.3.1.1" = @{ DefaultValue = "Disabled"; ExpectedValue = "Disabled" }
    "2.3.1.2" = @{ DefaultValue = "1"; ExpectedValue = "1" }
    "2.3.2.1" = @{ DefaultValue = "1"; ExpectedValue = "1" }
    "2.3.4.1" = @{ DefaultValue = "1"; ExpectedValue = "1" }
    "2.3.6.1" = @{ DefaultValue = "1"; ExpectedValue = "1" }
    "2.3.6.2" = @{ DefaultValue = "1"; ExpectedValue = "1" }
    "2.3.6.3" = @{ DefaultValue = "1"; ExpectedValue = "1" }
    "2.3.6.4" = @{ DefaultValue = "0"; ExpectedValue = "0" }
    "2.3.6.5" = @{ DefaultValue = "30"; ExpectedValue = "30" }
    "2.3.6.6" = @{ DefaultValue = "1"; ExpectedValue = "1" }
    "2.3.7.1" = @{ DefaultValue = "0"; ExpectedValue = "0" }
    "2.3.8.2" = @{ DefaultValue = "1"; ExpectedValue = "1" }
    "2.3.8.3" = @{ DefaultValue = "0"; ExpectedValue = "0" }
    "2.3.9.1" = @{ DefaultValue = "15"; ExpectedValue = "15" }
    "2.3.9.4" = @{ DefaultValue = "1"; ExpectedValue = "1" }
    "2.3.10.1" = @{ DefaultValue = "0"; ExpectedValue = "0" }
    "2.3.10.2" = @{ DefaultValue = "1"; ExpectedValue = "1" }
    "2.3.10.5" = @{ DefaultValue = "0"; ExpectedValue = "0" }
    "2.3.10.10" = @{ DefaultValue = "1"; ExpectedValue = "1" }
    "2.3.10.13" = @{ DefaultValue = "1"; ExpectedValue = "1" }
    "2.3.15.1" = @{ DefaultValue = "1"; ExpectedValue = "1" }
    "2.3.15.2" = @{ DefaultValue = "1"; ExpectedValue = "1" }
}

# In scanner:
if ($defaultEnabledControls.ContainsKey($controlId)) {
    if (-not $keyExists) {
        # Registry key missing = default value in effect
        $status = "PASS"
        $actualValue = "Enabled by default (registry key not required)"
        $evidence = "Windows Server 2016 default configuration is compliant"
    }
}
```

---

## Client-Only Controls (EXCLUDE from Windows Server 2016)

Total: **135 controls** tagged as [NOT APPLICABLE - Client Only]

### Windows 10/11 Specific Features:
- Lock screen camera/slideshow
- Online speech recognition
- Online Tips
- Windows Spotlight
- Toast notifications
- App Installer / Microsoft Store
- Network Sharing (user profile sharing)
- Attachment Manager
- mDNS / NetBIOS settings
- Network Bridge / Internet Connection Sharing
- EDR in block mode
- Microsoft MAPS
- Attack Surface Reduction rules
- Many Section 18 and 19 controls

**Action:** Scanner should skip these controls entirely for Windows Server 2016.

---

## Deprecated/Not Applicable Controls

### LAN Manager (Deprecated)
- 2.3.11.5: Do not store LAN Manager hash - Not in Windows Server 2016

### MS Security Guide (May not apply)
- Section 18.4.x: Verify if applicable to Server 2016
- If not applicable, exclude from scan

### MSS Legacy (May not apply)
- Section 18.5.x: Verify if applicable to Server 2016
- Some may be deprecated in 2016

---

## DC vs Member Server Detection

**CRITICAL:** Scanner MUST detect server role and skip inappropriate controls.

```powershell
# At start of scanner
$domainRole = (Get-WmiObject -Class Win32_ComputerSystem).DomainRole
$isDC = $domainRole -ge 4  # 4 = Backup DC, 5 = Primary DC

Write-Host "Server Role: $(if ($isDC) {'Domain Controller'} else {'Member Server'})"

# In each control:
if ($control.AppliesTo -eq "DC only" -and -not $isDC) {
    Write-Host "Skipping $($control.Id) - DC only control on Member Server"
    continue
}

if ($control.AppliesTo -eq "MS only" -and $isDC) {
    Write-Host "Skipping $($control.Id) - MS only control on Domain Controller"
    continue
}
```

---

## Manual Controls

Controls with Type='Manual' should be marked as **MANUAL**, not FAIL.

```powershell
if ($control.Type -eq "Manual") {
    $status = "MANUAL"
    $actualValue = "Manual verification required"
    $evidence = "This control cannot be automated and requires manual review"
}
```

---

## Summary

### DO NOT REPEAT These Mistakes:

1. ❌ Marking default-enabled controls as FAIL when registry key missing
2. ❌ Including client-only controls in server scans
3. ❌ Not detecting DC vs Member Server
4. ❌ Marking manual controls as FAIL
5. ❌ Using shorthand control IDs
6. ❌ Truncating control titles
7. ❌ Creating duplicate control IDs

### DO THIS Instead:

1. ✅ Check if control is default-enabled before marking FAIL
2. ✅ Exclude all 135 client-only controls
3. ✅ Detect server role and skip inappropriate controls
4. ✅ Mark manual controls as MANUAL
5. ✅ Use full control IDs (18.10.x.x.x)
6. ✅ Use complete control titles
7. ✅ Ensure each control ID appears only once

---

## Testing Checklist

Before scanning production:
- [ ] Test on 1 Member Server - verify no false positives
- [ ] Test on 1 Domain Controller - verify DC/MS controls handled correctly
- [ ] Verify no duplicate control IDs in CSV
- [ ] Verify all control IDs are full format
- [ ] Verify all titles are complete
- [ ] Verify default-enabled controls show PASS
- [ ] Verify client-only controls excluded
- [ ] Verify manual controls marked MANUAL

---

## Reference

See LESSONS_LEARNED_AND_ALL_BUGS.md for complete bug history from 2025 implementation.
