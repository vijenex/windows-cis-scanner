# Scanner TODO - Critical Fixes Required

## PRIORITY 1: DC Detection and Control Filtering ⚠️ CRITICAL

**Issue:** Scanner checks DC-only controls on Member Servers and marks them as FAIL

**Impact:** 
- 22 DC-only controls incorrectly reported as FAIL on all Member Servers
- Inflates failure count (480 instead of 458)
- Wastes audit time on inapplicable controls

**Fix Required:**
```powershell
# Add at beginning of scanner script:
$isDomainController = (Get-WmiObject -Class Win32_ComputerSystem).DomainRole -in @(4,5)
# 4 = Backup Domain Controller
# 5 = Primary Domain Controller

# When loading controls, skip DC-only controls if not a DC:
if (-not $isDomainController -and $control.Title -match '\(DC only\)|\(DC Only\)') {
    # Mark as N/A instead of checking
    $result = "N/A"
    $actualValue = "Not Applicable - Member Server"
    continue
}
```

**Test Cases:**
- [ ] Run on Domain Controller - DC controls should be checked
- [ ] Run on Member Server - DC controls should be N/A
- [ ] Run on Standalone Server - DC controls should be N/A
- [ ] Verify CSV shows "N/A" status for inapplicable controls

**Files to Modify:**
- `vijenex-scanner.ps1` - Main scanner script
- Add DC detection at line ~50 (after parameter validation)
- Add control filtering in control loop

---

## PRIORITY 2: Fix Duplicate Control IDs ⚠️ CRITICAL

**Issue:** Scanner assigns duplicate control IDs to different controls

**Impact:**
- Multiple controls share the same ID (e.g., 2.2.16 appears twice with different titles)
- Causes confusion in audit reports
- Makes it impossible to uniquely identify controls
- Breaks audit trail and remediation tracking

**Examples Found:**
```
2.2.16 = "Create global objects" (PASS)
2.2.16 = "Deny access to this computer from the network" (FAIL)  ← DUPLICATE!

2.2.17 = "Create permanent shared objects" (PASS)
2.2.17 = "Deny log on as a batch job" (FAIL)  ← DUPLICATE!

2.2.18 = "Create symbolic links" (DC only) (PASS)
2.2.18 = "Deny log on as a service" (FAIL)  ← DUPLICATE!

2.2.19 = "Create symbolic links" (MS only) (FAIL)
2.2.19 = "Deny log on locally" (FAIL)  ← DUPLICATE!

2.2.20 = "Debug programs" (FAIL)
2.2.20 = "Deny log on through Remote Desktop Services" (FAIL)  ← DUPLICATE!
```

**Root Cause:**
Scanner is likely reading control IDs from an incorrect or corrupted CIS benchmark JSON file, or has a bug in the control ID assignment logic.

**Fix Required:**
1. Verify CIS benchmark JSON file has correct, unique control IDs
2. Add validation to ensure no duplicate IDs
3. Cross-reference with official CIS Windows Server 2019 Benchmark v3.0.1
4. Re-map all control IDs correctly

```powershell
# Add validation after loading controls:
$controlIds = $controls | Group-Object -Property Id | Where-Object { $_.Count -gt 1 }
if ($controlIds) {
    Write-Error "CRITICAL: Duplicate control IDs found: $($controlIds.Name -join ', ')"
    exit 1
}
```

**Test Cases:**
- [ ] Verify all control IDs are unique
- [ ] Cross-check with official CIS benchmark
- [ ] Ensure control titles match official benchmark
- [ ] Verify no ID reuse across different controls

---

## PRIORITY 3: Fix Incorrect Control ID Assignments

**Issue:** Some controls have wrong IDs assigned (related to Priority 2)

**Impact:**
- Control 2.2.10 incorrectly flagged as FAIL on some servers
- Audit reports show wrong control numbers
- Remediation guidance points to wrong controls

**Examples:**
- 2.2.10 shows PASS on some servers, FAIL on others (should be consistent)
- Controls 2.2.16-2.2.20 have wrong titles assigned

**Fix Required:**
1. Download fresh CIS Windows Server 2019 Benchmark PDF/Excel
2. Rebuild control ID mapping from scratch
3. Verify each control ID matches official benchmark
4. Add unit tests to validate control IDs

---

## PRIORITY 4: Add N/A Status to CSV Output

**Issue:** CSV only has PASS/FAIL, no N/A status

**Fix Required:**
```powershell
# Add N/A as valid status
$validStatuses = @("PASS", "FAIL", "N/A")

# When writing CSV, include N/A controls
$result | Export-Csv -Path $outputFile -NoTypeInformation
```

**Test Cases:**
- [ ] CSV includes N/A status
- [ ] Audit report correctly counts N/A controls
- [ ] Summary shows: Total, Pass, Fail, N/A

---

## PRIORITY 3: Improve Control Applicability Logic

**Issue:** Need better detection of control applicability

**Controls to Handle:**
- `(DC only)` - Domain Controller only
- `(MS only)` - Member Server only  
- `(Standalone only)` - Standalone server only
- Role-specific controls (IIS, SQL, etc.)

**Fix Required:**
```powershell
function Test-ControlApplicability {
    param($control, $serverRole, $installedRoles)
    
    if ($control.Title -match '\(DC only\)' -and $serverRole -ne 'DC') {
        return $false
    }
    if ($control.Title -match '\(MS only\)' -and $serverRole -ne 'MemberServer') {
        return $false
    }
    # Add more logic as needed
    return $true
}
```

---

## PRIORITY 4: Add Server Role Detection to Report

**Issue:** Report doesn't show server role

**Fix Required:**
Add to CSV output:
- ServerRole column (DC, Member Server, Standalone)
- DomainName column
- InstalledRoles column (IIS, SQL, etc.)

---

## PRIORITY 5: Validation Before Production

**Checklist before claiming "Production Ready":**
- [ ] Test on Domain Controller
- [ ] Test on Member Server
- [ ] Test on Standalone Server
- [ ] Verify DC controls are N/A on Member Servers
- [ ] Verify MS controls are N/A on DCs
- [ ] Test on Windows 2019, 2022, 2025
- [ ] Run on 3+ different servers
- [ ] Manually verify 10 random controls
- [ ] Check CSV format is correct
- [ ] Verify no false positives
- [ ] Verify no false negatives

---

## Testing Matrix

| Server Type | Windows Version | DC Controls | MS Controls | Expected Result |
|-------------|----------------|-------------|-------------|-----------------|
| DC | 2019 | CHECK | N/A | DC controls checked |
| Member | 2019 | N/A | CHECK | MS controls checked |
| Standalone | 2019 | N/A | CHECK | MS controls checked |
| DC | 2022 | CHECK | N/A | DC controls checked |
| Member | 2022 | N/A | CHECK | MS controls checked |
| DC | 2025 | CHECK | N/A | DC controls checked |
| Member | 2025 | N/A | CHECK | MS controls checked |

---

## Implementation Plan

### Phase 1: DC Detection (1-2 hours)
1. Add DC detection function
2. Test on DC and Member Server
3. Verify detection works correctly

### Phase 2: Control Filtering (2-3 hours)
1. Add control applicability logic
2. Filter controls based on server role
3. Mark inapplicable controls as N/A

### Phase 3: CSV Output (1 hour)
1. Add N/A status to CSV
2. Add ServerRole column
3. Update report generation

### Phase 4: Testing (2-3 hours)
1. Test on all server types
2. Verify all controls work correctly
3. Check for false positives/negatives

### Phase 5: Documentation (1 hour)
1. Update README
2. Document server role detection
3. Add troubleshooting guide

**Total Estimated Time: 7-10 hours**

---

## Current Workaround (Temporary)

Until scanner is fixed:
1. Run scanner as-is
2. Post-process CSV to filter DC-only controls
3. Use `filter-dc-controls.py` script
4. Generate audit report from filtered results

---

## Reference

**DC-only controls to exclude (22 total):**
- 2.2.2, 2.2.5, 2.2.7, 2.2.9, 2.2.21, 2.2.26, 2.2.28
- 2.3.5.1, 2.3.5.2, 2.3.5.3, 2.3.5.4, 2.3.5.5
- 2.3.10.6
- 17.4.1
- Plus others marked "(DC only)"

**Verification Command:**
```powershell
# On server, check role:
(Get-WmiObject -Class Win32_ComputerSystem).DomainRole
# 0 = Standalone Workstation
# 1 = Member Workstation
# 2 = Standalone Server
# 3 = Member Server
# 4 = Backup Domain Controller
# 5 = Primary Domain Controller
```

---

Last Updated: November 21, 2024
Status: PENDING - Must fix before next production scan
Priority: CRITICAL
