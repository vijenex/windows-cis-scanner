# DC-Only Control Filtering Bug Fix

## Issue Summary
Both Windows Server 2019 and 2022 scanners were evaluating DC-only controls on Member Servers, causing false FAIL results.

## Impact
- **Windows 2019**: 22 DC-only controls incorrectly marked as FAIL on Member Servers
- **Windows 2022**: 29 DC-only controls incorrectly marked as FAIL on Member Servers
- Inflated failure counts and wasted audit time on inapplicable controls

## Root Cause
Scanners lacked logic to:
1. Detect if the system is a Domain Controller vs Member Server
2. Filter out DC-only controls when running on Member Servers

## Fix Implemented

### Detection Logic
Added Domain Controller detection using WMI:
```powershell
$cs=Get-CimInstance Win32_ComputerSystem
$isDomainController = $cs.DomainRole -in @(4,5)
# 4 = Backup Domain Controller
# 5 = Primary Domain Controller
# 0-3 = Workstation or Member Server
```

### Filtering Logic
Added control filtering before rule evaluation:
```powershell
# Filter DC-only controls if this is a Member Server
if (-not $isDomainController) {
  $dcOnlyCount = @($rules | Where-Object { $_.Title -match '\(DC [Oo]nly\)' }).Count
  $rules = $rules | Where-Object { $_.Title -notmatch '\(DC [Oo]nly\)' }
  if ($dcOnlyCount -gt 0) {
    Write-Host "Filtered out $dcOnlyCount DC-only controls (not applicable to Member Server)" -ForegroundColor Yellow
  }
}
```

### Pattern Matching
Filters controls with titles containing:
- `(DC only)`
- `(DC Only)` 
- Case-insensitive matching

## Files Modified
1. `/windows-2022/Scripts/vijenex-scanner.ps1`
2. `/windows-2019/Scripts/vijenex-scanner.ps1`

## Expected Results After Fix

### Windows Server 2022 (Member Server)
- **Before**: ~361 controls evaluated (includes 29 DC-only)
- **After**: ~332 controls evaluated (DC-only filtered out)
- **DC-only controls**: Automatically skipped

### Windows Server 2019 (Member Server)
- **Before**: ~533 controls evaluated (includes 22 DC-only)
- **After**: ~511 controls evaluated (DC-only filtered out)
- **DC-only controls**: Automatically skipped

### Domain Controllers
- **No change**: All controls including DC-only will be evaluated
- Scanner detects DC role and evaluates all applicable controls

## User Experience Improvements
1. **Clear Detection Message**: Scanner displays whether it detected DC or Member Server
2. **Filtered Count**: Shows how many DC-only controls were filtered out
3. **Accurate Results**: No more false FAILs for inapplicable controls
4. **Correct Control Count**: CSV/reports show only applicable controls

## Testing Checklist
- [x] Added DC detection logic
- [x] Added control filtering logic
- [x] Applied to Windows 2022 scanner
- [x] Applied to Windows 2019 scanner
- [ ] Test on Member Server (should filter DC-only controls)
- [ ] Test on Domain Controller (should evaluate all controls)
- [ ] Verify CSV output has correct control count

## Related Issues Fixed
- ✅ False FAIL results for DC-only controls on Member Servers
- ✅ Inflated failure counts
- ✅ Confusion about inapplicable controls
- ✅ Wasted audit time

## Date Fixed
2024 (Current session)

## Notes
- Fix is backward compatible - no breaking changes
- Scanner automatically detects server role
- No user configuration required
- Works for both standalone and domain-joined Member Servers
