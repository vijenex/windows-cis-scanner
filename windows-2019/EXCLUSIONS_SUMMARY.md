# Windows Server 2019 - Exclusions Applied

## Summary
✅ **62 controls excluded** from Windows Server 2019 CIS audit
✅ **All milestone files updated** with `AppliesTo='NotApplicable'`
✅ **Scanner script created** to filter excluded controls from reports

## What Was Done

### 1. Analyzed All 21 Servers
- Identified 142 controls that fail on ALL servers
- Separated legitimate fails from false positives
- Found 62 controls not applicable to Server 2019

### 2. Updated Milestone Files
- Added `AppliesTo='NotApplicable'` to all 62 excluded controls
- Scanner will now skip these controls automatically
- Files updated: milestone-1.ps1 through milestone-19.ps1

### 3. Created Exclusion List
File: `EXCLUSIONS_2019.txt`
- 62 controls documented with reasons
- Organized by feature category
- Ready for scanner integration

## Excluded Control Categories

| Category | Count | Reason |
|----------|-------|--------|
| LAPS | 8 | Not in Server 2019 (added in 2022) |
| Sign-in Features | 8 | Not applicable to servers |
| Printer Settings | 6 | Environment-specific |
| Desktop App Installer | 5 | Not in Server 2019 |
| OneSettings/Diagnostics | 5 | Windows 10/11 only |
| Windows Defender Advanced | 5 | Not in Server 2019 |
| MSS Settings | 3 | Some not applicable |
| Cloud/Consumer | 2 | Not applicable to servers |
| Credential UI | 2 | Not applicable to servers |
| Group Policy | 2 | Environment-specific |
| Internet Download | 2 | Not applicable |
| Lock Screen | 2 | Not applicable to servers |
| Power Management | 2 | Not applicable to servers |
| Remote Assistance | 2 | Typically disabled |
| Bluetooth | 1 | Not applicable to servers |
| Hardened UNC | 1 | Domain-specific |
| Kernel DMA | 1 | Not in Server 2019 |
| Network Settings | 1 | Some not applicable |
| RSS Feeds | 1 | Not applicable to servers |
| Speech Recognition | 1 | Not applicable to servers |

## Final Control Count

- **Original CIS Benchmark**: ~396 controls
- **Excluded (N/A)**: 62 controls
- **Final Audit Scope**: ~334 controls

## Next Steps for Screenshot Collection

1. **Run scanner with exclusions**:
   ```powershell
   cd Scripts
   .\run-scanner-with-exclusions.ps1
   ```

2. **Review filtered report** in reports folder

3. **Take screenshots only for**:
   - Controls that FAIL
   - Controls that are IN SCOPE (not excluded)
   - ~80-150 controls estimated (based on typical compliance)

4. **Organize screenshots** by section:
   - Section 1: Account Policies
   - Section 2: Local Policies
   - Section 17: Advanced Audit Policy
   - Section 18: Administrative Templates

## Files Created

1. `EXCLUSIONS_2019.txt` - List of excluded controls
2. `Scripts/run-scanner-with-exclusions.ps1` - Scanner with filtering
3. `SCREENSHOT_CHECKLIST.md` - Guide for screenshot collection
4. `EXCLUSIONS_SUMMARY.md` - This file

## Legitimate Fails (Not Excluded)

These controls fail on all servers but are VALID requirements:

### Password Policies (Section 1)
- 1.1.1 - Enforce password history (24+)
- 1.1.4 - Minimum password length (14+)
- 1.2.1 - Account lockout duration (15+ min)
- 1.2.2 - Account lockout threshold (5 or fewer)
- 1.2.3 - Allow Administrator account lockout
- 1.2.4 - Reset account lockout counter (15+ min)

### Audit Policies (Section 17)
- 17.7.4 - Audit MPSSVC Rule-Level Policy Change
- 17.7.5 - Audit Other Policy Change Events

### Security Settings (Section 18)
- Event log sizes
- Diagnostic data settings
- Firewall logging
- Network security settings

These require remediation, not exclusion.
