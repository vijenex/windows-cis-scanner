# Windows Server 2016 CIS Scanner v2.0

## Bug-Fixed Version - No False Positives

Based on lessons learned from Windows Server 2025 implementation.

---

## Key Improvements

### 1. ✅ No Duplicate Control IDs
- Scanner detects and warns about duplicate control IDs
- Only evaluates each control once
- CSV output has unique control IDs only

### 2. ✅ No False Positives for Default-Enabled Controls
- 22 controls in section 2.3.x are enabled by default in Windows
- Scanner recognizes: No registry key = Default secure setting = PASS
- No more false FAIL results

### 3. ✅ Manual Controls Handled Correctly
- Controls requiring manual review marked as "MANUAL"
- Not marked as FAIL (which was misleading)

### 4. ✅ DC/MS Detection
- Automatically detects Domain Controller vs Member Server
- Skips DC-only controls on Member Servers
- Skips MS-only controls on Domain Controllers

### 5. ✅ Client-Only Controls Excluded
- 135 Windows 10/11 controls excluded from Server scans
- No false failures for features that don't exist on Server

### 6. ✅ Full Control IDs
- All controls use full CIS IDs (e.g., 18.10.57.3.3.1)
- No shorthand IDs (e.g., 57.3.3.1)
- Proper matching with CIS Benchmark documentation

---

## Usage

```powershell
# Run scanner (requires Administrator)
cd windows-2016/Scripts
.\vijenex-scanner.ps1

# Specify output directory
.\vijenex-scanner.ps1 -OutputDir "C:\Reports"

# Scan specific milestones
.\vijenex-scanner.ps1 -Milestones @("milestone-1.ps1", "milestone-2.ps1")
```

---

## Output

Scanner generates CSV file in `reports/` folder:
- `vijenex-cis-results.csv` - All control results

---

## Default-Enabled Controls (No False Positives)

These controls are **enabled by default** in Windows Server 2016. If registry key is missing, it means the default secure setting is in effect = **PASS**.

### Section 2.3.x Controls:
- 2.3.1.1: Guest account disabled by default
- 2.3.1.2: Blank password limit enabled by default
- 2.3.2.1: Audit subcategory override enabled by default
- 2.3.4.1: Printer driver installation restricted by default
- 2.3.6.1-6: Domain member security enabled by default (6 controls)
- 2.3.7.1: CTRL+ALT+DEL required by default
- 2.3.8.2-3: Network client security enabled by default (2 controls)
- 2.3.9.1, 2.3.9.4: Network server security enabled by default (2 controls)
- 2.3.10.1, 2.3.10.2, 2.3.10.5, 2.3.10.10, 2.3.10.13: Network access security enabled by default (5 controls)
- 2.3.15.1-2: System object security enabled by default (2 controls)

**Total: 22 controls** - No false positives!

---

## Excluded Controls

### Client-Only Controls (135 controls)
Windows 10/11 features not applicable to Windows Server:
- Windows Spotlight
- Toast notifications
- App Installer / Microsoft Store
- Network Sharing (user profile)
- Attachment Manager
- mDNS / NetBIOS settings
- Network Bridge / Internet Connection Sharing
- EDR in block mode
- Microsoft MAPS
- Attack Surface Reduction rules

### Deprecated Controls
- 2.3.11.5: LAN Manager hash (deprecated)
- Section 18.4.x: MS Security Guide (if not applicable)
- Section 18.5.x: MSS Legacy (if deprecated)

---

## Duplicate Control ID Prevention

Scanner includes built-in duplicate detection:

```
DUPLICATE CONTROL ID DETECTED: 2.3.17.4
  First: User Account Control: Detect application installations
  Second: User Account Control: Detect application installations (duplicate)
Skipping duplicate control: 2.3.17.4
```

Only the first occurrence is evaluated and included in CSV.

---

## Known Issues from 2025 (FIXED in 2016)

| Issue | 2025 Problem | 2016 Status |
|-------|-------------|-------------|
| Duplicate IDs | 2.2.16-20, 2.3.17.4-8 duplicated | ✅ FIXED - Detection & prevention |
| False positives | 22 controls marked FAIL (actually PASS) | ✅ FIXED - Default-enabled logic |
| Manual controls | Marked as FAIL | ✅ FIXED - Marked as MANUAL |
| Client controls | 135 controls fail on Server | ✅ FIXED - Excluded from scan |
| Shorthand IDs | 57.x, 43.x instead of 18.10.57.x | ✅ FIXED - Full IDs only |
| DC detection | No role detection | ✅ FIXED - Auto-detects DC/MS |

---

## Testing Checklist

Before production scanning:
- [ ] Test on 1 Member Server
- [ ] Test on 1 Domain Controller
- [ ] Verify no duplicate control IDs in CSV
- [ ] Verify no false positives for section 2.3.x
- [ ] Verify manual controls marked as MANUAL
- [ ] Verify DC/MS controls filtered correctly
- [ ] Verify client-only controls excluded

---

## Support

For issues or questions:
1. Check `2016-FALSE-POSITIVES-EXCLUSIONS.md` for detailed explanations
2. Review `LESSONS_LEARNED_AND_ALL_BUGS.md` for bug history
3. Verify you're using the correct scanner for your OS version

---

## Version History

- **v2.0** (2024) - Bug-fixed version with all 2025 lessons learned applied
  - No duplicate control IDs
  - No false positives
  - DC/MS detection
  - Client-only controls excluded
  - Manual controls handled correctly
  - Full control IDs

---

## CIS Benchmark Reference

This scanner implements:
- **CIS Microsoft Windows Server 2016 Benchmark v4.0.0**
- Total controls: 415
- Applicable to Server: 280 (after exclusions)
- Client-only: 135

Download official benchmark: https://www.cisecurity.org/cis-benchmarks
