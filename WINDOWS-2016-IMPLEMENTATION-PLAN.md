# Windows Server 2016 CIS Audit - Implementation Plan

## Status: NOT STARTED - Planning Phase

## Objective
Implement Windows Server 2016 CIS audit scanner and report generator WITHOUT repeating the bugs found in 2022 and 2025 implementations.

---

## Phase 1: Pre-Implementation Analysis (MANDATORY - Do This FIRST)

### Step 1.1: Get Official CIS Benchmark
- [ ] Download CIS Windows Server 2016 Benchmark PDF/RTF from cisecurity.org
- [ ] Extract complete control list with IDs and titles to text file
- [ ] Count total controls (expected: ~300-350 controls)
- [ ] Save as: `CIS_Windows_Server_2016_Controls_List.txt`

### Step 1.2: Identify 2016-Specific Exclusions
- [ ] Compare 2016 vs 2022/2025 benchmarks
- [ ] List controls NOT in 2016 (features added in 2019+)
- [ ] List controls ONLY in 2016 (deprecated in newer versions)
- [ ] Document Windows Server 2016 default-enabled settings
- [ ] Create exclusion list: `2016-EXCLUSIONS.md`

### Step 1.3: Analyze Existing 2016 Scanner (If Exists)
- [ ] Check if windows-2016 scanner already exists
- [ ] Count controls in existing milestone files
- [ ] Compare with CIS benchmark count
- [ ] Identify missing controls
- [ ] Identify duplicate control IDs
- [ ] Document findings in: `2016-SCANNER-AUDIT.md`

**Deliverables:**
- CIS_Windows_Server_2016_Controls_List.txt (complete control list)
- 2016-EXCLUSIONS.md (controls to exclude)
- 2016-SCANNER-AUDIT.md (existing scanner analysis)

---

## Phase 2: Scanner Code Review & Bug Fixes (BEFORE Any Scanning)

### Step 2.1: Check for Known Bugs from 2022/2025

**Bug 1: Duplicate Control IDs**
- [ ] Search for duplicate control IDs in milestone files
- [ ] Verify each control ID appears only once
- [ ] Check controls: 2.2.16-2.2.20, 2.3.17.4-8
- [ ] Fix: Remove duplicates, ensure unique IDs

**Bug 2: Shorthand Control IDs**
- [ ] Check if any controls use shorthand (57.x, 43.x instead of 18.10.57.x)
- [ ] Fix: Update to full CIS control IDs
- [ ] Verify format: X.X.X.X (not shortened)

**Bug 3: Truncated Control Titles**
- [ ] Review all control titles in milestone files
- [ ] Compare with CIS benchmark titles
- [ ] Fix: Update with complete titles
- [ ] Create TITLE_FIXES dictionary for report generator

**Bug 4: Manual Controls Marked as FAIL**
- [ ] Find all Type='Manual' controls
- [ ] Fix: Add logic to mark as MANUAL not FAIL
- [ ] Code location: vijenex-scanner.ps1

**Bug 5: False Positives (Default-Enabled Controls)**
- [ ] Identify controls enabled by default in Windows Server 2016
- [ ] List controls where missing registry key = enabled
- [ ] Fix: Add logic to mark PASS when key missing AND default=enabled
- [ ] Document in: `2016-DEFAULT-ENABLED-CONTROLS.md`

**Bug 6: No DC Detection**
- [ ] Add DC detection logic at start of scanner
- [ ] Skip DC-only controls on Member Servers
- [ ] Skip MS-only controls on Domain Controllers
- [ ] Code to add:
```powershell
$domainRole = (Get-WmiObject -Class Win32_ComputerSystem).DomainRole
# 0,1,2,3 = Member Server
# 4,5 = Domain Controller
if ($domainRole -ge 4) {
    Write-Host "Domain Controller detected"
    # Skip MS-only controls
} else {
    Write-Host "Member Server detected"
    # Skip DC-only controls
}
```

### Step 2.2: Add Missing Features

**Feature 1: Exclusion Logic**
- [ ] Add exclusion list for non-applicable controls
- [ ] Exclude: DC-only (if MS), MS-only (if DC)
- [ ] Exclude: Windows 10/11 client controls
- [ ] Exclude: Features not in Server 2016
- [ ] Exclude: Deprecated/legacy controls

**Feature 2: Default-Enabled Logic**
- [ ] Add function to check if control is default-enabled
- [ ] If registry key missing AND default=enabled, mark PASS
- [ ] Document all default-enabled controls

**Feature 3: Manual Control Handling**
- [ ] Check if Type='Manual'
- [ ] Set Status='MANUAL' or 'NOT_TESTED'
- [ ] Add note: "This control requires manual verification"

### Step 2.3: Validate Scanner Code

- [ ] Count controls in all milestone files
- [ ] Total must match: CIS benchmark - exclusions
- [ ] Verify no duplicate control IDs
- [ ] Verify all IDs are full format (not shorthand)
- [ ] Verify all titles are complete (not truncated)
- [ ] Run PowerShell syntax check on all files

**Deliverables:**
- Fixed milestone files (all bugs corrected)
- Updated vijenex-scanner.ps1 (with new logic)
- 2016-DEFAULT-ENABLED-CONTROLS.md
- Scanner validation report

---

## Phase 3: Test Scan (ONE Server Only)

### Step 3.1: Prepare Test Environment
- [ ] Select 1 Windows Server 2016 test system
- [ ] Verify it's Member Server (not DC)
- [ ] Document server details (IP, hostname, role)

### Step 3.2: Run Test Scan
- [ ] Execute scanner on test server
- [ ] Monitor for errors
- [ ] Check scan completion time
- [ ] Verify CSV output generated

### Step 3.3: Validate Test Results
- [ ] Open CSV file
- [ ] Count total controls in CSV
- [ ] Verify control count matches expected
- [ ] Check for duplicate control IDs
- [ ] Review PASS/FAIL distribution
- [ ] Look for false positives
- [ ] Verify no controls marked FAIL that are actually enabled
- [ ] Check manual controls marked as MANUAL not FAIL

**Quality Checks:**
- [ ] No duplicate control IDs in CSV
- [ ] All control IDs are full format
- [ ] All titles are complete
- [ ] PASS/FAIL distribution is reasonable
- [ ] No obvious false positives
- [ ] Manual controls handled correctly

**If ANY check fails: STOP, fix scanner, repeat test scan**

**Deliverables:**
- Test scan CSV results
- Test scan validation report
- List of any issues found

---

## Phase 4: Report Generator Development

### Step 4.1: Get CIS Benchmark RTF
- [ ] Obtain CIS Windows Server 2016 Benchmark RTF file
- [ ] Save as: `CIS_Microsoft_Windows_Server_2016_Benchmark_vX.X.X.txt.rtf`
- [ ] Test RTF parsing on sample controls
- [ ] Verify descriptions/impact/remediation extracted correctly

### Step 4.2: Create Report Generator Script
- [ ] Copy template from 2025 report generator
- [ ] Update for Windows Server 2016
- [ ] Add RTF parsing logic
- [ ] Add exclusion logic (DC-only, client-only, deprecated)
- [ ] Add TITLE_FIXES dictionary
- [ ] Add control ID mapping (if needed)

### Step 4.3: Test Report Generation
- [ ] Generate test report from test scan CSV
- [ ] Review report format
- [ ] Verify all controls have descriptions
- [ ] Check for duplicate controls
- [ ] Verify exclusions working
- [ ] Check Evidence Screenshot sections for failures

**Quality Checks:**
- [ ] Report matches 2022/2025 format
- [ ] All controls have Description/Impact/Remediation
- [ ] No duplicate controls
- [ ] Exclusions applied correctly
- [ ] Failed controls have Evidence Screenshot section
- [ ] Executive Summary shows correct counts

**Deliverables:**
- create_2016_report.py (report generator)
- Test report DOCX
- Report validation checklist

---

## Phase 5: Production Scanning (Only After All Validation Passes)

### Step 5.1: Prepare Production Scan
- [ ] List all Windows Server 2016 production systems
- [ ] Separate by environment (Prod, Non-Prod)
- [ ] Get approval to scan production
- [ ] Schedule scan window

### Step 5.2: Execute Production Scans
- [ ] Scan all Windows Server 2016 systems
- [ ] Collect all CSV results
- [ ] Organize by server IP/hostname
- [ ] Verify all scans completed successfully

### Step 5.3: Generate Production Report
- [ ] Run report generator on all production CSVs
- [ ] Review generated report
- [ ] Verify quality
- [ ] Add screenshots for failed controls
- [ ] Final review before client delivery

**Deliverables:**
- All production scan CSV files
- Windows-Server-2016-CIS-Audit-Report.docx
- Screenshot evidence for failures

---

## Phase 6: Client Delivery

### Step 6.1: Final Report Review
- [ ] Executive summary accurate
- [ ] All controls documented
- [ ] Evidence screenshots attached
- [ ] Remediation steps included
- [ ] Format professional and consistent

### Step 6.2: Deliver to Client
- [ ] Submit final report
- [ ] Provide CSV scan results
- [ ] Document any exclusions/limitations
- [ ] Answer client questions

**Deliverables:**
- Final Windows Server 2016 CIS Audit Report
- All scan CSV files
- Delivery confirmation

---

## Quality Checklist (Use Before Each Phase)

### Before Scanning Production:
- [ ] Control count in scanner = CIS benchmark count (minus known exclusions)
- [ ] No duplicate control IDs in milestone files
- [ ] All control IDs are full format (not shorthand)
- [ ] All titles are complete (not truncated)
- [ ] DC detection logic added and tested
- [ ] Default-enabled logic added and tested
- [ ] Manual control logic added and tested
- [ ] Test scan completed successfully
- [ ] Test CSV reviewed - no issues found
- [ ] Test report generated successfully

### Before Generating Report:
- [ ] RTF parsing tested and working
- [ ] Title fixes dictionary populated
- [ ] Exclusion lists finalized
- [ ] Test report generated and reviewed
- [ ] No duplicate controls in report
- [ ] All controls have descriptions
- [ ] Evidence sections for failures

### Before Client Delivery:
- [ ] All production scans completed
- [ ] Report generated and reviewed
- [ ] Screenshots attached
- [ ] Format matches 2022/2025 reports
- [ ] Executive summary accurate
- [ ] No obvious errors or issues

---

## Expected Differences in Windows Server 2016

### Controls Likely NOT in Server 2016:
- Windows Defender ATP/EDR features (18.10.43.4.x)
- Attack Surface Reduction rules (18.10.43.6.x)
- Modern Windows 10/11 features
- App Installer controls (18.10.18.x)
- Some Group Policy settings added in 2019+

### Controls Likely ONLY in Server 2016:
- Older legacy settings removed in 2019+
- Different default values
- Different registry paths
- Deprecated features

### Known Exclusions (Based on 2022/2025):
- DC-only controls (if scanning Member Servers)
- Windows 10/11 client controls (Section 19.x subset)
- MS Security Guide (18.4.x) - if not applicable
- MSS Legacy (18.5.x) - if deprecated
- Features not available in 2016

---

## Risk Mitigation

### If Issues Found During Test Scan:
1. STOP production scanning
2. Document the issue
3. Fix the scanner code
4. Re-run test scan
5. Validate fix worked
6. Only then proceed to production

### If Issues Found During Report Generation:
1. STOP client delivery
2. Document the issue
3. Fix report generator
4. Re-generate report
5. Validate fix worked
6. Only then deliver to client

---

## Success Criteria

### Scanner Success:
- ✅ All CIS controls implemented (minus documented exclusions)
- ✅ No duplicate control IDs
- ✅ No false positives
- ✅ Manual controls handled correctly
- ✅ DC detection working
- ✅ Test scan passes all quality checks

### Report Success:
- ✅ All controls documented
- ✅ Descriptions/Impact/Remediation included
- ✅ No duplicate controls
- ✅ Exclusions applied correctly
- ✅ Format matches 2022/2025
- ✅ Professional quality

### Client Delivery Success:
- ✅ Report delivered on time
- ✅ No errors or issues found
- ✅ Client satisfied with quality
- ✅ All questions answered

---

## Timeline Estimate

- Phase 1 (Analysis): 1-2 days
- Phase 2 (Bug Fixes): 2-3 days
- Phase 3 (Test Scan): 1 day
- Phase 4 (Report Generator): 1-2 days
- Phase 5 (Production Scan): 1 day
- Phase 6 (Client Delivery): 1 day

**Total: 7-10 days** (assuming no major issues)

---

## Next Steps

1. **Obtain CIS Windows Server 2016 Benchmark** - Get official PDF/RTF
2. **Extract Control List** - Create complete list with IDs and titles
3. **Share with Team** - Review and analyze
4. **Start Phase 1** - Pre-implementation analysis
5. **Follow Plan** - Don't skip steps!

---

## Notes

- This plan is based on lessons learned from 2022 and 2025 implementations
- Do NOT skip validation steps
- Do NOT scan production before test scan passes
- Do NOT deliver report before quality review
- Document everything
- When in doubt, test first
