# Windows Server 2022 CIS Controls Migration Status

## Overview
Windows Server 2022 milestones have been migrated from Windows Server 2019 as a baseline.

## Migration Status by Section

### ✅ COMPLETE - Core Security Controls
- **Section 1 (Account Policies)**: 11 controls - VERIFIED MATCH
- **Section 2.2 (User Rights Assignment)**: 49 controls - VERIFIED MATCH  
- **Section 2.3 (Security Options)**: Majority match with Windows 2019

### ⚠️ NEEDS REVIEW - Advanced Controls
- **Section 17 (Advanced Audit Policy)**: 
  - Windows 2019 milestones: 56 controls
  - Windows 2022 CIS benchmark: 34 controls
  - **Action needed**: Remove 22 deprecated controls from Windows 2022 milestones

- **Section 18 (Administrative Templates)**:
  - Windows 2019 milestones: 341 controls
  - Windows 2022 CIS benchmark: 487 controls
  - **Action needed**: Add 146 new controls to Windows 2022 milestones

## Current Milestone Files (19 total)
1. milestone-1.ps1 - Account Policies (Section 1)
2. milestone-2.ps1 - User Rights Assignment & Security Options (Section 2)
3. milestone-3.ps1 - Event Log (Section 3)
4. milestone-4.ps1 - Restricted Groups (Section 4)
5. milestone-5.ps1 - System Services (Section 5)
6. milestone-6.ps1 - Windows Firewall Domain Profile (Section 9.1)
7. milestone-7.ps1 - Windows Firewall Private Profile (Section 9.2)
8. milestone-8.ps1 - Windows Firewall Public Profile (Section 9.3)
9. milestone-9.ps1 - Advanced Audit Policy Part 1 (Section 17.1-17.5)
10. milestone-10.ps1 - Advanced Audit Policy Part 2 & Admin Templates Start (Section 17.6-18.10.26)
11. milestone-11.ps1 - Admin Templates Event Log (Section 18.10.26)
12. milestone-12.ps1 - Admin Templates File Explorer (Section 18.10.29)
13. milestone-13.ps1 - Admin Templates Microsoft Account (Section 18.10.42)
14. milestone-14.ps1 - Admin Templates Microsoft Defender (Section 18.10.43)
15. milestone-15.ps1 - Admin Templates OneDrive (Section 18.10.51)
16. milestone-16.ps1 - Admin Templates Remote Desktop (Section 18.10.57)
17. milestone-17.ps1 - Admin Templates RSS Feeds & Search (Section 18.10.58-18.10.59)
18. milestone-18.ps1 - Admin Templates Windows Components (Section 18.10)
19. milestone-19.ps1 - Admin Templates User (Section 19)

## Known Differences Between Windows 2019 and 2022

### New Controls in Windows 2022 (Sample)
- 18.6.7.1 - Mandate the minimum version of SMB
- 18.6.8.2 - Require Encryption
- 18.9.26.1 - Allow Custom SSPs and APs to be loaded into LSASS
- 18.9.39.1 - Configure validation of ROCA-vulnerable WHfB keys
- 18.10.13.3 - Turn off Microsoft consumer experiences
- 18.10.57.3.3.5 - Do not allow LPT port redirection
- 18.10.57.3.3.6 - Do not allow supported Plug and Play device redirection
- 18.10.57.3.3.7 - Do not allow WebAuthn redirection
- 18.10.82.2 - Sign-in and lock last interactive user automatically after a restart
- 2.3.11.14 - Network security: Restrict NTLM: Outgoing NTLM traffic to remote servers

### Deprecated Controls from Windows 2019 (Sample)
- Various Section 17 audit controls that were consolidated or removed

## Recommendation

**For Production Use:**
- Sections 1-2 are ready for immediate use
- Sections 3-16 should work but need validation against Windows 2022 systems
- Sections 17-19 require detailed review and updates

**Next Steps:**
1. Test current milestones on Windows Server 2022 system
2. Identify which controls fail or are not applicable
3. Add missing Windows 2022-specific controls
4. Remove deprecated controls
5. Update control descriptions and remediation steps for Windows 2022

## Testing Status
- [ ] Milestone 1-2 tested on Windows Server 2022
- [ ] Milestone 3-8 tested on Windows Server 2022
- [ ] Milestone 9-19 tested on Windows Server 2022
- [ ] All failures documented
- [ ] Missing controls added
- [ ] Deprecated controls removed

## Version
- Current: v1.0.0 (Migrated from Windows 2019)
- Target: v2.0.0 (Fully validated for Windows 2022)
