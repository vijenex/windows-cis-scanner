# milestone-9.ps1 — Windows Defender Firewall (9.2 Private Profile, 9.3 Public Profile)
$Global:Rules += @(
  # 9.2 Private Profile
  # 9.2.1 Windows Firewall: Private: Firewall state = On (recommended)
  @{
    Id='9.2.1'; Title='(L1) Ensure ''Windows Firewall: Private: Firewall state'' is set to ''On (recommended)'' (Automated)';
    Section='9.2 Private Profile'; Profile='Level1'; Type='Manual';
    Expected='On'; Evidence='Check Windows Firewall settings';
    Description='This policy setting controls whether Windows Firewall is enabled for the Private profile.';
    Impact='Enabling Windows Firewall helps protect against network-based attacks and unauthorized access.';
    Remediation='Set Windows Firewall Private profile state to On in Windows Firewall with Advanced Security.'
  },

  # 9.2.2 Windows Firewall: Private: Inbound connections = Block (default)
  @{
    Id='9.2.2'; Title='(L1) Ensure ''Windows Firewall: Private: Inbound connections'' is set to ''Block (default)'' (Automated)';
    Section='9.2 Private Profile'; Profile='Level1'; Type='Manual';
    Expected='Block'; Evidence='Check Windows Firewall settings';
    Description='This policy setting controls the default behavior for inbound connections on the Private profile.';
    Impact='Blocking inbound connections by default provides protection against unauthorized network access.';
    Remediation='Set Windows Firewall Private profile inbound connections to Block in Windows Firewall with Advanced Security.'
  },

  # 9.2.3 Windows Firewall: Private: Settings: Display a notification = No
  @{
    Id='9.2.3'; Title='(L1) Ensure ''Windows Firewall: Private: Settings: Display a notification'' is set to ''No'' (Automated)';
    Section='9.2 Private Profile'; Profile='Level1'; Type='Manual';
    Expected='No'; Evidence='Check Windows Firewall settings';
    Description='This policy setting controls whether Windows Firewall displays notifications when programs are blocked.';
    Impact='Disabling notifications prevents user distraction while maintaining security protection.';
    Remediation='Set Windows Firewall Private profile notification display to No in Windows Firewall with Advanced Security.'
  },

  # 9.2.4 Windows Firewall: Private: Logging: Name = %SystemRoot%\System32\logfiles\firewall\privatefw.log
  @{
    Id='9.2.4'; Title='(L1) Ensure ''Windows Firewall: Private: Logging: Name'' is set to ''%SystemRoot%\System32\logfiles\firewall\privatefw.log'' (Automated)';
    Section='9.2 Private Profile'; Profile='Level1'; Type='Manual';
    Expected='%SystemRoot%\System32\logfiles\firewall\privatefw.log'; Evidence='Check Windows Firewall logging settings';
    Description='This policy setting specifies the path and filename for the Windows Firewall log file for the Private profile.';
    Impact='Proper logging configuration enables security monitoring and forensic analysis of firewall activity.';
    Remediation='Set Windows Firewall Private profile log file name to %SystemRoot%\System32\logfiles\firewall\privatefw.log.'
  },

  # 9.2.5 Windows Firewall: Private: Logging: Size limit (KB) = 16,384 KB or greater
  @{
    Id='9.2.5'; Title='(L1) Ensure ''Windows Firewall: Private: Logging: Size limit (KB)'' is set to ''16,384 KB or greater'' (Automated)';
    Section='9.2 Private Profile'; Profile='Level1'; Type='Manual';
    Expected='16384 KB or greater'; Evidence='Check Windows Firewall logging settings';
    Description='This policy setting specifies the maximum size of the Windows Firewall log file for the Private profile.';
    Impact='Adequate log file size ensures sufficient logging capacity for security monitoring and analysis.';
    Remediation='Set Windows Firewall Private profile log size limit to 16,384 KB or greater.'
  },

  # 9.2.6 Windows Firewall: Private: Logging: Log dropped packets = Yes
  @{
    Id='9.2.6'; Title='(L1) Ensure ''Windows Firewall: Private: Logging: Log dropped packets'' is set to ''Yes'' (Automated)';
    Section='9.2 Private Profile'; Profile='Level1'; Type='Manual';
    Expected='Yes'; Evidence='Check Windows Firewall logging settings';
    Description='This policy setting controls whether Windows Firewall logs dropped packets for the Private profile.';
    Impact='Logging dropped packets provides valuable information for security monitoring and attack detection.';
    Remediation='Set Windows Firewall Private profile to log dropped packets.'
  },

  # 9.2.7 Windows Firewall: Private: Logging: Log successful connections = Yes
  @{
    Id='9.2.7'; Title='(L1) Ensure ''Windows Firewall: Private: Logging: Log successful connections'' is set to ''Yes'' (Automated)';
    Section='9.2 Private Profile'; Profile='Level1'; Type='Manual';
    Expected='Yes'; Evidence='Check Windows Firewall logging settings';
    Description='This policy setting controls whether Windows Firewall logs successful connections for the Private profile.';
    Impact='Logging successful connections provides audit trail for network activity and helps with forensic analysis.';
    Remediation='Set Windows Firewall Private profile to log successful connections.'
  },

  # 9.3 Public Profile
  # 9.3.1 Windows Firewall: Public: Firewall state = On (recommended)
  @{
    Id='9.3.1'; Title='(L1) Ensure ''Windows Firewall: Public: Firewall state'' is set to ''On (recommended)'' (Automated)';
    Section='9.3 Public Profile'; Profile='Level1'; Type='Manual';
    Expected='On'; Evidence='Check Windows Firewall settings';
    Description='This policy setting controls whether Windows Firewall is enabled for the Public profile.';
    Impact='Enabling Windows Firewall helps protect against network-based attacks and unauthorized access.';
    Remediation='Set Windows Firewall Public profile state to On in Windows Firewall with Advanced Security.'
  },

  # 9.3.2 Windows Firewall: Public: Inbound connections = Block (default)
  @{
    Id='9.3.2'; Title='(L1) Ensure ''Windows Firewall: Public: Inbound connections'' is set to ''Block (default)'' (Automated)';
    Section='9.3 Public Profile'; Profile='Level1'; Type='Manual';
    Expected='Block'; Evidence='Check Windows Firewall settings';
    Description='This policy setting controls the default behavior for inbound connections on the Public profile.';
    Impact='Blocking inbound connections by default provides protection against unauthorized network access.';
    Remediation='Set Windows Firewall Public profile inbound connections to Block in Windows Firewall with Advanced Security.'
  },

  # 9.3.3 Windows Firewall: Public: Settings: Display a notification = No
  @{
    Id='9.3.3'; Title='(L1) Ensure ''Windows Firewall: Public: Settings: Display a notification'' is set to ''No'' (Automated)';
    Section='9.3 Public Profile'; Profile='Level1'; Type='Manual';
    Expected='No'; Evidence='Check Windows Firewall settings';
    Description='This policy setting controls whether Windows Firewall displays notifications when programs are blocked.';
    Impact='Disabling notifications prevents user distraction while maintaining security protection.';
    Remediation='Set Windows Firewall Public profile notification display to No in Windows Firewall with Advanced Security.'
  },

  # 9.3.4 Windows Firewall: Public: Logging: Name = %SystemRoot%\System32\logfiles\firewall\publicfw.log
  @{
    Id='9.3.4'; Title='(L1) Ensure ''Windows Firewall: Public: Logging: Name'' is set to ''%SystemRoot%\System32\logfiles\firewall\publicfw.log'' (Automated)';
    Section='9.3 Public Profile'; Profile='Level1'; Type='Manual';
    Expected='%SystemRoot%\System32\logfiles\firewall\publicfw.log'; Evidence='Check Windows Firewall logging settings';
    Description='This policy setting specifies the path and filename for the Windows Firewall log file for the Public profile.';
    Impact='Proper logging configuration enables security monitoring and forensic analysis of firewall activity.';
    Remediation='Set Windows Firewall Public profile log file name to %SystemRoot%\System32\logfiles\firewall\publicfw.log.'
  },

  # 9.3.5 Windows Firewall: Public: Logging: Size limit (KB) = 16,384 KB or greater
  @{
    Id='9.3.5'; Title='(L1) Ensure ''Windows Firewall: Public: Logging: Size limit (KB)'' is set to ''16,384 KB or greater'' (Automated)';
    Section='9.3 Public Profile'; Profile='Level1'; Type='Manual';
    Expected='16384 KB or greater'; Evidence='Check Windows Firewall logging settings';
    Description='This policy setting specifies the maximum size of the Windows Firewall log file for the Public profile.';
    Impact='Adequate log file size ensures sufficient logging capacity for security monitoring and analysis.';
    Remediation='Set Windows Firewall Public profile log size limit to 16,384 KB or greater.'
  },

  # 9.3.6 Windows Firewall: Public: Logging: Log dropped packets = Yes
  @{
    Id='9.3.6'; Title='(L1) Ensure ''Windows Firewall: Public: Logging: Log dropped packets'' is set to ''Yes'' (Automated)';
    Section='9.3 Public Profile'; Profile='Level1'; Type='Manual';
    Expected='Yes'; Evidence='Check Windows Firewall logging settings';
    Description='This policy setting controls whether Windows Firewall logs dropped packets for the Public profile.';
    Impact='Logging dropped packets provides valuable information for security monitoring and attack detection.';
    Remediation='Set Windows Firewall Public profile to log dropped packets.'
  },

  # 9.3.7 Windows Firewall: Public: Logging: Log successful connections = Yes
  @{
    Id='9.3.7'; Title='(L1) Ensure ''Windows Firewall: Public: Logging: Log successful connections'' is set to ''Yes'' (Automated)';
    Section='9.3 Public Profile'; Profile='Level1'; Type='Manual';
    Expected='Yes'; Evidence='Check Windows Firewall logging settings';
    Description='This policy setting controls whether Windows Firewall logs successful connections for the Public profile.';
    Impact='Logging successful connections provides audit trail for network activity and helps with forensic analysis.';
    Remediation='Set Windows Firewall Public profile to log successful connections.'
  }

  # Note: Section 9.1 Domain Profile has no rules per CIS documentation structure
)