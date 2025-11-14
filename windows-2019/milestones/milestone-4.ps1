# 17 Advanced Audit Policy Configuration (Windows Server 2019) — Audit-only
$Global:Rules += @(
  # 17.1 Account Logon
  @{
    Id='17.1.1'
    Title='(L1) Ensure ''Audit Credential Validation'' is set to ''Success and Failure'' (Automated)'
    Section='17.1 Account Logon'
    Profile='Level1'
    Type='AuditPolicy'
    Subcategory='Credential Validation'
    Expected='Success and Failure'
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='17.1.1'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, please refer to the official CIS Microsoft Windows Server 2019 Benchmark document at the above URL.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },

  # 17.2 Account Management
  @{
    Id='17.2.1'
    Title='(L1) Ensure ''Audit Application Group Management'' is set to ''Success and Failure'' (Automated)'
    Section='17.2 Account Management'
    Profile='Level1'
    Type='AuditPolicy'
    Subcategory='Application Group Management'
    Expected='Success and Failure'
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='17.2.1'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, please refer to the official CIS Microsoft Windows Server 2019 Benchmark document at the above URL.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='17.2.5'
    Title='(L1) Ensure ''Audit Security Group Management'' is set to include ''Success'' (Automated)'
    Section='17.2 Account Management'
    Profile='Level1'
    Type='AuditPolicy'
    Subcategory='Security Group Management'
    Expected='Success'
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='17.2.5'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, please refer to the official CIS Microsoft Windows Server 2019 Benchmark document at the above URL.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='17.2.6'
    Title='(L1) Ensure ''Audit User Account Management'' is set to ''Success and Failure'' (Automated)'
    Section='17.2 Account Management'
    Profile='Level1'
    Type='AuditPolicy'
    Subcategory='User Account Management'
    Expected='Success and Failure'
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='17.2.6'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, please refer to the official CIS Microsoft Windows Server 2019 Benchmark document at the above URL.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },

  # 17.3 Detailed Tracking
  @{
    Id='17.3.1'
    Title='(L1) Ensure ''Audit PNP Activity'' is set to include ''Success'' (Automated)'
    Section='17.3 Detailed Tracking'
    Profile='Level1'
    Type='AuditPolicy'
    Subcategory='Plug and Play Events'
    Expected='Success'
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='17.3.1'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, please refer to the official CIS Microsoft Windows Server 2019 Benchmark document at the above URL.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='17.3.2'
    Title='(L1) Ensure ''Audit Process Creation'' is set to include ''Success'' (Automated)'
    Section='17.3 Detailed Tracking'
    Profile='Level1'
    Type='AuditPolicy'
    Subcategory='Process Creation'
    Expected='Success'
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='17.3.2'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, please refer to the official CIS Microsoft Windows Server 2019 Benchmark document at the above URL.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },

  # 17.5 Logon/Logoff
  @{
    Id='17.5.1'
    Title='(L1) Ensure ''Audit Account Lockout'' is set to include ''Failure'' (Automated)'
    Section='17.5 Logon/Logoff'
    Profile='Level1'
    Type='AuditPolicy'
    Subcategory='Account Lockout'
    Expected='Failure'
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='17.5.1'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, please refer to the official CIS Microsoft Windows Server 2019 Benchmark document at the above URL.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='17.5.2'
    Title='(L1) Ensure ''Audit Group Membership'' is set to include ''Success'' (Automated)'
    Section='17.5 Logon/Logoff'
    Profile='Level1'
    Type='AuditPolicy'
    Subcategory='Group Membership'
    Expected='Success'
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='17.5.2'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, please refer to the official CIS Microsoft Windows Server 2019 Benchmark document at the above URL.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='17.5.3'
    Title='(L1) Ensure ''Audit Logoff'' is set to include ''Success'' (Automated)'
    Section='17.5 Logon/Logoff'
    Profile='Level1'
    Type='AuditPolicy'
    Subcategory='Logoff'
    Expected='Success'
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='17.5.3'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, please refer to the official CIS Microsoft Windows Server 2019 Benchmark document at the above URL.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='17.5.4'
    Title='(L1) Ensure ''Audit Logon'' is set to ''Success and Failure'' (Automated)'
    Section='17.5 Logon/Logoff'
    Profile='Level1'
    Type='AuditPolicy'
    Subcategory='Logon'
    Expected='Success and Failure'
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='17.5.4'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, please refer to the official CIS Microsoft Windows Server 2019 Benchmark document at the above URL.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='17.5.5'
    Title='(L1) Ensure ''Audit Other Logon/Logoff Events'' is set to ''Success and Failure'' (Automated)'
    Section='17.5 Logon/Logoff'
    Profile='Level1'
    Type='AuditPolicy'
    Subcategory='Other Logon/Logoff Events'
    Expected='Success and Failure'
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='17.5.5'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, please refer to the official CIS Microsoft Windows Server 2019 Benchmark document at the above URL.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='17.5.6'
    Title='(L1) Ensure ''Audit Special Logon'' is set to include ''Success'' (Automated)'
    Section='17.5 Logon/Logoff'
    Profile='Level1'
    Type='AuditPolicy'
    Subcategory='Special Logon'
    Expected='Success'
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='17.5.6'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, please refer to the official CIS Microsoft Windows Server 2019 Benchmark document at the above URL.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },

  # 17.6 Object Access
  @{
    Id='17.6.1'
    Title='(L1) Ensure ''Audit Detailed File Share'' is set to include ''Failure'' (Automated)'
    Section='17.6 Object Access'
    Profile='Level1'
    Type='AuditPolicy'
    Subcategory='Detailed File Share'
    Expected='Failure'
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='17.6.1'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, please refer to the official CIS Microsoft Windows Server 2019 Benchmark document at the above URL.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='17.6.2'
    Title='(L1) Ensure ''Audit File Share'' is set to ''Success and Failure'' (Automated)'
    Section='17.6 Object Access'
    Profile='Level1'
    Type='AuditPolicy'
    Subcategory='File Share'
    Expected='Success and Failure'
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='17.6.2'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, please refer to the official CIS Microsoft Windows Server 2019 Benchmark document at the above URL.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },

  # 17.7 Policy Change
  @{
    Id='17.7.1'
    Title='(L1) Ensure ''Audit Audit Policy Change'' is set to include ''Success'' (Automated)'
    Section='17.7 Policy Change'
    Profile='Level1'
    Type='AuditPolicy'
    Subcategory='Audit Policy Change'
    Expected='Success'
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='17.7.1'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, please refer to the official CIS Microsoft Windows Server 2019 Benchmark document at the above URL.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='17.7.2'
    Title='(L1) Ensure ''Audit Authentication Policy Change'' is set to include ''Success'' (Automated)'
    Section='17.7 Policy Change'
    Profile='Level1'
    Type='AuditPolicy'
    Subcategory='Authentication Policy Change'
    Expected='Success'
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='17.7.2'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, please refer to the official CIS Microsoft Windows Server 2019 Benchmark document at the above URL.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },

  # 17.8 Privilege Use
  @{
    Id='17.8.1'
    Title='(L1) Ensure ''Audit Sensitive Privilege Use'' is set to ''Success and Failure'' (Automated)'
    Section='17.8 Privilege Use'
    Profile='Level1'
    Type='AuditPolicy'
    Subcategory='Sensitive Privilege Use'
    Expected='Success and Failure'
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='17.8.1'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, please refer to the official CIS Microsoft Windows Server 2019 Benchmark document at the above URL.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },

  # 17.9 System
  @{
    Id='17.9.1'
    Title='(L1) Ensure ''Audit IPsec Driver'' is set to ''Success and Failure'' (Automated)'
    Section='17.9 System'
    Profile='Level1'
    Type='AuditPolicy'
    Subcategory='IPsec Driver'
    Expected='Success and Failure'
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='17.9.1'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, please refer to the official CIS Microsoft Windows Server 2019 Benchmark document at the above URL.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='17.9.2'
    Title='(L1) Ensure ''Audit Other System Events'' is set to ''Success and Failure'' (Automated)'
    Section='17.9 System'
    Profile='Level1'
    Type='AuditPolicy'
    Subcategory='Other System Events'
    Expected='Success and Failure'
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='17.9.2'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, please refer to the official CIS Microsoft Windows Server 2019 Benchmark document at the above URL.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='17.9.3'
    Title='(L1) Ensure ''Audit Security State Change'' is set to include ''Success'' (Automated)'
    Section='17.9 System'
    Profile='Level1'
    Type='AuditPolicy'
    Subcategory='Security State Change'
    Expected='Success'
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='17.9.3'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, please refer to the official CIS Microsoft Windows Server 2019 Benchmark document at the above URL.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='17.9.4'
    Title='(L1) Ensure ''Audit Security System Extension'' is set to include ''Success'' (Automated)'
    Section='17.9 System'
    Profile='Level1'
    Type='AuditPolicy'
    Subcategory='Security System Extension'
    Expected='Success'
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='17.9.4'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, please refer to the official CIS Microsoft Windows Server 2019 Benchmark document at the above URL.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  },
  @{
    Id='17.9.5'
    Title='(L1) Ensure ''Audit System Integrity'' is set to ''Success and Failure'' (Automated)'
    Section='17.9 System'
    Profile='Level1'
    Type='AuditPolicy'
    Subcategory='System Integrity'
    Expected='Success and Failure'
    CISReference='https://www.cisecurity.org/benchmark/microsoft_windows_server'
    CISControlID='17.9.5'
    ReferenceNote='For detailed description, rationale, impact assessment, and remediation steps, please refer to the official CIS Microsoft Windows Server 2019 Benchmark document at the above URL.'
    Remediation='Refer to official CIS Microsoft Windows Server 2019 Benchmark documentation for detailed remediation steps.'
  }
)