# Milestone 17 - CIS Windows Server 2025 Benchmark
# Auto-generated from CIS Benchmark v1.0.0
# Total controls: 34


$Global:Rules += @{
  Id = "17.1.1"
  Title = "Ensure 'Audit Credential Validation' is set to 'Success"
  Section = "Section 17"
  Profile = "Level1"
  Type = "AuditPolicy"
  # TODO: Add specific check parameters
  # Key = ""
  # Expected = ""
  # Operator = "Equals"
  CISReference = "https://www.cisecurity.org/benchmark/microsoft_windows_server"
  Remediation = "Refer to official CIS Microsoft Windows Server 2025 Benchmark documentation for detailed remediation steps."
}

$Global:Rules += @{
  Id = "17.1.2"
  Title = "Ensure 'Audit Kerberos Authentication Service' is set"
  Section = "Section 17"
  Profile = "Level1"
  Type = "AuditPolicy"
  # TODO: Add specific check parameters
  # Key = ""
  # Expected = ""
  # Operator = "Equals"
  CISReference = "https://www.cisecurity.org/benchmark/microsoft_windows_server"
  Remediation = "Refer to official CIS Microsoft Windows Server 2025 Benchmark documentation for detailed remediation steps." # DC-only
}

$Global:Rules += @{
  Id = "17.1.3"
  Title = "Ensure 'Audit Kerberos Service Ticket Operations' is"
  Section = "Section 17"
  Profile = "Level1"
  Type = "AuditPolicy"
  # TODO: Add specific check parameters
  # Key = ""
  # Expected = ""
  # Operator = "Equals"
  CISReference = "https://www.cisecurity.org/benchmark/microsoft_windows_server"
  Remediation = "Refer to official CIS Microsoft Windows Server 2025 Benchmark documentation for detailed remediation steps." # DC-only
}

$Global:Rules += @{
  Id = "17.2.1"
  Title = "Ensure 'Audit Application Group Management' is set"
  Section = "Section 17"
  Profile = "Level1"
  Type = "AuditPolicy"
  # TODO: Add specific check parameters
  # Key = ""
  # Expected = ""
  # Operator = "Equals"
  CISReference = "https://www.cisecurity.org/benchmark/microsoft_windows_server"
  Remediation = "Refer to official CIS Microsoft Windows Server 2025 Benchmark documentation for detailed remediation steps."
}

$Global:Rules += @{
  Id = "17.2.2"
  Title = "Ensure 'Audit Computer Account Management' is set"
  Section = "Section 17"
  Profile = "Level1"
  Type = "AuditPolicy"
  # TODO: Add specific check parameters
  # Key = ""
  # Expected = ""
  # Operator = "Equals"
  CISReference = "https://www.cisecurity.org/benchmark/microsoft_windows_server"
  Remediation = "Refer to official CIS Microsoft Windows Server 2025 Benchmark documentation for detailed remediation steps." # DC-only
}

$Global:Rules += @{
  Id = "17.2.3"
  Title = "Ensure 'Audit Distribution Group Management' is set"
  Section = "Section 17"
  Profile = "Level1"
  Type = "AuditPolicy"
  # TODO: Add specific check parameters
  # Key = ""
  # Expected = ""
  # Operator = "Equals"
  CISReference = "https://www.cisecurity.org/benchmark/microsoft_windows_server"
  Remediation = "Refer to official CIS Microsoft Windows Server 2025 Benchmark documentation for detailed remediation steps." # DC-only
}

$Global:Rules += @{
  Id = "17.2.4"
  Title = "Ensure 'Audit Other Account Management Events' is"
  Section = "Section 17"
  Profile = "Level1"
  Type = "AuditPolicy"
  # TODO: Add specific check parameters
  # Key = ""
  # Expected = ""
  # Operator = "Equals"
  CISReference = "https://www.cisecurity.org/benchmark/microsoft_windows_server"
  Remediation = "Refer to official CIS Microsoft Windows Server 2025 Benchmark documentation for detailed remediation steps." # DC-only
}

$Global:Rules += @{
  Id = "17.2.5"
  Title = "Ensure 'Audit Security Group Management' is set to"
  Section = "Section 17"
  Profile = "Level1"
  Type = "AuditPolicy"
  # TODO: Add specific check parameters
  # Key = ""
  # Expected = ""
  # Operator = "Equals"
  CISReference = "https://www.cisecurity.org/benchmark/microsoft_windows_server"
  Remediation = "Refer to official CIS Microsoft Windows Server 2025 Benchmark documentation for detailed remediation steps."
}

$Global:Rules += @{
  Id = "17.2.6"
  Title = "Ensure 'Audit User Account Management' is set to"
  Section = "Section 17"
  Profile = "Level1"
  Type = "AuditPolicy"
  # TODO: Add specific check parameters
  # Key = ""
  # Expected = ""
  # Operator = "Equals"
  CISReference = "https://www.cisecurity.org/benchmark/microsoft_windows_server"
  Remediation = "Refer to official CIS Microsoft Windows Server 2025 Benchmark documentation for detailed remediation steps."
}

$Global:Rules += @{
  Id = "17.3.1"
  Title = "Ensure 'Audit PNP Activity' is set to include 'Success'"
  Section = "Section 17"
  Profile = "Level1"
  Type = "AuditPolicy"
  # TODO: Add specific check parameters
  # Key = ""
  # Expected = ""
  # Operator = "Equals"
  CISReference = "https://www.cisecurity.org/benchmark/microsoft_windows_server"
  Remediation = "Refer to official CIS Microsoft Windows Server 2025 Benchmark documentation for detailed remediation steps." # Windows 10/11 - Not Applicable
}

$Global:Rules += @{
  Id = "17.3.2"
  Title = "Ensure 'Audit Process Creation' is set to include"
  Section = "Section 17"
  Profile = "Level1"
  Type = "AuditPolicy"
  # TODO: Add specific check parameters
  # Key = ""
  # Expected = ""
  # Operator = "Equals"
  CISReference = "https://www.cisecurity.org/benchmark/microsoft_windows_server"
  Remediation = "Refer to official CIS Microsoft Windows Server 2025 Benchmark documentation for detailed remediation steps."
}

$Global:Rules += @{
  Id = "17.4.1"
  Title = "Ensure 'Audit Directory Service Access' is set to"
  Section = "Section 17"
  Profile = "Level1"
  Type = "AuditPolicy"
  # TODO: Add specific check parameters
  # Key = ""
  # Expected = ""
  # Operator = "Equals"
  CISReference = "https://www.cisecurity.org/benchmark/microsoft_windows_server"
  Remediation = "Refer to official CIS Microsoft Windows Server 2025 Benchmark documentation for detailed remediation steps." # DC-only
}

$Global:Rules += @{
  Id = "17.4.2"
  Title = "Ensure 'Audit Directory Service Changes' is set to"
  Section = "Section 17"
  Profile = "Level1"
  Type = "AuditPolicy"
  # TODO: Add specific check parameters
  # Key = ""
  # Expected = ""
  # Operator = "Equals"
  CISReference = "https://www.cisecurity.org/benchmark/microsoft_windows_server"
  Remediation = "Refer to official CIS Microsoft Windows Server 2025 Benchmark documentation for detailed remediation steps." # DC-only
}

$Global:Rules += @{
  Id = "17.5.1"
  Title = "Ensure 'Audit Account Lockout' is set to include"
  Section = "Section 17"
  Profile = "Level1"
  Type = "AuditPolicy"
  # TODO: Add specific check parameters
  # Key = ""
  # Expected = ""
  # Operator = "Equals"
  CISReference = "https://www.cisecurity.org/benchmark/microsoft_windows_server"
  Remediation = "Refer to official CIS Microsoft Windows Server 2025 Benchmark documentation for detailed remediation steps."
}

$Global:Rules += @{
  Id = "17.5.2"
  Title = "Ensure 'Audit Group Membership' is set to include"
  Section = "Section 17"
  Profile = "Level1"
  Type = "AuditPolicy"
  # TODO: Add specific check parameters
  # Key = ""
  # Expected = ""
  # Operator = "Equals"
  CISReference = "https://www.cisecurity.org/benchmark/microsoft_windows_server"
  Remediation = "Refer to official CIS Microsoft Windows Server 2025 Benchmark documentation for detailed remediation steps."
}

$Global:Rules += @{
  Id = "17.5.3"
  Title = "Ensure 'Audit Logoff' is set to include 'Success'"
  Section = "Section 17"
  Profile = "Level1"
  Type = "AuditPolicy"
  # TODO: Add specific check parameters
  # Key = ""
  # Expected = ""
  # Operator = "Equals"
  CISReference = "https://www.cisecurity.org/benchmark/microsoft_windows_server"
  Remediation = "Refer to official CIS Microsoft Windows Server 2025 Benchmark documentation for detailed remediation steps."
}

$Global:Rules += @{
  Id = "17.5.4"
  Title = "Ensure 'Audit Logon' is set to 'Success and Failure'"
  Section = "Section 17"
  Profile = "Level1"
  Type = "AuditPolicy"
  # TODO: Add specific check parameters
  # Key = ""
  # Expected = ""
  # Operator = "Equals"
  CISReference = "https://www.cisecurity.org/benchmark/microsoft_windows_server"
  Remediation = "Refer to official CIS Microsoft Windows Server 2025 Benchmark documentation for detailed remediation steps."
}

$Global:Rules += @{
  Id = "17.5.5"
  Title = "Ensure 'Audit Other Logon/Logoff Events' is set to"
  Section = "Section 17"
  Profile = "Level1"
  Type = "AuditPolicy"
  # TODO: Add specific check parameters
  # Key = ""
  # Expected = ""
  # Operator = "Equals"
  CISReference = "https://www.cisecurity.org/benchmark/microsoft_windows_server"
  Remediation = "Refer to official CIS Microsoft Windows Server 2025 Benchmark documentation for detailed remediation steps."
}

$Global:Rules += @{
  Id = "17.5.6"
  Title = "Ensure 'Audit Special Logon' is set to include"
  Section = "Section 17"
  Profile = "Level1"
  Type = "AuditPolicy"
  # TODO: Add specific check parameters
  # Key = ""
  # Expected = ""
  # Operator = "Equals"
  CISReference = "https://www.cisecurity.org/benchmark/microsoft_windows_server"
  Remediation = "Refer to official CIS Microsoft Windows Server 2025 Benchmark documentation for detailed remediation steps."
}

$Global:Rules += @{
  Id = "17.6.1"
  Title = "Ensure 'Audit Detailed File Share' is set to include"
  Section = "Section 17"
  Profile = "Level1"
  Type = "AuditPolicy"
  # TODO: Add specific check parameters
  # Key = ""
  # Expected = ""
  # Operator = "Equals"
  CISReference = "https://www.cisecurity.org/benchmark/microsoft_windows_server"
  Remediation = "Refer to official CIS Microsoft Windows Server 2025 Benchmark documentation for detailed remediation steps."
}

$Global:Rules += @{
  Id = "17.6.2"
  Title = "Ensure 'Audit File Share' is set to 'Success and"
  Section = "Section 17"
  Profile = "Level1"
  Type = "AuditPolicy"
  # TODO: Add specific check parameters
  # Key = ""
  # Expected = ""
  # Operator = "Equals"
  CISReference = "https://www.cisecurity.org/benchmark/microsoft_windows_server"
  Remediation = "Refer to official CIS Microsoft Windows Server 2025 Benchmark documentation for detailed remediation steps."
}

$Global:Rules += @{
  Id = "17.6.3"
  Title = "Ensure 'Audit Other Object Access Events' is set to"
  Section = "Section 17"
  Profile = "Level1"
  Type = "AuditPolicy"
  # TODO: Add specific check parameters
  # Key = ""
  # Expected = ""
  # Operator = "Equals"
  CISReference = "https://www.cisecurity.org/benchmark/microsoft_windows_server"
  Remediation = "Refer to official CIS Microsoft Windows Server 2025 Benchmark documentation for detailed remediation steps."
}

$Global:Rules += @{
  Id = "17.6.4"
  Title = "Ensure 'Audit Removable Storage' is set to 'Success"
  Section = "Section 17"
  Profile = "Level1"
  Type = "AuditPolicy"
  # TODO: Add specific check parameters
  # Key = ""
  # Expected = ""
  # Operator = "Equals"
  CISReference = "https://www.cisecurity.org/benchmark/microsoft_windows_server"
  Remediation = "Refer to official CIS Microsoft Windows Server 2025 Benchmark documentation for detailed remediation steps."
}

$Global:Rules += @{
  Id = "17.7.1"
  Title = "Ensure 'Audit Audit Policy Change' is set to include"
  Section = "Section 17"
  Profile = "Level1"
  Type = "AuditPolicy"
  # TODO: Add specific check parameters
  # Key = ""
  # Expected = ""
  # Operator = "Equals"
  CISReference = "https://www.cisecurity.org/benchmark/microsoft_windows_server"
  Remediation = "Refer to official CIS Microsoft Windows Server 2025 Benchmark documentation for detailed remediation steps."
}

$Global:Rules += @{
  Id = "17.7.2"
  Title = "Ensure 'Audit Authentication Policy Change' is set to"
  Section = "Section 17"
  Profile = "Level1"
  Type = "AuditPolicy"
  # TODO: Add specific check parameters
  # Key = ""
  # Expected = ""
  # Operator = "Equals"
  CISReference = "https://www.cisecurity.org/benchmark/microsoft_windows_server"
  Remediation = "Refer to official CIS Microsoft Windows Server 2025 Benchmark documentation for detailed remediation steps."
}

$Global:Rules += @{
  Id = "17.7.3"
  Title = "Ensure 'Audit Authorization Policy Change' is set to"
  Section = "Section 17"
  Profile = "Level1"
  Type = "AuditPolicy"
  # TODO: Add specific check parameters
  # Key = ""
  # Expected = ""
  # Operator = "Equals"
  CISReference = "https://www.cisecurity.org/benchmark/microsoft_windows_server"
  Remediation = "Refer to official CIS Microsoft Windows Server 2025 Benchmark documentation for detailed remediation steps."
}

$Global:Rules += @{
  Id = "17.7.4"
  Title = "Ensure 'Audit MPSSVC Rule-Level Policy Change' is"
  Section = "Section 17"
  Profile = "Level1"
  Type = "AuditPolicy"
  # TODO: Add specific check parameters
  # Key = ""
  # Expected = ""
  # Operator = "Equals"
  CISReference = "https://www.cisecurity.org/benchmark/microsoft_windows_server"
  Remediation = "Refer to official CIS Microsoft Windows Server 2025 Benchmark documentation for detailed remediation steps."
}

$Global:Rules += @{
  Id = "17.7.5"
  Title = "Ensure 'Audit Other Policy Change Events' is set to"
  Section = "Section 17"
  Profile = "Level1"
  Type = "AuditPolicy"
  # TODO: Add specific check parameters
  # Key = ""
  # Expected = ""
  # Operator = "Equals"
  CISReference = "https://www.cisecurity.org/benchmark/microsoft_windows_server"
  Remediation = "Refer to official CIS Microsoft Windows Server 2025 Benchmark documentation for detailed remediation steps."
}

$Global:Rules += @{
  Id = "17.8.1"
  Title = "Ensure 'Audit Sensitive Privilege Use' is set to"
  Section = "Section 17"
  Profile = "Level1"
  Type = "AuditPolicy"
  # TODO: Add specific check parameters
  # Key = ""
  # Expected = ""
  # Operator = "Equals"
  CISReference = "https://www.cisecurity.org/benchmark/microsoft_windows_server"
  Remediation = "Refer to official CIS Microsoft Windows Server 2025 Benchmark documentation for detailed remediation steps."
}

$Global:Rules += @{
  Id = "17.9.1"
  Title = "Ensure 'Audit IPsec Driver' is set to 'Success and"
  Section = "Section 17"
  Profile = "Level1"
  Type = "AuditPolicy"
  # TODO: Add specific check parameters
  # Key = ""
  # Expected = ""
  # Operator = "Equals"
  CISReference = "https://www.cisecurity.org/benchmark/microsoft_windows_server"
  Remediation = "Refer to official CIS Microsoft Windows Server 2025 Benchmark documentation for detailed remediation steps."
}

$Global:Rules += @{
  Id = "17.9.2"
  Title = "Ensure 'Audit Other System Events' is set to 'Success"
  Section = "Section 17"
  Profile = "Level1"
  Type = "AuditPolicy"
  # TODO: Add specific check parameters
  # Key = ""
  # Expected = ""
  # Operator = "Equals"
  CISReference = "https://www.cisecurity.org/benchmark/microsoft_windows_server"
  Remediation = "Refer to official CIS Microsoft Windows Server 2025 Benchmark documentation for detailed remediation steps."
}

$Global:Rules += @{
  Id = "17.9.3"
  Title = "Ensure 'Audit Security State Change' is set to include"
  Section = "Section 17"
  Profile = "Level1"
  Type = "AuditPolicy"
  # TODO: Add specific check parameters
  # Key = ""
  # Expected = ""
  # Operator = "Equals"
  CISReference = "https://www.cisecurity.org/benchmark/microsoft_windows_server"
  Remediation = "Refer to official CIS Microsoft Windows Server 2025 Benchmark documentation for detailed remediation steps."
}

$Global:Rules += @{
  Id = "17.9.4"
  Title = "Ensure 'Audit Security System Extension' is set to"
  Section = "Section 17"
  Profile = "Level1"
  Type = "AuditPolicy"
  # TODO: Add specific check parameters
  # Key = ""
  # Expected = ""
  # Operator = "Equals"
  CISReference = "https://www.cisecurity.org/benchmark/microsoft_windows_server"
  Remediation = "Refer to official CIS Microsoft Windows Server 2025 Benchmark documentation for detailed remediation steps."
}

$Global:Rules += @{
  Id = "17.9.5"
  Title = "Ensure 'Audit System Integrity' is set to 'Success and"
  Section = "Section 17"
  Profile = "Level1"
  Type = "AuditPolicy"
  # TODO: Add specific check parameters
  # Key = ""
  # Expected = ""
  # Operator = "Equals"
  CISReference = "https://www.cisecurity.org/benchmark/microsoft_windows_server"
  Remediation = "Refer to official CIS Microsoft Windows Server 2025 Benchmark documentation for detailed remediation steps."
}
