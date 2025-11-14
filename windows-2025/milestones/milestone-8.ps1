# Sections 8-16: Network and Security Policies (Windows Server 2025)
$Global:Rules += @(
  # Section 8: Wired Network (IEEE 802.3) Policies
  @{ Id='8.1'; Title='(L2) Configure IEEE 802.3 wired network policies'; Section='8 Wired Network'; Profile='Level2'; Type='Manual'; Expected='Configured per organizational requirements'; Evidence='Check Group Policy'; Description='Configures wired network authentication'; Impact='Improves network security'; Remediation='Configure 802.3 policies' },
  
  # Section 10: Network List Manager Policies
  @{ Id='10.1'; Title='(L1) Configure Network List Manager policies'; Section='10 Network List Manager'; Profile='Level1'; Type='Registry'; Key='HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkListManager'; ValueName='AllowedNetworkTypes'; Expected=1; Description='Controls network identification'; Impact='Improves network security'; Remediation='Configure network list policies' },
  
  # Section 11: Wireless Network (IEEE 802.11) Policies
  @{ Id='11.1'; Title='(L2) Configure IEEE 802.11 wireless network policies'; Section='11 Wireless Network'; Profile='Level2'; Type='Manual'; Expected='Configured per organizational requirements'; Evidence='Check Group Policy'; Description='Configures wireless network security'; Impact='Improves wireless security'; Remediation='Configure 802.11 policies' },
  
  # Section 12: Public Key Policies
  @{ Id='12.1'; Title='(L1) Configure Certificate Services Client - Auto-Enrollment'; Section='12 Public Key Policies'; Profile='Level1'; Type='Manual'; Expected='Enabled for computer certificates'; Evidence='Check Group Policy'; Description='Configures certificate auto-enrollment'; Impact='Improves PKI management'; Remediation='Configure auto-enrollment' },
  @{ Id='12.2'; Title='(L1) Configure Certificate Services Client - Certificate Enrollment Policy'; Section='12 Public Key Policies'; Profile='Level1'; Type='Manual'; Expected='Configured per organizational requirements'; Evidence='Check Group Policy'; Description='Configures certificate enrollment'; Impact='Improves PKI security'; Remediation='Configure enrollment policy' },
  
  # Section 13: Software Restriction Policies
  @{ Id='13.1'; Title='(L1) Configure Software Restriction Policies'; Section='13 Software Restriction Policies'; Profile='Level1'; Type='Manual'; Expected='Configured to restrict unauthorized software'; Evidence='Check Group Policy'; Description='Restricts software execution'; Impact='Prevents malware execution'; Remediation='Configure software restrictions' },
  
  # Section 14: Network Access Protection NAP Client Configuration
  @{ Id='14.1'; Title='(L2) Configure NAP Client Configuration'; Section='14 NAP Client Configuration'; Profile='Level2'; Type='Manual'; Expected='Configured per organizational requirements'; Evidence='Check Group Policy'; Description='Configures NAP client'; Impact='Improves network compliance'; Remediation='Configure NAP client' },
  
  # Section 15: Application Control Policies
  @{ Id='15.1'; Title='(L1) Configure AppLocker policies'; Section='15 Application Control Policies'; Profile='Level1'; Type='Manual'; Expected='Configured to allow only authorized applications'; Evidence='Check Group Policy'; Description='Controls application execution'; Impact='Prevents unauthorized software'; Remediation='Configure AppLocker policies' },
  
  # Section 16: IP Security Policies
  @{ Id='16.1'; Title='(L2) Configure IPSec policies'; Section='16 IP Security Policies'; Profile='Level2'; Type='Manual'; Expected='Configured per organizational requirements'; Evidence='Check Group Policy'; Description='Configures IPSec encryption'; Impact='Protects network communications'; Remediation='Configure IPSec policies' }
)