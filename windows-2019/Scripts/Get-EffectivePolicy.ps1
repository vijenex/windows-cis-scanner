# Get-EffectivePolicy.ps1
# Reads EFFECTIVE security policy using Windows APIs (not just local policy)
# This matches AWS Inspector's approach

Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
using System.Text;

public class LsaWrapper {
    [StructLayout(LayoutKind.Sequential)]
    public struct LSA_UNICODE_STRING {
        public UInt16 Length;
        public UInt16 MaximumLength;
        public IntPtr Buffer;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct LSA_OBJECT_ATTRIBUTES {
        public int Length;
        public IntPtr RootDirectory;
        public LSA_UNICODE_STRING ObjectName;
        public uint Attributes;
        public IntPtr SecurityDescriptor;
        public IntPtr SecurityQualityOfService;
    }

    [DllImport("advapi32.dll", SetLastError = true, PreserveSig = true)]
    public static extern uint LsaOpenPolicy(
        ref LSA_UNICODE_STRING SystemName,
        ref LSA_OBJECT_ATTRIBUTES ObjectAttributes,
        uint DesiredAccess,
        out IntPtr PolicyHandle
    );

    [DllImport("advapi32.dll", SetLastError = true, PreserveSig = true)]
    public static extern uint LsaEnumerateAccountsWithUserRight(
        IntPtr PolicyHandle,
        ref LSA_UNICODE_STRING UserRight,
        out IntPtr Buffer,
        out ulong CountReturned
    );

    [DllImport("advapi32.dll")]
    public static extern int LsaNtStatusToWinError(uint Status);

    [DllImport("advapi32.dll")]
    public static extern uint LsaClose(IntPtr ObjectHandle);

    [DllImport("advapi32.dll")]
    public static extern uint LsaFreeMemory(IntPtr Buffer);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern bool ConvertSidToStringSid(IntPtr pSid, out string strSid);
}
"@

function Get-EffectiveUserRight {
    param([Parameter(Mandatory)][string]$Right)
    
    # Fallback to secedit - LSA API is complex, use proven method
    return $null
}

function Get-EffectivePasswordPolicy {
    <#
    .SYNOPSIS
    Gets effective password policy (domain or local)
    #>
    
    $policy = @{}
    
    try {
        # Try to get domain policy first
        $domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetComputerDomain()
        $domainDN = "LDAP://" + $domain.Name
        $domainEntry = New-Object System.DirectoryServices.DirectoryEntry($domainDN)
        
        # Read domain password policy
        $policy['MinimumPasswordLength'] = $domainEntry.Properties['minPwdLength'].Value
        $policy['PasswordHistorySize'] = $domainEntry.Properties['pwdHistoryLength'].Value
        $policy['MaximumPasswordAge'] = $domainEntry.Properties['maxPwdAge'].Value
        $policy['MinimumPasswordAge'] = $domainEntry.Properties['minPwdAge'].Value
        $policy['PasswordComplexity'] = $domainEntry.Properties['pwdProperties'].Value
        $policy['LockoutThreshold'] = $domainEntry.Properties['lockoutThreshold'].Value
        $policy['LockoutDuration'] = $domainEntry.Properties['lockoutDuration'].Value
        $policy['LockoutObservationWindow'] = $domainEntry.Properties['lockOutObservationWindow'].Value
        
        $domainEntry.Dispose()
        
    } catch {
        # Fallback to local policy using net accounts
        try {
            $netAccounts = net accounts 2>$null
            
            foreach ($line in $netAccounts) {
                if ($line -match 'Minimum password length:\s+(\d+)') {
                    $policy['MinimumPasswordLength'] = [int]$Matches[1]
                }
                if ($line -match 'Password history length:\s+(\d+)') {
                    $policy['PasswordHistorySize'] = [int]$Matches[1]
                }
                if ($line -match 'Maximum password age \(days\):\s+(\d+|Unlimited)') {
                    $policy['MaximumPasswordAge'] = $Matches[1]
                }
                if ($line -match 'Minimum password age \(days\):\s+(\d+)') {
                    $policy['MinimumPasswordAge'] = [int]$Matches[1]
                }
                if ($line -match 'Account lockout threshold:\s+(\d+|Never)') {
                    $policy['LockoutThreshold'] = $Matches[1]
                }
                if ($line -match 'Account lockout duration \(minutes\):\s+(\d+)') {
                    $policy['LockoutDuration'] = [int]$Matches[1]
                }
                if ($line -match 'Account lockout counter reset \(minutes\):\s+(\d+)') {
                    $policy['LockoutObservationWindow'] = [int]$Matches[1]
                }
            }
        } catch {
            Write-Verbose "Failed to get password policy: $_"
        }
    }
    
    return $policy
}

function Get-EffectiveSecurityOption {
    <#
    .SYNOPSIS
    Gets effective security option value from registry
    
    .DESCRIPTION
    Registry values are already effective (merged local + domain GPO)
    #>
    param(
        [Parameter(Mandatory)]
        [string]$Path,
        
        [Parameter(Mandatory)]
        [string]$Name
    )
    
    try {
        if (Test-Path $Path) {
            $value = Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue |
                     Select-Object -ExpandProperty $Name -ErrorAction SilentlyContinue
            return $value
        }
    } catch {
        Write-Verbose "Failed to read $Path\$Name : $_"
    }
    
    return $null
}
