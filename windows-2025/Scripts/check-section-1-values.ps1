# Check Current Values for Section 1.x.x Controls
# This script shows actual current values on the system

Write-Host "`n=== SECTION 1: Account Policies ===" -ForegroundColor Cyan
Write-Host ""

# Export security policy
$tempFile = "$env:TEMP\secpol_check.inf"
secedit /export /cfg $tempFile /quiet | Out-Null

if (Test-Path $tempFile) {
    $content = Get-Content $tempFile
    
    Write-Host "--- 1.1 Password Policy ---" -ForegroundColor Yellow
    Write-Host ""
    
    # 1.1.1 - Enforce password history
    $val = ($content | Select-String "PasswordHistorySize").ToString().Split('=')[1].Trim()
    Write-Host "1.1.1 - Enforce password history: $val (Expected: 24 or more)" -ForegroundColor $(if([int]$val -ge 24){"Green"}else{"Red"})
    
    # 1.1.2 - Maximum password age
    $val = ($content | Select-String "MaximumPasswordAge").ToString().Split('=')[1].Trim()
    Write-Host "1.1.2 - Maximum password age: $val days (Expected: 1-365)" -ForegroundColor $(if([int]$val -ge 1 -and [int]$val -le 365){"Green"}else{"Red"})
    
    # 1.1.3 - Minimum password age
    $val = ($content | Select-String "MinimumPasswordAge").ToString().Split('=')[1].Trim()
    Write-Host "1.1.3 - Minimum password age: $val days (Expected: 1 or more)" -ForegroundColor $(if([int]$val -ge 1){"Green"}else{"Red"})
    
    # 1.1.4 - Minimum password length
    $val = ($content | Select-String "MinimumPasswordLength").ToString().Split('=')[1].Trim()
    Write-Host "1.1.4 - Minimum password length: $val characters (Expected: 14 or more)" -ForegroundColor $(if([int]$val -ge 14){"Green"}else{"Red"})
    
    # 1.1.5 - Password complexity
    $val = ($content | Select-String "PasswordComplexity").ToString().Split('=')[1].Trim()
    Write-Host "1.1.5 - Password complexity: $val (Expected: 1=Enabled)" -ForegroundColor $(if($val -eq "1"){"Green"}else{"Red"})
    
    # 1.1.6 - Relax minimum password length (Registry)
    $regVal = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SAM" -Name "RelaxMinimumPasswordLengthLimits" -ErrorAction SilentlyContinue
    if ($regVal) {
        Write-Host "1.1.6 - Relax minimum password length: $($regVal.RelaxMinimumPasswordLengthLimits) (Expected: 1=Enabled)" -ForegroundColor $(if($regVal.RelaxMinimumPasswordLengthLimits -eq 1){"Green"}else{"Red"})
    } else {
        Write-Host "1.1.6 - Relax minimum password length: NOT SET (Expected: 1=Enabled)" -ForegroundColor Red
    }
    
    # 1.1.7 - Store passwords using reversible encryption
    $val = ($content | Select-String "ClearTextPassword").ToString().Split('=')[1].Trim()
    Write-Host "1.1.7 - Store passwords reversible encryption: $val (Expected: 0=Disabled)" -ForegroundColor $(if($val -eq "0"){"Green"}else{"Red"})
    
    Write-Host ""
    Write-Host "--- 1.2 Account Lockout Policy ---" -ForegroundColor Yellow
    Write-Host ""
    
    # 1.2.1 - Account lockout duration
    $val = ($content | Select-String "LockoutDuration").ToString().Split('=')[1].Trim()
    Write-Host "1.2.1 - Account lockout duration: $val minutes (Expected: 15 or more)" -ForegroundColor $(if([int]$val -ge 15){"Green"}else{"Red"})
    
    # 1.2.2 - Account lockout threshold
    $val = ($content | Select-String "LockoutBadCount").ToString().Split('=')[1].Trim()
    Write-Host "1.2.2 - Account lockout threshold: $val attempts (Expected: 1-5)" -ForegroundColor $(if([int]$val -ge 1 -and [int]$val -le 5){"Green"}else{"Red"})
    
    # 1.2.3 - Allow Administrator account lockout (Manual check)
    Write-Host "1.2.3 - Allow Administrator account lockout: MANUAL CHECK REQUIRED" -ForegroundColor Yellow
    
    # 1.2.4 - Reset account lockout counter
    $val = ($content | Select-String "ResetLockoutCount").ToString().Split('=')[1].Trim()
    Write-Host "1.2.4 - Reset account lockout counter: $val minutes (Expected: 15 or more)" -ForegroundColor $(if([int]$val -ge 15){"Green"}else{"Red"})
    
    Remove-Item $tempFile -Force
} else {
    Write-Host "ERROR: Could not export security policy" -ForegroundColor Red
}

Write-Host ""
Write-Host "=== END OF SECTION 1 ===" -ForegroundColor Cyan
Write-Host ""
