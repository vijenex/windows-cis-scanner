<#
.SYNOPSIS
  Automated Evidence Collection for CIS Scanner Failed Controls
  
.DESCRIPTION
  Reads the scanner CSV output and automatically collects evidence for all FAIL controls.
  Generates an HTML evidence report with actual system values for audit purposes.
  
.PARAMETER CSVPath
  Path to the scanner CSV results file
  
.PARAMETER OutputPath
  Path where the evidence report will be saved (default: same folder as CSV)
  
.EXAMPLE
  .\Collect-FailureEvidence.ps1 -CSVPath ".\reports\vijenex-cis-results.csv"
#>

param(
  [Parameter(Mandatory=$true)]
  [string]$CSVPath,
  
  [string]$OutputPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Continue'

# Check admin rights
$id = [Security.Principal.WindowsIdentity]::GetCurrent()
$pr = New-Object Security.Principal.WindowsPrincipal($id)
if (-not $pr.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  throw "Run this script as Administrator"
}

# Validate CSV exists
if (-not (Test-Path $CSVPath)) {
  throw "CSV file not found: $CSVPath"
}

# Set default output path
if (-not $OutputPath) {
  $csvFolder = Split-Path $CSVPath
  $OutputPath = Join-Path $csvFolder "vijenex-evidence-report.html"
}

Write-Host "`n==============================================================" -ForegroundColor Cyan
Write-Host "         CIS SCANNER - EVIDENCE COLLECTION TOOL              " -ForegroundColor Cyan
Write-Host "==============================================================" -ForegroundColor Cyan
Write-Host "Reading: $CSVPath" -ForegroundColor White
Write-Host ""

# Read CSV
$results = Import-Csv -Path $CSVPath
$failedControls = $results | Where-Object { $_.Status -eq 'FAIL' }

Write-Host "Total Controls: $($results.Count)" -ForegroundColor White
Write-Host "Failed Controls: $($failedControls.Count)" -ForegroundColor Red
Write-Host ""
Write-Host "Collecting evidence for $($failedControls.Count) failed controls..." -ForegroundColor Yellow
Write-Host ""

# Export security policy once
Write-Host "[*] Exporting security policy..." -ForegroundColor Cyan
$secpolPath = "$env:TEMP\secpol-evidence.cfg"
secedit /export /cfg $secpolPath /quiet | Out-Null

# Evidence collection functions
function Get-SecEditValue {
  param([string]$Section, [string]$Key)
  try {
    $content = Get-Content $secpolPath -ErrorAction Stop
    $inSection = $false
    foreach ($line in $content) {
      if ($line -match "^\[$Section\]") {
        $inSection = $true
        continue
      }
      if ($line -match "^\[") {
        $inSection = $false
      }
      if ($inSection -and $line -match "^$Key\s*=\s*(.+)$") {
        return $Matches[1].Trim()
      }
    }
    return "<not configured>"
  } catch {
    return "<error: $($_.Exception.Message)>"
  }
}

function Get-AuditPolValue {
  param([string]$Subcategory)
  try {
    $output = auditpol /get /subcategory:"$Subcategory" 2>&1
    if ($output -match 'Success and Failure') {
      return "Success and Failure"
    } elseif ($output -match '\s+Success\s*$') {
      return "Success"
    } elseif ($output -match '\s+Failure\s*$') {
      return "Failure"
    } elseif ($output -match 'No Auditing') {
      return "No Auditing"
    } else {
      return "<not configured>"
    }
  } catch {
    return "<error: $($_.Exception.Message)>"
  }
}

function Get-RegistryValue {
  param([string]$Path, [string]$Name)
  try {
    if (Test-Path $Path) {
      $val = Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue
      if ($null -ne $val) {
        return $val.$Name
      } else {
        return "<value not set>"
      }
    } else {
      return "<key not found>"
    }
  } catch {
    return "<error: $($_.Exception.Message)>"
  }
}

# Collect evidence for each failed control
$evidenceData = @()
$counter = 0

foreach ($control in $failedControls) {
  $counter++
  Write-Host "[$counter/$($failedControls.Count)] Collecting evidence for $($control.Id)..." -ForegroundColor Gray
  
  $evidence = [PSCustomObject]@{
    Id = $control.Id
    Title = $control.Title
    Section = $control.Section
    ActualValue = ""
    VerificationCommand = ""
    Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
  }
  
  # Determine control type and collect evidence
  if ($control.Title -match 'password history|password age|password length|password complexity|reversible encryption') {
    # Password policies
    if ($control.Title -match 'password history') {
      $evidence.ActualValue = Get-SecEditValue -Section "System Access" -Name "PasswordHistorySize"
      $evidence.VerificationCommand = "net accounts | findstr /i 'password history'"
    } elseif ($control.Title -match 'Maximum password age') {
      $evidence.ActualValue = Get-SecEditValue -Section "System Access" -Name "MaximumPasswordAge"
      $evidence.VerificationCommand = "net accounts | findstr /i 'Maximum password age'"
    } elseif ($control.Title -match 'Minimum password age') {
      $evidence.ActualValue = Get-SecEditValue -Section "System Access" -Name "MinimumPasswordAge"
      $evidence.VerificationCommand = "net accounts | findstr /i 'Minimum password age'"
    } elseif ($control.Title -match 'Minimum password length') {
      $evidence.ActualValue = Get-SecEditValue -Section "System Access" -Name "MinimumPasswordLength"
      $evidence.VerificationCommand = "net accounts | findstr /i 'Minimum password length'"
    } elseif ($control.Title -match 'password complexity') {
      $evidence.ActualValue = Get-SecEditValue -Section "System Access" -Name "PasswordComplexity"
      $evidence.VerificationCommand = "secedit /export /cfg temp.cfg && findstr PasswordComplexity temp.cfg"
    } elseif ($control.Title -match 'reversible encryption') {
      $evidence.ActualValue = Get-SecEditValue -Section "System Access" -Name "ClearTextPassword"
      $evidence.VerificationCommand = "secedit /export /cfg temp.cfg && findstr ClearTextPassword temp.cfg"
    }
  } elseif ($control.Title -match 'lockout duration|lockout threshold|lockout observation') {
    # Account lockout policies
    if ($control.Title -match 'lockout duration') {
      $evidence.ActualValue = Get-SecEditValue -Section "System Access" -Name "LockoutDuration"
      $evidence.VerificationCommand = "net accounts | findstr /i 'Lockout duration'"
    } elseif ($control.Title -match 'lockout threshold') {
      $evidence.ActualValue = Get-SecEditValue -Section "System Access" -Name "LockoutBadCount"
      $evidence.VerificationCommand = "net accounts | findstr /i 'Lockout threshold'"
    } elseif ($control.Title -match 'lockout observation|Reset account lockout') {
      $evidence.ActualValue = Get-SecEditValue -Section "System Access" -Name "ResetLockoutCount"
      $evidence.VerificationCommand = "net accounts | findstr /i 'Lockout observation'"
    }
  } elseif ($control.Title -match 'Audit') {
    # Audit policies - extract subcategory name
    if ($control.Title -match "'([^']+)'") {
      $subcategory = $Matches[1]
      $evidence.ActualValue = Get-AuditPolValue -Subcategory $subcategory
      $evidence.VerificationCommand = "auditpol /get /subcategory:`"$subcategory`""
    } else {
      $evidence.ActualValue = "<unable to determine subcategory>"
      $evidence.VerificationCommand = "auditpol /get /category:*"
    }
  } elseif ($control.Id -match '^2\.2\.') {
    # User rights assignments
    $rightName = ""
    if ($control.Title -match 'Access Credential Manager') { $rightName = "SeTrustedCredManAccessPrivilege" }
    elseif ($control.Title -match 'Access this computer from') { $rightName = "SeNetworkLogonRight" }
    elseif ($control.Title -match 'Act as part of') { $rightName = "SeTcbPrivilege" }
    elseif ($control.Title -match 'Add workstations') { $rightName = "SeMachineAccountPrivilege" }
    elseif ($control.Title -match 'Allow log on locally') { $rightName = "SeInteractiveLogonRight" }
    elseif ($control.Title -match 'Allow log on through Remote Desktop') { $rightName = "SeRemoteInteractiveLogonRight" }
    elseif ($control.Title -match 'Back up files') { $rightName = "SeBackupPrivilege" }
    elseif ($control.Title -match 'Change the system time') { $rightName = "SeSystemtimePrivilege" }
    elseif ($control.Title -match 'Create a pagefile') { $rightName = "SeCreatePagefilePrivilege" }
    elseif ($control.Title -match 'Create a token object') { $rightName = "SeCreateTokenPrivilege" }
    elseif ($control.Title -match 'Create global objects') { $rightName = "SeCreateGlobalPrivilege" }
    elseif ($control.Title -match 'Create permanent shared') { $rightName = "SeCreatePermanentPrivilege" }
    elseif ($control.Title -match 'Create symbolic links') { $rightName = "SeCreateSymbolicLinkPrivilege" }
    elseif ($control.Title -match 'Debug programs') { $rightName = "SeDebugPrivilege" }
    elseif ($control.Title -match 'Deny access to this computer from the network') { $rightName = "SeDenyNetworkLogonRight" }
    elseif ($control.Title -match 'Deny log on as a batch') { $rightName = "SeDenyBatchLogonRight" }
    elseif ($control.Title -match 'Deny log on as a service') { $rightName = "SeDenyServiceLogonRight" }
    elseif ($control.Title -match 'Deny log on locally') { $rightName = "SeDenyInteractiveLogonRight" }
    elseif ($control.Title -match 'Deny log on through Remote Desktop') { $rightName = "SeDenyRemoteInteractiveLogonRight" }
    
    if ($rightName) {
      $evidence.ActualValue = Get-SecEditValue -Section "Privilege Rights" -Name $rightName
      $evidence.VerificationCommand = "secedit /export /cfg temp.cfg && findstr $rightName temp.cfg"
    } else {
      $evidence.ActualValue = "<unable to determine privilege right>"
      $evidence.VerificationCommand = "secedit /export /cfg temp.cfg"
    }
  } elseif ($control.Id -match '^2\.3\.') {
    # Security options - registry based
    $evidence.ActualValue = "<registry check required - see remediation>"
    $evidence.VerificationCommand = "See CIS Benchmark for specific registry path"
  } else {
    $evidence.ActualValue = "<manual verification required>"
    $evidence.VerificationCommand = "See CIS Benchmark documentation"
  }
  
  $evidenceData += $evidence
}

Write-Host ""
Write-Host "[*] Generating HTML evidence report..." -ForegroundColor Cyan

# Generate HTML report
$htmlRows = $evidenceData | ForEach-Object {
  $valueColor = if ($_.ActualValue -match '<not configured>|<error') { '#ff6b6b' } else { '#333' }
  @"
<tr>
  <td><code>$($_.Id)</code></td>
  <td>$($_.Title)</td>
  <td>$($_.Section)</td>
  <td style="color:$valueColor;font-weight:bold">$($_.ActualValue)</td>
  <td><code style="font-size:11px">$($_.VerificationCommand)</code></td>
  <td style="font-size:11px">$($_.Timestamp)</td>
</tr>
"@
}

$systemInfo = @{
  ComputerName = $env:COMPUTERNAME
  Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
  TotalFailed = $failedControls.Count
}

$htmlContent = @"
<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8"/>
  <title>CIS Scanner - Evidence Report</title>
  <style>
    body { font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }
    h1 { color: #2c3e50; border-bottom: 3px solid #3498db; padding-bottom: 10px; }
    .info-box { background: white; padding: 20px; border-radius: 5px; margin: 20px 0; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
    .info-box h2 { margin-top: 0; color: #2c3e50; }
    .info-box p { margin: 8px 0; }
    .warning { background: #fff3cd; border-left: 4px solid #ffc107; padding: 15px; margin: 20px 0; }
    table { border-collapse: collapse; width: 100%; background: white; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
    th, td { border: 1px solid #ddd; padding: 12px; text-align: left; }
    th { background: #3498db; color: white; font-weight: bold; position: sticky; top: 0; }
    tr:nth-child(even) { background: #f9f9f9; }
    tr:hover { background: #e8f4f8; }
    code { background: #f4f4f4; padding: 2px 6px; border-radius: 3px; font-family: 'Courier New', monospace; }
    .footer { margin-top: 30px; padding: 20px; text-align: center; color: #666; font-size: 12px; }
  </style>
</head>
<body>
  <h1>CIS Scanner - Evidence Collection Report</h1>
  
  <div class="info-box">
    <h2>System Information</h2>
    <p><strong>Computer Name:</strong> $($systemInfo.ComputerName)</p>
    <p><strong>Evidence Collection Date:</strong> $($systemInfo.Timestamp)</p>
    <p><strong>Total Failed Controls:</strong> $($systemInfo.TotalFailed)</p>
  </div>
  
  <div class="warning">
    <strong>Purpose:</strong> This report provides automated evidence collection for all failed CIS controls. 
    The "Actual Value" column shows what the scanner detected on the system at scan time. 
    Use the "Verification Command" to manually verify these values if needed.
  </div>
  
  <h2>Failed Controls Evidence</h2>
  <table>
    <thead>
      <tr>
        <th>Control ID</th>
        <th>Control Title</th>
        <th>Section</th>
        <th>Actual Value</th>
        <th>Verification Command</th>
        <th>Timestamp</th>
      </tr>
    </thead>
    <tbody>
      $($htmlRows -join "`n")
    </tbody>
  </table>
  
  <div class="footer">
    <p>Evidence collected automatically by Vijenex CIS Scanner Evidence Collection Tool</p>
    <p>This is an audit-only report. No system changes were made.</p>
  </div>
</body>
</html>
"@

Set-Content -Path $OutputPath -Value $htmlContent -Encoding UTF8

# Cleanup
if (Test-Path $secpolPath) {
  Remove-Item $secpolPath -Force -ErrorAction SilentlyContinue
}

Write-Host ""
Write-Host "==============================================================" -ForegroundColor Green
Write-Host "         EVIDENCE COLLECTION COMPLETED                       " -ForegroundColor Green
Write-Host "==============================================================" -ForegroundColor Green
Write-Host "Evidence Report: $OutputPath" -ForegroundColor White
Write-Host "Total Failed Controls: $($failedControls.Count)" -ForegroundColor Yellow
Write-Host ""
Write-Host "Open the HTML file in a browser to view the evidence report." -ForegroundColor Cyan
Write-Host "==============================================================" -ForegroundColor Green
Write-Host ""
