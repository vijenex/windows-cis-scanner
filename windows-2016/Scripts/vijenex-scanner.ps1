<#
  Windows Server 2016 CIS Scanner v2.0 - Bug-Fixed Version
  Based on lessons learned from 2025 implementation
  
  Key Improvements:
  - DC/MS detection and filtering
  - Default-enabled controls handling
  - No false positives for section 2.3.x
  - Client-only controls excluded
  - Manual controls marked as MANUAL
  - Full control IDs (no shorthand)
#>

param(
  [string]$OutputDir,
  [string]$Profile = "Level1",
  [string[]]$Milestones,
  [string[]]$Include,
  [string[]]$Exclude
)

if (-not $OutputDir) {
  $OutputDir = Join-Path (Split-Path $PSScriptRoot) "reports"
}

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$Global:Rules = @()

# Default-enabled controls (no registry key = compliant)
$Global:DefaultEnabledControls = @{
    "1.1.6" = @{ DefaultValue = "0"; ExpectedValue = "0" }  # Reversible encryption disabled
    "2.3.1.1" = @{ DefaultValue = "0"; ExpectedValue = "0" }  # Guest disabled
    "2.3.1.2" = @{ DefaultValue = "1"; ExpectedValue = "1" }  # Blank password limit
    "2.3.2.1" = @{ DefaultValue = "1"; ExpectedValue = "1" }  # Audit subcategory
    "2.3.4.1" = @{ DefaultValue = "1"; ExpectedValue = "1" }  # Printer drivers
    "2.3.6.1" = @{ DefaultValue = "1"; ExpectedValue = "1" }  # Encrypt/sign
    "2.3.6.2" = @{ DefaultValue = "1"; ExpectedValue = "1" }  # Encrypt
    "2.3.6.3" = @{ DefaultValue = "1"; ExpectedValue = "1" }  # Sign
    "2.3.6.4" = @{ DefaultValue = "0"; ExpectedValue = "0" }  # Disable pwd change
    "2.3.6.6" = @{ DefaultValue = "1"; ExpectedValue = "1" }  # Strong key
    "2.3.7.1" = @{ DefaultValue = "0"; ExpectedValue = "0" }  # CTRL+ALT+DEL
    "2.3.8.2" = @{ DefaultValue = "1"; ExpectedValue = "1" }  # Sign if agrees
    "2.3.8.3" = @{ DefaultValue = "0"; ExpectedValue = "0" }  # No unencrypted
    "2.3.9.1" = @{ DefaultValue = "15"; ExpectedValue = "15" } # Idle time
    "2.3.9.4" = @{ DefaultValue = "1"; ExpectedValue = "1" }  # Disconnect
    "2.3.10.1" = @{ DefaultValue = "0"; ExpectedValue = "0" } # No anon SID
    "2.3.10.2" = @{ DefaultValue = "1"; ExpectedValue = "1" } # No anon SAM
    "2.3.10.5" = @{ DefaultValue = "0"; ExpectedValue = "0" } # No Everyone=anon
    "2.3.10.10" = @{ DefaultValue = "1"; ExpectedValue = "1" } # Restrict anon
    "2.3.10.13" = @{ DefaultValue = "1"; ExpectedValue = "1" } # Classic model
    "2.3.15.1" = @{ DefaultValue = "1"; ExpectedValue = "1" } # Case insensitive
    "2.3.15.2" = @{ DefaultValue = "1"; ExpectedValue = "1" } # Strengthen perms
}

function Assert-Admin {
  $id = [Security.Principal.WindowsIdentity]::GetCurrent()
  $pr = New-Object Security.Principal.WindowsPrincipal($id)
  if (-not $pr.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Run this script as Administrator."
  }
}

function Get-OSInfo { 
  $os=Get-CimInstance Win32_OperatingSystem
  $cs=Get-CimInstance Win32_ComputerSystem
  $net=Get-CimInstance Win32_NetworkAdapterConfiguration | Where-Object {$_.IPEnabled -eq $true} | Select-Object -First 1
  
  $domainRole = $cs.DomainRole
  $isDC = $domainRole -ge 4
  
  $osType = switch ($domainRole) {
    0 { "$($os.Caption) (Standalone Workstation)" }
    1 { "$($os.Caption) (Member Workstation)" }
    2 { "$($os.Caption) (Standalone Server)" }
    3 { "$($os.Caption) (Member Server)" }
    4 { "$($os.Caption) (Backup Domain Controller)" }
    5 { "$($os.Caption) (Primary Domain Controller)" }
    default { "$($os.Caption) (Unknown Role)" }
  }
  
  [pscustomobject]@{
    Caption=$osType
    Version=$os.Version
    BuildNumber=[int]$os.BuildNumber
    ComputerName=$env:COMPUTERNAME
    MachineID=$cs.Name
    IPAddress=if($net.IPAddress){$net.IPAddress[0]}else{'N/A'}
    ScanDate=Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    IsDC=$isDC
  } 
}

function Export-SecEdit { 
  try {
    $tmp = Join-Path $env:TEMP ("secpol-" + [guid]::NewGuid().Guid + ".inf")
    $result = Start-Process -FilePath "secedit.exe" -ArgumentList "/export", "/cfg", "`"$tmp`"" -Wait -PassThru -NoNewWindow
    if ($result.ExitCode -ne 0 -or -not (Test-Path $tmp)) {
      throw "secedit export failed"
    }
    return $tmp
  } catch {
    Write-Warning "Failed to export security policy: $($_.Exception.Message)"
    return $null
  }
}

function Parse-InfFile([string]$Path){
  $map=@{}
  if ([string]::IsNullOrWhiteSpace($Path) -or -not (Test-Path $Path)) { return $map }
  $section=''
  foreach($line in Get-Content -LiteralPath $Path){
    $t=$line.Trim()
    if (-not $t -or $t.StartsWith(';')){continue}
    if ($t.StartsWith('[')){
      $section=$t.Trim('[',']')
      if (-not $map.ContainsKey($section)){$map[$section]=@{}}
      continue
    }
    $kv=$t -split '=',2
    if ($kv.Count -eq 2){ 
      $map[$section][$kv[0].Trim()] = $kv[1].Trim() 
    }
  }
  $map
}

function Convert-SIDToName {
  param([string]$SID)
  try {
    $objSID = New-Object System.Security.Principal.SecurityIdentifier($SID)
    $objUser = $objSID.Translate([System.Security.Principal.NTAccount])
    return $objUser.Value
  } catch {
    return $SID
  }
}

function Evaluate-Rule([hashtable]$Rule,[hashtable]$Context){
  $result=[pscustomobject]@{
    Id=$Rule.Id
    Title=$Rule.Title
    Section=$Rule.Section
    Status=''
    Passed=$false
    ActualValue=''
  }
  
  # Handle Manual controls
  if ($Rule.Type -eq 'Manual') {
    $result.Status = 'MANUAL'
    $result.ActualValue = 'Manual verification required'
    return $result
  }
  
  # Handle default-enabled controls
  if ($Global:DefaultEnabledControls.ContainsKey($Rule.Id)) {
    $defInfo = $Global:DefaultEnabledControls[$Rule.Id]
    $valueExists = $false
    
    if ($Rule.Type -eq 'Registry') {
      $keyExists = Test-Path $Rule.Key
      if ($keyExists) {
        $val = Get-ItemProperty -Path $Rule.Key -Name $Rule.ValueName -ErrorAction SilentlyContinue | 
               Select-Object -ExpandProperty $Rule.ValueName -ErrorAction SilentlyContinue
        if ($null -ne $val) {
          $valueExists = $true
          $result.Passed = ($val -eq $Rule.Expected)
          $result.ActualValue = "$val"
        }
      }
    } elseif ($Rule.Type -eq 'SecEdit') {
      if ($Global:SecEditData.ContainsKey($Rule.SectionName) -and $Global:SecEditData[$Rule.SectionName].ContainsKey($Rule.Key)) {
        $valueExists = $true
        $val = $Global:SecEditData[$Rule.SectionName][$Rule.Key]
        $result.Passed = ($val -eq $Rule.Expected)
        $result.ActualValue = "$val"
      }
    }
    
    if (-not $valueExists) {
      # Value missing = default value in effect
      $result.Passed = ($defInfo.DefaultValue -eq $defInfo.ExpectedValue)
      $result.ActualValue = "Default (compliant)"
    }
    
    $result.Status = if ($result.Passed) { 'PASS' } else { 'FAIL' }
    return $result
  }
  
  # Normal evaluation
  try {
    switch ($Rule.Type) {
      'Registry' {
        if (Test-Path $Rule.Key) {
          $val = Get-ItemProperty -Path $Rule.Key -Name $Rule.ValueName -ErrorAction SilentlyContinue | 
                 Select-Object -ExpandProperty $Rule.ValueName -ErrorAction SilentlyContinue
          if ($null -ne $val) {
            $result.Passed = ($val -eq $Rule.Expected)
            $result.ActualValue = "$val"
          } else {
            $result.Passed = $false
            $result.ActualValue = "Value not found"
          }
        } else {
          $result.Passed = $false
          $result.ActualValue = "Key not found"
        }
      }
      'PrivRight' {
        if ($Global:SecEditData.ContainsKey('Privilege Rights') -and $Global:SecEditData['Privilege Rights'].ContainsKey($Rule.Key)) {
          $actualSIDs = $Global:SecEditData['Privilege Rights'][$Rule.Key] -split ','
          $actualNames = $actualSIDs | ForEach-Object { Convert-SIDToName $_.Trim() }
          $expectedNames = $Rule.ExpectedPrincipals
          
          if ($Rule.SetMode -eq 'Exact') {
            $result.Passed = (Compare-Object $actualNames $expectedNames | Measure-Object).Count -eq 0
          } else {
            $result.Passed = ($expectedNames | Where-Object { $actualNames -contains $_ }).Count -eq $expectedNames.Count
          }
          $result.ActualValue = ($actualNames -join ', ')
        } else {
          $result.Passed = $false
          $result.ActualValue = "Not configured"
        }
      }
      default {
        $result.Passed = $false
        $result.ActualValue = "Not implemented"
      }
    }
  } catch {
    $result.Passed = $false
    $result.ActualValue = "Error: $($_.Exception.Message)"
  }
  
  $result.Status = if ($result.Passed) { 'PASS' } else { 'FAIL' }
  $result
}

function Write-CSV([System.Collections.Generic.List[object]]$Results,[string]$OutDir,[object]$SystemInfo){
  if (-not (Test-Path $OutDir)) { New-Item -ItemType Directory -Path $OutDir | Out-Null }
  $csv = Join-Path $OutDir 'vijenex-cis-results.csv'
  $Results | Export-Csv -Path $csv -NoTypeInformation -Encoding UTF8
  Write-Host "CSV: $csv" -ForegroundColor Green
}

function Write-HTML([System.Collections.Generic.List[object]]$Results,[string]$OutDir,[object]$SystemInfo){
  $html = Join-Path $OutDir 'vijenex-cis-results.html'
  $passed = @($Results | Where-Object { $_.Passed }).Count
  $failed = @($Results | Where-Object { $_.Status -eq 'FAIL' }).Count
  $manual = @($Results | Where-Object { $_.Status -eq 'MANUAL' }).Count
  
  $htmlContent = @"
<!DOCTYPE html>
<html><head><meta charset='UTF-8'><title>CIS Audit Report</title>
<style>
body{font-family:Arial,sans-serif;margin:20px;background:#f5f5f5}
.header{background:#232f3e;color:#fff;padding:20px;border-radius:5px}
.summary{background:#fff;padding:15px;margin:20px 0;border-radius:5px;box-shadow:0 2px 4px rgba(0,0,0,0.1)}
.summary-grid{display:grid;grid-template-columns:repeat(4,1fr);gap:15px;margin-top:15px}
.stat-box{text-align:center;padding:15px;border-radius:5px}
.stat-box.total{background:#e3f2fd}
.stat-box.pass{background:#e8f5e9}
.stat-box.fail{background:#ffebee}
.stat-box.manual{background:#fff3e0}
.stat-number{font-size:32px;font-weight:bold;margin:10px 0}
.stat-label{font-size:14px;color:#666}
table{width:100%;border-collapse:collapse;background:#fff;box-shadow:0 2px 4px rgba(0,0,0,0.1)}
th{background:#232f3e;color:#fff;padding:12px;text-align:left}
td{padding:10px;border-bottom:1px solid #ddd}
tr:hover{background:#f5f5f5}
.PASS{color:#2e7d32;font-weight:bold}
.FAIL{color:#c62828;font-weight:bold}
.MANUAL{color:#f57c00;font-weight:bold}
</style></head><body>
<div class='header'>
<h1>Windows Server 2016 CIS Audit Report</h1>
<p><strong>Host:</strong> $($SystemInfo.Caption) | <strong>Computer:</strong> $($SystemInfo.ComputerName) | <strong>IP:</strong> $($SystemInfo.IPAddress)</p>
<p><strong>Scan Date:</strong> $($SystemInfo.ScanDate) | <strong>DC Mode:</strong> $($SystemInfo.IsDC)</p>
</div>
<div class='summary'>
<h2>Executive Summary</h2>
<div class='summary-grid'>
<div class='stat-box total'><div class='stat-number'>$($Results.Count)</div><div class='stat-label'>Total Controls</div></div>
<div class='stat-box pass'><div class='stat-number'>$passed</div><div class='stat-label'>Passed</div></div>
<div class='stat-box fail'><div class='stat-number'>$failed</div><div class='stat-label'>Failed</div></div>
<div class='stat-box manual'><div class='stat-number'>$manual</div><div class='stat-label'>Manual</div></div>
</div></div>
<table><thead><tr><th>Control ID</th><th>Title</th><th>Status</th><th>Actual Value</th></tr></thead><tbody>
"@
  
  foreach($r in $Results){
    $htmlContent += "<tr><td>$($r.Id)</td><td>$($r.Title)</td><td class='$($r.Status)'>$($r.Status)</td><td>$($r.ActualValue)</td></tr>`n"
  }
  
  $htmlContent += "</tbody></table></body></html>"
  $htmlContent | Out-File -FilePath $html -Encoding UTF8
  Write-Host "HTML: $html" -ForegroundColor Green
}

function Write-DOC([System.Collections.Generic.List[object]]$Results,[string]$OutDir,[object]$SystemInfo){
  $doc = Join-Path $OutDir 'vijenex-cis-results.doc'
  $passed = @($Results | Where-Object { $_.Passed }).Count
  $failed = @($Results | Where-Object { $_.Status -eq 'FAIL' }).Count
  $manual = @($Results | Where-Object { $_.Status -eq 'MANUAL' }).Count
  
  $docContent = @"
<html xmlns:o='urn:schemas-microsoft-com:office:office' xmlns:w='urn:schemas-microsoft-com:office:word' xmlns='http://www.w3.org/TR/REC-html40'>
<head><meta charset='UTF-8'><title>CIS Audit Report</title></head><body>
<h1>Windows Server 2016 CIS Audit Report</h1>
<p><b>Host:</b> $($SystemInfo.Caption)</p>
<p><b>Computer:</b> $($SystemInfo.ComputerName)</p>
<p><b>IP Address:</b> $($SystemInfo.IPAddress)</p>
<p><b>Scan Date:</b> $($SystemInfo.ScanDate)</p>
<p><b>DC Mode:</b> $($SystemInfo.IsDC)</p>
<h2>Executive Summary</h2>
<table border='1' cellpadding='5' cellspacing='0' style='border-collapse:collapse'>
<tr><td><b>Total Controls</b></td><td>$($Results.Count)</td></tr>
<tr><td><b>Passed</b></td><td>$passed</td></tr>
<tr><td><b>Failed</b></td><td>$failed</td></tr>
<tr><td><b>Manual</b></td><td>$manual</td></tr>
</table>
<h2>Detailed Results</h2>
<table border='1' cellpadding='5' cellspacing='0' style='border-collapse:collapse'>
<tr><th>Control ID</th><th>Title</th><th>Status</th><th>Actual Value</th></tr>
"@
  
  foreach($r in $Results){
    $docContent += "<tr><td>$($r.Id)</td><td>$($r.Title)</td><td>$($r.Status)</td><td>$($r.ActualValue)</td></tr>`n"
  }
  
  $docContent += "</table></body></html>"
  $docContent | Out-File -FilePath $doc -Encoding UTF8
  Write-Host "DOC: $doc" -ForegroundColor Green
}

# Main execution
Assert-Admin
$systemInfo = Get-OSInfo

Write-Host "`n=============================================================" -ForegroundColor Cyan
Write-Host "         Windows Server 2016 CIS Scanner v2.0              " -ForegroundColor Cyan
Write-Host "              Bug-Fixed Version (No False Positives)        " -ForegroundColor White
Write-Host "=============================================================" -ForegroundColor Cyan
Write-Host "Host: $($systemInfo.Caption)" -ForegroundColor White
Write-Host "DC Mode: $($systemInfo.IsDC)" -ForegroundColor Yellow
Write-Host "`n"

# Load milestones
$milestoneFolder = Join-Path (Split-Path $PSScriptRoot) "milestones"
if (-not (Test-Path $milestoneFolder)) {
  throw "Milestones folder not found: $milestoneFolder"
}

if (-not $Milestones) {
  $Milestones = Get-ChildItem -Path $milestoneFolder -Filter *.ps1 | Select-Object -ExpandProperty Name
}

foreach ($m in $Milestones) {
  $p = Join-Path $milestoneFolder $m
  if (Test-Path $p) { 
    Write-Host "Loading $m ..." -ForegroundColor Cyan
    . $p 
  }
}

Write-Host "Loaded rules: $($Global:Rules.Count)" -ForegroundColor Yellow

# Export data
$seceditPath = Export-SecEdit
$secMap = Parse-InfFile -Path $seceditPath
$ctx = @{ SecEdit = $secMap }

# Filter rules based on DC/MS
$rules = $Global:Rules | Where-Object {
  $rule = $_
  $appliesTo = if ($rule.ContainsKey('AppliesTo')) { $rule.AppliesTo } else { 'Both' }
  if ($systemInfo.IsDC -and $appliesTo -eq 'MS') { return $false }
  if (-not $systemInfo.IsDC -and $appliesTo -eq 'DC') { return $false }
  return $true
}

Write-Host "Evaluating $($rules.Count) rules...`n" -ForegroundColor Cyan

# Check for duplicate control IDs BEFORE evaluation
$duplicateCheck = @{}
foreach($rule in $rules) {
  if ($duplicateCheck.ContainsKey($rule.Id)) {
    Write-Warning "DUPLICATE CONTROL ID DETECTED: $($rule.Id)"
    Write-Warning "  First: $($duplicateCheck[$rule.Id])"
    Write-Warning "  Second: $($rule.Title)"
  } else {
    $duplicateCheck[$rule.Id] = $rule.Title
  }
}

# Evaluate
$results = New-Object System.Collections.Generic.List[object]
$seenIds = @{}

foreach($rule in $rules){ 
  # Skip if already evaluated (prevent duplicates in CSV)
  if ($seenIds.ContainsKey($rule.Id)) {
    Write-Warning "Skipping duplicate control: $($rule.Id)"
    continue
  }
  $seenIds[$rule.Id] = $true
  
  $result = Evaluate-Rule -Rule $rule -Context $ctx
  $results.Add($result)
  
  # Display real-time progress
  $status = if($result.Passed){"[PASS]"}else{if($result.Status -eq 'MANUAL'){"[MANUAL]"}else{"[FAIL]"}}
  $statusColor = if($result.Passed){"Green"}else{if($result.Status -eq 'MANUAL'){"Yellow"}else{"Red"}}
  $manualNote = if($result.Status -eq 'MANUAL'){" (Manual Review Required)"}else{""}
  
  Write-Host "[$($result.Id)] $($result.Title)$manualNote" -ForegroundColor White
  Write-Host "    Status: " -NoNewline -ForegroundColor Gray
  Write-Host $status -ForegroundColor $statusColor
  Write-Host ""
}

# Summary
$total = $results.Count
$passed = @($results | Where-Object { $_.Passed }).Count
$manual = @($results | Where-Object { $_.Status -eq 'MANUAL' }).Count
$failed = $total - $passed - $manual
$successRate = if ($total -gt 0) { [math]::Round(($passed / $total) * 100, 1) } else { 0 }

Write-Host "`n" -ForegroundColor White
Write-Host "=============================================================" -ForegroundColor Cyan
Write-Host "                    SCAN COMPLETED                           " -ForegroundColor Cyan
Write-Host "=============================================================" -ForegroundColor Cyan
Write-Host "Total Checks: $total" -ForegroundColor White
Write-Host "Passed: " -NoNewline -ForegroundColor White
Write-Host "$passed" -ForegroundColor Green
Write-Host "Failed: " -NoNewline -ForegroundColor White
Write-Host "$failed" -ForegroundColor Red
Write-Host "Manual: " -NoNewline -ForegroundColor White
Write-Host "$manual" -ForegroundColor Yellow
Write-Host "Success Rate: $successRate%" -ForegroundColor Yellow
Write-Host "=============================================================" -ForegroundColor Cyan
Write-Host "`n" -ForegroundColor White

Write-CSV -Results $results -OutDir $OutputDir -SystemInfo $systemInfo
Write-HTML -Results $results -OutDir $OutputDir -SystemInfo $systemInfo
Write-DOC -Results $results -OutDir $OutputDir -SystemInfo $systemInfo

if ($seceditPath -and (Test-Path $seceditPath)) { 
  Remove-Item $seceditPath -Force -ErrorAction SilentlyContinue 
}

exit $failed
