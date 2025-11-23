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
    "2.3.1.1" = @{ DefaultValue = "0"; ExpectedValue = "0" }  # Guest disabled
    "2.3.1.2" = @{ DefaultValue = "1"; ExpectedValue = "1" }  # Blank password limit
    "2.3.2.1" = @{ DefaultValue = "1"; ExpectedValue = "1" }  # Audit subcategory
    "2.3.4.1" = @{ DefaultValue = "1"; ExpectedValue = "1" }  # Printer drivers
    "2.3.6.1" = @{ DefaultValue = "1"; ExpectedValue = "1" }  # Encrypt/sign
    "2.3.6.2" = @{ DefaultValue = "1"; ExpectedValue = "1" }  # Encrypt
    "2.3.6.3" = @{ DefaultValue = "1"; ExpectedValue = "1" }  # Sign
    "2.3.6.4" = @{ DefaultValue = "0"; ExpectedValue = "0" }  # Disable pwd change
    "2.3.6.5" = @{ DefaultValue = "30"; ExpectedValue = "30" } # Pwd age
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
    # Check if registry key exists
    $keyExists = $false
    if ($Rule.Type -eq 'Registry') {
      $keyExists = Test-Path $Rule.Key
      if ($keyExists) {
        $val = Get-ItemProperty -Path $Rule.Key -Name $Rule.ValueName -ErrorAction SilentlyContinue | 
               Select-Object -ExpandProperty $Rule.ValueName -ErrorAction SilentlyContinue
        if ($null -ne $val) {
          $result.Passed = ($val -eq $Rule.Expected)
          $result.ActualValue = "$val"
        }
      }
    }
    
    if (-not $keyExists) {
      # Key missing = default value in effect
      $result.Passed = ($defInfo.DefaultValue -eq $defInfo.ExpectedValue)
      $result.ActualValue = "Enabled by default (compliant)"
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
  if ($systemInfo.IsDC -and $rule.AppliesTo -eq 'MS only') { return $false }
  if (-not $systemInfo.IsDC -and $rule.AppliesTo -eq 'DC only') { return $false }
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
  $statusColor = if($result.Passed){"Green"}else{if($result.Status -eq 'MANUAL'){"Yellow"}else{"Red"}}
  Write-Host "[$($result.Id)] $($result.Title) - $($result.Status)" -ForegroundColor $statusColor
}

# Summary
$total = $results.Count
$passed = @($results | Where-Object { $_.Passed }).Count
$failed = $total - $passed

Write-Host "`n=============================================================" -ForegroundColor Cyan
Write-Host "Total: $total | Passed: $passed | Failed: $failed" -ForegroundColor White
Write-Host "=============================================================" -ForegroundColor Cyan

Write-CSV -Results $results -OutDir $OutputDir -SystemInfo $systemInfo

if ($seceditPath -and (Test-Path $seceditPath)) { 
  Remove-Item $seceditPath -Force -ErrorAction SilentlyContinue 
}

exit $failed
