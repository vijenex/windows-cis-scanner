<#
  Windows Server 2025 CIS-style Scanner (Audit-only)
  - Loads all *.ps1 rule packs from ../milestones (unless -Milestones passed)
  - Reads live settings via `secedit` and `auditpol`
  - Writes HTML + CSV to -OutputDir (defaults ../reports)
  - No remediation; audit-only
#>

param(
  [string]$OutputDir,
  [string]$Profile = "Level1",
  [string[]]$Milestones,
  [string[]]$Include,
  [string[]]$Exclude,
  [ValidateSet('All','HTML','CSV','PDF','Word')][string[]]$OutputFormat = @('HTML','CSV')
)

# Set default output directory to reports folder in parent directory
if (-not $OutputDir) {
  $OutputDir = Join-Path (Split-Path $PSScriptRoot) "reports"
}

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$Global:Rules = @()

# ===== ALL FUNCTIONS DEFINED FIRST =====
function Assert-Admin {
  $id = [Security.Principal.WindowsIdentity]::GetCurrent()
  $pr = New-Object Security.Principal.WindowsPrincipal($id)
  if (-not $pr.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Run this script as Administrator."
  }
}

function New-Dir([string]$Path){ 
  if (-not (Test-Path $Path)) { [void](New-Item -ItemType Directory -Path $Path) } 
}

function Get-OSInfo { 
  $os=Get-CimInstance Win32_OperatingSystem
  $cs=Get-CimInstance Win32_ComputerSystem
  $net=Get-CimInstance Win32_NetworkAdapterConfiguration | Where-Object {$_.IPEnabled -eq $true} | Select-Object -First 1
  
  # Determine if system is domain-joined or standalone
  $domainRole = $cs.DomainRole
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
  } 
}

function Export-SecEdit { 
  try {
    $tmp = Join-Path $env:TEMP ("secpol-" + [guid]::NewGuid().Guid + ".inf")
    
    # Validate temp path to prevent path traversal
    $resolvedPath = [System.IO.Path]::GetFullPath($tmp)
    if (-not $resolvedPath.StartsWith([System.IO.Path]::GetTempPath())) {
      throw "Invalid temp path detected"
    }
    
    $errFile = Join-Path $env:TEMP ("secpol-err-" + [guid]::NewGuid().Guid + ".txt")
    $result = Start-Process -FilePath "secedit.exe" -ArgumentList "/export", "/cfg", "`"$tmp`"" -Wait -PassThru -NoNewWindow -RedirectStandardError $errFile
    
    if ($result.ExitCode -ne 0) {
      $errContent = if (Test-Path $errFile) { Get-Content $errFile -Raw } else { "Unknown error" }
      Remove-Item $errFile -Force -ErrorAction SilentlyContinue
      throw "secedit export failed with exit code $($result.ExitCode): $errContent"
    }
    
    Remove-Item $errFile -Force -ErrorAction SilentlyContinue
    
    if (-not (Test-Path $tmp)) {
      throw "secedit export did not create expected file"
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

# ===== Helpers for User Rights (Privilege Rights) =====
function Split-PrivilegeValue {
  param([string]$Raw)
  if ([string]::IsNullOrWhiteSpace($Raw)) { return @() }
  $parts = $Raw -split '\s*,\s*' | Where-Object { $_ -and $_.Trim() -ne '' }
  return $parts | ForEach-Object { $_.Trim() }
}

function Resolve-Principal {
  param([string]$Tok)
  try {
    $t = $Tok.Trim().TrimStart('*')
    if ($t -match '^S-\d-\d+-.+$') {
      $sid = New-Object System.Security.Principal.SecurityIdentifier($t)
      $acc = $sid.Translate([System.Security.Principal.NTAccount])
      return ($acc.Value.ToUpperInvariant())
    } else {
      return ($t.ToUpperInvariant())
    }
  } catch {
    return ($Tok.Trim().TrimStart('*').ToUpperInvariant())
  }
}

function Normalize-PrincipalSet {
  param([string[]]$Tokens)
  $hs = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
  foreach ($x in ($Tokens | Where-Object { $_ })) {
    [void]$hs.Add( (Resolve-Principal $x) )
  }
  return $hs
}

function Compare-StringSets {
  param([System.Collections.Generic.HashSet[string]]$Current,
        [System.Collections.Generic.HashSet[string]]$Expected,
        [ValidateSet('Exact','Superset')] [string]$Mode = 'Exact')
  switch ($Mode) {
    'Exact' {
      if ($Current.Count -ne $Expected.Count) { return $false }
      foreach ($e in $Expected) { if (-not $Current.Contains($e)) { return $false } }
      return $true
    }
    'Superset' {
      foreach ($e in $Expected) { if (-not $Current.Contains($e)) { return $false } }
      return $true
    }
  }
}

function Get-PrivilegeRaw {
  param([hashtable]$SecEditMap, [string]$Key)
  if ($SecEditMap.ContainsKey('Privilege Rights') -and $SecEditMap['Privilege Rights'].ContainsKey($Key)) {
    return $SecEditMap['Privilege Rights'][$Key]
  }
  return $null
}

function Get-AuditPolicies {
  $map = @{}
  try {
    $auditpolPath = Get-Command "auditpol.exe" -ErrorAction SilentlyContinue
    if (-not $auditpolPath) {
      Write-Warning "auditpol.exe not found in system PATH"
      return $map
    }
    
    # GUID to subcategory name mapping from CIS benchmark
    $guidMap = @{
      '0cce923f-69ae-11d9-bed3-505054503030' = 'Credential Validation'
      '0cce9242-69ae-11d9-bed3-505054503030' = 'Kerberos Authentication Service'
      '0cce9240-69ae-11d9-bed3-505054503030' = 'Kerberos Service Ticket Operations'
      '0cce9239-69ae-11d9-bed3-505054503030' = 'Application Group Management'
      '0cce9236-69ae-11d9-bed3-505054503030' = 'Computer Account Management'
      '0cce9238-69ae-11d9-bed3-505054503030' = 'Distribution Group Management'
      '0cce923a-69ae-11d9-bed3-505054503030' = 'Other Account Management Events'
      '0cce9237-69ae-11d9-bed3-505054503030' = 'Security Group Management'
      '0cce9235-69ae-11d9-bed3-505054503030' = 'User Account Management'
      '0cce9248-69ae-11d9-bed3-505054503030' = 'PNP Activity'
      '0cce922b-69ae-11d9-bed3-505054503030' = 'Process Creation'
      '0cce923b-69ae-11d9-bed3-505054503030' = 'Directory Service Access'
      '0cce923c-69ae-11d9-bed3-505054503030' = 'Directory Service Changes'
      '0cce9217-69ae-11d9-bed3-505054503030' = 'Account Lockout'
      '0cce9249-69ae-11d9-bed3-505054503030' = 'Group Membership'
      '0cce9216-69ae-11d9-bed3-505054503030' = 'Logoff'
      '0cce9215-69ae-11d9-bed3-505054503030' = 'Logon'
      '0cce921c-69ae-11d9-bed3-505054503030' = 'Other Logon/Logoff Events'
      '0cce921b-69ae-11d9-bed3-505054503030' = 'Special Logon'
      '0cce9244-69ae-11d9-bed3-505054503030' = 'Detailed File Share'
      '0cce9224-69ae-11d9-bed3-505054503030' = 'File Share'
      '0cce9227-69ae-11d9-bed3-505054503030' = 'Other Object Access Events'
      '0cce9245-69ae-11d9-bed3-505054503030' = 'Removable Storage'
      '0cce922f-69ae-11d9-bed3-505054503030' = 'Audit Policy Change'
      '0cce9230-69ae-11d9-bed3-505054503030' = 'Authentication Policy Change'
      '0cce9231-69ae-11d9-bed3-505054503030' = 'Authorization Policy Change'
      '0cce9232-69ae-11d9-bed3-505054503030' = 'MPSSVC Rule-Level Policy Change'
      '0cce9234-69ae-11d9-bed3-505054503030' = 'Other Policy Change Events'
      '0cce9228-69ae-11d9-bed3-505054503030' = 'Sensitive Privilege Use'
      '0cce9213-69ae-11d9-bed3-505054503030' = 'IPsec Driver'
      '0cce9214-69ae-11d9-bed3-505054503030' = 'Other System Events'
      '0cce9210-69ae-11d9-bed3-505054503030' = 'Security State Change'
      '0cce9211-69ae-11d9-bed3-505054503030' = 'Security System Extension'
      '0cce9212-69ae-11d9-bed3-505054503030' = 'System Integrity'
    }
    
    # Query each GUID
    foreach ($guid in $guidMap.Keys) {
      $subcatName = $guidMap[$guid]
      $result = Start-Process -FilePath $auditpolPath.Source -ArgumentList "/get", "/subcategory:{$guid}" -Wait -PassThru -NoNewWindow -RedirectStandardOutput "temp_audit_$guid.txt" -RedirectStandardError "temp_audit_err.txt" 2>$null
      
      if ($result.ExitCode -eq 0 -and (Test-Path "temp_audit_$guid.txt")) {
        $raw = Get-Content "temp_audit_$guid.txt" -Raw
        
        # Extract setting value
        if ($raw -match 'Success and Failure') {
          $map[$subcatName] = 'Success and Failure'
        } elseif ($raw -match '\s+Success\s*$') {
          $map[$subcatName] = 'Success'
        } elseif ($raw -match '\s+Failure\s*$') {
          $map[$subcatName] = 'Failure'
        } elseif ($raw -match 'No Auditing') {
          $map[$subcatName] = 'No Auditing'
        }
        
        Remove-Item "temp_audit_$guid.txt" -Force -ErrorAction SilentlyContinue
      }
    }
    
    Remove-Item "temp_audit_err.txt" -Force -ErrorAction SilentlyContinue
  } catch { }
  return $map
}

function Test-Compare {
  param([Parameter(Mandatory)]$Current,[Parameter(Mandatory)]$Expected,[ValidateSet('Equals','NotEquals','GreaterOrEqual','LessOrEqual')]$Operator)
  
  if ($null -eq $Current) { return $false }
  
  switch ($Operator) {
    'Equals' { $Current -eq $Expected }
    'NotEquals' { $Current -ne $Expected }
    'GreaterOrEqual' { 
      try { [double]$Current -ge [double]$Expected } 
      catch { $false }
    }
    'LessOrEqual' { 
      try { [double]$Current -le [double]$Expected } 
      catch { $false }
    }
  }
}

function Evaluate-Rule([hashtable]$Rule,[hashtable]$Context){
  $result=[pscustomobject]@{
    Id=$Rule.Id
    Title=$Rule.Title
    Section=$Rule.Section
    Profile=$Rule.Profile

    Type=$Rule.Type
    Expected=''
    Current=''
    Passed=$false
    Evidence=''
    Remediation=$Rule.Remediation
    CISReference=if($Rule.ContainsKey('CISReference')){$Rule.CISReference}else{$null}
    CISControlID=if($Rule.ContainsKey('CISControlID')){$Rule.CISControlID}else{$null}
    ReferenceNote=if($Rule.ContainsKey('ReferenceNote')){$Rule.ReferenceNote}else{$null}
  }
  
  try{
    switch ($Rule.Type){
      'SecEdit' {
        $secpol=$Context.SecEdit
        $section=$Rule.SectionName
        $key=$Rule.Key
        $val = if ($secpol.ContainsKey($section) -and $secpol[$section].ContainsKey($key)){ 
          $secpol[$section][$key] 
        } else { 
          $null 
        }
        
        $result.Current = if ($null -eq $val){'<unset>'} else { $val }
        $result.Expected = "$($Rule.Operator) $($Rule.Expected)"
        $result.Passed = Test-Compare -Current $val -Expected $Rule.Expected -Operator $Rule.Operator
        $result.Evidence = "[$section] $key"
      }
      
      'AuditPolicy' {
        $ap=$Context.AuditPolicies
        $sub=$Rule.Subcategory
        $val = if ($ap.ContainsKey($sub)) { $ap[$sub] } else { $null }
        
        $result.Current = if ($null -eq $val){'<unset>'} else { $val }
        $result.Expected = $Rule.Expected
        $result.Passed = ($val -ieq $Rule.Expected)
        $result.Evidence = "auditpol:$sub"
      }
      
      'Composite' {
        $parts=@()
        $ev=@()
        $ok=$true
        $secpol=$Context.SecEdit
        
        foreach($sub in $Rule.AllOf){
          $section=$sub.SectionName
          $key=$sub.Key
          $val = if ($secpol.ContainsKey($section) -and $secpol[$section].ContainsKey($key)){ 
            $secpol[$section][$key] 
          } else { 
            $null 
          }
          
          $pass = Test-Compare -Current $val -Expected $sub.Expected -Operator $sub.Operator
          $ok = $ok -and $pass
          $parts += "$key $($sub.Operator) $($sub.Expected) => current:$val => $([string]$pass)"
          $ev += "[$section] $key"
        }
        
        $result.Passed=$ok
        $result.Expected=($parts -join '; ')
        $result.Current=''
        $result.Evidence=($ev|Select-Object -Unique) -join ', '
      }
      
      'PrivRight' {
        $raw = Get-PrivilegeRaw -SecEditMap $Context.SecEdit -Key $Rule.Key
        $curTokens = Split-PrivilegeValue -Raw $raw
        $curSet = Normalize-PrincipalSet -Tokens $curTokens
        $expSet = Normalize-PrincipalSet -Tokens $Rule.ExpectedPrincipals
        $mode = if ($Rule.SetMode) { $Rule.SetMode } else { 'Exact' }

        # Resolve current tokens for display
        $resolvedCurrent = @()
        foreach ($tok in $curTokens) {
          $resolvedCurrent += Resolve-Principal $tok
        }
        
        $result.Current = if ($resolvedCurrent.Count -gt 0) { ($resolvedCurrent -join ', ') } else { '<none>' }
        $result.Expected = ($Rule.ExpectedPrincipals -join ', ')
        $result.Passed = Compare-StringSets -Current $curSet -Expected $expSet -Mode $mode
        $result.Evidence = "[Privilege Rights] $($Rule.Key)"
      }
      
      'Registry' {
        try {
          $regPath = $Rule.Key
          $valueName = $Rule.ValueName
          $expectedValue = $Rule.Expected
          
          if (Test-Path $regPath) {
            $currentValue = Get-ItemProperty -Path $regPath -Name $valueName -ErrorAction SilentlyContinue | Select-Object -ExpandProperty $valueName -ErrorAction SilentlyContinue
            if ($null -ne $currentValue) {
              $result.Current = $currentValue
              $result.Passed = ($currentValue -eq $expectedValue)
            } else {
              $result.Current = '<not set>'
              $result.Passed = $false
            }
          } else {
            $result.Current = '<key not found>'
            $result.Passed = $false
          }
          
          $result.Expected = $expectedValue
          $result.Evidence = "$regPath\$valueName"
        } catch {
          $result.Current = "<error: $($_.Exception.Message)>"
          $result.Passed = $false
          $result.Evidence = 'registry-error'
        }
      }
      
      'Manual' { 
        $result.Current='<manual-review>'
        $result.Expected=$Rule.Expected
        $result.Passed=$false
        $result.Evidence=$Rule.Evidence 
      }
      
      default { 
        $result.Current='<unsupported>'
        $result.Passed=$false 
      }
    }
  } catch { 
    $result.Current="<error: $($_.Exception.Message)>"
    $result.Passed=$false
    $result.Evidence='exception' 
  }
  
  $result
}

function Write-Reports([System.Collections.Generic.List[object]]$Results,[string]$OutDir,[object]$SystemInfo,[string[]]$Formats){
  New-Dir $OutDir
  $csv = Join-Path $OutDir 'vijenex-cis-results.csv'
  $html = Join-Path $OutDir 'vijenex-cis-report.html'
  $pdf = Join-Path $OutDir 'vijenex-cis-report-pdf.html'
  $word = Join-Path $OutDir 'vijenex-cis-report.docx'
  $outputs = @{}
  
  # Copy CIS documentation if available
  $docFolder = Join-Path (Split-Path $PSScriptRoot) "documentation"
  if (Test-Path $docFolder) {
    $cisDoc = Get-ChildItem -Path $docFolder -Filter "*.pdf" -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($cisDoc) {
      $destDoc = Join-Path $OutDir $cisDoc.Name
      Copy-Item -Path $cisDoc.FullName -Destination $destDoc -Force -ErrorAction SilentlyContinue
      Write-Host "CIS Documentation: $destDoc" -ForegroundColor Green
    }
  }
  
  # Generate CSV if requested
  if ($Formats -contains 'All' -or $Formats -contains 'CSV') {
    # Generate CSV with required columns including Passed status, Current and Expected values
  $csvData = $Results | Select-Object Id, Title, Section, @{Name='Status';Expression={if($_.Passed){'Pass'}else{'Fail'}}}, Passed, Current, Expected, Evidence, CISReference, ReferenceNote, Remediation
  $csvData | Export-Csv -Path $csv -NoTypeInformation -Encoding UTF8
    $outputs['CSV'] = $csv
    Write-Host "CSV:  $csv" -ForegroundColor Green
  }
  
  $total=$Results.Count
  $passed=@($Results|Where-Object{$_.Passed}).Count
  $failed=$total-$passed
  
  $rows = $Results | ForEach-Object {
    $status = if($_.Passed){'[PASS]'}else{'[FAIL]'}
    $cls = if($_.Passed){'pass-row'}else{'fail-row'}
    $cisLink = if($_.CISReference){"<a href='$($_.CISReference)' target='_blank'>CIS Benchmark</a>"}else{'N/A'}
    $refNote = if($_.ReferenceNote){$_.ReferenceNote}else{'Refer to official CIS benchmark documentation'}
    "<tr class='$cls'><td><code>$($_.Id)</code></td><td>$($_.Title)</td><td>$($_.Section)</td><td><b>$status</b></td><td>$cisLink</td><td class='desc'>$refNote</td></tr>"
  }
  
  # Generate HTML if requested
  if ($Formats -contains 'All' -or $Formats -contains 'HTML') {
    $htmlContent = @"
<!doctype html>
<html><head><meta charset="utf-8"/><title>CIS Scan Report - $($SystemInfo.Caption)</title>
<style>body{font-family:Arial,sans-serif;margin:20px}h1{margin-bottom:0}.system-info{background:#f8f9fa;padding:15px;border-radius:5px;margin:15px 0}.system-info h3{margin-top:0}table{border-collapse:collapse;width:100%}th,td{border:1px solid #ccc;padding:6px;text-align:left;font-size:12px}th{background:#f0f0f0}tr.fail-row{background:#ffe6e6}tr.pass-row{background:#e6ffe6}.desc,.impact{max-width:300px;word-wrap:break-word}</style>
</head><body>
<h1>CIS Compliance Audit Report</h1>
<div class="system-info">
<h3>System Information</h3>
<p><strong>Operating System:</strong> $($SystemInfo.Caption)</p>
<p><strong>Version:</strong> $($SystemInfo.Version) (Build $($SystemInfo.BuildNumber))</p>
<p><strong>Computer Name:</strong> $($SystemInfo.ComputerName)</p>
<p><strong>Machine ID:</strong> $($SystemInfo.MachineID)</p>
<p><strong>IP Address:</strong> $($SystemInfo.IPAddress)</p>
<p><strong>Scan Date:</strong> $($SystemInfo.ScanDate)</p>
</div>
<div class="summary"><div>Total checks: <b>$total</b></div><div>Passed: <span class="pass">$passed</span> | Failed: <span class="fail">$failed</span></div></div>
<table><thead><tr><th>ID</th><th>Control</th><th>Section</th><th>Status</th><th>CIS Reference</th><th>Details</th></tr></thead><tbody>
$($rows -join "`n")
</tbody></table>
<p style='margin-top:24px;color:#666;font-size:12px;'>Audit-only; no changes made. Generated by Vijenex Security Platform.</p></body></html>
"@
    Set-Content -Path $html -Value $htmlContent -Encoding UTF8
    $outputs['HTML'] = $html
    Write-Host "HTML: $html" -ForegroundColor Green
  }
  
  # Generate PDF-ready HTML if requested
  if ($Formats -contains 'All' -or $Formats -contains 'PDF') {
    $pdfHtml = @"
<!doctype html>
<html><head><meta charset="utf-8"/><title>CIS Scan Report - $($SystemInfo.Caption)</title>
<style>
@media print {
  body { margin: 0; }
  .no-print { display: none; }
}
body{font-family:Arial,sans-serif;margin:20px;font-size:12px;line-height:1.4}
h1{margin-bottom:10px;color:#333}
.system-info{background:#f8f9fa;padding:15px;border:1px solid #ddd;margin:15px 0;border-radius:5px}
.system-info h3{margin-top:0;font-size:14px;color:#333}
.system-info p{margin:5px 0}
table{border-collapse:collapse;width:100%;margin-top:20px;font-size:11px}
th,td{border:1px solid #333;padding:8px;text-align:left;vertical-align:top}
th{background:#f0f0f0;font-weight:bold}
tr.fail-row{background:#ffe6e6}
tr.pass-row{background:#e6ffe6}
.desc,.impact{max-width:250px;word-wrap:break-word}
.summary{margin:20px 0;padding:15px;background:#f8f9fa;border-radius:5px}
.print-btn{margin:20px 0;padding:10px 20px;background:#007bff;color:white;border:none;border-radius:5px;cursor:pointer;font-size:14px}
.print-btn:hover{background:#0056b3}
</style>
<script>
function printToPDF() {
  window.print();
}
</script>
</head><body>
<div class="no-print">
<button class="print-btn" onclick="printToPDF()">&#x1F5A8; Print to PDF (Ctrl+P)</button>
<p><strong>Instructions:</strong> Click the button above or press Ctrl+P, then select "Save as PDF" as your printer.</p>
</div>
<h1>CIS Compliance Audit Report</h1>
<div class="system-info">
<h3>System Information</h3>
<p><strong>Operating System:</strong> $($SystemInfo.Caption)</p>
<p><strong>Version:</strong> $($SystemInfo.Version) (Build $($SystemInfo.BuildNumber))</p>
<p><strong>Computer Name:</strong> $($SystemInfo.ComputerName)</p>
<p><strong>Machine ID:</strong> $($SystemInfo.MachineID)</p>
<p><strong>IP Address:</strong> $($SystemInfo.IPAddress)</p>
<p><strong>Scan Date:</strong> $($SystemInfo.ScanDate)</p>
</div>
<div class="summary">
<h3>Summary</h3>
<p><strong>Total Checks:</strong> $total</p>
<p><strong>Passed:</strong> $passed</p>
<p><strong>Failed:</strong> $failed</p>
<p><strong>Success Rate:</strong> $([math]::Round(($passed/$total)*100,1))%</p>
</div>
<h3>Detailed Results</h3>
<table>
<thead><tr><th>ID</th><th>Control</th><th>Section</th><th>Status</th><th>Description</th><th>Impact</th><th>Remediation</th></tr></thead>
<tbody>
$($rows -join "`n")
</tbody></table>
<div style="margin-top:30px;color:#666;font-size:10px;text-align:center;">
<p>Audit-only scan; no changes made. Generated by Vijenex Security Platform.</p>
<p>Report generated on $($SystemInfo.ScanDate) for $($SystemInfo.ComputerName)</p>
</div>
</body></html>
"@
    Set-Content -Path $pdf -Value $pdfHtml -Encoding UTF8
    $outputs['PDF'] = $pdf
    Write-Host "PDF:  $pdf (Open in browser, click Print to PDF button)" -ForegroundColor Green
  }
  
  # Generate Word DOCX document if requested
  if ($Formats -contains 'All' -or $Formats -contains 'Word') {
    # Generate Word-compatible HTML (skip COM to avoid hanging)
      $wordHtml = @"
<!DOCTYPE html>
<html><head><meta charset="utf-8"/><title>CIS Compliance Audit Report</title>
<style>body{font-family:Calibri,Arial,sans-serif;margin:40px;line-height:1.4}h1{color:#2E75B6;border-bottom:2px solid #2E75B6;padding-bottom:10px}h2{color:#2E75B6;margin-top:30px}.info-table{border-collapse:collapse;margin:20px 0}.info-table td{padding:8px;border:1px solid #ddd}.info-table td:first-child{background:#f0f0f0;font-weight:bold;width:150px}table{border-collapse:collapse;width:100%;margin-top:20px;font-size:11px}th,td{border:1px solid #333;padding:6px;text-align:left;vertical-align:top}th{background:#2E75B6;color:white;font-weight:bold}.pass{background:#d4edda;color:#155724}.fail{background:#f8d7da;color:#721c24}</style>
</head><body>
<h1>CIS Compliance Audit Report</h1>
<h2>System Information</h2>
<table class="info-table">
<tr><td>Operating System</td><td>$($SystemInfo.Caption)</td></tr>
<tr><td>Version</td><td>$($SystemInfo.Version) (Build $($SystemInfo.BuildNumber))</td></tr>
<tr><td>Computer Name</td><td>$($SystemInfo.ComputerName)</td></tr>
<tr><td>Machine ID</td><td>$($SystemInfo.MachineID)</td></tr>
<tr><td>IP Address</td><td>$($SystemInfo.IPAddress)</td></tr>
<tr><td>Scan Date</td><td>$($SystemInfo.ScanDate)</td></tr>
</table>
<h2>Summary</h2>
<table class="info-table">
<tr><td>Total Checks</td><td>$total</td></tr>
<tr><td>Passed</td><td class="pass">$passed</td></tr>
<tr><td>Failed</td><td class="fail">$failed</td></tr>
<tr><td>Success Rate</td><td>$([math]::Round(($passed/$total)*100,1))%</td></tr>
</table>
<h2>Detailed Results</h2>
<table>
<thead><tr><th>ID</th><th>Control</th><th>Section</th><th>Status</th><th>Description</th><th>Impact</th><th>Remediation</th></tr></thead>
<tbody>
"@
      
      foreach ($result in $Results) {
        $statusClass = if($result.Passed){"pass"}else{"fail"}
        $status = if($result.Passed){"Pass"}else{"Fail"}
        $refNote = if($result.ReferenceNote){$result.ReferenceNote}else{"N/A"}
        $evidence = if($result.Evidence){$result.Evidence}else{"N/A"}
        $wordHtml += "<tr class='$statusClass'><td>$($result.Id)</td><td>$($result.Title)</td><td>$($result.Section)</td><td>$status</td><td>$refNote</td><td>$evidence</td><td>$($result.Remediation)</td></tr>`n"
      }
      
      $wordHtml += @"
</tbody></table>
<p style="margin-top:30px;color:#666;font-size:12px;text-align:center;">
Audit-only scan; no changes made. Generated by Vijenex Security Platform.<br>
Report generated on $($SystemInfo.ScanDate) for $($SystemInfo.ComputerName)
</p>
<p style="color:#666;font-size:10px;text-align:center;">Note: Open this file in Microsoft Word and save as DOCX for native Word format.</p>
</body></html>
"@
    
    Set-Content -Path $word -Value $wordHtml -Encoding UTF8
    $outputs['Word'] = $word
    Write-Host "Word: $word (HTML format - open in Word to save as DOCX)" -ForegroundColor Yellow
  }
  
  return $outputs
}

# ===== MAIN EXECUTION =====
Assert-Admin
New-Dir $OutputDir

# Display Verityx CLI signature
Write-Host "`n" -ForegroundColor White
Write-Host "=============================================================" -ForegroundColor Cyan
Write-Host "                        VIJENEX                              " -ForegroundColor Cyan
Write-Host "      Windows Server 2025 CIS Compliance Scanner           " -ForegroundColor White
Write-Host "                 (Standalone/Workgroup)                     " -ForegroundColor White
Write-Host "           Powered by Vijenex Security Platform             " -ForegroundColor Yellow
Write-Host "        https://github.com/vijenex/windows-cis-scanner       " -ForegroundColor Gray
Write-Host "=============================================================" -ForegroundColor Cyan
Write-Host "`n" -ForegroundColor White

$systemInfo=Get-OSInfo

# Validate Windows version
$expectedBuild = 26100  # Windows Server 2025
if ($systemInfo.BuildNumber -lt ($expectedBuild - 1000) -or $systemInfo.BuildNumber -gt ($expectedBuild + 1000)) {
  Write-Host "`n" -ForegroundColor Red
  Write-Host "=============================================================" -ForegroundColor Red
  Write-Host "                VERSION MISMATCH WARNING                     " -ForegroundColor Yellow
  Write-Host "=============================================================" -ForegroundColor Red
  Write-Host "Expected: Windows Server 2025 (Build ~$expectedBuild)" -ForegroundColor Yellow
  Write-Host "Detected: Build $($systemInfo.BuildNumber)" -ForegroundColor Yellow
  Write-Host "`nYou may be running the wrong scanner version!" -ForegroundColor Red
  Write-Host "Please use the correct folder for your Windows version." -ForegroundColor Yellow
  Write-Host "=============================================================" -ForegroundColor Red
  Write-Host "`n" -ForegroundColor White
  
  $response = Read-Host "Continue anyway? (yes/no)"
  if ($response -ne 'yes') {
    throw "Scan cancelled due to version mismatch"
  }
}

Write-Host "Scanning host: $($systemInfo.Caption) ($($systemInfo.Version) build $($systemInfo.BuildNumber))" -ForegroundColor Cyan
Write-Host "Machine: $($systemInfo.ComputerName) | IP: $($systemInfo.IPAddress) | Date: $($systemInfo.ScanDate)" -ForegroundColor Gray

# Load milestones (all if not specified)
$milestoneFolder = Join-Path (Split-Path $PSScriptRoot) "milestones"

# Validate milestone folder exists
if (-not (Test-Path $milestoneFolder)) {
  throw "Milestones folder not found: $milestoneFolder"
}

if (-not $Milestones -or $Milestones.Count -eq 0) {
  $Milestones = Get-ChildItem -Path $milestoneFolder -Filter *.ps1 -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name
  # Ensure all milestone files are loaded in order
  $Milestones = $Milestones | Sort-Object { [int]($_ -replace '\D') }
}

foreach ($m in $Milestones) {
  # Validate milestone filename to prevent path traversal
  if ($m -match '[\\/\.]\.' -or $m -notmatch '^[a-zA-Z0-9_-]+\.ps1$') {
    Write-Warning "Invalid milestone filename: $m"
    continue
  }
  
  $p = Join-Path $milestoneFolder $m
  
  # Ensure the resolved path is within the milestones folder
  $resolvedPath = [System.IO.Path]::GetFullPath($p)
  $resolvedMilestoneFolder = [System.IO.Path]::GetFullPath($milestoneFolder)
  
  if (-not $resolvedPath.StartsWith($resolvedMilestoneFolder)) {
    Write-Warning "Path traversal attempt detected: $m"
    continue
  }
  
  if (Test-Path $p) { 
    Write-Host "Loading $m ..." -ForegroundColor Cyan
    try {
      . $p 
    } catch {
      Write-Warning "Failed to load milestone $m : $($_.Exception.Message)"
    }
  } else { 
    Write-Warning "Milestone not found: $m" 
  }
}

Write-Host "Loaded rules: $($Global:Rules.Count)" -ForegroundColor Yellow

# Get system data
$seceditPath = Export-SecEdit
$secMap = Parse-InfFile -Path $seceditPath
$auditMap = Get-AuditPolicies
$ctx = @{ SecEdit=$secMap; AuditPolicies=$auditMap }

# Filter rules
$rules = $Global:Rules
if ($Profile){ 
  $rules = $rules | Where-Object { $_.Profile -eq $Profile } 
}
if ($Include){ 
  $hi=[System.Collections.Generic.HashSet[string]]::new($Include,[System.StringComparer]::OrdinalIgnoreCase)
  $rules = $rules | Where-Object { $hi.Contains($_.Id) } 
}
if ($Exclude){ 
  $hx=[System.Collections.Generic.HashSet[string]]::new($Exclude,[System.StringComparer]::OrdinalIgnoreCase)
  $rules = $rules | Where-Object { -not $hx.Contains($_.Id) } 
}
$rules = @($rules)

Write-Host "Evaluating $($rules.Count) rules..." -ForegroundColor Cyan
Write-Host ""

# Evaluate rules
$results = New-Object System.Collections.Generic.List[object]
foreach($rule in $rules){ 
  $result = Evaluate-Rule -Rule $rule -Context $ctx
  $results.Add($result)
  
  # Display real-time progress like Linux scanner
  $status = if($result.Passed){"[PASS]"}else{"[FAIL]"}
  $statusColor = if($result.Passed){"Green"}else{"Red"}
  $manualNote = if($result.Type -eq 'Manual'){" (Manual Review Required)"}else{""}
  
  Write-Host "[$($result.Id)] $($result.Title)$manualNote" -ForegroundColor White
  Write-Host "    Status: " -NoNewline -ForegroundColor Gray
  Write-Host $status -ForegroundColor $statusColor
  if($result.Evidence){ Write-Host "    Evidence: $($result.Evidence)" -ForegroundColor Gray }
  Write-Host ""
}

# Display summary like Linux scanner
$totalChecks = $results.Count
$passedChecks = @($results | Where-Object { $_.Passed }).Count
$failedChecks = $totalChecks - $passedChecks
$successRate = if ($totalChecks -gt 0) { [math]::Round(($passedChecks / $totalChecks) * 100, 1) } else { 0 }

Write-Host "`n" -ForegroundColor White
Write-Host "=============================================================" -ForegroundColor Cyan
Write-Host "                    SCAN COMPLETED                           " -ForegroundColor Cyan
Write-Host "=============================================================" -ForegroundColor Cyan
Write-Host "Total Checks: $totalChecks" -ForegroundColor White
Write-Host "Passed: " -NoNewline -ForegroundColor White
Write-Host "$passedChecks" -ForegroundColor Green
Write-Host "Failed: " -NoNewline -ForegroundColor White
Write-Host "$failedChecks" -ForegroundColor Red
Write-Host "Success Rate: $successRate%" -ForegroundColor Yellow
Write-Host "=============================================================" -ForegroundColor Cyan
Write-Host "`n" -ForegroundColor White

# Handle output format parameter
if ($OutputFormat -contains 'All') {
  $formats = @('HTML','CSV','PDF','Word')
} else {
  $formats = $OutputFormat
}

# Generate reports
$paths = Write-Reports -Results $results -OutDir $OutputDir -SystemInfo $systemInfo -Formats $formats

# Cleanup
if ($seceditPath -and (Test-Path $seceditPath)) { 
  try {
    Remove-Item $seceditPath -Force -ErrorAction SilentlyContinue 
  } catch {
    Write-Warning "Failed to cleanup temporary file: $seceditPath"
  }
}

exit (@($results | Where-Object { -not $_.Passed }).Count)
